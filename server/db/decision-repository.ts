import {
  DECISION_RECORD_COLUMNS,
  parseDecisionPayload,
  serializeDecisionExtras,
} from '../normalized-record';
import { deriveDecisionIndexValues, deriveDecisionIndexValuesFromRecord } from '../record-index';
import { normalizeIsoTimestamp } from '../utils/date-time';
import { readOptionalString, runChunkedIdMutation } from './connection';
import type { SearchIndexRepository } from './search-index-repository';
import {
  DECISION_DUPLICATE_RANK_VERSION,
  type CountRow,
  type Database,
  type DecisionDataRow,
  type DecisionDuplicateKeyRow,
  type DecisionInsertParams,
  type DecisionUpdateParams,
  type IdRow,
  type SqliteStatement,
} from './types';

export interface DecisionRepositoryOptions {
  searchIndex: SearchIndexRepository;
  getPrimaryInstanceId?: () => string;
  hasTombstone?: (tombstoneId: string, alertId?: string | number) => boolean;
  resolveAlertInternalId?: (instanceId: string, upstreamId: string | number) => number;
  getAlertInternalId?: (instanceId: string, upstreamId: string | number) => number | null;
}

export class DecisionRepository {
  private decisionDuplicateFlagsDirty = true;
  private decisionDuplicateFlagsInitialized = false;
  private lastDecisionDuplicateRefreshAt: string | null = null;
  private ownsDecisionDuplicateDirtyMarker = false;
  private decisionDuplicateDirtyKeys = new Map<string, DecisionDuplicateKeyRow>();

  private readonly insertDecisionStatement: SqliteStatement;
  private readonly updateDecisionStatement: SqliteStatement;
  private readonly getAllDecisionsStatement: SqliteStatement;
  private readonly getActiveDecisionsStatement: SqliteStatement;
  private readonly getActiveAlertIdsStatement: SqliteStatement;
  private readonly getDecisionsSinceStatement: SqliteStatement;
  private readonly deleteDecisionStatement: SqliteStatement;
  private readonly getDecisionByIdStatement: SqliteStatement;
  private readonly getDecisionIdsByAlertIdStatement: SqliteStatement;
  private readonly getActiveDecisionByValueStatement: SqliteStatement;
  private readonly deleteDecisionsByAlertIdStatement: SqliteStatement;
  private readonly countDecisionsStatement: SqliteStatement;

  private searchIndex: SearchIndexRepository;
  private options: DecisionRepositoryOptions;

  constructor(
    private readonly db: Database,
    options: DecisionRepositoryOptions,
  ) {
    this.options = options;
    this.searchIndex = options.searchIndex;

    this.countDecisionsStatement = this.db.query('SELECT COUNT(*) as count FROM decisions');

    this.insertDecisionStatement = this.db.query(`
      INSERT INTO decisions (
        id, instance_id, upstream_id, uuid, alert_id, alert_upstream_id, created_at, stop_at, value, type, origin, scenario, duration, scope, extra_data, raw_data,
        country, country_name, region, city, as_name, target, machine, simulated, search_text, is_duplicate
      )
      VALUES (
        $internal_id, $instance_id, $id, $uuid, $internal_alert_id, $alert_id, $created_at, $stop_at, $value, $type, $origin, $scenario, $duration, $scope, $extra_data, NULL,
        $country, $country_name, $region, $city, $as_name, $target, $machine, $simulated, $search_text, 0
      )
      ON CONFLICT(instance_id, upstream_id) DO UPDATE SET
        uuid = excluded.uuid,
        alert_id = excluded.alert_id,
        created_at = excluded.created_at,
        stop_at = excluded.stop_at,
        value = excluded.value,
        type = excluded.type,
        origin = excluded.origin,
        scenario = excluded.scenario,
        duration = excluded.duration,
        scope = excluded.scope,
        extra_data = excluded.extra_data,
        raw_data = NULL,
        country = excluded.country,
        country_name = excluded.country_name,
        region = excluded.region,
        city = excluded.city,
        as_name = excluded.as_name,
        target = excluded.target,
        machine = excluded.machine,
        simulated = excluded.simulated,
        search_text = excluded.search_text,
        is_duplicate = 0
      WHERE decisions.uuid IS NOT excluded.uuid
        OR decisions.alert_id IS NOT excluded.alert_id
        OR decisions.created_at IS NOT excluded.created_at
        OR decisions.stop_at IS NOT excluded.stop_at
        OR decisions.value IS NOT excluded.value
        OR decisions.type IS NOT excluded.type
        OR decisions.origin IS NOT excluded.origin
        OR decisions.scenario IS NOT excluded.scenario
        OR decisions.duration IS NOT excluded.duration
        OR decisions.scope IS NOT excluded.scope
        OR decisions.extra_data IS NOT excluded.extra_data
        OR decisions.raw_data IS NOT NULL
        OR decisions.country IS NOT excluded.country
        OR decisions.country_name IS NOT excluded.country_name
        OR decisions.region IS NOT excluded.region
        OR decisions.city IS NOT excluded.city
        OR decisions.as_name IS NOT excluded.as_name
        OR decisions.target IS NOT excluded.target
        OR decisions.machine IS NOT excluded.machine
        OR decisions.simulated IS NOT excluded.simulated
        OR decisions.search_text IS NOT excluded.search_text
    `);

    this.updateDecisionStatement = this.db.query(`
      UPDATE decisions SET
        stop_at = $stop_at,
        duration = $duration,
        scope = $scope,
        extra_data = $extra_data,
        raw_data = NULL,
        country = $country,
        country_name = $country_name,
        region = $region,
        city = $city,
        as_name = $as_name,
        target = $target,
        machine = $machine,
        simulated = $simulated,
        search_text = $search_text
      WHERE id = $id
    `);

    this.getAllDecisionsStatement = this.db.query(`
      SELECT ${DECISION_RECORD_COLUMNS} FROM decisions
      ORDER BY stop_at DESC
    `);
    this.getActiveDecisionsStatement = this.db.query(`
      SELECT ${DECISION_RECORD_COLUMNS} FROM decisions
      WHERE stop_at > $now
      ORDER BY stop_at DESC
    `);
    this.getActiveAlertIdsStatement = this.db.query(`
      SELECT DISTINCT active.alert_id AS id
      FROM decisions AS active
      WHERE active.stop_at > $now
        AND active.alert_id IS NOT NULL
        AND EXISTS (
          SELECT 1
          FROM alerts
          WHERE alerts.id = active.alert_id
            AND alerts.created_at >= $since
        )
    `);

    this.getDecisionsSinceStatement = this.db.query(`
      SELECT ${DECISION_RECORD_COLUMNS} FROM decisions
      WHERE created_at >= $since OR stop_at > $now
      ORDER BY stop_at DESC
    `);

    this.deleteDecisionStatement = this.db.query('DELETE FROM decisions WHERE id = $id');
    this.getDecisionByIdStatement = this.db.query(`SELECT ${DECISION_RECORD_COLUMNS} FROM decisions WHERE id = $id`);
    this.getDecisionIdsByAlertIdStatement = this.db.query('SELECT id FROM decisions WHERE alert_id = $alert_id');
    this.getActiveDecisionByValueStatement = this.db.query(`
      SELECT ${DECISION_RECORD_COLUMNS} FROM decisions
      WHERE value = $value AND stop_at > $now AND id NOT LIKE 'dup\\_%' ESCAPE '\\'
      ORDER BY stop_at DESC
      LIMIT 1
    `);
    this.deleteDecisionsByAlertIdStatement = this.db.query('DELETE FROM decisions WHERE alert_id = $alert_id');
  }

  setOptions(options: Partial<DecisionRepositoryOptions>): void {
    this.options = { ...this.options, ...options };
    if (options.searchIndex) this.searchIndex = options.searchIndex;
  }

  resolveDecisionInternalId(instanceId: string, upstreamId: string | number): string {
    const existing = this.db.prepare('SELECT id FROM decisions WHERE instance_id = ? AND upstream_id = ?')
      .get(instanceId, String(upstreamId)) as { id: string } | undefined;
    if (existing) return String(existing.id);
    const rawId = String(upstreamId);
    const primaryId = this.options.getPrimaryInstanceId ? this.options.getPrimaryInstanceId() : 'default';
    const owner = this.db.prepare('SELECT instance_id FROM decisions WHERE id = ?').get(rawId) as { instance_id: string } | undefined;
    return instanceId === primaryId && !owner ? rawId : `${instanceId}\u001f${rawId}`;
  }

  insertDecision(params: DecisionInsertParams): boolean {
    const instanceId = params.$instance_id || 'default';
    const tombstoneId = `${instanceId}\u0000${params.$alert_id}`;
    if (this.options.hasTombstone && this.options.hasTombstone(tombstoneId, params.$alert_id)) {
      return false;
    }
    const rawData = params.$raw_data || '{}';
    const decision = params.$record || parseDecisionPayload(rawData);
    const fallback = {
      value: params.$value,
      type: params.$type,
      origin: params.$origin,
      scenario: params.$scenario,
    };
    const index = decision
      ? deriveDecisionIndexValuesFromRecord(decision, fallback)
      : deriveDecisionIndexValues(rawData, fallback);
    const { $record, $raw_data: _rawData, ...dbParams } = params;
    const internalAlertId = this.options.resolveAlertInternalId
      ? this.options.resolveAlertInternalId(instanceId, params.$alert_id)
      : Number(params.$alert_id);
    const result = this.insertDecisionStatement.run({
      ...dbParams,
      $id: String(params.$id),
      $alert_id: String(params.$alert_id),
      $instance_id: instanceId,
      $internal_id: this.resolveDecisionInternalId(instanceId, params.$id),
      $internal_alert_id: internalAlertId,
      $created_at: normalizeIsoTimestamp(params.$created_at),
      $stop_at: normalizeIsoTimestamp(params.$stop_at),
      $value: params.$value ?? readOptionalString(decision?.value),
      $type: params.$type ?? readOptionalString(decision?.type),
      $origin: params.$origin ?? readOptionalString(decision?.origin),
      $scenario: params.$scenario ?? readOptionalString(decision?.scenario),
      $duration: readOptionalString(decision?.duration),
      $scope: readOptionalString(decision?.scope),
      $extra_data: serializeDecisionExtras(decision),
      $country: index.country,
      $country_name: index.countryName,
      $region: index.region,
      $city: index.city,
      $as_name: index.asName,
      $target: index.target,
      $machine: index.machine,
      $simulated: index.simulated,
      $search_text: index.searchText,
    });
    if (result.changes > 0) {
      this.markDecisionDuplicateKey(params.$value ?? readOptionalString(decision?.value), index.simulated);
      this.searchIndex.upsertDecisionSearchIndex(this.resolveDecisionInternalId(instanceId, params.$id), index.searchText);
      return true;
    }
    return false;
  }

  updateDecision(params: DecisionUpdateParams): void {
    const existing = this.getDecisionById(params.$id);
    if (existing) this.markDecisionDuplicateKey(existing.value, existing.simulated);
    const decision = parseDecisionPayload(params.$raw_data);
    const fallback = existing ? {
      value: existing.value,
      type: existing.type,
      origin: existing.origin,
      scenario: existing.scenario,
    } : {};
    const index = decision
      ? deriveDecisionIndexValuesFromRecord(decision, fallback)
      : deriveDecisionIndexValues(params.$raw_data, fallback);
    this.updateDecisionStatement.run({
      $id: params.$id,
      $stop_at: normalizeIsoTimestamp(params.$stop_at),
      $duration: readOptionalString(decision?.duration) ?? existing?.duration ?? null,
      $scope: readOptionalString(decision?.scope) ?? existing?.scope ?? null,
      $extra_data: serializeDecisionExtras(decision),
      $country: index.country,
      $country_name: index.countryName,
      $region: index.region,
      $city: index.city,
      $as_name: index.asName,
      $target: index.target,
      $machine: index.machine,
      $simulated: index.simulated,
      $search_text: index.searchText,
    });
    this.markDecisionDuplicateKey(existing?.value ?? readOptionalString(decision?.value), index.simulated);
    this.searchIndex.upsertDecisionSearchIndex(params.$id, index.searchText);
  }

  getAllDecisions(): DecisionDataRow[] {
    return this.getAllDecisionsStatement.all() as DecisionDataRow[];
  }

  getActiveDecisions(now: string): DecisionDataRow[] {
    return this.getActiveDecisionsStatement.all({ $now: now }) as DecisionDataRow[];
  }

  deleteActiveAlertsMissing(keepIds: Array<string | number>, now: string, since: string): { alerts: number; decisions: number } {
    const keepSet = new Set(keepIds.map(String));
    const rows = this.getActiveAlertIdsStatement.all({ $now: now, $since: since }) as IdRow[];
    const staleIds = rows
      .map((row) => String(row.id))
      .filter((id) => !keepSet.has(id));

    this.searchIndex.deleteDecisionSearchIndexesByAlertIds(staleIds);
    this.markDecisionDuplicateKeysByAlertIds(staleIds);
    const decisions = runChunkedIdMutation(this.db, 'DELETE FROM decisions WHERE alert_id IN', staleIds);
    const alerts = runChunkedIdMutation(this.db, 'DELETE FROM alerts WHERE id IN', staleIds);
    this.searchIndex.deleteAlertSearchIndexes(staleIds);
    return { alerts, decisions };
  }

  getDecisionsSince(since: string, now: string): DecisionDataRow[] {
    return this.getDecisionsSinceStatement.all({ $since: since, $now: now }) as DecisionDataRow[];
  }

  deleteOldDecisions(cutoff: string, limit?: number): number {
    if (limit !== undefined) {
      const deleteBatch = this.db.transaction((threshold: string) => {
        const ids = (
          this.db.prepare('SELECT id FROM decisions WHERE stop_at < ? LIMIT ?').all(threshold, limit) as IdRow[]
        ).map((row) => String(row.id));
        this.searchIndex.deleteDecisionSearchIndexes(ids);
        return runChunkedIdMutation(this.db, 'DELETE FROM decisions WHERE id IN', ids);
      });
      return deleteBatch(cutoff);
    }

    const cleanup = this.db.transaction((threshold: string) => {
      if (this.searchIndex.searchIndexAvailable) {
        this.db.prepare(`
          DELETE FROM decisions_fts
          WHERE rowid IN (
            SELECT search_rows.fts_rowid
            FROM decision_fts_rows AS search_rows
            JOIN decisions ON decisions.id = search_rows.decision_id
            WHERE decisions.stop_at < ?
          )
        `).run(threshold);
        this.db.prepare(`
          DELETE FROM decision_fts_rows
          WHERE decision_id IN (
            SELECT id
            FROM decisions
            WHERE stop_at < ?
          )
        `).run(threshold);
      }

      return this.db.prepare('DELETE FROM decisions WHERE stop_at < ?').run(threshold).changes;
    });

    return cleanup(cutoff);
  }

  deleteDecision(id: string | number): void {
    const existing = this.getDecisionById(id);
    if (existing) this.markDecisionDuplicateKey(existing.value, existing.simulated);
    this.deleteDecisionStatement.run({ $id: String(id) });
    this.searchIndex.deleteDecisionSearchIndex(id);
  }

  deleteCachedDecisions(ids: Array<string | number>): number {
    const normalizedIds = ids.map(String);
    this.markDecisionDuplicateKeysByIds(normalizedIds);
    const changes = runChunkedIdMutation(this.db, 'DELETE FROM decisions WHERE id IN', normalizedIds);
    this.searchIndex.deleteDecisionSearchIndexes(normalizedIds);
    return changes;
  }

  getDecisionById(id: string | number): DecisionDataRow | null {
    return (this.getDecisionByIdStatement.get({ $id: String(id) }) as DecisionDataRow | null) || null;
  }

  getDecisionInternalId(instanceId: string, upstreamId: string | number): string | null {
    const row = this.db.prepare('SELECT id FROM decisions WHERE instance_id = ? AND upstream_id = ?')
      .get(instanceId, String(upstreamId)) as { id: string } | undefined;
    return row ? String(row.id) : null;
  }

  deleteDecisionByInstanceId(instanceId: string, upstreamId: string | number): void {
    const internalId = this.getDecisionInternalId(instanceId, upstreamId);
    if (internalId !== null) this.deleteDecision(internalId);
  }

  getDecisionIdsByAlertId(alertId: string | number, instanceId?: string): string[] {
    const internalAlertId = instanceId && this.options.getAlertInternalId
      ? this.options.getAlertInternalId(instanceId, alertId)
      : alertId;
    if (internalAlertId === null) return [];
    if (instanceId) {
      return (this.db.prepare(`
        SELECT COALESCE(upstream_id, CAST(id AS TEXT)) AS id
        FROM decisions
        WHERE instance_id = ? AND alert_id = ?
      `).all(instanceId, internalAlertId) as Array<{ id: string | number }>).map((row) => String(row.id));
    }
    return (this.getDecisionIdsByAlertIdStatement.all({ $alert_id: internalAlertId }) as Array<{ id: string | number }>)
      .map((row) => String(row.id));
  }

  getDecisionDataByAlertIds(alertIds: Array<string | number>): Map<string, DecisionDataRow[]> {
    const result = new Map<string, DecisionDataRow[]>();
    const uniqueIds = Array.from(new Set(alertIds.map(String)));
    for (let offset = 0; offset < uniqueIds.length; offset += 900) {
      const chunk = uniqueIds.slice(offset, offset + 900);
      const placeholders = chunk.map(() => '?').join(',');
      const rows = this.db.prepare(`
        SELECT ${DECISION_RECORD_COLUMNS}
        FROM decisions
        WHERE alert_id IN (${placeholders})
        ORDER BY created_at DESC, id DESC
      `).all(...chunk) as DecisionDataRow[];
      for (const row of rows) {
        const key = String(row.alert_id);
        const items = result.get(key);
        if (items) items.push(row);
        else result.set(key, [row]);
      }
    }
    return result;
  }

  deleteDecisionsByAlertIdExcept(alertId: string | number, keepIds: string[], instanceId?: string): number {
    const keepSet = new Set(keepIds.map(String));
    const internalAlertId = instanceId && this.options.getAlertInternalId
      ? this.options.getAlertInternalId(instanceId, alertId)
      : alertId;
    if (internalAlertId === null) return 0;
    const rows = instanceId
      ? this.db.prepare(`
          SELECT id, COALESCE(upstream_id, CAST(id AS TEXT)) AS upstream_id
          FROM decisions
          WHERE instance_id = ? AND alert_id = ?
        `).all(instanceId, internalAlertId) as Array<{ id: string | number; upstream_id: string }>
      : this.getDecisionIdsByAlertIdStatement.all({ $alert_id: internalAlertId }) as Array<{ id: string | number; upstream_id?: string }>;
    const staleIds = rows
      .filter((row) => !keepSet.has(String(row.upstream_id ?? row.id)))
      .map((row) => String(row.id));

    if (staleIds.length === 0) {
      return 0;
    }

    this.markDecisionDuplicateKeysByIds(staleIds);
    let changes = 0;
    const chunkSize = 900;
    for (let offset = 0; offset < staleIds.length; offset += chunkSize) {
      const chunk = staleIds.slice(offset, offset + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      const statement = this.db.prepare(`DELETE FROM decisions WHERE id IN (${placeholders})`);
      changes += statement.run(...chunk).changes;
      this.searchIndex.deleteDecisionSearchIndexes(chunk);
    }

    return changes;
  }

  getDecisionStopAtBatch(ids: string[], instanceId?: string): Map<string, string> {
    const result = new Map<string, string>();
    if (ids.length === 0) return result;

    const chunkSize = 900;
    for (let offset = 0; offset < ids.length; offset += chunkSize) {
      const chunk = ids.slice(offset, offset + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      const statement = instanceId
        ? this.db.prepare(`
            SELECT COALESCE(upstream_id, CAST(id AS TEXT)) AS id, stop_at
            FROM decisions
            WHERE instance_id = ? AND upstream_id IN (${placeholders})
          `)
        : this.db.prepare(`SELECT id, stop_at FROM decisions WHERE id IN (${placeholders})`);
      const rows = statement.all(...(instanceId ? [instanceId, ...chunk] : chunk)) as Array<{ id: string; stop_at: string }>;
      for (const row of rows) {
        result.set(String(row.id), row.stop_at);
      }
    }

    return result;
  }

  getDecisionDataBatch(ids: string[]): Map<string, DecisionDataRow> {
    const result = new Map<string, DecisionDataRow>();
    if (ids.length === 0) return result;

    const uniqueIds = Array.from(new Set(ids));
    const chunkSize = 900;
    for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
      const chunk = uniqueIds.slice(offset, offset + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      const rows = this.db.prepare(`
        SELECT ${DECISION_RECORD_COLUMNS}
        FROM decisions
        WHERE id IN (${placeholders})
      `).all(...chunk) as Array<DecisionDataRow & { id: string | number }>;
      for (const row of rows) {
        result.set(String(row.id), row);
      }
    }

    return result;
  }

  getActiveDecisionByValue(value: string, now: string): DecisionDataRow | null {
    return (this.getActiveDecisionByValueStatement.get({ $value: value, $now: now }) as DecisionDataRow | null) || null;
  }

  deleteDecisionsByAlertId(alertId: string | number): void {
    this.searchIndex.deleteDecisionSearchIndexesByAlertIds([String(alertId)]);
    this.markDecisionDuplicateKeysByAlertIds([String(alertId)]);
    this.deleteDecisionsByAlertIdStatement.run({ $alert_id: alertId });
  }

  countDecisions(instanceId?: string): number {
    if (instanceId) {
      return (this.db.prepare('SELECT COUNT(*) as count FROM decisions WHERE instance_id = ?').get(instanceId) as CountRow).count;
    }
    return (this.countDecisionsStatement.get() as CountRow).count;
  }

  loadDecisionDuplicateRefreshState(): void {
    const rows = this.db.prepare(`
      SELECT key, value
      FROM meta
      WHERE key IN (
        'decision_duplicate_refresh_at',
        'decision_duplicate_flags_dirty',
        'decision_duplicate_rank_version'
      )
    `).all() as Array<{ key: string; value: string }>;
    const state = new Map(rows.map((row) => [row.key, row.value]));
    const refreshAt = state.get('decision_duplicate_refresh_at') || null;
    const rankVersionMatches = state.get('decision_duplicate_rank_version') === DECISION_DUPLICATE_RANK_VERSION;
    const dirty = state.get('decision_duplicate_flags_dirty') === 'true' || !rankVersionMatches;
    this.lastDecisionDuplicateRefreshAt = refreshAt;
    this.decisionDuplicateFlagsInitialized = refreshAt !== null && !dirty;
    this.decisionDuplicateFlagsDirty = dirty || refreshAt === null;
    this.ownsDecisionDuplicateDirtyMarker = false;
  }

  markDecisionDuplicateKey(value: string | null | undefined, simulated: number | boolean | null | undefined): void {
    if (!this.decisionDuplicateFlagsInitialized && this.decisionDuplicateDirtyKeys.size === 0) {
      this.loadDecisionDuplicateRefreshState();
    }
    const key: DecisionDuplicateKeyRow = {
      value: value ?? null,
      simulated: simulated ? 1 : 0,
    };
    this.decisionDuplicateDirtyKeys.set(
      `${key.simulated}\u0000${key.value === null ? '\u0001' : `\u0002${key.value}`}`,
      key,
    );
    if (!this.decisionDuplicateFlagsDirty) {
      this.db.prepare(`
        INSERT INTO meta(key, value)
        VALUES ('decision_duplicate_flags_dirty', 'true')
        ON CONFLICT(key) DO UPDATE SET value = 'true'
      `).run();
      this.ownsDecisionDuplicateDirtyMarker = true;
    }
    this.decisionDuplicateFlagsDirty = true;
  }

  markDecisionDuplicateKeysByIds(ids: string[]): void {
    this.markDecisionDuplicateKeysForColumn('id', ids);
  }

  markDecisionDuplicateKeysByAlertIds(alertIds: string[]): void {
    this.markDecisionDuplicateKeysForColumn('alert_id', alertIds);
  }

  private markDecisionDuplicateKeysForColumn(column: 'id' | 'alert_id', values: string[]): void {
    const uniqueValues = Array.from(new Set(values));
    for (let offset = 0; offset < uniqueValues.length; offset += 900) {
      const chunk = uniqueValues.slice(offset, offset + 900);
      if (chunk.length === 0) continue;
      const placeholders = chunk.map(() => '?').join(',');
      const rows = this.db.prepare(`
        SELECT DISTINCT value, simulated
        FROM decisions
        WHERE ${column} IN (${placeholders})
      `).all(...chunk) as DecisionDuplicateKeyRow[];
      for (const row of rows) this.markDecisionDuplicateKey(row.value, row.simulated);
    }
  }

  refreshDecisionDuplicateFlags(now: string, force = false): number {
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_decisions_duplicate_primary
      ON decisions(value, simulated, stop_at DESC, id)
    `);
    if (!this.decisionDuplicateFlagsInitialized && this.decisionDuplicateDirtyKeys.size === 0) {
      this.loadDecisionDuplicateRefreshState();
    }
    const mustRefreshAll = force
      || !this.decisionDuplicateFlagsInitialized
      || (this.decisionDuplicateFlagsDirty && !this.ownsDecisionDuplicateDirtyMarker && this.decisionDuplicateDirtyKeys.size === 0);
    if (mustRefreshAll) {
      const result = this.db.prepare(`
      WITH ranked AS (
        SELECT
          id,
          ROW_NUMBER() OVER (
            PARTITION BY instance_id, value, simulated
            ORDER BY
              stop_at DESC,
              CASE WHEN id GLOB '[0-9]*' THEN CAST(id AS INTEGER) ELSE -1 END DESC,
              id DESC
          ) AS duplicate_rank
        FROM decisions
        WHERE stop_at > ?
      ), desired AS (
        SELECT
          decisions.id,
          CASE WHEN ranked.duplicate_rank > 1 THEN 1 ELSE 0 END AS is_duplicate
        FROM decisions
        LEFT JOIN ranked ON ranked.id = decisions.id
      )
      UPDATE decisions
      SET is_duplicate = desired.is_duplicate
      FROM desired
      WHERE decisions.id = desired.id
        AND decisions.is_duplicate <> desired.is_duplicate
      `).run(now);
      this.decisionDuplicateDirtyKeys.clear();
      this.decisionDuplicateFlagsDirty = false;
      this.decisionDuplicateFlagsInitialized = true;
      this.lastDecisionDuplicateRefreshAt = now;
      this.ownsDecisionDuplicateDirtyMarker = false;
      this.persistDecisionDuplicateRefreshState(now);
      return result.changes;
    }

    const uniqueKeys = new Map<string, DecisionDuplicateKeyRow>(this.decisionDuplicateDirtyKeys);
    if (this.lastDecisionDuplicateRefreshAt) {
      const expiredKeys = this.db.prepare(`
        SELECT DISTINCT value, simulated
        FROM decisions
        WHERE stop_at > ? AND stop_at <= ?
      `).all(this.lastDecisionDuplicateRefreshAt, now) as DecisionDuplicateKeyRow[];
      for (const key of expiredKeys) {
        uniqueKeys.set(
          `${key.simulated}\u0000${key.value === null ? '\u0001' : `\u0002${key.value}`}`,
          key,
        );
      }
    }
    if (uniqueKeys.size === 0 && !this.decisionDuplicateFlagsDirty) {
      this.lastDecisionDuplicateRefreshAt = now;
      this.persistDecisionDuplicateRefreshState(now);
      return 0;
    }
    if (uniqueKeys.size === 0 && this.decisionDuplicateFlagsDirty) {
      return this.refreshDecisionDuplicateFlags(now, true);
    }

    this.db.exec(`
      CREATE TEMP TABLE IF NOT EXISTS decision_duplicate_refresh_keys (
        value TEXT NOT NULL,
        value_is_null INTEGER NOT NULL,
        simulated INTEGER NOT NULL,
        PRIMARY KEY (value, value_is_null, simulated)
      ) WITHOUT ROWID;
      CREATE TEMP TABLE IF NOT EXISTS decision_duplicate_refresh_updates (
        id TEXT PRIMARY KEY,
        is_duplicate INTEGER NOT NULL
      ) WITHOUT ROWID;
      DELETE FROM decision_duplicate_refresh_keys;
      DELETE FROM decision_duplicate_refresh_updates;
    `);
    const insertKey = this.db.prepare(`
      INSERT OR IGNORE INTO decision_duplicate_refresh_keys(value, value_is_null, simulated)
      VALUES (?, ?, ?)
    `);
    const populateKeys = (keys: DecisionDuplicateKeyRow[]) => {
      for (const key of keys) insertKey.run(key.value ?? '', key.value === null ? 1 : 0, key.simulated);
    };

    const populateUpdates = this.db.prepare(`
      INSERT INTO decision_duplicate_refresh_updates(id, is_duplicate)
      WITH ranked AS (
        SELECT
          decisions.id,
          ROW_NUMBER() OVER (
            PARTITION BY decisions.instance_id, decisions.value, decisions.simulated
            ORDER BY
              decisions.stop_at DESC,
              CASE WHEN decisions.id GLOB '[0-9]*' THEN CAST(decisions.id AS INTEGER) ELSE -1 END DESC,
              decisions.id DESC
          ) AS duplicate_rank
        FROM decision_duplicate_refresh_keys AS dirty
        CROSS JOIN decisions INDEXED BY idx_decisions_duplicate_primary
          ON decisions.simulated = dirty.simulated
         AND (decisions.value = dirty.value OR (dirty.value_is_null = 1 AND decisions.value IS NULL))
        WHERE decisions.stop_at > ?
      )
      SELECT
        decisions.id,
        CASE WHEN ranked.duplicate_rank > 1 THEN 1 ELSE 0 END
      FROM decision_duplicate_refresh_keys AS dirty
      CROSS JOIN decisions INDEXED BY idx_decisions_duplicate_primary
        ON decisions.simulated = dirty.simulated
       AND (decisions.value = dirty.value OR (dirty.value_is_null = 1 AND decisions.value IS NULL))
      LEFT JOIN ranked ON ranked.id = decisions.id
    `);
    const updateFlags = this.db.prepare(`
      UPDATE decisions
      SET is_duplicate = (
        SELECT refresh.is_duplicate
        FROM decision_duplicate_refresh_updates AS refresh
        WHERE refresh.id = decisions.id
      )
      WHERE id IN (SELECT id FROM decision_duplicate_refresh_updates)
        AND is_duplicate <> (
          SELECT refresh.is_duplicate
          FROM decision_duplicate_refresh_updates AS refresh
          WHERE refresh.id = decisions.id
        )
    `);
    const clearKeys = this.db.prepare('DELETE FROM decision_duplicate_refresh_keys');
    const clearUpdates = this.db.prepare('DELETE FROM decision_duplicate_refresh_updates');
    const refreshDirtyKeys = this.db.transaction((keys: DecisionDuplicateKeyRow[]) => {
      populateKeys(keys);
      populateUpdates.run(now);
      const changes = updateFlags.run().changes;
      clearKeys.run();
      clearUpdates.run();
      return changes;
    });
    const changes = refreshDirtyKeys(Array.from(uniqueKeys.values()));
    this.decisionDuplicateDirtyKeys.clear();
    this.decisionDuplicateFlagsDirty = false;
    this.decisionDuplicateFlagsInitialized = true;
    this.lastDecisionDuplicateRefreshAt = now;
    this.ownsDecisionDuplicateDirtyMarker = false;
    this.persistDecisionDuplicateRefreshState(now);
    return changes;
  }

  private persistDecisionDuplicateRefreshState(now: string): void {
    const persist = this.db.transaction(() => {
      this.db.prepare(`
        INSERT INTO meta(key, value)
        VALUES ('decision_duplicate_refresh_at', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `).run(now);
      this.db.prepare(`
        INSERT INTO meta(key, value)
        VALUES ('decision_duplicate_flags_dirty', 'false')
        ON CONFLICT(key) DO UPDATE SET value = 'false'
      `).run();
      this.db.prepare(`
        INSERT INTO meta(key, value)
        VALUES ('decision_duplicate_rank_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `).run(DECISION_DUPLICATE_RANK_VERSION);
    });
    persist();
  }
}
