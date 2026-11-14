import {
  ALERT_RECORD_COLUMNS,
  alertFromRow,
  alertMetadataFingerprint,
  parseAlertPayload,
  serializeAlertExtras,
  serializeAlertSourceExtras,
} from '../normalized-record';
import { deriveAlertIndexValues, deriveAlertIndexValuesFromRecord } from '../record-index';
import {
  alertRowsToLegacyPayloads,
  normalizeOptionalTimestamp,
  readOptionalString,
  runChunkedIdMutation,
} from './connection';
import type { DecisionRepository } from './decision-repository';
import type { SearchIndexRepository } from './search-index-repository';
import type {
  AlertDataRow,
  AlertDecisionSnapshotRow,
  AlertInsertParams,
  CountRow,
  Database,
  IdRow,
  PendingAlertDeletionRow,
  RowWithRawData,
  SqliteStatement,
} from './types';

export interface AlertRepositoryOptions {
  searchIndex: SearchIndexRepository;
  decisions?: DecisionRepository;
  getPrimaryInstanceId?: () => string;
}

export class AlertRepository {
  private alertDeletionTombstones = new Set<string>();

  private readonly insertAlertStatement: SqliteStatement;
  private readonly getAllAlertsStatement: SqliteStatement;
  private readonly getAlertsStatement: SqliteStatement;
  private readonly getAlertsBetweenStatement: SqliteStatement;
  private readonly getAlertIdsBetweenStatement: SqliteStatement;
  private readonly getAlertDecisionSnapshotStatement: SqliteStatement;
  private readonly updateAlertRawDataStatement: SqliteStatement;
  private readonly countAlertsStatement: SqliteStatement;
  private readonly deleteAlertStatement: SqliteStatement;

  private searchIndex: SearchIndexRepository;
  private decisions?: DecisionRepository;
  private options: AlertRepositoryOptions;

  constructor(
    private readonly db: Database,
    options: AlertRepositoryOptions,
  ) {
    this.options = options;
    this.searchIndex = options.searchIndex;
    this.decisions = options.decisions;

    this.refreshAlertDeletionTombstones();

    this.countAlertsStatement = this.db.query('SELECT COUNT(*) as count FROM alerts');

    this.insertAlertStatement = this.db.query(`
      INSERT INTO alerts (
        id, instance_id, upstream_id, uuid, created_at, start_at, stop_at, scenario, record_scenario, kind, reason,
        source_ip, source_value, source_scope, source_range, source_as_number, source_extra_data,
        message, machine_id, machine_alias, events_count, extra_data, metadata_hash, raw_data,
        latitude, longitude, country, country_name, region, city, as_name, target, machine, meta_search, origins, simulated, search_text
      )
      VALUES (
        $internal_id, $instance_id, $id, $uuid, $created_at, $start_at, $stop_at, $scenario, $record_scenario, $kind, $reason,
        $source_ip, $source_value, $source_scope, $source_range, $source_as_number, $source_extra_data,
        $message, $machine_id, $machine_alias, $events_count, $extra_data, $metadata_hash, NULL,
        $latitude, $longitude, $country, $country_name, $region, $city, $as_name, $target, $machine, $meta_search, $origins, $simulated, $search_text
      )
      ON CONFLICT(instance_id, upstream_id) DO UPDATE SET
        uuid = excluded.uuid,
        created_at = excluded.created_at,
        start_at = excluded.start_at,
        stop_at = excluded.stop_at,
        scenario = excluded.scenario,
        record_scenario = excluded.record_scenario,
        kind = excluded.kind,
        reason = excluded.reason,
        source_ip = excluded.source_ip,
        source_value = excluded.source_value,
        source_scope = excluded.source_scope,
        source_range = excluded.source_range,
        source_as_number = excluded.source_as_number,
        source_extra_data = excluded.source_extra_data,
        message = excluded.message,
        machine_id = excluded.machine_id,
        machine_alias = excluded.machine_alias,
        events_count = excluded.events_count,
        extra_data = excluded.extra_data,
        metadata_hash = excluded.metadata_hash,
        raw_data = NULL,
        latitude = excluded.latitude,
        longitude = excluded.longitude,
        country = excluded.country,
        country_name = excluded.country_name,
        region = excluded.region,
        city = excluded.city,
        as_name = excluded.as_name,
        target = excluded.target,
        machine = excluded.machine,
        meta_search = excluded.meta_search,
        origins = excluded.origins,
        simulated = excluded.simulated,
        search_text = excluded.search_text
      WHERE alerts.uuid IS NOT excluded.uuid
        OR alerts.created_at IS NOT excluded.created_at
        OR alerts.start_at IS NOT excluded.start_at
        OR alerts.stop_at IS NOT excluded.stop_at
        OR alerts.scenario IS NOT excluded.scenario
        OR alerts.record_scenario IS NOT excluded.record_scenario
        OR alerts.kind IS NOT excluded.kind
        OR alerts.reason IS NOT excluded.reason
        OR alerts.source_ip IS NOT excluded.source_ip
        OR alerts.source_value IS NOT excluded.source_value
        OR alerts.source_scope IS NOT excluded.source_scope
        OR alerts.source_range IS NOT excluded.source_range
        OR alerts.source_as_number IS NOT excluded.source_as_number
        OR alerts.source_extra_data IS NOT excluded.source_extra_data
        OR alerts.message IS NOT excluded.message
        OR alerts.machine_id IS NOT excluded.machine_id
        OR alerts.machine_alias IS NOT excluded.machine_alias
        OR alerts.events_count IS NOT excluded.events_count
        OR alerts.extra_data IS NOT excluded.extra_data
        OR alerts.metadata_hash IS NOT excluded.metadata_hash
        OR alerts.raw_data IS NOT NULL
        OR alerts.latitude IS NOT excluded.latitude
        OR alerts.longitude IS NOT excluded.longitude
        OR alerts.country IS NOT excluded.country
        OR alerts.country_name IS NOT excluded.country_name
        OR alerts.region IS NOT excluded.region
        OR alerts.city IS NOT excluded.city
        OR alerts.as_name IS NOT excluded.as_name
        OR alerts.target IS NOT excluded.target
        OR alerts.machine IS NOT excluded.machine
        OR alerts.meta_search IS NOT excluded.meta_search
        OR alerts.origins IS NOT excluded.origins
        OR alerts.simulated IS NOT excluded.simulated
        OR alerts.search_text IS NOT excluded.search_text
    `);

    this.getAllAlertsStatement = this.db.query(`
      SELECT ${ALERT_RECORD_COLUMNS} FROM alerts
      ORDER BY created_at DESC
    `);
    this.getAlertsStatement = this.db.query(`
      SELECT ${ALERT_RECORD_COLUMNS} FROM alerts
      WHERE created_at >= $since
      ORDER BY created_at DESC
    `);
    this.getAlertsBetweenStatement = this.db.query(`
      SELECT ${ALERT_RECORD_COLUMNS} FROM alerts
      WHERE created_at >= $start AND created_at < $end
      ORDER BY created_at DESC
    `);
    this.getAlertIdsBetweenStatement = this.db.query(`
      SELECT id FROM alerts
      WHERE created_at >= $start AND created_at < $end
    `);
    this.getAlertDecisionSnapshotStatement = this.db.query(`
      SELECT
        ${ALERT_RECORD_COLUMNS},
        alerts.origins,
        alerts.simulated,
        (
          SELECT COUNT(*)
          FROM decisions
          WHERE decisions.alert_id = alerts.id
        ) AS decision_count
      FROM alerts
      WHERE alerts.id = $id
    `);
    this.updateAlertRawDataStatement = this.db.query(`
      UPDATE alerts
      SET raw_data = NULL
      WHERE id = $id AND raw_data IS NOT NULL
    `);
    this.deleteAlertStatement = this.db.query('DELETE FROM alerts WHERE id = $id');
  }

  setDecisions(decisions: DecisionRepository): void {
    this.decisions = decisions;
  }

  hasTombstone(tombstoneId: string, alertId?: string | number): boolean {
    if (this.alertDeletionTombstones.has(tombstoneId)) return true;
    if (alertId !== undefined && this.alertDeletionTombstones.has(String(alertId))) return true;
    return false;
  }

  resolveAlertInternalId(instanceId: string, upstreamId: string | number): number {
    const existing = this.db.prepare('SELECT id FROM alerts WHERE instance_id = ? AND upstream_id = ?')
      .get(instanceId, String(upstreamId)) as { id: number } | undefined;
    if (existing) return Number(existing.id);
    const numeric = Number(upstreamId);
    const primaryId = this.options.getPrimaryInstanceId ? this.options.getPrimaryInstanceId() : 'default';
    const numericOwner = Number.isSafeInteger(numeric) && numeric > 0
      ? this.db.prepare('SELECT instance_id FROM alerts WHERE id = ?').get(numeric) as { instance_id: string } | undefined
      : undefined;
    if (instanceId === primaryId && Number.isSafeInteger(numeric) && numeric > 0 && !numericOwner) return numeric;
    const row = this.db.prepare('SELECT MIN(id) AS minimum FROM alerts').get() as { minimum: number | null };
    return row.minimum === null || row.minimum >= 0 ? -1 : row.minimum - 1;
  }

  getAlertInternalId(instanceId: string, upstreamId: string | number): number | null {
    const row = this.db.prepare('SELECT id FROM alerts WHERE instance_id = ? AND upstream_id = ?')
      .get(instanceId, String(upstreamId)) as { id: number } | undefined;
    return row ? Number(row.id) : null;
  }

  insertAlert(params: AlertInsertParams): boolean {
    const instanceId = params.$instance_id || 'default';
    const tombstoneId = `${instanceId}\u0000${params.$id}`;
    if (this.hasTombstone(tombstoneId, instanceId === 'default' ? params.$id : undefined)) return false;
    const rawData = params.$raw_data || '{}';
    const alert = params.$record || parseAlertPayload(rawData);
    const source = alert?.source || null;
    const fallback = {
      createdAt: params.$created_at,
      scenario: params.$scenario,
      sourceIp: params.$source_ip,
      message: params.$message,
    };
    const index = params.$record
      ? deriveAlertIndexValuesFromRecord(params.$record, fallback)
      : deriveAlertIndexValues(rawData, fallback);
    const { $record, $raw_data: _rawData, ...dbParams } = params;
    const result = this.insertAlertStatement.run({
      ...dbParams,
      $id: String(params.$id),
      $instance_id: instanceId,
      $internal_id: this.resolveAlertInternalId(instanceId, params.$id),
      $created_at: index.historyAt,
      $start_at: normalizeOptionalTimestamp(alert?.start_at),
      $stop_at: normalizeOptionalTimestamp(alert?.stop_at),
      $record_scenario: readOptionalString(alert?.scenario),
      $kind: index.kind,
      $reason: readOptionalString(alert?.reason),
      $source_value: readOptionalString(source?.value),
      $source_scope: readOptionalString(source?.scope),
      $source_range: readOptionalString(source?.range),
      $source_as_number: source?.as_number === undefined || source?.as_number === null ? null : String(source.as_number),
      $source_extra_data: serializeAlertSourceExtras(source),
      $machine_id: readOptionalString(alert?.machine_id),
      $machine_alias: readOptionalString(alert?.machine_alias),
      $events_count: typeof alert?.events_count === 'number' ? alert.events_count : null,
      $extra_data: serializeAlertExtras(alert),
      $metadata_hash: alertMetadataFingerprint(alert),
      $scenario: index.scenario ?? params.$scenario,
      $source_ip: index.sourceIp ?? params.$source_ip,
      $latitude: index.latitude,
      $longitude: index.longitude,
      $country: index.country,
      $country_name: index.countryName,
      $region: index.region,
      $city: index.city,
      $as_name: index.asName,
      $target: index.target,
      $machine: index.machine,
      $meta_search: index.metaSearch,
      $origins: index.origins,
      $simulated: index.simulated,
      $search_text: index.searchText,
    });
    if (result.changes > 0) {
      const internalId = this.resolveAlertInternalId(instanceId, params.$id);
      this.searchIndex.upsertAlertSearchIndex(internalId, index.searchText);
      return true;
    }
    return false;
  }

  getAllAlerts(): RowWithRawData[] {
    return alertRowsToLegacyPayloads(this.getAllAlertsStatement.all() as AlertDataRow[]);
  }

  getAlertsSince(since: string): RowWithRawData[] {
    return alertRowsToLegacyPayloads(this.getAlertsStatement.all({ $since: since }) as AlertDataRow[]);
  }

  getAlertsBetween(start: string, end: string): RowWithRawData[] {
    return alertRowsToLegacyPayloads(this.getAlertsBetweenStatement.all({ $start: start, $end: end }) as AlertDataRow[]);
  }

  getAlertDecisionSnapshot(id: string | number, instanceId?: string): AlertDecisionSnapshotRow | null {
    const internalId = instanceId ? this.getAlertInternalId(instanceId, id) : id;
    if (internalId === null) return null;
    const row = this.getAlertDecisionSnapshotStatement.get({ $id: internalId }) as (AlertDataRow & Omit<AlertDecisionSnapshotRow, 'raw_data'>) | null;
    return row ? {
      raw_data: JSON.stringify(alertFromRow(row)),
      metadata_hash: row.metadata_hash,
      decision_count: row.decision_count,
      origins: row.origins,
      simulated: row.simulated ? 1 : 0,
    } : null;
  }

  updateAlertRawData(id: string | number, _rawData?: string, instanceId?: string): boolean {
    const tombstoneId = instanceId ? `${instanceId}\u0000${id}` : String(id);
    if (this.alertDeletionTombstones.has(tombstoneId)) return false;
    const internalId = instanceId ? this.getAlertInternalId(instanceId, id) : id;
    if (internalId === null) return false;
    return this.updateAlertRawDataStatement.run({
      $id: internalId,
    }).changes > 0;
  }

  deleteAlertsMissingBetween(
    start: string,
    end: string,
    keepIds: Array<string | number>,
    instanceId?: string,
  ): { alerts: number; decisions: number } {
    const keepSet = new Set(keepIds.map(String));
    const rows = instanceId
      ? this.db.prepare(`
          SELECT id, COALESCE(upstream_id, CAST(id AS TEXT)) AS upstream_id
          FROM alerts
          WHERE instance_id = ? AND created_at >= ? AND created_at < ?
        `).all(instanceId, start, end) as Array<IdRow & { upstream_id: string }>
      : this.getAlertIdsBetweenStatement.all({ $start: start, $end: end }) as Array<IdRow & { upstream_id?: string }>;
    const staleIds = rows
      .filter((row) => !keepSet.has(String(row.upstream_id ?? row.id)))
      .map((row) => String(row.id));

    this.searchIndex.deleteDecisionSearchIndexesByAlertIds(staleIds);
    if (this.decisions) {
      this.decisions.markDecisionDuplicateKeysByAlertIds(staleIds);
    }
    const decisions = runChunkedIdMutation(this.db, 'DELETE FROM decisions WHERE alert_id IN', staleIds);
    const alerts = runChunkedIdMutation(this.db, 'DELETE FROM alerts WHERE id IN', staleIds);
    this.searchIndex.deleteAlertSearchIndexes(staleIds);
    return { alerts, decisions };
  }

  countAlerts(instanceId?: string): number {
    if (instanceId) {
      return (this.db.prepare('SELECT COUNT(*) as count FROM alerts WHERE instance_id = ?').get(instanceId) as CountRow).count;
    }
    return (this.countAlertsStatement.get() as CountRow).count;
  }

  deleteOldAlerts(cutoff: string, limit = Infinity): number {
    let changes = 0;
    let remaining = limit;
    const selectOldAlerts = this.db.prepare('SELECT id FROM alerts WHERE created_at < ? LIMIT ?');
    while (remaining > 0) {
      const ids = (selectOldAlerts.all(cutoff, Math.min(900, remaining)) as IdRow[]).map((row) => String(row.id));
      if (ids.length === 0) break;
      remaining -= ids.length;
      changes += runChunkedIdMutation(this.db, 'DELETE FROM alerts WHERE id IN', ids);
      this.searchIndex.deleteAlertSearchIndexes(ids);
    }
    return changes;
  }

  deleteAlert(id: string | number): void {
    this.deleteAlertStatement.run({ $id: id });
    this.searchIndex.deleteAlertSearchIndex(id);
  }

  deleteAlertByInstanceId(instanceId: string, upstreamId: string | number): void {
    const internalId = this.getAlertInternalId(instanceId, upstreamId);
    if (internalId !== null) this.deleteCachedAlerts([internalId]);
  }

  deleteCachedAlerts(ids: Array<string | number>): { alerts: number; decisions: number } {
    const normalizedIds = ids.map(String);
    this.searchIndex.deleteDecisionSearchIndexesByAlertIds(normalizedIds);
    if (this.decisions) {
      this.decisions.markDecisionDuplicateKeysByAlertIds(normalizedIds);
    }
    const decisions = runChunkedIdMutation(this.db, 'DELETE FROM decisions WHERE alert_id IN', normalizedIds);
    const alerts = runChunkedIdMutation(this.db, 'DELETE FROM alerts WHERE id IN', normalizedIds);
    this.searchIndex.deleteAlertSearchIndexes(normalizedIds);
    return { alerts, decisions };
  }

  queueAlertDeletion(alertId: string | number, decisionIds: string[], requestedAt: string): void {
    this.db.prepare(`
      INSERT INTO pending_alert_deletions (
        alert_id, decision_ids_json, requested_at, decisions_deleted_at,
        delete_after, completed_at, attempt_count, last_attempt_at, last_error
      ) VALUES (?, ?, ?, NULL, NULL, NULL, 0, NULL, NULL)
      ON CONFLICT(alert_id) DO NOTHING
    `).run(String(alertId), JSON.stringify(Array.from(new Set(decisionIds.map(String)))), requestedAt);
    this.db.prepare('INSERT OR IGNORE INTO alert_deletion_tombstones (alert_id) VALUES (?)').run(String(alertId));
    this.alertDeletionTombstones.add(String(alertId));
  }

  refreshAlertDeletionTombstones(): void {
    const rows = this.db.prepare('SELECT alert_id FROM alert_deletion_tombstones').all() as Array<{ alert_id: string }>;
    this.alertDeletionTombstones = new Set(rows.map((row) => row.alert_id));
  }

  getPendingAlertDeletions(): PendingAlertDeletionRow[] {
    return this.db.prepare(`
      SELECT alert_id, decision_ids_json, requested_at, decisions_deleted_at,
             delete_after, completed_at, attempt_count, last_attempt_at, last_error
      FROM pending_alert_deletions
      WHERE completed_at IS NULL
      ORDER BY requested_at, alert_id
    `).all() as PendingAlertDeletionRow[];
  }

  markAlertDeletionDecisionsExpired(alertId: string | number, deletedAt: string, deleteAfter: string): void {
    this.db.prepare(`
      UPDATE pending_alert_deletions
      SET decisions_deleted_at = ?, delete_after = ?,
          attempt_count = attempt_count + 1, last_attempt_at = ?, last_error = NULL
      WHERE alert_id = ? AND completed_at IS NULL
    `).run(deletedAt, deleteAfter, deletedAt, String(alertId));
  }

  recordAlertDeletionFailure(alertId: string | number, attemptedAt: string, error: string): void {
    this.db.prepare(`
      UPDATE pending_alert_deletions
      SET attempt_count = attempt_count + 1, last_attempt_at = ?, last_error = ?
      WHERE alert_id = ? AND completed_at IS NULL
    `).run(attemptedAt, error, String(alertId));
  }

  completeAlertDeletion(alertId: string | number, completedAt: string): void {
    this.db.prepare(`
      UPDATE pending_alert_deletions
      SET completed_at = ?, last_attempt_at = ?, last_error = NULL
      WHERE alert_id = ? AND completed_at IS NULL
    `).run(completedAt, completedAt, String(alertId));
  }

  expireAlertDeletion(alertId: string | number, completedAt: string, error: string): void {
    this.db.prepare(`
      UPDATE pending_alert_deletions
      SET completed_at = ?, last_attempt_at = ?, last_error = ?
      WHERE alert_id = ? AND completed_at IS NULL
    `).run(completedAt, completedAt, error, String(alertId));
  }

  purgeCompletedAlertDeletions(completedBefore: string): number {
    const changes = this.db.prepare(`
      DELETE FROM pending_alert_deletions
      WHERE completed_at IS NOT NULL AND completed_at < ?
    `).run(completedBefore).changes;
    if (changes > 0) {
      this.db.exec('DELETE FROM alert_deletion_tombstones WHERE alert_id NOT IN (SELECT alert_id FROM pending_alert_deletions)');
      this.refreshAlertDeletionTombstones();
    }
    return changes;
  }

  getAlertDeletionTombstone(alertId: string | number): PendingAlertDeletionRow | null {
    return (this.db.prepare(`
      SELECT alert_id, decision_ids_json, requested_at, decisions_deleted_at,
             delete_after, completed_at, attempt_count, last_attempt_at, last_error
      FROM pending_alert_deletions
      WHERE alert_id = ?
    `).get(String(alertId)) as PendingAlertDeletionRow | null) || null;
  }
}
