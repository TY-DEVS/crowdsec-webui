import fs from 'node:fs';
import { normalizeIsoTimestamp, normalizeTimestampJson } from '../utils/date-time';
import {
  CREATE_SYNC_SECONDARY_INDEXES_SQL,
  OIDC_END_SESSION_LEGACY_DEFAULT_KEY,
  RECENT_FILTER_LIMIT,
  isStateSettingKey,
  type CountRow,
  type Database,
} from './types';
import { createDatabase, removeDatabaseFiles } from './connection';

export function initCacheSchema(db: Database): boolean {
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY,
      instance_id TEXT NOT NULL DEFAULT 'default',
      upstream_id TEXT,
      uuid TEXT,
      created_at TEXT NOT NULL,
      start_at TEXT,
      stop_at TEXT,
      scenario TEXT,
      record_scenario TEXT,
      kind TEXT,
      reason TEXT,
      source_ip TEXT,
      source_value TEXT,
      source_scope TEXT,
      source_range TEXT,
      source_as_number TEXT,
      source_extra_data TEXT,
      message TEXT,
      machine_id TEXT,
      machine_alias TEXT,
      events_count INTEGER,
      extra_data TEXT,
      metadata_hash TEXT,
      raw_data TEXT,
      latitude REAL,
      longitude REAL,
      country TEXT,
      country_name TEXT,
      region TEXT,
      city TEXT,
      as_name TEXT,
      target TEXT,
      machine TEXT,
      meta_search TEXT,
      origins TEXT,
      simulated INTEGER NOT NULL DEFAULT 0,
      search_text TEXT,
      UNIQUE(instance_id, upstream_id),
      UNIQUE(instance_id, uuid)
    );

    CREATE TABLE IF NOT EXISTS decisions (
      id TEXT PRIMARY KEY,
      instance_id TEXT NOT NULL DEFAULT 'default',
      upstream_id TEXT,
      uuid TEXT,
      alert_id INTEGER,
      alert_upstream_id TEXT,
      created_at TEXT NOT NULL,
      stop_at TEXT NOT NULL,
      value TEXT,
      type TEXT,
      origin TEXT,
      scenario TEXT,
      duration TEXT,
      scope TEXT,
      extra_data TEXT,
      raw_data TEXT,
      country TEXT,
      country_name TEXT,
      region TEXT,
      city TEXT,
      as_name TEXT,
      target TEXT,
      machine TEXT,
      simulated INTEGER NOT NULL DEFAULT 0,
      search_text TEXT,
      is_duplicate INTEGER NOT NULL DEFAULT 0,
      UNIQUE(instance_id, upstream_id),
      UNIQUE(instance_id, uuid)
    );

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS cve_cache (
      id TEXT PRIMARY KEY,
      published_at TEXT NOT NULL,
      fetched_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS alert_deletion_tombstones (
      alert_id TEXT PRIMARY KEY
    );

    CREATE TABLE IF NOT EXISTS allowlists (
      instance_id TEXT NOT NULL,
      name TEXT NOT NULL,
      allowlist_id TEXT,
      description TEXT,
      created_at TEXT,
      updated_at TEXT,
      console_managed INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (instance_id, name)
    ) WITHOUT ROWID;

    CREATE TABLE IF NOT EXISTS allowlist_items (
      instance_id TEXT NOT NULL,
      allowlist_name TEXT NOT NULL,
      value TEXT NOT NULL,
      description TEXT,
      created_at TEXT,
      expiration TEXT,
      PRIMARY KEY (instance_id, allowlist_name, value)
    ) WITHOUT ROWID;

    CREATE INDEX IF NOT EXISTS idx_allowlist_items_name_created
      ON allowlist_items(allowlist_name, created_at DESC, value);
  `);
  // A refresh drops the secondary indexes while it bulk-loads and recreates them afterwards.
  // Recreate them here too in case the previous process stopped in between.
  db.exec(CREATE_SYNC_SECONDARY_INDEXES_SQL);
  initDashboardChangeTracking(db);
  const searchIndexAvailable = initSearchIndexes(db);
  if (searchIndexAvailable) {
    backfillSearchIndexes(db);
  }
  return searchIndexAvailable;
}

// One transaction, because the state database syncs every commit to disk: a fresh install would
// otherwise wait for hundreds of syncs, and a crash could leave it half created and no longer fresh.
export function initStateSchema(db: Database, schema: string, fresh: boolean): void {
  db.transaction(() => createStateSchema(db, schema, fresh))();
}

export function createStateSchema(db: Database, schema: string, fresh: boolean): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS ${schema}.settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS ${schema}.auth_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      totp_secret TEXT,
      totp_enabled INTEGER NOT NULL DEFAULT 0,
      totp_last_step INTEGER,
      role TEXT NOT NULL DEFAULT 'admin',
      auth_provider TEXT NOT NULL DEFAULT 'password',
      oidc_issuer TEXT,
      oidc_subject TEXT,
      session_version INTEGER NOT NULL DEFAULT 1,
      disabled INTEGER NOT NULL DEFAULT 0,
      password_change_required INTEGER NOT NULL DEFAULT 0,
      oidc_linked_at TEXT,
      oidc_link_method TEXT,
      oidc_username TEXT,
      oidc_role TEXT,
      oidc_session_version INTEGER NOT NULL DEFAULT 0,
      oidc_auto_link_blocked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_auth_users_username ON auth_users(username);
    CREATE UNIQUE INDEX IF NOT EXISTS ${schema}.idx_auth_users_oidc_identity
      ON auth_users(oidc_issuer, oidc_subject)
      WHERE oidc_issuer IS NOT NULL AND oidc_subject IS NOT NULL;

    CREATE TABLE IF NOT EXISTS ${schema}.webauthn_credentials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      credential_id TEXT NOT NULL UNIQUE,
      public_key TEXT NOT NULL,
      sign_count INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      name TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_webauthn_credentials_user_id ON webauthn_credentials(user_id);

    CREATE TABLE IF NOT EXISTS ${schema}.user_preferences (
      user_id INTEGER NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      key TEXT NOT NULL,
      value TEXT NOT NULL,
      PRIMARY KEY (user_id, key)
    );

    CREATE TABLE IF NOT EXISTS ${schema}.oidc_revoked_sessions (
      issuer TEXT NOT NULL,
      session_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (issuer, session_id)
    );

    CREATE TABLE IF NOT EXISTS ${schema}.revoked_auth_sessions (
      session_id TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ${schema}.oidc_processed_logouts (
      issuer TEXT NOT NULL,
      token_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (issuer, token_id)
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_oidc_processed_logouts_expiry ON oidc_processed_logouts(expires_at);

    CREATE TABLE IF NOT EXISTS ${schema}.oidc_logout_versions (
      issuer TEXT NOT NULL,
      subject TEXT NOT NULL,
      version INTEGER NOT NULL,
      PRIMARY KEY (issuer, subject)
    );

    CREATE TABLE IF NOT EXISTS ${schema}.notification_channels (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      config_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ${schema}.notification_rules (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      severity TEXT NOT NULL,
      channel_ids_json TEXT NOT NULL,
      config_json TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ${schema}.notifications (
      id TEXT PRIMARY KEY,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      rule_name TEXT NOT NULL,
      rule_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      read_at TEXT,
      metadata_json TEXT NOT NULL,
      deliveries_json TEXT NOT NULL,
      dedupe_key TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_notifications_created_at ON notifications(created_at);
    CREATE INDEX IF NOT EXISTS ${schema}.idx_notifications_read_at ON notifications(read_at);
    CREATE INDEX IF NOT EXISTS ${schema}.idx_notifications_rule_id ON notifications(rule_id);

    CREATE TABLE IF NOT EXISTS ${schema}.notification_incidents (
      rule_id TEXT NOT NULL,
      incident_key TEXT NOT NULL,
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      resolved_at TEXT,
      PRIMARY KEY (rule_id, incident_key)
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_notification_incidents_rule_id ON notification_incidents(rule_id);
    CREATE INDEX IF NOT EXISTS ${schema}.idx_notification_incidents_resolved_at ON notification_incidents(resolved_at);

    CREATE TABLE IF NOT EXISTS ${schema}.saved_search_filters (
      id TEXT PRIMARY KEY,
      owner_id INTEGER NOT NULL,
      name TEXT NOT NULL COLLATE NOCASE,
      query TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(owner_id, name)
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_saved_search_filters_owner
      ON saved_search_filters(owner_id, name);

    CREATE TABLE IF NOT EXISTS ${schema}.recent_search_filters (
      owner_id INTEGER NOT NULL,
      query TEXT NOT NULL,
      used_at_ms INTEGER NOT NULL,
      PRIMARY KEY(owner_id, query)
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_recent_search_filters_owner_used
      ON recent_search_filters(owner_id, used_at_ms DESC);

    CREATE TABLE IF NOT EXISTS ${schema}.pending_alert_deletions (
      alert_id TEXT PRIMARY KEY,
      decision_ids_json TEXT NOT NULL,
      requested_at TEXT NOT NULL,
      decisions_deleted_at TEXT,
      delete_after TEXT,
      completed_at TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      last_attempt_at TEXT,
      last_error TEXT
    );
    CREATE INDEX IF NOT EXISTS ${schema}.idx_pending_alert_deletions_due
      ON pending_alert_deletions(completed_at, delete_after, requested_at);
  `);
  // Columns added after auth_users was introduced.
  const authUserColumns = (db.prepare(`PRAGMA ${schema}.table_info(auth_users)`).all() as Array<{ name: string }>)
    .map((column) => column.name);
  for (const column of ['disabled', 'password_change_required', 'oidc_session_version', 'oidc_auto_link_blocked']) {
    if (!authUserColumns.includes(column)) {
      db.exec(`ALTER TABLE ${schema}.auth_users ADD COLUMN ${column} INTEGER NOT NULL DEFAULT 0`);
    }
  }
  for (const column of ['oidc_linked_at', 'oidc_link_method', 'oidc_username', 'oidc_role']) {
    if (!authUserColumns.includes(column)) {
      db.exec(`ALTER TABLE ${schema}.auth_users ADD COLUMN ${column} TEXT`);
    }
  }
  // Only new installations enable authentication by default; migrated ones keep their previous state.
  db.prepare(`INSERT OR IGNORE INTO ${schema}.settings (key, value) VALUES ('auth_existing_install_default_disabled', ?)`)
    .run(fresh ? 'false' : 'true');
  // Long-term statistics are opt-in for installations that existed before them.
  db.prepare(`INSERT OR IGNORE INTO ${schema}.settings (key, value) VALUES ('statistics_existing_install_default_disabled', ?)`)
    .run(fresh ? 'false' : 'true');
  // Existing installations are resolved on startup, once the effective OIDC configuration is known.
  db.prepare(`INSERT OR IGNORE INTO ${schema}.settings (key, value) VALUES ('${OIDC_END_SESSION_LEGACY_DEFAULT_KEY}', ?)`)
    .run(fresh ? 'false' : 'pending');
}

export function migrateLegacyDatabase(legacyPath: string, statePath: string): void {
  const tempPath = `${statePath}.tmp`;
  removeDatabaseFiles(tempPath);
  if (fs.existsSync(statePath) || !fs.existsSync(legacyPath)) return;

  console.log(`Migrating durable data from ${legacyPath} to ${statePath}...`);
  const legacy = createDatabase(legacyPath);
  try {
    const target = createDatabase(tempPath);
    try {
      target.exec('PRAGMA journal_mode = DELETE');
      target.exec('PRAGMA synchronous = FULL');
      initStateSchema(target, 'main', false);
      target.transaction(() => importLegacyState(legacy, target))();
    } finally {
      target.close();
    }
  } finally {
    legacy.close();
  }
  fs.renameSync(tempPath, statePath);
  try {
    removeDatabaseFiles(legacyPath);
  } catch (error) {
    console.warn(`Migrated durable data to ${statePath}, but could not remove ${legacyPath}: ${(error as Error).message}`);
    return;
  }
  console.log(`Migrated durable data to ${statePath} and removed ${legacyPath}. Cached alerts and decisions are rebuilt by the next sync.`);
}

export const LEGACY_STATE_TABLES = [
  'auth_users',
  'webauthn_credentials',
  'notification_channels',
  'notification_rules',
  'notifications',
  'notification_incidents',
  'saved_search_filters',
  'recent_search_filters',
  'pending_alert_deletions',
] as const;

export const LEGACY_TIMESTAMP_COLUMNS = new Set(['created_at', 'updated_at', 'read_at', 'first_seen_at', 'last_seen_at', 'resolved_at']);
export const LEGACY_TIMESTAMP_JSON_COLUMNS = new Set(['metadata_json', 'deliveries_json']);

export function importLegacyState(legacy: Database, target: Database): void {
  for (const table of LEGACY_STATE_TABLES) {
    const legacyColumns = tableColumns(legacy, table);
    if (legacyColumns.length === 0) continue;
    const columns = tableColumns(target, table).filter((column) => legacyColumns.includes(column));
    const insert = target.prepare(`
      INSERT OR REPLACE INTO ${table} (${columns.join(', ')})
      VALUES (${columns.map(() => '?').join(', ')})
    `);
    const rows = legacy.prepare(`SELECT ${columns.join(', ')} FROM ${table}`).all() as Array<Record<string, unknown>>;
    for (const row of rows) {
      insert.run(...columns.map((column) => normalizeLegacyValue(column, row[column])));
    }
  }

  if (tableColumns(legacy, 'meta').length > 0) {
    const insertSetting = target.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)');
    const rows = legacy.prepare('SELECT key, value FROM meta').all() as Array<{ key: string; value: string | null }>;
    for (const row of rows) {
      if (isStateSettingKey(row.key)) insertSetting.run(row.key, row.value);
    }
  }

  target.exec(`
    DELETE FROM recent_search_filters WHERE rowid IN (
      SELECT rowid FROM (
        SELECT rowid, ROW_NUMBER() OVER (
          PARTITION BY owner_id ORDER BY used_at_ms DESC, rowid DESC
        ) AS position
        FROM recent_search_filters
      ) WHERE position > ${RECENT_FILTER_LIMIT}
    );
  `);
  seedNotificationIncidentsFromHistoryIfEmpty(target);
}

export function tableColumns(db: Database, table: string): string[] {
  return (db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map((column) => column.name);
}

export function normalizeLegacyValue(column: string, value: unknown): unknown {
  if (typeof value !== 'string') return value;
  if (LEGACY_TIMESTAMP_COLUMNS.has(column)) return normalizeIsoTimestamp(value);
  if (LEGACY_TIMESTAMP_JSON_COLUMNS.has(column)) return normalizeTimestampJson(value);
  return value;
}

export function initDashboardChangeTracking(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS dashboard_record_changes (
      revision INTEGER PRIMARY KEY AUTOINCREMENT,
      table_name TEXT NOT NULL CHECK(table_name IN ('alerts', 'decisions')),
      record_id TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_dashboard_record_changes_record
      ON dashboard_record_changes(table_name, record_id, revision DESC);
    INSERT OR IGNORE INTO meta(key, value) VALUES ('dashboard_change_epoch', '1');
    INSERT OR IGNORE INTO meta(key, value) VALUES ('dashboard_change_floor', '0');
    INSERT OR IGNORE INTO meta(key, value) VALUES ('dashboard_change_tracking_enabled', 'true');

    CREATE TRIGGER IF NOT EXISTS dashboard_alert_insert
    AFTER INSERT ON alerts
    WHEN COALESCE((SELECT value FROM meta WHERE key = 'dashboard_change_tracking_enabled'), 'true') = 'true'
    BEGIN
      INSERT INTO dashboard_record_changes(table_name, record_id)
      VALUES ('alerts', CAST(NEW.id AS TEXT));
    END;
    CREATE TRIGGER IF NOT EXISTS dashboard_alert_update
    AFTER UPDATE ON alerts
    WHEN COALESCE((SELECT value FROM meta WHERE key = 'dashboard_change_tracking_enabled'), 'true') = 'true'
      AND (
        OLD.instance_id IS NOT NEW.instance_id OR OLD.upstream_id IS NOT NEW.upstream_id
        OR OLD.created_at IS NOT NEW.created_at OR OLD.country IS NOT NEW.country
        OR OLD.region IS NOT NEW.region OR OLD.city IS NOT NEW.city
        OR OLD.scenario IS NOT NEW.scenario OR OLD.kind IS NOT NEW.kind
        OR OLD.as_name IS NOT NEW.as_name
        OR OLD.source_ip IS NOT NEW.source_ip OR OLD.source_value IS NOT NEW.source_value
        OR OLD.source_range IS NOT NEW.source_range OR OLD.latitude IS NOT NEW.latitude
        OR OLD.longitude IS NOT NEW.longitude OR OLD.target IS NOT NEW.target
        OR OLD.machine_id IS NOT NEW.machine_id OR OLD.machine_alias IS NOT NEW.machine_alias
        OR OLD.machine IS NOT NEW.machine OR OLD.origins IS NOT NEW.origins
        OR OLD.simulated IS NOT NEW.simulated OR OLD.extra_data IS NOT NEW.extra_data
      )
    BEGIN
      INSERT INTO dashboard_record_changes(table_name, record_id)
      VALUES ('alerts', CAST(NEW.id AS TEXT));
    END;
    CREATE TRIGGER IF NOT EXISTS dashboard_alert_delete
    AFTER DELETE ON alerts
    WHEN COALESCE((SELECT value FROM meta WHERE key = 'dashboard_change_tracking_enabled'), 'true') = 'true'
    BEGIN
      INSERT INTO dashboard_record_changes(table_name, record_id)
      VALUES ('alerts', CAST(OLD.id AS TEXT));
    END;
    CREATE TRIGGER IF NOT EXISTS dashboard_decision_insert
    AFTER INSERT ON decisions
    WHEN COALESCE((SELECT value FROM meta WHERE key = 'dashboard_change_tracking_enabled'), 'true') = 'true'
    BEGIN
      INSERT INTO dashboard_record_changes(table_name, record_id)
      VALUES ('decisions', CAST(NEW.id AS TEXT));
    END;
    CREATE TRIGGER IF NOT EXISTS dashboard_decision_update
    AFTER UPDATE ON decisions
    WHEN COALESCE((SELECT value FROM meta WHERE key = 'dashboard_change_tracking_enabled'), 'true') = 'true'
      AND (
        OLD.instance_id IS NOT NEW.instance_id OR OLD.upstream_id IS NOT NEW.upstream_id
        OR OLD.alert_upstream_id IS NOT NEW.alert_upstream_id
        OR OLD.created_at IS NOT NEW.created_at OR OLD.stop_at IS NOT NEW.stop_at
        OR OLD.value IS NOT NEW.value OR OLD.country IS NOT NEW.country
        OR OLD.region IS NOT NEW.region OR OLD.city IS NOT NEW.city
        OR OLD.scenario IS NOT NEW.scenario OR OLD.as_name IS NOT NEW.as_name
        OR OLD.target IS NOT NEW.target OR OLD.type IS NOT NEW.type
        OR OLD.origin IS NOT NEW.origin OR OLD.machine IS NOT NEW.machine
        OR OLD.duration IS NOT NEW.duration OR OLD.is_duplicate IS NOT NEW.is_duplicate
        OR OLD.simulated IS NOT NEW.simulated OR OLD.extra_data IS NOT NEW.extra_data
      )
    BEGIN
      INSERT INTO dashboard_record_changes(table_name, record_id)
      VALUES ('decisions', CAST(NEW.id AS TEXT));
    END;
    CREATE TRIGGER IF NOT EXISTS dashboard_decision_delete
    AFTER DELETE ON decisions
    WHEN COALESCE((SELECT value FROM meta WHERE key = 'dashboard_change_tracking_enabled'), 'true') = 'true'
    BEGIN
      INSERT INTO dashboard_record_changes(table_name, record_id)
      VALUES ('decisions', CAST(OLD.id AS TEXT));
    END;
  `);
}

export function initSearchIndexes(db: Database): boolean {
  try {
    db.exec(`
      CREATE VIRTUAL TABLE IF NOT EXISTS alerts_fts USING fts5(
        alert_id UNINDEXED,
        search_text,
        tokenize = 'trigram'
      );
      CREATE VIRTUAL TABLE IF NOT EXISTS decisions_fts USING fts5(
        decision_id UNINDEXED,
        search_text,
        tokenize = 'trigram'
      );
      CREATE TABLE IF NOT EXISTS decision_fts_rows (
        decision_id TEXT PRIMARY KEY,
        fts_rowid INTEGER NOT NULL UNIQUE
      );
    `);
    synchronizeDecisionSearchRows(db);
    return true;
  } catch (error) {
    console.warn('SQLite FTS5 is unavailable; falling back to LIKE search.', (error as Error).message);
    return false;
  }
}

export function backfillSearchIndexes(db: Database): void {
  const alertCount = (db.query('SELECT COUNT(*) AS count FROM alerts_fts').get() as CountRow | null)?.count || 0;
  if (alertCount === 0) {
    db.exec(`
      INSERT INTO alerts_fts(rowid, alert_id, search_text)
      SELECT CAST(id AS INTEGER), CAST(id AS TEXT), search_text
      FROM alerts
      WHERE id <> 0
        AND search_text IS NOT NULL
        AND search_text <> ''
    `);
  }

  const decisionCount = (db.query('SELECT COUNT(*) AS count FROM decisions_fts').get() as CountRow | null)?.count || 0;
  if (decisionCount === 0) {
    db.exec(`
      INSERT INTO decisions_fts(decision_id, search_text)
      SELECT CAST(id AS TEXT), search_text
      FROM decisions
      WHERE search_text IS NOT NULL
        AND search_text <> ''
    `);
  }
  synchronizeDecisionSearchRows(db);
}

export function synchronizeDecisionSearchRows(db: Database): void {
  const searchCount = (db.query('SELECT COUNT(*) AS count FROM decisions_fts').get() as CountRow | null)?.count || 0;
  const mappingCount = (db.query('SELECT COUNT(*) AS count FROM decision_fts_rows').get() as CountRow | null)?.count || 0;
  if (searchCount === mappingCount) return;

  const synchronize = db.transaction(() => {
    db.exec('DELETE FROM decision_fts_rows');
    db.exec(`
      INSERT OR REPLACE INTO decision_fts_rows (decision_id, fts_rowid)
      SELECT CAST(decision_id AS TEXT), rowid
      FROM decisions_fts
    `);
  });
  synchronize();
}

export async function backfillSearchIndexesCooperative(db: Database, yieldControl: () => Promise<void>, batchSize: number): Promise<void> {
  let lastAlertId = 0;
  const selectAlerts = db.query(`
    SELECT id, search_text
    FROM alerts
    WHERE id > ?
      AND search_text IS NOT NULL
      AND search_text <> ''
    ORDER BY id
    LIMIT ?
  `);
  const insertAlerts = db.transaction((rows: Array<{ id: number; search_text: string }>) => {
    const insert = db.prepare('INSERT INTO alerts_fts(rowid, alert_id, search_text) VALUES (?, ?, ?)');
    for (const row of rows) {
      insert.run(row.id, String(row.id), row.search_text);
    }
  });

  while (true) {
    const rows = selectAlerts.all(lastAlertId, batchSize) as Array<{ id: number; search_text: string }>;
    if (rows.length === 0) {
      break;
    }
    insertAlerts(rows);
    lastAlertId = rows[rows.length - 1].id;
    await yieldControl();
  }

  let lastDecisionRowId = 0;
  const selectDecisions = db.query(`
    SELECT rowid, id, search_text
    FROM decisions
    WHERE rowid > ?
      AND search_text IS NOT NULL
      AND search_text <> ''
    ORDER BY rowid
    LIMIT ?
  `);
  const insertDecisions = db.transaction((rows: Array<{ id: string; rowid: number; search_text: string }>) => {
    const insert = db.prepare('INSERT INTO decisions_fts(decision_id, search_text) VALUES (?, ?)');
    const insertMapping = db.prepare('INSERT OR REPLACE INTO decision_fts_rows(decision_id, fts_rowid) VALUES (?, ?)');
    for (const row of rows) {
      const result = insert.run(String(row.id), row.search_text);
      if (result.lastInsertRowid !== undefined) {
        insertMapping.run(String(row.id), result.lastInsertRowid);
      }
    }
  });

  while (true) {
    const rows = selectDecisions.all(lastDecisionRowId, batchSize) as Array<{ id: string; rowid: number; search_text: string }>;
    if (rows.length === 0) {
      break;
    }
    insertDecisions(rows);
    lastDecisionRowId = rows[rows.length - 1].rowid;
    await yieldControl();
  }
}

export function seedNotificationIncidentsFromHistoryIfEmpty(db: Database): void {
  const countRow = db.query('SELECT COUNT(*) as count FROM notification_incidents').get() as CountRow | null;
  if ((countRow?.count || 0) > 0) {
    return;
  }

  const rows = db.query(`
    SELECT rule_id, rule_type, dedupe_key, created_at
    FROM notifications
    ORDER BY created_at DESC
  `).all() as Array<{ rule_id?: string; rule_type?: string; dedupe_key?: string; created_at?: string }>;

  if (rows.length === 0) {
    return;
  }

  const latestByIncident = new Map<string, { ruleId: string; incidentKey: string; createdAt: string }>();
  for (const row of rows) {
    const ruleId = String(row.rule_id || '');
    const ruleType = String(row.rule_type || '');
    const incidentKey = normalizeIncidentKeyForSeed(ruleId, ruleType, String(row.dedupe_key || ''));
    const createdAt = normalizeIsoTimestamp(String(row.created_at || ''));
    if (!ruleId || !incidentKey || !createdAt) {
      continue;
    }

    const compositeKey = `${ruleId}\u0000${incidentKey}`;
    if (!latestByIncident.has(compositeKey)) {
      latestByIncident.set(compositeKey, { ruleId, incidentKey, createdAt });
    }
  }

  if (latestByIncident.size === 0) {
    return;
  }

  const insertStatement = db.query(`
    INSERT OR REPLACE INTO notification_incidents (rule_id, incident_key, first_seen_at, last_seen_at, resolved_at)
    VALUES ($rule_id, $incident_key, $first_seen_at, $last_seen_at, $resolved_at)
  `);

  const restore = db.transaction((entries: Array<{ ruleId: string; incidentKey: string; createdAt: string }>) => {
    for (const entry of entries) {
      (insertStatement as any).run({
        $rule_id: entry.ruleId,
        $incident_key: entry.incidentKey,
        $first_seen_at: entry.createdAt,
        $last_seen_at: entry.createdAt,
        $resolved_at: null,
      });
    }
  });

  restore([...latestByIncident.values()]);
}

export function normalizeIncidentKeyForSeed(ruleId: string, ruleType: string, dedupeKey: string): string | null {
  if (!dedupeKey) {
    return null;
  }

  const scopedPrefix = `${ruleId}:`;
  const normalized = dedupeKey.startsWith(scopedPrefix)
    ? dedupeKey.slice(scopedPrefix.length)
    : dedupeKey;

  if (ruleType === 'alert-threshold') {
    return normalized.startsWith('threshold:') ? 'threshold:active' : null;
  }
  if (ruleType === 'alert-spike') {
    return normalized.startsWith('spike:') ? 'spike:active' : null;
  }
  if (ruleType === 'new-cve') {
    return normalized.startsWith('cve:') ? normalized : null;
  }
  if (ruleType === 'application-update') {
    return normalized.startsWith('application-update:') ? normalized : null;
  }
  if (ruleType === 'crowdsec-update') {
    return normalized.startsWith('crowdsec-update:') ? normalized : null;
  }
  if (ruleType === 'lapi-availability') {
    return normalized.startsWith('lapi-availability:') ? normalized : null;
  }

  return normalized || null;
}
