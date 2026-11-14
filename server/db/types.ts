import type { AlertDecision, AlertRecord } from '../../shared/contracts';
import type { NormalizedAlertRow, NormalizedDecisionRow } from '../normalized-record';

export type SqliteStatement = {
  run: (...params: any[]) => { changes: number; lastInsertRowid?: number | bigint };
  get: (...params: any[]) => unknown;
  all: (...params: any[]) => unknown[];
};

export type Database = {
  exec: (sql: string) => void;
  close: () => void;
  prepare: (sql: string) => SqliteStatement;
  transaction: <T extends (...args: any[]) => any>(callback: T) => T;
  query: (sql: string) => SqliteStatement;
  function?: (name: string, optionsOrFn: unknown, fn?: (...args: unknown[]) => unknown) => void;
};

export const RECENT_FILTER_LIMIT = 5;
export const DEFAULT_DATA_DIR = '/app/data';
export const CACHE_DATABASE_FILE = 'cache.db';
export const STATE_DATABASE_FILE = 'state.db';
export const LEGACY_DATABASE_FILE = 'crowdsec.db';
export const STATE_SCHEMA = 'state';
export const INITIAL_OIDC_LOGOUT_VERSION = 1;
export const OIDC_END_SESSION_LEGACY_DEFAULT_KEY = 'auth_oidc_end_session_legacy_default';
/** Per-instance allowlist sync state: `<prefix><instance id>` holds JSON with the status and snapshot hash. */
export const ALLOWLIST_SYNC_META_PREFIX = 'allowlist_sync:';

export const STATE_SETTING_KEYS = new Set([
  'statistics_settings',
  'statistics_existing_install_default_disabled',
  'notification_secret_key',
  'language',
  'metrics_sidebar_visible',
  'allowlists_sidebar_visible',
  'statistics_sidebar_visible',
  'manual_decision_scenarios',
  'refresh_interval_ms',
  'manual_refresh_enabled',
]);
export const STATE_SETTING_PREFIXES = ['auth_', 'branding_'];
export const DECISION_DUPLICATE_RANK_VERSION = '2';
export const DEFAULT_JOURNAL_SIZE_LIMIT_BYTES = 128 * 1024 * 1024;
export const INCREMENTAL_VACUUM_META_KEY = 'sqlite_incremental_vacuum_at';
export const SQLITE_RECLAIM_WARNING_MIN_BYTES = 128 * 1024 * 1024;
export const SQLITE_RECLAIM_WARNING_MIN_RATIO = 0.25;
export const SQLITE_MAINTENANCE_GUIDE_URL = 'https://github.com/TheDuffman85/crowdsec-web-ui#sqlite-database-maintenance';

export const SYNC_SECONDARY_INDEX_NAMES = [
  'idx_alerts_created_at',
  'idx_alerts_country',
  'idx_alerts_region',
  'idx_alerts_city',
  'idx_alerts_scenario',
  'idx_alerts_kind',
  'idx_alerts_as_name',
  'idx_alerts_target',
  'idx_alerts_source_ip',
  'idx_alerts_simulated',
  'idx_alerts_simulated_created_at',
  'idx_alerts_country_created_at',
  'idx_alerts_scenario_created_at',
  'idx_alerts_filters',
  'idx_alerts_instance_created',
  'idx_decisions_stop_at',
  'idx_decisions_alert_summary',
  'idx_decisions_value',
  'idx_decisions_created_at',
  'idx_decisions_created_id_stop_at',
  'idx_decisions_stop_alert_id',
  'idx_decisions_value_stop_at',
  'idx_decisions_country',
  'idx_decisions_region',
  'idx_decisions_city',
  'idx_decisions_scenario',
  'idx_decisions_as_name',
  'idx_decisions_target',
  'idx_decisions_simulated',
  'idx_decisions_simulated_created_at',
  'idx_decisions_alert_created_id',
  'idx_decisions_duplicate_paging',
  'idx_decisions_duplicate_filters',
  'idx_decisions_duplicate_value_paging',
  'idx_decisions_duplicate_primary',
  'idx_decisions_instance_created',
  'idx_decisions_instance_duplicate_paging',
] as const;

export const CREATE_SYNC_SECONDARY_INDEXES_SQL = `
  CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
  CREATE INDEX IF NOT EXISTS idx_alerts_country ON alerts(country);
  CREATE INDEX IF NOT EXISTS idx_alerts_region ON alerts(region);
  CREATE INDEX IF NOT EXISTS idx_alerts_city ON alerts(city);
  CREATE INDEX IF NOT EXISTS idx_alerts_scenario ON alerts(scenario);
  CREATE INDEX IF NOT EXISTS idx_alerts_kind ON alerts(kind, created_at DESC, id DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_as_name ON alerts(as_name);
  CREATE INDEX IF NOT EXISTS idx_alerts_target ON alerts(target);
  CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
  CREATE INDEX IF NOT EXISTS idx_alerts_simulated ON alerts(simulated);
  CREATE INDEX IF NOT EXISTS idx_alerts_simulated_created_at ON alerts(simulated, created_at DESC, id DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_country_created_at ON alerts(country, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_scenario_created_at ON alerts(scenario, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_alerts_filters ON alerts(
    instance_id, country, scenario, kind, as_name, source_ip, target, country_name,
    region, city, machine, origins, message, upstream_id, simulated, created_at DESC, id DESC
  );
  CREATE INDEX IF NOT EXISTS idx_alerts_instance_created ON alerts(instance_id, created_at DESC, id DESC);
  CREATE INDEX IF NOT EXISTS idx_decisions_stop_at ON decisions(stop_at);
  CREATE INDEX IF NOT EXISTS idx_decisions_alert_summary ON decisions(alert_id, origin, simulated, stop_at);
  CREATE INDEX IF NOT EXISTS idx_decisions_value ON decisions(value);
  CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions(created_at);
  CREATE INDEX IF NOT EXISTS idx_decisions_created_id_stop_at ON decisions(created_at DESC, id DESC, stop_at);
  CREATE INDEX IF NOT EXISTS idx_decisions_stop_alert_id ON decisions(stop_at, alert_id, instance_id);
  CREATE INDEX IF NOT EXISTS idx_decisions_value_stop_at ON decisions(value, stop_at DESC);
  CREATE INDEX IF NOT EXISTS idx_decisions_country ON decisions(country);
  CREATE INDEX IF NOT EXISTS idx_decisions_region ON decisions(region);
  CREATE INDEX IF NOT EXISTS idx_decisions_city ON decisions(city);
  CREATE INDEX IF NOT EXISTS idx_decisions_scenario ON decisions(scenario);
  CREATE INDEX IF NOT EXISTS idx_decisions_as_name ON decisions(as_name);
  CREATE INDEX IF NOT EXISTS idx_decisions_target ON decisions(target);
  CREATE INDEX IF NOT EXISTS idx_decisions_simulated ON decisions(simulated);
  CREATE INDEX IF NOT EXISTS idx_decisions_simulated_created_at ON decisions(simulated, created_at DESC, id DESC);
  CREATE INDEX IF NOT EXISTS idx_decisions_alert_created_id ON decisions(alert_id, created_at DESC, id DESC, stop_at);
  CREATE INDEX IF NOT EXISTS idx_decisions_duplicate_paging ON decisions(is_duplicate, created_at DESC, id DESC, stop_at);
  CREATE INDEX IF NOT EXISTS idx_decisions_duplicate_filters ON decisions(
    is_duplicate, instance_id, stop_at, scenario, value, as_name, target, country, country_name,
    region, city, machine, origin, type, simulated, alert_id, created_at DESC, id DESC
  );
  CREATE INDEX IF NOT EXISTS idx_decisions_duplicate_value_paging ON decisions(
    value, is_duplicate, created_at DESC, id DESC, stop_at
  );
  CREATE INDEX IF NOT EXISTS idx_decisions_duplicate_primary ON decisions(value, simulated, stop_at DESC, id);
  CREATE INDEX IF NOT EXISTS idx_decisions_instance_created ON decisions(instance_id, created_at DESC, id DESC);
  CREATE INDEX IF NOT EXISTS idx_decisions_instance_duplicate_paging ON decisions(
    instance_id, is_duplicate, created_at DESC, id DESC, stop_at
  );
`;

export interface AlertInsertParams {
  $id: string | number;
  $instance_id?: string;
  $uuid: string;
  $created_at: string;
  $scenario?: string;
  $source_ip?: string;
  $message: string;
  $raw_data?: string;
  $record?: AlertRecord;
}

export interface DecisionInsertParams {
  $id: string;
  $instance_id?: string;
  $uuid: string;
  $alert_id: string | number;
  $created_at: string;
  $stop_at: string;
  $value?: string;
  $type?: string;
  $origin?: string;
  $scenario?: string;
  $raw_data?: string;
  $record?: AlertDecision & Record<string, unknown>;
}

export interface DecisionUpdateParams {
  $id: string;
  $stop_at: string;
  $raw_data: string;
}

export interface CachedAllowlistItem {
  value: string;
  description?: string;
  created_at?: string;
  /** Null when the entry never expires. */
  expiration: string | null;
}

export interface CachedAllowlist {
  name: string;
  allowlist_id?: string;
  description?: string;
  created_at?: string;
  updated_at?: string;
  console_managed: boolean;
  items: CachedAllowlistItem[];
}

export interface SearchIndexRebuildScope {
  alertIds: Array<string | number>;
  decisionIds: Array<string | number>;
}

export interface DatabaseOptions {
  /** Directory of state.db, and of a legacy crowdsec.db to migrate. */
  dataDir?: string;
  /** Directory of cache.db; defaults to dataDir. */
  cacheDir?: string;
  /** Explicit cache.db path. state.db then defaults to the same directory and no migration runs. */
  cachePath?: string;
  /** Explicit state.db path, or null for a connection that only uses the cache. */
  statePath?: string | null;
  /** Journal mode of cache.db; state.db always uses a rollback journal. */
  walEnabled?: boolean;
  incrementalVacuumEnabled?: boolean;
  journalSizeLimitBytes?: number;
}

export interface SqliteStorageStats {
  autoVacuum: number;
  pageSize: number;
  pageCount: number;
  freelistCount: number;
  reclaimableBytes: number;
  freeRatio: number;
  journalMode: string;
}

export interface IncrementalVacuumOptions {
  now: number;
  minFreeRatio: number;
  minFreeBytes: number;
  maxPages: number;
  cooldownMs: number;
}

export interface IncrementalVacuumResult {
  performed: boolean;
  reason: 'completed' | 'disabled' | 'below-threshold' | 'cooldown';
  before: SqliteStorageStats;
  after: SqliteStorageStats;
}

export function isStateSettingKey(key: string): boolean {
  return STATE_SETTING_KEYS.has(key) || STATE_SETTING_PREFIXES.some((prefix) => key.startsWith(prefix));
}

export function getSqliteMaintenanceWarning(storage: SqliteStorageStats): string | null {
  if (
    storage.autoVacuum !== 0
    || storage.freeRatio < SQLITE_RECLAIM_WARNING_MIN_RATIO
    || storage.reclaimableBytes < SQLITE_RECLAIM_WARNING_MIN_BYTES
  ) return null;
  const size = storage.reclaimableBytes >= 1024 ** 3
    ? `${(storage.reclaimableBytes / 1024 ** 3).toFixed(1).replace(/\.0$/, '')} GiB`
    : `${Math.round(storage.reclaimableBytes / 1024 ** 2)} MiB`;
  return `SQLite can reclaim ~${size}. Stop the app and delete cache.db to rebuild it with incremental vacuum: ${SQLITE_MAINTENANCE_GUIDE_URL}`;
}

export type RowWithRawData = { raw_data: string; created_at?: string; stop_at?: string; alert_id?: string | number | null };
export type AlertDataRow = NormalizedAlertRow;
export type DecisionDataRow = NormalizedDecisionRow;
export type AlertDecisionSnapshotRow = {
  raw_data: string;
  metadata_hash: string | null;
  decision_count: number;
  origins: string | null;
  simulated: number;
};
export type PendingAlertDeletionRow = {
  alert_id: string;
  decision_ids_json: string;
  requested_at: string;
  decisions_deleted_at: string | null;
  delete_after: string | null;
  completed_at: string | null;
  attempt_count: number;
  last_attempt_at: string | null;
  last_error: string | null;
};
export type MetaRow = { value: string };
export type CountRow = { count: number };
export type IdRow = { id: string | number };
export type DecisionDuplicateKeyRow = { value: string | null; simulated: number };
export type JsonRow = {
  id: string;
  created_at: string;
  updated_at: string;
  name?: string;
  type?: string;
  enabled?: number;
  config_json?: string;
  severity?: string;
  channel_ids_json?: string;
  rule_id?: string;
  rule_name?: string;
  rule_type?: string;
  title?: string;
  message?: string;
  read_at?: string | null;
  metadata_json?: string;
  deliveries_json?: string;
  dedupe_key?: string;
  incident_key?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  resolved_at?: string | null;
  published_at?: string;
  fetched_at?: string;
};

export interface AuthUserRow {
  id: number;
  username: string;
  password_hash: string | null;
  totp_secret: string | null;
  totp_enabled: number;
  totp_last_step: number | null;
  role: 'admin' | 'read-only';
  auth_provider: 'password' | 'oidc';
  oidc_issuer: string | null;
  oidc_subject: string | null;
  session_version: number;
  disabled: number;
  password_change_required: number;
  oidc_linked_at: string | null;
  oidc_link_method: OidcLinkMethod | null;
  oidc_username: string | null;
  oidc_role: 'admin' | 'read-only' | null;
  oidc_session_version: number;
  oidc_auto_link_blocked: number;
  created_at: string;
  updated_at: string;
}

export type OidcLinkMethod = 'verified' | 'username';

export interface AuthUserListRow extends AuthUserRow {
  passkey_count: number;
}

export interface OidcUserUpsertParams {
  username: string;
  preferredUsername?: string;
  role: 'admin' | 'read-only';
  issuer: string;
  subject: string;
}

export interface WebAuthnCredentialRow {
  id: number;
  user_id: number;
  credential_id: string;
  public_key: string;
  sign_count: number;
  transports: string | null;
  name: string | null;
  created_at: string;
}

export interface DatabasePaths {
  cachePath: string;
  statePath: string | null;
  legacyPath: string | null;
}
