import fs from 'node:fs';
import path from 'node:path';
import BetterSqlite3 from 'better-sqlite3';
import { matchesIpSearchValue } from '../../shared/search';
import { alertFromRow } from '../normalized-record';
import { normalizeIsoTimestamp } from '../utils/date-time';
import {
  CACHE_DATABASE_FILE,
  DEFAULT_DATA_DIR,
  DEFAULT_JOURNAL_SIZE_LIMIT_BYTES,
  LEGACY_DATABASE_FILE,
  STATE_DATABASE_FILE,
  STATE_SCHEMA,
  type AlertDataRow,
  type CountRow,
  type Database,
  type DatabaseOptions,
  type DatabasePaths,
  type RowWithRawData,
} from './types';
import { initStateSchema } from './schema';

export function runChunkedIdMutation(
  db: Database,
  statementPrefix: string,
  ids: string[],
  leadingParams: unknown[] = [],
): number {
  if (ids.length === 0) {
    return 0;
  }

  let changes = 0;
  const chunkSize = 900;
  for (let offset = 0; offset < ids.length; offset += chunkSize) {
    const chunk = ids.slice(offset, offset + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const statement = db.prepare(`${statementPrefix} (${placeholders})`);
    changes += statement.run(...leadingParams, ...chunk).changes;
  }

  return changes;
}

export function resolveDatabasePaths(options: DatabaseOptions): DatabasePaths {
  if (options.cachePath) {
    ensureDirectory(path.dirname(options.cachePath));
    return {
      cachePath: options.cachePath,
      statePath: options.statePath === undefined
        ? path.join(path.dirname(options.cachePath), STATE_DATABASE_FILE)
        : options.statePath,
      legacyPath: null,
    };
  }

  const dataDir = resolveDataDirectory(options.dataDir || DEFAULT_DATA_DIR);
  const cacheDir = options.cacheDir ? resolveDataDirectory(options.cacheDir) : dataDir;
  return {
    cachePath: path.join(cacheDir, CACHE_DATABASE_FILE),
    statePath: options.statePath === undefined ? path.join(dataDir, STATE_DATABASE_FILE) : options.statePath,
    legacyPath: path.join(dataDir, LEGACY_DATABASE_FILE),
  };
}

export function resolveDataDirectory(dirPath: string): string {
  try {
    ensureDirectory(dirPath);
    return dirPath;
  } catch (error) {
    if (dirPath !== DEFAULT_DATA_DIR) throw error;
    // Local runs outside the container cannot create /app/data; use ./data like the config file does.
    const fallback = path.resolve(process.cwd(), 'data');
    ensureDirectory(fallback);
    return fallback;
  }
}

export function ensureDirectory(dirPath: string): void {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

export function openDatabase(
  dbPath: string,
  walEnabled: boolean,
  journalSizeLimitBytes: number,
  incrementalVacuumEnabled: boolean,
): { database: Database; wasFresh: boolean } {
  return prepareDatabase(createDatabase(dbPath), walEnabled, journalSizeLimitBytes, incrementalVacuumEnabled);
}

// The state database is small and rarely written. A rollback journal keeps it usable on
// network filesystems and leaves a single file to back up, independent of storage.walEnabled.
export function attachStateDatabase(db: Database, statePath: string): void {
  ensureDirectory(path.dirname(statePath));
  db.prepare(`ATTACH DATABASE ? AS ${STATE_SCHEMA}`).run(statePath);
  const fresh = isDatabaseFresh(db, STATE_SCHEMA);
  db.exec(`PRAGMA ${STATE_SCHEMA}.journal_mode = DELETE`);
  db.exec(`PRAGMA ${STATE_SCHEMA}.synchronous = FULL`);
  initStateSchema(db, STATE_SCHEMA, fresh);
}

// Rebuilds the cache-side mirror of the deletion queue, for example after cache.db was lost.
export function restoreAlertDeletionTombstones(db: Database): void {
  db.transaction(() => {
    db.exec(`
      DELETE FROM main.alert_deletion_tombstones;
      INSERT INTO main.alert_deletion_tombstones (alert_id)
      SELECT alert_id FROM ${STATE_SCHEMA}.pending_alert_deletions;
    `);
  })();
}

export function prepareDatabase(
  database: Database,
  walEnabled: boolean,
  journalSizeLimitBytes: number,
  incrementalVacuumEnabled: boolean,
): { database: Database; wasFresh: boolean } {
  const wasFresh = isDatabaseFresh(database);
  if (wasFresh && incrementalVacuumEnabled) database.exec('PRAGMA auto_vacuum = INCREMENTAL');
  return {
    database: configureDatabase(database, walEnabled, journalSizeLimitBytes),
    wasFresh,
  };
}

export function configureDatabase(database: Database, walEnabled: boolean, journalSizeLimitBytes: number): Database {
  database.exec(`PRAGMA journal_mode = ${walEnabled ? 'WAL' : 'DELETE'}`);
  if (walEnabled) {
    const limit = Number.isSafeInteger(journalSizeLimitBytes) && journalSizeLimitBytes >= -1
      ? journalSizeLimitBytes
      : DEFAULT_JOURNAL_SIZE_LIMIT_BYTES;
    database.exec(`PRAGMA journal_size_limit = ${limit}`);
  }
  database.exec('PRAGMA foreign_keys = ON');
  database.exec('PRAGMA synchronous = NORMAL');
  database.exec('PRAGMA cache_size = -32000');
  database.exec('PRAGMA temp_store = MEMORY');
  database.exec('PRAGMA busy_timeout = 5000');
  database.exec('PRAGMA mmap_size = 268435456');
  registerDatabaseFunctions(database);
  return database;
}

export function pragmaNumber(database: Database, name: string): number {
  const row = database.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined;
  const value = row ? Object.values(row)[0] : 0;
  return Number(value) || 0;
}

export function pragmaString(database: Database, name: string): string {
  const row = database.prepare(`PRAGMA ${name}`).get() as Record<string, unknown> | undefined;
  const value = row ? Object.values(row)[0] : '';
  return String(value || '').toLowerCase();
}

export function registerDatabaseFunctions(database: Database): void {
  try {
    database.function?.('matches_ip_search_value', { deterministic: true }, (candidate: unknown, value: unknown) =>
      matchesIpSearchValue(candidate as string | number | null | undefined, String(value ?? '')) ? 1 : 0,
    );
  } catch {
    // Older better-sqlite3 builds may not expose custom functions; SQL callers also keep LIKE fallbacks.
  }
}

export function isDatabaseFresh(db: Database, schema = 'main'): boolean {
  const row = db.query(`
    SELECT COUNT(*) AS count
    FROM ${schema}.sqlite_master
    WHERE type = 'table'
      AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'
  `).get() as CountRow;
  return row.count === 0;
}

export function createDatabase(dbPath: string): Database {
  const database = new BetterSqlite3(dbPath) as Database;
  database.query = (sql: string) => {
    const statement = database.prepare(sql);
    return {
      run: (...params: any[]) => (statement.run as any)(...params.map(normalizeBindingValue)),
      get: (...params: any[]) => (statement.get as any)(...params.map(normalizeBindingValue)),
      all: (...params: any[]) => (statement.all as any)(...params.map(normalizeBindingValue)),
    };
  };
  return database;
}

export function normalizeBindingValue(value: unknown): unknown {
  if (!value || Array.isArray(value) || Buffer.isBuffer(value) || value instanceof Date || typeof value !== 'object') {
    return value;
  }

  const normalized: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    normalized[key.replace(/^[$:@]/, '')] = entry;
  }
  return normalized;
}

export function removeDatabaseFiles(dbPath: string): void {
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    fs.rmSync(`${dbPath}${suffix}`, { force: true });
  }
}

export function readOptionalString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

export function normalizeOptionalTimestamp(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? normalizeIsoTimestamp(value) : null;
}

export function alertRowsToLegacyPayloads(rows: AlertDataRow[]): RowWithRawData[] {
  return rows.map((row) => ({
    raw_data: JSON.stringify(alertFromRow(row)),
    created_at: row.created_at,
  }));
}
