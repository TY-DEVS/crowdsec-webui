import { normalizeIsoTimestamp } from '../utils/date-time';
import {
  ALLOWLIST_SYNC_META_PREFIX,
  STATE_SCHEMA,
  isStateSettingKey,
  type CachedAllowlist,
  type Database,
  type JsonRow,
  type MetaRow,
  type SqliteStatement,
} from './types';

export class MetaRepository {
  private readonly getMetaStatement: SqliteStatement;
  private readonly setMetaStatement: SqliteStatement;
  private readonly getSettingStatement: SqliteStatement;
  private readonly setSettingStatement: SqliteStatement;
  private readonly getCveCacheEntryStatement: SqliteStatement;
  private readonly upsertCveCacheEntryStatement: SqliteStatement;

  constructor(
    private readonly db: Database,
    stateQuery: (sql: string) => SqliteStatement,
  ) {
    this.getMetaStatement = db.query('SELECT value FROM meta WHERE key = ?');
    this.setMetaStatement = db.query('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)');
    this.getSettingStatement = stateQuery(`SELECT value FROM ${STATE_SCHEMA}.settings WHERE key = ?`);
    this.setSettingStatement = stateQuery(`INSERT OR REPLACE INTO ${STATE_SCHEMA}.settings (key, value) VALUES (?, ?)`);
    this.getCveCacheEntryStatement = db.query('SELECT id, published_at, fetched_at FROM cve_cache WHERE id = $id');
    this.upsertCveCacheEntryStatement = db.query(`
      INSERT OR REPLACE INTO cve_cache (id, published_at, fetched_at)
      VALUES ($id, $published_at, $fetched_at)
    `);
  }

  getMeta(key: string): MetaRow | null {
    const statement = isStateSettingKey(key) ? this.getSettingStatement : this.getMetaStatement;
    return (statement.get(key) as MetaRow | null) || null;
  }

  setMeta(key: string, value: string): void {
    const statement = isStateSettingKey(key) ? this.setSettingStatement : this.setMetaStatement;
    statement.run(key, value);
  }

  isAuthMigrationDefaultDisabled(): boolean {
    return this.getMeta('auth_existing_install_default_disabled')?.value === 'true';
  }

  isStatisticsMigrationDefaultDisabled(): boolean {
    return this.getMeta('statistics_existing_install_default_disabled')?.value === 'true';
  }

  getCveCacheEntry(id: string): JsonRow | null {
    return (this.getCveCacheEntryStatement.get({ $id: id }) as JsonRow | null) || null;
  }

  upsertCveCacheEntry(id: string, publishedAt: string, fetchedAt: string): void {
    this.upsertCveCacheEntryStatement.run({
      $id: id,
      $published_at: normalizeIsoTimestamp(publishedAt),
      $fetched_at: normalizeIsoTimestamp(fetchedAt),
    });
  }

  replaceAllowlists(instanceId: string, allowlists: CachedAllowlist[] | null, syncState: string): { changed: boolean } {
    let changed = false;
    const replace = this.db.transaction(() => {
      this.setMeta(`${ALLOWLIST_SYNC_META_PREFIX}${instanceId}`, syncState);
      if (!allowlists) return;
      const cachedLists = new Map((this.db.prepare(`
        SELECT name, allowlist_id, description, created_at, updated_at, console_managed
        FROM allowlists WHERE instance_id = ?
      `).all(instanceId) as Array<Record<string, string | number | null>>).map((row) => [String(row.name), row]));
      const upsertList = this.db.prepare(`
        INSERT INTO allowlists (instance_id, name, allowlist_id, description, created_at, updated_at, console_managed)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(instance_id, name) DO UPDATE SET
          allowlist_id = excluded.allowlist_id,
          description = excluded.description,
          created_at = excluded.created_at,
          updated_at = excluded.updated_at,
          console_managed = excluded.console_managed
      `);
      for (const allowlist of allowlists) {
        const values = [
          allowlist.allowlist_id ?? null,
          allowlist.description ?? null,
          allowlist.created_at ?? null,
          allowlist.updated_at ?? null,
          allowlist.console_managed ? 1 : 0,
        ];
        const cached = cachedLists.get(allowlist.name);
        cachedLists.delete(allowlist.name);
        if (cached && [cached.allowlist_id, cached.description, cached.created_at, cached.updated_at, cached.console_managed]
          .every((value, index) => value === values[index])) continue;
        upsertList.run(instanceId, allowlist.name, ...values);
        changed = true;
      }
      const deleteList = this.db.prepare('DELETE FROM allowlists WHERE instance_id = ? AND name = ?');
      const deleteListItems = this.db.prepare('DELETE FROM allowlist_items WHERE instance_id = ? AND allowlist_name = ?');
      for (const name of cachedLists.keys()) {
        deleteList.run(instanceId, name);
        deleteListItems.run(instanceId, name);
        changed = true;
      }

      const cachedItems = new Map<string, Record<string, string | null>>();
      for (const row of this.db.prepare(`
        SELECT allowlist_name, value, description, created_at, expiration
        FROM allowlist_items WHERE instance_id = ?
      `).all(instanceId) as Array<Record<string, string | null>>) {
        cachedItems.set(`${row.allowlist_name}\u0000${row.value}`, row);
      }
      const upsertItem = this.db.prepare(`
        INSERT INTO allowlist_items (instance_id, allowlist_name, value, description, created_at, expiration)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(instance_id, allowlist_name, value) DO UPDATE SET
          description = excluded.description,
          created_at = excluded.created_at,
          expiration = excluded.expiration
      `);
      for (const allowlist of allowlists) {
        for (const item of allowlist.items) {
          const key = `${allowlist.name}\u0000${item.value}`;
          const values = [item.description ?? null, item.created_at ?? null, item.expiration];
          const cached = cachedItems.get(key);
          cachedItems.delete(key);
          if (cached && cached.description === values[0] && cached.created_at === values[1] && cached.expiration === values[2]) continue;
          upsertItem.run(instanceId, allowlist.name, item.value, ...values);
          changed = true;
        }
      }
      const deleteItem = this.db.prepare('DELETE FROM allowlist_items WHERE instance_id = ? AND allowlist_name = ? AND value = ?');
      for (const row of cachedItems.values()) {
        deleteItem.run(instanceId, row.allowlist_name, row.value);
        changed = true;
      }
    });
    replace();
    return { changed };
  }
}
