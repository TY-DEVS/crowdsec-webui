import { runChunkedIdMutation } from './connection';
import type { Database, SqliteStatement } from './types';

export interface SearchIndexRepositoryOptions {
  searchIndexAvailable: boolean;
  isSearchIndexUpdatesDeferred: () => boolean;
}

export class SearchIndexRepository {
  public readonly searchIndexAvailable: boolean;
  private readonly isDeferred: () => boolean;
  private readonly deleteAlertSearchIndexStatement: SqliteStatement | null;
  private readonly insertAlertSearchIndexStatement: SqliteStatement | null;
  private readonly deleteDecisionSearchIndexStatement: SqliteStatement | null;
  private readonly deleteDecisionSearchRowStatement: SqliteStatement | null;
  private readonly insertDecisionSearchIndexStatement: SqliteStatement | null;
  private readonly upsertDecisionSearchRowStatement: SqliteStatement | null;

  constructor(
    private readonly db: Database,
    options: SearchIndexRepositoryOptions,
  ) {
    this.searchIndexAvailable = options.searchIndexAvailable;
    this.isDeferred = options.isSearchIndexUpdatesDeferred;

    this.deleteAlertSearchIndexStatement = this.searchIndexAvailable
      ? db.prepare('DELETE FROM alerts_fts WHERE rowid = ?')
      : null;
    this.insertAlertSearchIndexStatement = this.searchIndexAvailable
      ? db.prepare('INSERT INTO alerts_fts(rowid, alert_id, search_text) VALUES (?, ?, ?)')
      : null;
    this.deleteDecisionSearchIndexStatement = this.searchIndexAvailable
      ? db.prepare(`
          DELETE FROM decisions_fts
          WHERE rowid = (
            SELECT fts_rowid
            FROM decision_fts_rows
            WHERE decision_id = ?
          )
        `)
      : null;
    this.deleteDecisionSearchRowStatement = this.searchIndexAvailable
      ? db.prepare('DELETE FROM decision_fts_rows WHERE decision_id = ?')
      : null;
    this.insertDecisionSearchIndexStatement = this.searchIndexAvailable
      ? db.prepare('INSERT INTO decisions_fts(decision_id, search_text) VALUES (?, ?)')
      : null;
    this.upsertDecisionSearchRowStatement = this.searchIndexAvailable
      ? db.prepare(`
          INSERT INTO decision_fts_rows (decision_id, fts_rowid)
          VALUES (?, ?)
          ON CONFLICT(decision_id) DO UPDATE SET fts_rowid = excluded.fts_rowid
        `)
      : null;
  }

  clearSearchIndexes(): void {
    if (!this.searchIndexAvailable) return;
    this.runSearchIndexStatement('DELETE FROM alerts_fts');
    this.runSearchIndexStatement('DELETE FROM decisions_fts');
    this.runSearchIndexStatement('DELETE FROM decision_fts_rows');
  }

  upsertAlertSearchIndex(id: string | number, searchText: string): void {
    if (this.isDeferred()) return;
    if (!this.searchIndexAvailable || !this.deleteAlertSearchIndexStatement || !this.insertAlertSearchIndexStatement) return;
    const numericId = Number(id);
    if (!Number.isSafeInteger(numericId) || numericId === 0) return;
    try {
      this.deleteAlertSearchIndexStatement.run(String(id));
      this.insertAlertSearchIndexStatement.run(numericId, String(id), searchText);
    } catch {
      // Search indexing is an optimization; core table data remains authoritative.
    }
  }

  insertAlertSearchIndex(numericId: number, id: string, searchText: string): void {
    if (!this.insertAlertSearchIndexStatement) return;
    try {
      this.insertAlertSearchIndexStatement.run(numericId, id, searchText);
    } catch {
      // Search indexing is an optimization; core table data remains authoritative.
    }
  }

  upsertDecisionSearchIndex(id: string | number, searchText: string): void {
    if (this.isDeferred()) return;
    if (!this.searchIndexAvailable || !this.deleteDecisionSearchIndexStatement || !this.insertDecisionSearchIndexStatement) return;
    try {
      this.deleteDecisionSearchIndex(id);
      this.insertDecisionSearchIndexRow(String(id), searchText);
    } catch {
      // Search indexing is an optimization; core table data remains authoritative.
    }
  }

  insertDecisionSearchIndexRow(id: string, searchText: string): void {
    if (!this.insertDecisionSearchIndexStatement || !this.upsertDecisionSearchRowStatement) return;
    const result = this.insertDecisionSearchIndexStatement.run(id, searchText);
    if (result.lastInsertRowid === undefined) return;
    this.upsertDecisionSearchRowStatement.run(id, result.lastInsertRowid);
  }

  deleteAlertSearchIndex(id: string | number): void {
    if (this.isDeferred()) return;
    if (!this.searchIndexAvailable || !this.deleteAlertSearchIndexStatement) return;
    try {
      this.deleteAlertSearchIndexStatement.run(String(id));
    } catch {
      // Search indexing is an optimization; core table data remains authoritative.
    }
  }

  deleteAlertSearchIndexes(ids: string[]): void {
    if (this.isDeferred()) return;
    if (!this.searchIndexAvailable || ids.length === 0) return;
    runChunkedIdMutation(this.db, 'DELETE FROM alerts_fts WHERE rowid IN', ids);
  }

  deleteDecisionSearchIndex(id: string | number): void {
    if (!this.searchIndexAvailable || !this.deleteDecisionSearchIndexStatement || !this.deleteDecisionSearchRowStatement) return;
    try {
      this.deleteDecisionSearchIndexStatement.run(String(id));
      this.deleteDecisionSearchRowStatement.run(String(id));
    } catch {
      // Search indexing is an optimization; core table data remains authoritative.
    }
  }

  deleteDecisionSearchIndexes(ids: string[]): void {
    if (!this.searchIndexAvailable || ids.length === 0) return;
    const chunkSize = 900;
    for (let offset = 0; offset < ids.length; offset += chunkSize) {
      const chunk = ids.slice(offset, offset + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      this.db.prepare(`
        DELETE FROM decisions_fts
        WHERE rowid IN (
          SELECT fts_rowid
          FROM decision_fts_rows
          WHERE decision_id IN (${placeholders})
        )
      `).run(...chunk);
      this.db.prepare(`DELETE FROM decision_fts_rows WHERE decision_id IN (${placeholders})`).run(...chunk);
    }
  }

  deleteDecisionSearchIndexesByAlertIds(alertIds: string[]): void {
    if (this.isDeferred()) return;
    if (!this.searchIndexAvailable || alertIds.length === 0) return;
    const decisionIds: string[] = [];
    const chunkSize = 900;
    for (let offset = 0; offset < alertIds.length; offset += chunkSize) {
      const chunk = alertIds.slice(offset, offset + chunkSize);
      const placeholders = chunk.map(() => '?').join(',');
      const rows = this.db.prepare(`SELECT id FROM decisions WHERE alert_id IN (${placeholders})`).all(...chunk) as Array<{ id: string | number }>;
      // One imported-blocklist alert can own many thousands of decisions; avoid spreading them into a call.
      for (const row of rows) decisionIds.push(String(row.id));
    }
    this.deleteDecisionSearchIndexes(decisionIds);
  }

  runSearchIndexStatement(sql: string, ...params: unknown[]): void {
    try {
      this.db.prepare(sql).run(...params);
    } catch {
      // Search indexing is an optimization; core table data remains authoritative.
    }
  }
}
