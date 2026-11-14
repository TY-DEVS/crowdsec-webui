import fs from 'node:fs';
import path from 'node:path';
import { initStatisticsCaptureSchema } from './statistics-capture';
import {
  attachStateDatabase,
  openDatabase,
  pragmaNumber,
  pragmaString,
  resolveDatabasePaths,
  restoreAlertDeletionTombstones,
  runChunkedIdMutation,
} from './db/connection';
import {
  backfillSearchIndexes,
  backfillSearchIndexesCooperative,
  initCacheSchema,
  migrateLegacyDatabase,
} from './db/schema';
import { SearchIndexRepository } from './db/search-index-repository';
import { MetaRepository } from './db/meta-repository';
import { UserRepository } from './db/user-repository';
import { NotificationRepository } from './db/notification-repository';
import { DecisionRepository } from './db/decision-repository';
import { AlertRepository } from './db/alert-repository';
import {
  ALLOWLIST_SYNC_META_PREFIX,
  CREATE_SYNC_SECONDARY_INDEXES_SQL,
  INCREMENTAL_VACUUM_META_KEY,
  SYNC_SECONDARY_INDEX_NAMES,
  type AlertDataRow,
  type AlertDecisionSnapshotRow,
  type AlertInsertParams,
  type AuthUserListRow,
  type AuthUserRow,
  type CachedAllowlist,
  type CountRow,
  type Database,
  type DatabaseOptions,
  type DecisionDataRow,
  type DecisionInsertParams,
  type DecisionUpdateParams,
  type IncrementalVacuumOptions,
  type IncrementalVacuumResult,
  type JsonRow,
  type MetaRow,
  type OidcLinkMethod,
  type OidcUserUpsertParams,
  type PendingAlertDeletionRow,
  type RowWithRawData,
  type SearchIndexRebuildScope,
  type SqliteStatement,
  type SqliteStorageStats,
  type WebAuthnCredentialRow,
} from './db/types';

export * from './db/types';

export class CrowdsecDatabase {
  public readonly db: Database;
  public readonly cachePath: string;
  public readonly statePath: string | null;
  public readonly wasFresh: boolean;
  public readonly searchIndexAvailable: boolean;

  public readonly searchIndex: SearchIndexRepository;
  public readonly meta: MetaRepository;
  public readonly users: UserRepository;
  public readonly notifications: NotificationRepository;
  public readonly decisions: DecisionRepository;
  public readonly alerts: AlertRepository;

  private searchIndexUpdatesDeferred = false;
  private dashboardChangeTrackingDeferred = false;

  constructor(options: DatabaseOptions = {}) {
    const paths = resolveDatabasePaths(options);
    this.cachePath = paths.cachePath;
    this.statePath = paths.statePath;

    if (paths.legacyPath && paths.statePath) {
      migrateLegacyDatabase(paths.legacyPath, paths.statePath);
    }

    const { database, wasFresh } = openDatabase(
      this.cachePath,
      options.walEnabled ?? true,
      options.journalSizeLimitBytes ?? -1,
      options.incrementalVacuumEnabled ?? true,
    );
    this.db = database;
    this.wasFresh = wasFresh;

    this.searchIndexAvailable = initCacheSchema(this.db);
    initStatisticsCaptureSchema(this.db);

    if (this.statePath) {
      attachStateDatabase(this.db, this.statePath);
      restoreAlertDeletionTombstones(this.db);
    }

    this.searchIndex = new SearchIndexRepository(this.db, {
      searchIndexAvailable: this.searchIndexAvailable,
      isSearchIndexUpdatesDeferred: () => this.searchIndexUpdatesDeferred,
    });

    this.meta = new MetaRepository(this.db, this.stateQuery.bind(this));
    this.users = new UserRepository(this.db, this.stateQuery.bind(this), {
      revokeOidcSession: (issuer, sid, exp) => this.revokeOidcSession(issuer, sid, exp),
      revokeOidcUserSessions: (issuer, sub) => this.revokeOidcUserSessions(issuer, sub),
      bumpOidcLogoutVersion: (issuer, sub) => this.bumpOidcLogoutVersion(issuer, sub),
    });
    this.notifications = new NotificationRepository(this.db, this.stateQuery.bind(this));

    this.decisions = new DecisionRepository(this.db, {
      searchIndex: this.searchIndex,
      getPrimaryInstanceId: () => this.meta.getMeta('multi_instance_primary_id')?.value || 'default',
      hasTombstone: (tombstoneId, alertId) => this.alerts.hasTombstone(tombstoneId, alertId),
      resolveAlertInternalId: (instanceId, alertId) => this.alerts.resolveAlertInternalId(instanceId, alertId),
      getAlertInternalId: (instanceId, alertId) => this.alerts.getAlertInternalId(instanceId, alertId),
    });

    this.alerts = new AlertRepository(this.db, {
      searchIndex: this.searchIndex,
      decisions: this.decisions,
      getPrimaryInstanceId: () => this.meta.getMeta('multi_instance_primary_id')?.value || 'default',
    });

    this.decisions.setOptions({
      hasTombstone: (tombstoneId, alertId) => this.alerts.hasTombstone(tombstoneId, alertId),
      resolveAlertInternalId: (instanceId, alertId) => this.alerts.resolveAlertInternalId(instanceId, alertId),
      getAlertInternalId: (instanceId, alertId) => this.alerts.getAlertInternalId(instanceId, alertId),
    });
  }

  close(): void {
    try {
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } finally {
      this.db.close();
    }
  }

  getStorageStats(): SqliteStorageStats {
    const pageSize = pragmaNumber(this.db, 'page_size');
    const pageCount = pragmaNumber(this.db, 'page_count');
    const freelistCount = pragmaNumber(this.db, 'freelist_count');
    return {
      autoVacuum: pragmaNumber(this.db, 'auto_vacuum'),
      pageSize,
      pageCount,
      freelistCount,
      reclaimableBytes: freelistCount * pageSize,
      freeRatio: pageCount > 0 ? freelistCount / pageCount : 0,
      journalMode: pragmaString(this.db, 'journal_mode'),
    };
  }

  runIncrementalVacuum(options: IncrementalVacuumOptions): IncrementalVacuumResult {
    const before = this.getStorageStats();
    if (before.autoVacuum !== 2) {
      return { performed: false, reason: 'disabled', before, after: before };
    }
    if (before.freeRatio < options.minFreeRatio || before.reclaimableBytes < options.minFreeBytes) {
      return { performed: false, reason: 'below-threshold', before, after: before };
    }

    const lastRun = Date.parse(this.getMeta(INCREMENTAL_VACUUM_META_KEY)?.value || '');
    if (Number.isFinite(lastRun) && options.now - lastRun < options.cooldownMs) {
      return { performed: false, reason: 'cooldown', before, after: before };
    }

    const maxPages = Math.max(1, Math.floor(options.maxPages));
    this.db.exec(`PRAGMA incremental_vacuum(${maxPages})`);
    this.setMeta(INCREMENTAL_VACUUM_META_KEY, new Date(options.now).toISOString());
    return { performed: true, reason: 'completed', before, after: this.getStorageStats() };
  }

  clearSyncData(): void {
    const dashboardTrackingEnabled = this.getMeta('dashboard_change_tracking_enabled')?.value !== 'false';
    if (dashboardTrackingEnabled) this.setMeta('dashboard_change_tracking_enabled', 'false');
    try {
      this.db.exec('DELETE FROM decisions');
      this.db.exec('DELETE FROM alerts');
      this.db.exec("DELETE FROM meta WHERE key IN ('statistics_backfill_alerts', 'statistics_backfill_decisions')");
      this.db.exec('DELETE FROM allowlists');
      this.db.exec('DELETE FROM allowlist_items');
      this.db.exec(`DELETE FROM meta WHERE key LIKE '${ALLOWLIST_SYNC_META_PREFIX}%'`);
      this.decisions.loadDecisionDuplicateRefreshState();
      this.db.prepare(`
        DELETE FROM meta
        WHERE key IN (
          'decision_duplicate_refresh_at',
          'decision_duplicate_flags_dirty',
          'decision_duplicate_rank_version'
        )
      `).run();
      this.searchIndex.clearSearchIndexes();
    } finally {
      if (dashboardTrackingEnabled) {
        this.resetDashboardRecordChanges();
        this.setMeta('dashboard_change_tracking_enabled', 'true');
      } else {
        this.db.exec('DELETE FROM dashboard_record_changes');
      }
    }
  }

  beginDeferredSearchIndexUpdates(dropSecondaryIndexes = true, clearSearchIndexes = true): void {
    this.searchIndexUpdatesDeferred = true;
    if (dropSecondaryIndexes) {
      const deferDashboardChanges = this.db.transaction(() => {
        this.db.prepare(`
          INSERT INTO meta(key, value)
          VALUES ('dashboard_change_tracking_enabled', 'false')
          ON CONFLICT(key) DO UPDATE SET value = 'false'
        `).run();
        this.db.prepare(`
          INSERT INTO meta(key, value)
          VALUES ('dashboard_change_epoch', '2')
          ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
        `).run();
        this.db.prepare(`
          INSERT INTO meta(key, value)
          VALUES ('dashboard_change_floor', '0')
          ON CONFLICT(key) DO UPDATE SET value = '0'
        `).run();
        this.db.exec('DELETE FROM dashboard_record_changes');
      });
      deferDashboardChanges();
      this.dashboardChangeTrackingDeferred = true;
    }
    if (this.searchIndexAvailable && clearSearchIndexes) this.searchIndex.clearSearchIndexes();
    if (dropSecondaryIndexes) {
      for (const indexName of SYNC_SECONDARY_INDEX_NAMES) {
        this.db.exec(`DROP INDEX IF EXISTS ${indexName}`);
      }
    }
  }

  rebuildSearchIndexes(scope?: SearchIndexRebuildScope): void {
    try {
      if (scope) {
        this.rebuildScopedSearchIndexes(scope);
      } else {
        this.db.exec(CREATE_SYNC_SECONDARY_INDEXES_SQL);
        if (this.searchIndexAvailable) {
          this.searchIndex.clearSearchIndexes();
          backfillSearchIndexes(this.db);
        }
      }
    } finally {
      this.searchIndexUpdatesDeferred = false;
      if (this.dashboardChangeTrackingDeferred) {
        const publishDashboardChanges = this.db.transaction(() => {
          this.db.prepare(`
            INSERT INTO meta(key, value)
            VALUES ('dashboard_change_epoch', '2')
            ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
          `).run();
          this.db.prepare(`
            INSERT INTO meta(key, value)
            VALUES ('dashboard_change_floor', '0')
            ON CONFLICT(key) DO UPDATE SET value = '0'
          `).run();
          this.db.exec('DELETE FROM dashboard_record_changes');
          this.db.prepare(`
            INSERT INTO meta(key, value)
            VALUES ('dashboard_change_tracking_enabled', 'true')
            ON CONFLICT(key) DO UPDATE SET value = 'true'
          `).run();
        });
        publishDashboardChanges();
        this.dashboardChangeTrackingDeferred = false;
      }
    }
  }

  pruneDashboardRecordChanges(changeEpoch: number, throughRevision: number): void {
    const currentEpoch = Number(this.getMeta('dashboard_change_epoch')?.value || 0);
    if (currentEpoch !== changeEpoch || !Number.isFinite(throughRevision) || throughRevision <= 0) return;
    this.runNonBlockingDashboardMaintenance(() => {
      const prune = this.db.transaction(() => {
        this.db.prepare(`
          INSERT INTO meta(key, value)
          VALUES ('dashboard_change_floor', ?)
          ON CONFLICT(key) DO UPDATE SET value = MAX(CAST(value AS INTEGER), CAST(excluded.value AS INTEGER))
        `).run(String(throughRevision));
        this.db.prepare('DELETE FROM dashboard_record_changes WHERE revision <= ?').run(throughRevision);
      });
      prune();
    });
  }

  countDashboardRecordChanges(): number {
    return Number((
      this.db.prepare('SELECT COUNT(*) AS count FROM dashboard_record_changes').get() as CountRow
    ).count) || 0;
  }

  resetDashboardRecordChanges(): void {
    this.runNonBlockingDashboardMaintenance(() => {
      const reset = this.db.transaction(() => {
        this.db.prepare(`
          INSERT INTO meta(key, value)
          VALUES ('dashboard_change_epoch', '2')
          ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1
        `).run();
        this.db.prepare(`
          INSERT INTO meta(key, value)
          VALUES ('dashboard_change_floor', '0')
          ON CONFLICT(key) DO UPDATE SET value = '0'
        `).run();
        this.db.exec('DELETE FROM dashboard_record_changes');
      });
      reset();
    });
  }

  private runNonBlockingDashboardMaintenance(action: () => void): void {
    const row = this.db.prepare('PRAGMA busy_timeout').get() as { timeout?: number } | undefined;
    const busyTimeout = Math.max(0, Number(row?.timeout) || 0);
    this.db.exec('PRAGMA busy_timeout = 0');
    try {
      action();
    } catch (error) {
      const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
      if (!message.includes('database is locked') && !message.includes('database is busy')) throw error;
    } finally {
      this.db.exec(`PRAGMA busy_timeout = ${busyTimeout}`);
    }
  }

  private rebuildScopedSearchIndexes(scope: SearchIndexRebuildScope): void {
    if (!this.searchIndexAvailable) return;

    const alertIds = Array.from(new Set(scope.alertIds.map(String)));
    const decisionIds = Array.from(new Set(scope.decisionIds.map(String)));
    const rebuild = this.db.transaction(() => {
      runChunkedIdMutation(this.db, 'DELETE FROM alerts_fts WHERE rowid IN', alertIds);
      this.searchIndex.deleteDecisionSearchIndexes(decisionIds);

      for (let offset = 0; offset < alertIds.length; offset += 900) {
        const chunk = alertIds.slice(offset, offset + 900);
        if (chunk.length === 0) continue;
        const placeholders = chunk.map(() => '?').join(',');
        const rows = this.db.prepare(`
          SELECT id, search_text
          FROM alerts
          WHERE id IN (${placeholders})
            AND search_text IS NOT NULL
            AND search_text <> ''
        `).all(...chunk) as Array<{ id: string | number; search_text: string }>;
        for (const row of rows) {
          const numericId = Number(row.id);
          if (!Number.isSafeInteger(numericId) || numericId === 0) continue;
          this.searchIndex.insertAlertSearchIndex(numericId, String(row.id), row.search_text);
        }
      }

      for (let offset = 0; offset < decisionIds.length; offset += 900) {
        const chunk = decisionIds.slice(offset, offset + 900);
        if (chunk.length === 0) continue;
        const placeholders = chunk.map(() => '?').join(',');
        const rows = this.db.prepare(`
          SELECT id, search_text
          FROM decisions
          WHERE id IN (${placeholders})
            AND search_text IS NOT NULL
            AND search_text <> ''
        `).all(...chunk) as Array<{ id: string | number; search_text: string }>;
        for (const row of rows) {
          this.searchIndex.insertDecisionSearchIndexRow(String(row.id), row.search_text);
        }
      }
    });
    rebuild();
  }

  async rebuildSearchIndexesCooperative(yieldControl: () => Promise<void>, batchSize = 1_000): Promise<void> {
    if (!this.searchIndexAvailable) {
      return;
    }
    try {
      this.searchIndex.clearSearchIndexes();
      await backfillSearchIndexesCooperative(this.db, yieldControl, batchSize);
    } finally {
      this.searchIndexUpdatesDeferred = false;
    }
  }

  // --- Alert Operations ---
  insertAlert(params: AlertInsertParams): boolean {
    return this.alerts.insertAlert(params);
  }

  getAllAlerts(): RowWithRawData[] {
    return this.alerts.getAllAlerts();
  }

  getAlertsSince(since: string): RowWithRawData[] {
    return this.alerts.getAlertsSince(since);
  }

  getAlertsBetween(start: string, end: string): RowWithRawData[] {
    return this.alerts.getAlertsBetween(start, end);
  }

  getAlertDecisionSnapshot(id: string | number, instanceId?: string): AlertDecisionSnapshotRow | null {
    return this.alerts.getAlertDecisionSnapshot(id, instanceId);
  }

  updateAlertRawData(id: string | number, rawData?: string, instanceId?: string): boolean {
    return this.alerts.updateAlertRawData(id, rawData, instanceId);
  }

  countAlerts(instanceId?: string): number {
    return this.alerts.countAlerts(instanceId);
  }

  deleteOldAlerts(cutoff: string, limit = Infinity): number {
    return this.alerts.deleteOldAlerts(cutoff, limit);
  }

  deleteAlert(id: string | number): void {
    this.alerts.deleteAlert(id);
  }

  deleteAlertByInstanceId(instanceId: string, upstreamId: string | number): void {
    this.alerts.deleteAlertByInstanceId(instanceId, upstreamId);
  }

  deleteCachedAlerts(ids: Array<string | number>): { alerts: number; decisions: number } {
    return this.alerts.deleteCachedAlerts(ids);
  }

  deleteAlertsMissingBetween(
    start: string,
    end: string,
    keepIds: Array<string | number>,
    instanceId?: string,
  ): { alerts: number; decisions: number } {
    return this.alerts.deleteAlertsMissingBetween(start, end, keepIds, instanceId);
  }

  getAlertInternalId(instanceId: string, upstreamId: string | number): number | null {
    return this.alerts.getAlertInternalId(instanceId, upstreamId);
  }

  queueAlertDeletion(alertId: string | number, decisionIds: string[], requestedAt: string): void {
    this.alerts.queueAlertDeletion(alertId, decisionIds, requestedAt);
  }

  refreshAlertDeletionTombstones(): void {
    this.alerts.refreshAlertDeletionTombstones();
  }

  getPendingAlertDeletions(): PendingAlertDeletionRow[] {
    return this.alerts.getPendingAlertDeletions();
  }

  markAlertDeletionDecisionsExpired(alertId: string | number, deletedAt: string, deleteAfter: string): void {
    this.alerts.markAlertDeletionDecisionsExpired(alertId, deletedAt, deleteAfter);
  }

  recordAlertDeletionFailure(alertId: string | number, attemptedAt: string, error: string): void {
    this.alerts.recordAlertDeletionFailure(alertId, attemptedAt, error);
  }

  completeAlertDeletion(alertId: string | number, completedAt: string): void {
    this.alerts.completeAlertDeletion(alertId, completedAt);
  }

  expireAlertDeletion(alertId: string | number, completedAt: string, error: string): void {
    this.alerts.expireAlertDeletion(alertId, completedAt, error);
  }

  purgeCompletedAlertDeletions(completedBefore: string): number {
    return this.alerts.purgeCompletedAlertDeletions(completedBefore);
  }

  getAlertDeletionTombstone(alertId: string | number): PendingAlertDeletionRow | null {
    return this.alerts.getAlertDeletionTombstone(alertId);
  }

  // --- Decision Operations ---
  insertDecision(params: DecisionInsertParams): boolean {
    return this.decisions.insertDecision(params);
  }

  updateDecision(params: DecisionUpdateParams): void {
    this.decisions.updateDecision(params);
  }

  getAllDecisions(): DecisionDataRow[] {
    return this.decisions.getAllDecisions();
  }

  getActiveDecisions(now: string): DecisionDataRow[] {
    return this.decisions.getActiveDecisions(now);
  }

  deleteActiveAlertsMissing(keepIds: Array<string | number>, now: string, since: string): { alerts: number; decisions: number } {
    return this.decisions.deleteActiveAlertsMissing(keepIds, now, since);
  }

  getDecisionsSince(since: string, now: string): DecisionDataRow[] {
    return this.decisions.getDecisionsSince(since, now);
  }

  deleteOldDecisions(cutoff: string, limit?: number): number {
    return this.decisions.deleteOldDecisions(cutoff, limit);
  }

  deleteDecision(id: string | number): void {
    this.decisions.deleteDecision(id);
  }

  deleteCachedDecisions(ids: Array<string | number>): number {
    return this.decisions.deleteCachedDecisions(ids);
  }

  getDecisionById(id: string | number): DecisionDataRow | null {
    return this.decisions.getDecisionById(id);
  }

  getDecisionInternalId(instanceId: string, upstreamId: string | number): string | null {
    return this.decisions.getDecisionInternalId(instanceId, upstreamId);
  }

  deleteDecisionByInstanceId(instanceId: string, upstreamId: string | number): void {
    this.decisions.deleteDecisionByInstanceId(instanceId, upstreamId);
  }

  getDecisionIdsByAlertId(alertId: string | number, instanceId?: string): string[] {
    return this.decisions.getDecisionIdsByAlertId(alertId, instanceId);
  }

  getDecisionDataByAlertIds(alertIds: Array<string | number>): Map<string, DecisionDataRow[]> {
    return this.decisions.getDecisionDataByAlertIds(alertIds);
  }

  deleteDecisionsByAlertIdExcept(alertId: string | number, keepIds: string[], instanceId?: string): number {
    return this.decisions.deleteDecisionsByAlertIdExcept(alertId, keepIds, instanceId);
  }

  getDecisionStopAtBatch(ids: string[], instanceId?: string): Map<string, string> {
    return this.decisions.getDecisionStopAtBatch(ids, instanceId);
  }

  getDecisionDataBatch(ids: string[]): Map<string, DecisionDataRow> {
    return this.decisions.getDecisionDataBatch(ids);
  }

  getActiveDecisionByValue(value: string, now: string): DecisionDataRow | null {
    return this.decisions.getActiveDecisionByValue(value, now);
  }

  deleteDecisionsByAlertId(alertId: string | number): void {
    this.decisions.deleteDecisionsByAlertId(alertId);
  }

  countDecisions(instanceId?: string): number {
    return this.decisions.countDecisions(instanceId);
  }

  refreshDecisionDuplicateFlags(now: string, force = false): number {
    return this.decisions.refreshDecisionDuplicateFlags(now, force);
  }

  // --- Notification Operations ---
  listNotificationChannels(): JsonRow[] {
    return this.notifications.listNotificationChannels();
  }

  getNotificationChannelById(id: string): JsonRow | null {
    return this.notifications.getNotificationChannelById(id);
  }

  upsertNotificationChannel(params: {
    $id: string;
    $created_at: string;
    $updated_at: string;
    $name: string;
    $type: string;
    $enabled: number;
    $config_json: string;
  }): void {
    this.notifications.upsertNotificationChannel(params);
  }

  deleteNotificationChannel(id: string): void {
    this.notifications.deleteNotificationChannel(id);
  }

  listNotificationRules(): JsonRow[] {
    return this.notifications.listNotificationRules();
  }

  getNotificationRuleById(id: string): JsonRow | null {
    return this.notifications.getNotificationRuleById(id);
  }

  upsertNotificationRule(params: {
    $id: string;
    $created_at: string;
    $updated_at: string;
    $name: string;
    $type: string;
    $enabled: number;
    $severity: string;
    $channel_ids_json: string;
    $config_json: string;
  }): void {
    this.notifications.upsertNotificationRule(params);
  }

  deleteNotificationRule(id: string): void {
    this.notifications.deleteNotificationRule(id);
  }

  listNotificationsPage(page: number, pageSize: number): JsonRow[] {
    return this.notifications.listNotificationsPage(page, pageSize);
  }

  listNotifications(limit = 100): JsonRow[] {
    return this.notifications.listNotifications(limit);
  }

  countNotifications(): number {
    return this.notifications.countNotifications();
  }

  listNotificationIds(): string[] {
    return this.notifications.listNotificationIds();
  }

  insertNotification(params: {
    $id: string;
    $created_at: string;
    $updated_at: string;
    $rule_id: string;
    $rule_name: string;
    $rule_type: string;
    $severity: string;
    $title: string;
    $message: string;
    $read_at: string | null;
    $metadata_json: string;
    $deliveries_json: string;
    $dedupe_key: string;
  }): boolean {
    return this.notifications.insertNotification(params);
  }

  listNotificationIncidentsByRule(ruleId: string): JsonRow[] {
    return this.notifications.listNotificationIncidentsByRule(ruleId);
  }

  upsertNotificationIncident(params: {
    $rule_id: string;
    $incident_key: string;
    $first_seen_at: string;
    $last_seen_at: string;
    $resolved_at: string | null;
  }): void {
    this.notifications.upsertNotificationIncident(params);
  }

  resolveNotificationIncident(ruleId: string, incidentKey: string, resolvedAt: string): boolean {
    return this.notifications.resolveNotificationIncident(ruleId, incidentKey, resolvedAt);
  }

  deleteNotificationIncidentsByRule(ruleId: string): void {
    this.notifications.deleteNotificationIncidentsByRule(ruleId);
  }

  deleteNotification(id: string): boolean {
    return this.notifications.deleteNotification(id);
  }

  deleteNotificationByRuleAndDedupeKey(ruleId: string, dedupeKey: string): boolean {
    return this.notifications.deleteNotificationByRuleAndDedupeKey(ruleId, dedupeKey);
  }

  deleteNotifications(ids: string[]): number {
    return this.notifications.deleteNotifications(ids);
  }

  markNotificationRead(id: string, readAt: string): boolean {
    return this.notifications.markNotificationRead(id, readAt);
  }

  markNotificationsRead(ids: string[], readAt: string): number {
    return this.notifications.markNotificationsRead(ids, readAt);
  }

  markAllNotificationsRead(readAt: string): number {
    return this.notifications.markAllNotificationsRead(readAt);
  }

  deleteReadNotifications(): number {
    return this.notifications.deleteReadNotifications();
  }

  countUnreadNotifications(): number {
    return this.notifications.countUnreadNotifications();
  }

  // --- User & Auth Operations ---
  countAuthUsers(): number {
    return this.users.countAuthUsers();
  }

  createAuthUser(params: {
    username: string;
    passwordHash: string | null;
    role: 'admin' | 'read-only';
    authProvider: 'password' | 'oidc';
    passwordChangeRequired?: boolean;
    oidcAutoLinkBlocked?: boolean;
  }): number {
    return this.users.createAuthUser(params);
  }

  getAuthUserById(id: number): AuthUserRow | null {
    return this.users.getAuthUserById(id);
  }

  getAuthUserByUsername(username: string): AuthUserRow | null {
    return this.users.getAuthUserByUsername(username);
  }

  getAuthUserByOidcIdentity(issuer: string, subject: string): AuthUserRow | null {
    return this.users.getAuthUserByOidcIdentity(issuer, subject);
  }

  updateAuthUserPassword(id: number, passwordHash: string): boolean {
    return this.users.updateAuthUserPassword(id, passwordHash);
  }

  listAuthUsers(): AuthUserListRow[] {
    return this.users.listAuthUsers();
  }

  countActiveAdmins(excludingId?: number): number {
    return this.users.countActiveAdmins(excludingId);
  }

  updateAuthUserRole(id: number, role: 'admin' | 'read-only'): boolean {
    return this.users.updateAuthUserRole(id, role);
  }

  setAuthUserDisabled(id: number, disabled: boolean): boolean {
    return this.users.setAuthUserDisabled(id, disabled);
  }

  resetAuthUserPassword(id: number, passwordHash: string, changeRequired: boolean): boolean {
    return this.users.resetAuthUserPassword(id, passwordHash, changeRequired);
  }

  resetAuthUserSecondFactors(id: number): boolean {
    return this.users.resetAuthUserSecondFactors(id);
  }

  deleteAuthUser(id: number): boolean {
    return this.users.deleteAuthUser(id);
  }

  getUserPreferences(userId: number): Record<string, string> {
    return this.users.getUserPreferences(userId);
  }

  setUserPreference(userId: number, key: string, value: string): void {
    this.users.setUserPreference(userId, key, value);
  }

  updateAuthUserTotp(id: number, secret: string | null, enabled: boolean): boolean {
    return this.users.updateAuthUserTotp(id, secret, enabled);
  }

  updateAuthUserTotpLastStep(id: number, lastStep: number): boolean {
    return this.users.updateAuthUserTotpLastStep(id, lastStep);
  }

  upsertOidcUser(params: OidcUserUpsertParams): AuthUserRow {
    return this.users.upsertOidcUser(params);
  }

  findOidcAutoLinkTarget(username: string): AuthUserRow | null {
    return this.users.findOidcAutoLinkTarget(username);
  }

  linkOidcIdentity(userId: number, identity: OidcUserUpsertParams, method: OidcLinkMethod): boolean {
    return this.users.linkOidcIdentity(userId, identity, method);
  }

  unlinkOidcIdentity(userId: number): boolean {
    return this.users.unlinkOidcIdentity(userId);
  }

  applyOidcLogout(params: {
    issuer: string;
    subject?: string;
    sessionId?: string;
    tokenId: string;
    tokenExpiresAt: number;
    sessionExpiresAt: number;
  }): void {
    this.users.applyOidcLogout(params);
  }

  revokeOidcUserSessions(issuer: string, subject: string): boolean {
    return this.users.revokeOidcUserSessions(issuer, subject);
  }

  denyOidcIdentity(issuer: string, subject: string): boolean {
    return this.users.denyOidcIdentity(issuer, subject);
  }

  revokeOidcSession(issuer: string, sessionId: string, expiresAt: number): void {
    this.users.revokeOidcSession(issuer, sessionId, expiresAt);
  }

  bumpOidcLogoutVersion(issuer: string, subject: string): void {
    this.users.bumpOidcLogoutVersion(issuer, subject);
  }

  getOidcLogoutVersion(issuer: string, subject: string): number {
    return this.users.getOidcLogoutVersion(issuer, subject);
  }

  isOidcSessionRevoked(issuer: string, sessionId: string): boolean {
    return this.users.isOidcSessionRevoked(issuer, sessionId);
  }

  revokeAuthSession(sessionId: string, expiresAt: number): void {
    this.users.revokeAuthSession(sessionId, expiresAt);
  }

  isAuthSessionRevoked(sessionId: string): boolean {
    return this.users.isAuthSessionRevoked(sessionId);
  }

  listWebAuthnCredentialsByUser(userId: number): WebAuthnCredentialRow[] {
    return this.users.listWebAuthnCredentialsByUser(userId);
  }

  countWebAuthnCredentials(): number {
    return this.users.countWebAuthnCredentials();
  }

  createWebAuthnCredential(params: {
    userId: number;
    credentialId: string;
    publicKey: string;
    signCount: number;
    transports: string | null;
    name: string | null;
  }): number {
    return this.users.createWebAuthnCredential(params);
  }

  getWebAuthnCredentialByCredentialId(credentialId: string): WebAuthnCredentialRow | null {
    return this.users.getWebAuthnCredentialByCredentialId(credentialId);
  }

  updateWebAuthnCredentialCounter(id: number, signCount: number): void {
    this.users.updateWebAuthnCredentialCounter(id, signCount);
  }

  renameWebAuthnCredential(id: number, userId: number, name: string | null): boolean {
    return this.users.renameWebAuthnCredential(id, userId, name);
  }

  deleteWebAuthnCredential(id: number, userId: number): boolean {
    return this.users.deleteWebAuthnCredential(id, userId);
  }

  // --- Meta & Settings Operations ---
  getMeta(key: string): MetaRow | null {
    return this.meta.getMeta(key);
  }

  setMeta(key: string, value: string): void {
    this.meta.setMeta(key, value);
  }

  isAuthMigrationDefaultDisabled(): boolean {
    return this.meta.isAuthMigrationDefaultDisabled();
  }

  isStatisticsMigrationDefaultDisabled(): boolean {
    return this.meta.isStatisticsMigrationDefaultDisabled();
  }

  getCveCacheEntry(id: string): JsonRow | null {
    return this.meta.getCveCacheEntry(id);
  }

  upsertCveCacheEntry(id: string, publishedAt: string, fetchedAt: string): void {
    this.meta.upsertCveCacheEntry(id, publishedAt, fetchedAt);
  }

  replaceAllowlists(instanceId: string, allowlists: CachedAllowlist[] | null, syncState: string): { changed: boolean } {
    return this.meta.replaceAllowlists(instanceId, allowlists, syncState);
  }

  transaction<T>(callback: (value: T) => void): (value: T) => void {
    return this.db.transaction(callback);
  }

  private stateQuery(sql: string): SqliteStatement {
    if (this.statePath) return this.db.query(sql);
    const unavailable = () => {
      throw new Error('The state database is not attached to this connection');
    };
    return { run: unavailable, get: unavailable, all: unavailable };
  }
}
