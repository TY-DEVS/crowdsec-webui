import { normalizeIsoTimestamp, normalizeTimestampJson } from '../utils/date-time';
import { runChunkedIdMutation } from './connection';
import type { CountRow, Database, JsonRow, SqliteStatement } from './types';

export class NotificationRepository {
  private readonly listNotificationChannelsStatement: SqliteStatement;
  private readonly getNotificationChannelByIdStatement: SqliteStatement;
  private readonly upsertNotificationChannelStatement: SqliteStatement;
  private readonly deleteNotificationChannelStatement: SqliteStatement;
  private readonly listNotificationRulesStatement: SqliteStatement;
  private readonly getNotificationRuleByIdStatement: SqliteStatement;
  private readonly upsertNotificationRuleStatement: SqliteStatement;
  private readonly deleteNotificationRuleStatement: SqliteStatement;
  private readonly listNotificationsPageStatement: SqliteStatement;
  private readonly countNotificationsStatement: SqliteStatement;
  private readonly listNotificationIdsStatement: SqliteStatement;
  private readonly insertNotificationStatement: SqliteStatement;
  private readonly listNotificationIncidentsByRuleStatement: SqliteStatement;
  private readonly upsertNotificationIncidentStatement: SqliteStatement;
  private readonly resolveNotificationIncidentStatement: SqliteStatement;
  private readonly deleteNotificationIncidentsByRuleStatement: SqliteStatement;
  private readonly deleteNotificationStatement: SqliteStatement;
  private readonly deleteNotificationByRuleAndDedupeKeyStatement: SqliteStatement;
  private readonly markNotificationReadStatement: SqliteStatement;
  private readonly markAllNotificationsReadStatement: SqliteStatement;
  private readonly deleteReadNotificationsStatement: SqliteStatement;
  private readonly countUnreadNotificationsStatement: SqliteStatement;

  constructor(
    private readonly db: Database,
    stateQuery: (sql: string) => SqliteStatement,
  ) {
    this.listNotificationChannelsStatement = stateQuery(`
      SELECT id, created_at, updated_at, name, type, enabled, config_json
      FROM notification_channels
      ORDER BY created_at DESC
    `);
    this.getNotificationChannelByIdStatement = stateQuery(`
      SELECT id, created_at, updated_at, name, type, enabled, config_json
      FROM notification_channels
      WHERE id = $id
    `);
    this.upsertNotificationChannelStatement = stateQuery(`
      INSERT OR REPLACE INTO notification_channels (id, created_at, updated_at, name, type, enabled, config_json)
      VALUES ($id, $created_at, $updated_at, $name, $type, $enabled, $config_json)
    `);
    this.deleteNotificationChannelStatement = stateQuery('DELETE FROM notification_channels WHERE id = $id');
    this.listNotificationRulesStatement = stateQuery(`
      SELECT id, created_at, updated_at, name, type, enabled, severity, channel_ids_json, config_json
      FROM notification_rules
      ORDER BY created_at DESC
    `);
    this.getNotificationRuleByIdStatement = stateQuery(`
      SELECT id, created_at, updated_at, name, type, enabled, severity, channel_ids_json, config_json
      FROM notification_rules
      WHERE id = $id
    `);
    this.upsertNotificationRuleStatement = stateQuery(`
      INSERT OR REPLACE INTO notification_rules (
        id, created_at, updated_at, name, type, enabled, severity, channel_ids_json, config_json
      )
      VALUES ($id, $created_at, $updated_at, $name, $type, $enabled, $severity, $channel_ids_json, $config_json)
    `);
    this.deleteNotificationRuleStatement = stateQuery('DELETE FROM notification_rules WHERE id = $id');
    this.listNotificationsPageStatement = stateQuery(`
      SELECT id, created_at, updated_at, rule_id, rule_name, rule_type, severity, title, message, read_at, metadata_json, deliveries_json, dedupe_key
      FROM notifications
      ORDER BY created_at DESC
      LIMIT $limit OFFSET $offset
    `);
    this.countNotificationsStatement = stateQuery('SELECT COUNT(*) as count FROM notifications');
    this.listNotificationIdsStatement = stateQuery(`
      SELECT id
      FROM notifications
      ORDER BY created_at DESC
    `);
    this.insertNotificationStatement = stateQuery(`
      INSERT OR IGNORE INTO notifications (
        id, created_at, updated_at, rule_id, rule_name, rule_type, severity, title, message, read_at, metadata_json, deliveries_json, dedupe_key
      )
      VALUES (
        $id, $created_at, $updated_at, $rule_id, $rule_name, $rule_type, $severity, $title, $message, $read_at, $metadata_json, $deliveries_json, $dedupe_key
      )
    `);
    this.listNotificationIncidentsByRuleStatement = stateQuery(`
      SELECT rule_id, incident_key, first_seen_at, last_seen_at, resolved_at
      FROM notification_incidents
      WHERE rule_id = $rule_id
      ORDER BY incident_key ASC
    `);
    this.upsertNotificationIncidentStatement = stateQuery(`
      INSERT OR REPLACE INTO notification_incidents (rule_id, incident_key, first_seen_at, last_seen_at, resolved_at)
      VALUES ($rule_id, $incident_key, $first_seen_at, $last_seen_at, $resolved_at)
    `);
    this.resolveNotificationIncidentStatement = stateQuery(`
      UPDATE notification_incidents
      SET resolved_at = $resolved_at, last_seen_at = $last_seen_at
      WHERE rule_id = $rule_id AND incident_key = $incident_key AND resolved_at IS NULL
    `);
    this.deleteNotificationIncidentsByRuleStatement = stateQuery('DELETE FROM notification_incidents WHERE rule_id = $rule_id');
    this.deleteNotificationStatement = stateQuery('DELETE FROM notifications WHERE id = $id');
    this.deleteNotificationByRuleAndDedupeKeyStatement = stateQuery(`
      DELETE FROM notifications
      WHERE rule_id = $rule_id AND dedupe_key = $dedupe_key
    `);
    this.markNotificationReadStatement = stateQuery('UPDATE notifications SET read_at = $read_at, updated_at = $updated_at WHERE id = $id');
    this.markAllNotificationsReadStatement = stateQuery(`
      UPDATE notifications
      SET read_at = $read_at, updated_at = $updated_at
      WHERE read_at IS NULL
    `);
    this.deleteReadNotificationsStatement = stateQuery('DELETE FROM notifications WHERE read_at IS NOT NULL');
    this.countUnreadNotificationsStatement = stateQuery('SELECT COUNT(*) as count FROM notifications WHERE read_at IS NULL');
  }

  listNotificationChannels(): JsonRow[] {
    return this.listNotificationChannelsStatement.all() as JsonRow[];
  }

  getNotificationChannelById(id: string): JsonRow | null {
    return (this.getNotificationChannelByIdStatement.get({ $id: id }) as JsonRow | null) || null;
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
    this.upsertNotificationChannelStatement.run({
      ...params,
      $created_at: normalizeIsoTimestamp(params.$created_at),
      $updated_at: normalizeIsoTimestamp(params.$updated_at),
    });
  }

  deleteNotificationChannel(id: string): void {
    this.deleteNotificationChannelStatement.run({ $id: id });
  }

  listNotificationRules(): JsonRow[] {
    return this.listNotificationRulesStatement.all() as JsonRow[];
  }

  getNotificationRuleById(id: string): JsonRow | null {
    return (this.getNotificationRuleByIdStatement.get({ $id: id }) as JsonRow | null) || null;
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
    this.upsertNotificationRuleStatement.run({
      ...params,
      $created_at: normalizeIsoTimestamp(params.$created_at),
      $updated_at: normalizeIsoTimestamp(params.$updated_at),
    });
  }

  deleteNotificationRule(id: string): void {
    this.deleteNotificationRuleStatement.run({ $id: id });
  }

  listNotificationsPage(page: number, pageSize: number): JsonRow[] {
    const safePage = Math.max(1, page);
    const safePageSize = Math.max(1, pageSize);
    return this.listNotificationsPageStatement.all({
      $limit: safePageSize,
      $offset: (safePage - 1) * safePageSize,
    }) as JsonRow[];
  }

  listNotifications(limit = 100): JsonRow[] {
    return this.listNotificationsPage(1, limit);
  }

  countNotifications(): number {
    return (this.countNotificationsStatement.get() as CountRow).count;
  }

  listNotificationIds(): string[] {
    return (this.listNotificationIdsStatement.all() as Array<{ id: string }>).map((row) => String(row.id));
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
    return this.insertNotificationStatement.run({
      ...params,
      $created_at: normalizeIsoTimestamp(params.$created_at),
      $updated_at: normalizeIsoTimestamp(params.$updated_at),
      $read_at: params.$read_at === null ? null : normalizeIsoTimestamp(params.$read_at),
      $metadata_json: normalizeTimestampJson(params.$metadata_json),
      $deliveries_json: normalizeTimestampJson(params.$deliveries_json),
    }).changes > 0;
  }

  listNotificationIncidentsByRule(ruleId: string): JsonRow[] {
    return this.listNotificationIncidentsByRuleStatement.all({ $rule_id: ruleId }) as JsonRow[];
  }

  upsertNotificationIncident(params: {
    $rule_id: string;
    $incident_key: string;
    $first_seen_at: string;
    $last_seen_at: string;
    $resolved_at: string | null;
  }): void {
    this.upsertNotificationIncidentStatement.run({
      ...params,
      $first_seen_at: normalizeIsoTimestamp(params.$first_seen_at),
      $last_seen_at: normalizeIsoTimestamp(params.$last_seen_at),
      $resolved_at: params.$resolved_at === null ? null : normalizeIsoTimestamp(params.$resolved_at),
    });
  }

  resolveNotificationIncident(ruleId: string, incidentKey: string, resolvedAt: string): boolean {
    const normalizedResolvedAt = normalizeIsoTimestamp(resolvedAt);
    return this.resolveNotificationIncidentStatement.run({
      $rule_id: ruleId,
      $incident_key: incidentKey,
      $resolved_at: normalizedResolvedAt,
      $last_seen_at: normalizedResolvedAt,
    }).changes > 0;
  }

  deleteNotificationIncidentsByRule(ruleId: string): void {
    this.deleteNotificationIncidentsByRuleStatement.run({ $rule_id: ruleId });
  }

  deleteNotification(id: string): boolean {
    return this.deleteNotificationStatement.run({ $id: id }).changes > 0;
  }

  deleteNotificationByRuleAndDedupeKey(ruleId: string, dedupeKey: string): boolean {
    return this.deleteNotificationByRuleAndDedupeKeyStatement.run({
      $rule_id: ruleId,
      $dedupe_key: dedupeKey,
    }).changes > 0;
  }

  deleteNotifications(ids: string[]): number {
    return runChunkedIdMutation(this.db, 'DELETE FROM notifications WHERE id IN', ids);
  }

  markNotificationRead(id: string, readAt: string): boolean {
    const normalizedReadAt = normalizeIsoTimestamp(readAt);
    return this.markNotificationReadStatement.run({
      $id: id,
      $read_at: normalizedReadAt,
      $updated_at: normalizedReadAt,
    }).changes > 0;
  }

  markNotificationsRead(ids: string[], readAt: string): number {
    const normalizedReadAt = normalizeIsoTimestamp(readAt);
    return runChunkedIdMutation(
      this.db,
      'UPDATE notifications SET read_at = ?, updated_at = ? WHERE read_at IS NULL AND id IN',
      ids,
      [normalizedReadAt, normalizedReadAt],
    );
  }

  markAllNotificationsRead(readAt: string): number {
    const normalizedReadAt = normalizeIsoTimestamp(readAt);
    return this.markAllNotificationsReadStatement.run({
      $read_at: normalizedReadAt,
      $updated_at: normalizedReadAt,
    }).changes;
  }

  deleteReadNotifications(): number {
    return this.deleteReadNotificationsStatement.run().changes;
  }

  countUnreadNotifications(): number {
    return (this.countUnreadNotificationsStatement.get() as CountRow).count;
  }
}
