import crypto from 'node:crypto';
import { isIP } from 'node:net';
import type { Hono } from 'hono';
import type {
  AlertRecord,
  InstanceOperationResult,
  PlaybookAction,
  PlaybookEvaluationResult,
  PlaybookExecutionRecord,
  PlaybookExecutionStatus,
  PlaybookGuardrails,
  PlaybookListResponse,
  PlaybookExecutionsResponse,
  PlaybookRule,
  PlaybookTrigger,
  UpsertPlaybookRuleRequest,
} from '../../shared/contracts';
import type { RuntimeConfig } from '../config';
import type { CrowdsecDatabase } from '../database';
import type { LapiClient } from '../lapi';
import type { AllowlistService } from './allowlists';
import type { AuditLogger, AuditEvent } from '../audit-log';
import { getAlertSourceValue } from '../utils/alerts';

type HonoContext = any;
type ConfiguredInstance = RuntimeConfig['instances'][number];

const DURATION_RE = /^\d+[smhd]$/;

export function isValidIpOrRange(value: string): boolean {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  const parts = trimmed.split('/');
  if (parts.length > 2) return false;
  const ip = parts[0];
  const version = isIP(ip);
  if (version === 0) return false;
  if (parts.length === 2) {
    const cidr = parts[1];
    if (!/^\d+$/.test(cidr)) return false;
    const prefix = Number.parseInt(cidr, 10);
    if (version === 4 && (prefix < 0 || prefix > 32)) return false;
    if (version === 6 && (prefix < 0 || prefix > 128)) return false;
  }
  return true;
}

export interface PlaybookServiceOptions {
  database?: CrowdsecDatabase;
  allowlistService?: Pick<AllowlistService, 'checkValue'>;
  lapiClients?: Map<string, Pick<LapiClient, 'addDecision'>>;
  primaryInstance?: ConfiguredInstance;
  instances?: ConfiguredInstance[];
  auditLog?: AuditLogger | {
    record: (context: any, event: AuditEvent | Record<string, unknown>) => void;
  };
  simulationMode?: boolean;
  defaultCooldownSeconds?: number;
  updateCacheDelta?: (options?: { publishUnchanged?: boolean }) => Promise<void>;
  writeDatabase?: <T>(operation: () => T) => Promise<T>;
  customAllowlist?: Set<string>;
}

export interface PlaybookValidationResult {
  valid: boolean;
  errors: string[];
}

export function validatePlaybookRule(input: unknown): PlaybookValidationResult {
  const errors: string[] = [];
  if (!input || typeof input !== 'object') {
    return { valid: false, errors: ['Request body must be a valid JSON object'] };
  }

  const data = input as Partial<UpsertPlaybookRuleRequest>;

  // Name validation
  if (typeof data.name !== 'string' || !data.name.trim()) {
    errors.push('Rule name is required and cannot be empty');
  } else if (data.name.trim().length > 100) {
    errors.push('Rule name cannot exceed 100 characters');
  }

  // Description validation
  if (data.description !== undefined && data.description !== null && typeof data.description !== 'string') {
    errors.push('Description must be a string');
  }

  // Priority validation
  if (data.priority !== undefined && (typeof data.priority !== 'number' || !Number.isInteger(data.priority))) {
    errors.push('Priority must be an integer');
  }

  // Trigger validation
  if (!data.trigger || typeof data.trigger !== 'object') {
    errors.push('Trigger configuration is required');
  } else {
    const trigger = data.trigger;
    const hasScenario = typeof trigger.scenario === 'string' && trigger.scenario.trim().length > 0;
    const hasPattern = typeof trigger.scenario_pattern === 'string' && trigger.scenario_pattern.trim().length > 0;
    const hasScenarios = Array.isArray(trigger.scenarios) && trigger.scenarios.some((s) => typeof s === 'string' && s.trim().length > 0);

    if (!hasScenario && !hasPattern && !hasScenarios) {
      errors.push('Trigger must define at least one scenario matcher (scenario, scenario_pattern, or scenarios list)');
    }

    if (trigger.events_count_threshold !== undefined) {
      if (typeof trigger.events_count_threshold !== 'number' || !Number.isInteger(trigger.events_count_threshold) || trigger.events_count_threshold < 1) {
        errors.push('events_count_threshold must be a positive integer (>= 1)');
      }
    }
  }

  // Action validation
  if (!data.action || typeof data.action !== 'object') {
    errors.push('Action configuration is required');
  } else {
    const action = data.action;
    const validTypes = ['ban', 'captcha'];
    if (action.type && !validTypes.includes(action.type)) {
      errors.push(`Action type must be one of: ${validTypes.join(', ')}`);
    }

    if (typeof action.duration !== 'string' || !DURATION_RE.test(action.duration.trim())) {
      errors.push('Action duration is required and must follow standard format (e.g. "4h", "30m", "1d")');
    }

    if (action.scope && !['fleet', 'local'].includes(action.scope)) {
      errors.push('Action scope must be either "fleet" or "local"');
    }
  }

  // Guardrails validation
  if (data.guardrails && typeof data.guardrails === 'object') {
    const guardrails = data.guardrails;
    if (guardrails.cooldown_seconds !== undefined) {
      if (typeof guardrails.cooldown_seconds !== 'number' || !Number.isInteger(guardrails.cooldown_seconds) || guardrails.cooldown_seconds < 0) {
        errors.push('cooldown_seconds must be a non-negative integer');
      }
    }

    if (guardrails.rate_limit && typeof guardrails.rate_limit === 'object') {
      const rl = guardrails.rate_limit;
      if (rl.max_actions !== undefined && (typeof rl.max_actions !== 'number' || rl.max_actions < 1)) {
        errors.push('rate_limit.max_actions must be a positive integer');
      }
      if (rl.window_seconds !== undefined && (typeof rl.window_seconds !== 'number' || rl.window_seconds < 1)) {
        errors.push('rate_limit.window_seconds must be a positive integer');
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Normalizes user input into a full PlaybookRule.
 */
function normalizeRule(
  id: string,
  input: UpsertPlaybookRuleRequest,
  existing?: PlaybookRule | null,
): PlaybookRule {
  const now = new Date().toISOString();
  return {
    id,
    name: input.name.trim(),
    description: input.description?.trim() || undefined,
    enabled: input.enabled !== false,
    priority: input.priority ?? existing?.priority ?? 0,
    trigger: {
      scenario: input.trigger.scenario?.trim() || undefined,
      scenario_pattern: input.trigger.scenario_pattern?.trim() || undefined,
      scenarios: Array.isArray(input.trigger.scenarios)
        ? input.trigger.scenarios.map((s) => s.trim()).filter(Boolean)
        : undefined,
      events_count_threshold: input.trigger.events_count_threshold || 1,
      origins: Array.isArray(input.trigger.origins)
        ? input.trigger.origins.map((o) => o.trim()).filter(Boolean)
        : undefined,
      include_simulated: Boolean(input.trigger.include_simulated),
    },
    action: {
      type: input.action.type || 'ban',
      duration: input.action.duration.trim(),
      reason: input.action.reason?.trim() || `Automated remediation: ${input.name.trim()}`,
      scenario: input.action.scenario?.trim() || input.trigger.scenario?.trim() || 'playbook-remediation',
      scope: input.action.scope || 'fleet',
      target_instance_ids: Array.isArray(input.action.target_instance_ids)
        ? input.action.target_instance_ids.filter((id): id is string => typeof id === 'string' && id.trim().length > 0)
        : undefined,
    },
    guardrails: {
      never_ban_allowlisted: input.guardrails?.never_ban_allowlisted !== false,
      cooldown_seconds: input.guardrails?.cooldown_seconds ?? 3600,
      rate_limit: input.guardrails?.rate_limit
        ? {
            max_actions: input.guardrails.rate_limit.max_actions ?? 1,
            window_seconds: input.guardrails.rate_limit.window_seconds ?? 3600,
          }
        : undefined,
      simulation_mode: Boolean(input.guardrails?.simulation_mode),
    },
    execution_count: existing?.execution_count ?? 0,
    last_triggered_at: existing?.last_triggered_at ?? null,
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };
}

/**
 * Matches a scenario against an exact string, wildcards (*), or prefix.
 */
function matchScenario(scenario: string, pattern: string): boolean {
  if (pattern === '*' || pattern === scenario) return true;
  if (pattern.includes('*')) {
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    return new RegExp(`^${escaped}$`, 'i').test(scenario);
  }
  return scenario.toLowerCase() === pattern.toLowerCase();
}

export class PlaybookService {
  private readonly database?: CrowdsecDatabase;
  private readonly allowlistService?: Pick<AllowlistService, 'checkValue'>;
  private readonly lapiClients: Map<string, Pick<LapiClient, 'addDecision'>>;
  private readonly primaryInstance?: ConfiguredInstance;
  private readonly instances: ConfiguredInstance[];
  private readonly auditLog?: AuditLogger | {
    record: (context: any, event: AuditEvent | Record<string, unknown>) => void;
  };
  private readonly defaultCooldownSeconds: number;
  private readonly updateCacheDelta?: (options?: { publishUnchanged?: boolean }) => Promise<void>;
  private readonly writeDatabase?: <T>(operation: () => T) => Promise<T>;
  private readonly customAllowlist: Set<string>;
  public simulationMode: boolean;

  // In-memory fallback stores and cooldown tracking
  private readonly memoryRules = new Map<string, PlaybookRule>();
  private readonly memoryExecutions: PlaybookExecutionRecord[] = [];
  private readonly ipCooldowns = new Map<string, { lastActionMs: number; ruleId: string }>();

  // Prepared SQL statements if database is available
  private listRulesStmt?: any;
  private getRuleStmt?: any;
  private upsertRuleStmt?: any;
  private deleteRuleStmt?: any;
  private incExecutionStmt?: any;
  private insertExecutionStmt?: any;
  private listExecutionsStmt?: any;
  private countExecutionsStmt?: any;
  private clearExecutionsStmt?: any;

  constructor(options: PlaybookServiceOptions = {}) {
    this.database = options.database;
    this.allowlistService = options.allowlistService;
    this.lapiClients = options.lapiClients || new Map();
    this.primaryInstance = options.primaryInstance;
    this.instances = options.instances || (options.primaryInstance ? [options.primaryInstance] : []);
    this.auditLog = options.auditLog;
    this.simulationMode = Boolean(options.simulationMode);
    this.defaultCooldownSeconds = options.defaultCooldownSeconds ?? 3600;
    this.updateCacheDelta = options.updateCacheDelta;
    this.writeDatabase = options.writeDatabase;
    this.customAllowlist = options.customAllowlist || new Set();

    if (this.database) {
      this.initSchema();
      this.initStatements();
    }
  }

  private initSchema(): void {
    if (!this.database) return;
    const schema = this.database.statePath ? 'state' : 'main';
    this.database.db.exec(`
      CREATE TABLE IF NOT EXISTS ${schema}.playbook_rules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        enabled INTEGER NOT NULL DEFAULT 1,
        priority INTEGER NOT NULL DEFAULT 0,
        trigger_json TEXT NOT NULL,
        action_json TEXT NOT NULL,
        guardrails_json TEXT NOT NULL,
        execution_count INTEGER NOT NULL DEFAULT 0,
        last_triggered_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS ${schema}.playbook_executions (
        id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        playbook_name TEXT NOT NULL,
        alert_id TEXT,
        ip TEXT NOT NULL,
        scenario TEXT NOT NULL,
        events_count INTEGER NOT NULL,
        action_type TEXT NOT NULL,
        action_duration TEXT NOT NULL,
        scope TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        details_json TEXT,
        executed_at TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS ${schema}.idx_playbook_executions_time ON playbook_executions (executed_at DESC);
      CREATE INDEX IF NOT EXISTS ${schema}.idx_playbook_executions_ip ON playbook_executions (ip);
      CREATE INDEX IF NOT EXISTS ${schema}.idx_playbook_executions_rule ON playbook_executions (playbook_id);
    `);
  }

  private initStatements(): void {
    if (!this.database) return;
    this.listRulesStmt = this.database.db.query(`
      SELECT id, name, description, enabled, priority, trigger_json, action_json, guardrails_json,
             execution_count, last_triggered_at, created_at, updated_at
      FROM playbook_rules
      ORDER BY priority DESC, created_at DESC
    `);

    this.getRuleStmt = this.database.db.query(`
      SELECT id, name, description, enabled, priority, trigger_json, action_json, guardrails_json,
             execution_count, last_triggered_at, created_at, updated_at
      FROM playbook_rules
      WHERE id = ?
    `);

    this.upsertRuleStmt = this.database.db.query(`
      INSERT OR REPLACE INTO playbook_rules (
        id, name, description, enabled, priority, trigger_json, action_json, guardrails_json,
        execution_count, last_triggered_at, created_at, updated_at
      )
      VALUES ($id, $name, $description, $enabled, $priority, $trigger_json, $action_json, $guardrails_json,
              $execution_count, $last_triggered_at, $created_at, $updated_at)
    `);

    this.deleteRuleStmt = this.database.db.query(`
      DELETE FROM playbook_rules WHERE id = ?
    `);

    this.incExecutionStmt = this.database.db.query(`
      UPDATE playbook_rules
      SET execution_count = execution_count + 1, last_triggered_at = ?
      WHERE id = ?
    `);

    this.insertExecutionStmt = this.database.db.query(`
      INSERT INTO playbook_executions (
        id, playbook_id, playbook_name, alert_id, ip, scenario, events_count,
        action_type, action_duration, scope, status, message, details_json, executed_at
      )
      VALUES ($id, $playbook_id, $playbook_name, $alert_id, $ip, $scenario, $events_count,
              $action_type, $action_duration, $scope, $status, $message, $details_json, $executed_at)
    `);

    this.listExecutionsStmt = this.database.db.query(`
      SELECT id, playbook_id, playbook_name, alert_id, ip, scenario, events_count,
             action_type, action_duration, scope, status, message, details_json, executed_at
      FROM playbook_executions
      ORDER BY executed_at DESC
      LIMIT ? OFFSET ?
    `);

    this.countExecutionsStmt = this.database.db.query(`
      SELECT COUNT(*) as count FROM playbook_executions
    `);

    this.clearExecutionsStmt = this.database.db.query(`
      DELETE FROM playbook_executions
    `);
  }

  private rowToRule(row: any): PlaybookRule {
    return {
      id: String(row.id),
      name: String(row.name),
      description: row.description ? String(row.description) : undefined,
      enabled: Boolean(row.enabled),
      priority: Number(row.priority || 0),
      trigger: JSON.parse(String(row.trigger_json || '{}')),
      action: JSON.parse(String(row.action_json || '{}')),
      guardrails: JSON.parse(String(row.guardrails_json || '{}')),
      execution_count: Number(row.execution_count || 0),
      last_triggered_at: row.last_triggered_at ? String(row.last_triggered_at) : null,
      created_at: String(row.created_at),
      updated_at: String(row.updated_at),
    };
  }

  private rowToExecution(row: any): PlaybookExecutionRecord {
    return {
      id: String(row.id),
      playbook_id: String(row.playbook_id),
      playbook_name: String(row.playbook_name),
      alert_id: row.alert_id ? String(row.alert_id) : undefined,
      ip: String(row.ip),
      scenario: String(row.scenario),
      events_count: Number(row.events_count || 0),
      action_type: String(row.action_type),
      action_duration: String(row.action_duration),
      scope: String(row.scope),
      status: row.status as PlaybookExecutionStatus,
      message: String(row.message),
      details: row.details_json ? JSON.parse(String(row.details_json)) : undefined,
      executed_at: String(row.executed_at),
    };
  }

  /**
   * Rule Management: List all playbook rules
   */
  public listRules(): PlaybookRule[] {
    if (this.listRulesStmt) {
      const rows = this.listRulesStmt.all() as any[];
      return rows.map((r) => this.rowToRule(r));
    }
    return [...this.memoryRules.values()].sort((a, b) => b.priority - a.priority || b.created_at.localeCompare(a.created_at));
  }

  /**
   * Rule Management: Get a single playbook rule by ID
   */
  public getRule(id: string): PlaybookRule | null {
    if (this.getRuleStmt) {
      const row = this.getRuleStmt.get(id) as any;
      return row ? this.rowToRule(row) : null;
    }
    return this.memoryRules.get(id) || null;
  }

  /**
   * Rule Management: Create a new playbook rule
   */
  public async createRule(request: UpsertPlaybookRuleRequest): Promise<PlaybookRule> {
    const validation = validatePlaybookRule(request);
    if (!validation.valid) {
      throw new Error(`Invalid playbook rule: ${validation.errors.join('; ')}`);
    }

    const id = crypto.randomUUID();
    const rule = normalizeRule(id, request);

    if (this.upsertRuleStmt) {
      const params = {
        $id: rule.id,
        $name: rule.name,
        $description: rule.description || null,
        $enabled: rule.enabled ? 1 : 0,
        $priority: rule.priority,
        $trigger_json: JSON.stringify(rule.trigger),
        $action_json: JSON.stringify(rule.action),
        $guardrails_json: JSON.stringify(rule.guardrails),
        $execution_count: rule.execution_count,
        $last_triggered_at: rule.last_triggered_at,
        $created_at: rule.created_at,
        $updated_at: rule.updated_at,
      };

      if (this.writeDatabase) {
        await this.writeDatabase(() => this.upsertRuleStmt.run(params));
      } else {
        this.upsertRuleStmt.run(params);
      }
    } else {
      this.memoryRules.set(rule.id, rule);
    }

    return rule;
  }

  /**
   * Rule Management: Update an existing playbook rule
   */
  public async updateRule(id: string, request: UpsertPlaybookRuleRequest): Promise<PlaybookRule | null> {
    const existing = this.getRule(id);
    if (!existing) return null;

    const validation = validatePlaybookRule(request);
    if (!validation.valid) {
      throw new Error(`Invalid playbook rule: ${validation.errors.join('; ')}`);
    }

    const updated = normalizeRule(id, request, existing);

    if (this.upsertRuleStmt) {
      const params = {
        $id: updated.id,
        $name: updated.name,
        $description: updated.description || null,
        $enabled: updated.enabled ? 1 : 0,
        $priority: updated.priority,
        $trigger_json: JSON.stringify(updated.trigger),
        $action_json: JSON.stringify(updated.action),
        $guardrails_json: JSON.stringify(updated.guardrails),
        $execution_count: updated.execution_count,
        $last_triggered_at: updated.last_triggered_at,
        $created_at: updated.created_at,
        $updated_at: updated.updated_at,
      };

      if (this.writeDatabase) {
        await this.writeDatabase(() => this.upsertRuleStmt.run(params));
      } else {
        this.upsertRuleStmt.run(params);
      }
    } else {
      this.memoryRules.set(id, updated);
    }

    return updated;
  }

  /**
   * Rule Management: Delete a playbook rule
   */
  public async deleteRule(id: string): Promise<boolean> {
    const existing = this.getRule(id);
    if (!existing) return false;

    if (this.deleteRuleStmt) {
      if (this.writeDatabase) {
        await this.writeDatabase(() => this.deleteRuleStmt.run(id));
      } else {
        this.deleteRuleStmt.run(id);
      }
    } else {
      this.memoryRules.delete(id);
    }

    return true;
  }

  /**
   * Rule Management: Toggle rule enabled state
   */
  public async toggleRule(id: string, enabled?: boolean): Promise<PlaybookRule | null> {
    const rule = this.getRule(id);
    if (!rule) return null;

    const newEnabled = enabled !== undefined ? enabled : !rule.enabled;
    const updated: UpsertPlaybookRuleRequest = {
      name: rule.name,
      description: rule.description,
      enabled: newEnabled,
      priority: rule.priority,
      trigger: rule.trigger,
      action: rule.action,
      guardrails: rule.guardrails,
    };

    return this.updateRule(id, updated);
  }

  /**
   * Execution History: Record execution
   */
  public async recordExecution(record: PlaybookExecutionRecord): Promise<void> {
    if (this.insertExecutionStmt) {
      const params = {
        $id: record.id,
        $playbook_id: record.playbook_id,
        $playbook_name: record.playbook_name,
        $alert_id: record.alert_id !== undefined ? String(record.alert_id) : null,
        $ip: record.ip,
        $scenario: record.scenario,
        $events_count: record.events_count,
        $action_type: record.action_type,
        $action_duration: record.action_duration,
        $scope: record.scope,
        $status: record.status,
        $message: record.message,
        $details_json: record.details ? JSON.stringify(record.details) : null,
        $executed_at: record.executed_at,
      };

      if (this.writeDatabase) {
        await this.writeDatabase(() => {
          this.insertExecutionStmt.run(params);
          if (record.status === 'executed' || record.status === 'simulated') {
            this.incExecutionStmt?.run(record.executed_at, record.playbook_id);
          }
        });
      } else {
        this.insertExecutionStmt.run(params);
        if (record.status === 'executed' || record.status === 'simulated') {
          this.incExecutionStmt?.run(record.executed_at, record.playbook_id);
        }
      }
    } else {
      this.memoryExecutions.unshift(record);
      if (record.status === 'executed' || record.status === 'simulated') {
        const rule = this.memoryRules.get(record.playbook_id);
        if (rule) {
          rule.execution_count++;
          rule.last_triggered_at = record.executed_at;
        }
      }
    }

    // Update in-memory cooldown tracker for executed or simulated actions
    if (record.status === 'executed' || record.status === 'simulated') {
      this.ipCooldowns.set(record.ip, {
        lastActionMs: Date.now(),
        ruleId: record.playbook_id,
      });
    }
  }

  /**
   * Execution History: List recorded executions with pagination & filtering
   */
  public listExecutions(filter: {
    playbook_id?: string;
    ip?: string;
    status?: string;
    limit?: number;
    offset?: number;
  } = {}): PlaybookExecutionsResponse {
    const limit = Math.min(Math.max(1, filter.limit || 50), 500);
    const offset = Math.max(0, filter.offset || 0);

    if (this.database && !filter.playbook_id && !filter.ip && !filter.status) {
      const rows = this.listExecutionsStmt.all(limit, offset) as any[];
      const totalRow = this.countExecutionsStmt.get() as { count: number };
      return {
        executions: rows.map((r) => this.rowToExecution(r)),
        total: totalRow?.count || 0,
      };
    }

    let records: PlaybookExecutionRecord[] = [];
    if (this.database) {
      // Dynamic query with filters
      const conditions: string[] = [];
      const params: any[] = [];
      if (filter.playbook_id) {
        conditions.push('playbook_id = ?');
        params.push(filter.playbook_id);
      }
      if (filter.ip) {
        conditions.push('ip = ?');
        params.push(filter.ip);
      }
      if (filter.status) {
        conditions.push('status = ?');
        params.push(filter.status);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
      const countStmt = this.database.db.query(`SELECT COUNT(*) as count FROM playbook_executions ${whereClause}`);
      const listStmt = this.database.db.query(`
        SELECT id, playbook_id, playbook_name, alert_id, ip, scenario, events_count,
               action_type, action_duration, scope, status, message, details_json, executed_at
        FROM playbook_executions
        ${whereClause}
        ORDER BY executed_at DESC
        LIMIT ? OFFSET ?
      `);

      const totalRow = countStmt.get(...params) as { count: number };
      const rows = listStmt.all(...params, limit, offset) as any[];
      return {
        executions: rows.map((r) => this.rowToExecution(r)),
        total: totalRow?.count || 0,
      };
    } else {
      records = this.memoryExecutions.filter((rec) => {
        if (filter.playbook_id && rec.playbook_id !== filter.playbook_id) return false;
        if (filter.ip && rec.ip !== filter.ip) return false;
        if (filter.status && rec.status !== filter.status) return false;
        return true;
      });

      return {
        executions: records.slice(offset, offset + limit),
        total: records.length,
      };
    }
  }

  /**
   * Execution History: Clear all execution logs (used in tests or maintenance)
   */
  public clearExecutions(): void {
    if (this.clearExecutionsStmt) {
      this.clearExecutionsStmt.run();
    }
    this.memoryExecutions.length = 0;
    this.ipCooldowns.clear();
  }

  /**
   * Safety Guardrail: Check allowlist status for an IP
   */
  public async isAllowlisted(ip: string, targetInstances: ConfiguredInstance[]): Promise<{ allowlisted: boolean; reason?: string }> {
    // 1. Custom in-memory allowlist check
    if (this.customAllowlist.has(ip)) {
      return { allowlisted: true, reason: 'Custom static allowlist match' };
    }

    // 2. AllowlistService check
    if (this.allowlistService) {
      try {
        const check = await this.allowlistService.checkValue(targetInstances, ip);
        if (check.allowlisted) {
          const matchInstances = check.results.filter((r) => r.allowlisted).map((r) => r.instance_name || r.instance_id);
          return {
            allowlisted: true,
            reason: `Allowlisted on instance(s): ${matchInstances.join(', ')}`,
          };
        }
      } catch (err: any) {
        console.warn(`[playbooks] Allowlist check error for ${ip}:`, err.message);
      }
    }

    return { allowlisted: false };
  }

  /**
   * Safety Guardrail: Check cooldown / rate-limit for an IP
   */
  public isCoolingDown(ip: string, rule: PlaybookRule, nowMs: number = Date.now()): { inCooldown: boolean; remainingSeconds?: number; reason?: string } {
    const cooldownSeconds = rule.guardrails?.cooldown_seconds ?? this.defaultCooldownSeconds;
    if (cooldownSeconds <= 0) return { inCooldown: false };

    const tracked = this.ipCooldowns.get(ip);
    if (tracked) {
      const elapsedSeconds = (nowMs - tracked.lastActionMs) / 1000;
      if (elapsedSeconds < cooldownSeconds) {
        const remainingSeconds = Math.ceil(cooldownSeconds - elapsedSeconds);
        return {
          inCooldown: true,
          remainingSeconds,
          reason: `Remediated ${Math.floor(elapsedSeconds)}s ago. Cooldown active for ${remainingSeconds}s.`,
        };
      }
    }

    // Also check database if available
    if (this.database) {
      const cutoff = new Date(nowMs - cooldownSeconds * 1000).toISOString();
      const recent = this.database.db.query(`
        SELECT executed_at FROM playbook_executions
        WHERE ip = ? AND status IN ('executed', 'simulated') AND executed_at >= ?
        ORDER BY executed_at DESC LIMIT 1
      `).get(ip, cutoff) as { executed_at: string } | undefined;

      if (recent) {
        const lastMs = new Date(recent.executed_at).getTime();
        const elapsedSeconds = (nowMs - lastMs) / 1000;
        const remainingSeconds = Math.ceil(cooldownSeconds - elapsedSeconds);
        // Sync into in-memory tracker
        this.ipCooldowns.set(ip, { lastActionMs: lastMs, ruleId: rule.id });
        return {
          inCooldown: true,
          remainingSeconds,
          reason: `Previous action at ${recent.executed_at}. Cooldown active for ${remainingSeconds}s.`,
        };
      }
    }

    return { inCooldown: false };
  }

  /**
   * Resolves target instances for an action.
   */
  private resolveTargets(action: PlaybookAction): ConfiguredInstance[] {
    if (action.scope === 'local') {
      return this.primaryInstance ? [this.primaryInstance] : this.instances.slice(0, 1);
    }

    if (Array.isArray(action.target_instance_ids) && action.target_instance_ids.length > 0) {
      const set = new Set(action.target_instance_ids);
      const filtered = this.instances.filter((inst) => set.has(inst.id));
      if (filtered.length > 0) return filtered;
    }

    // Default: fleet propagation (all configured instances)
    return this.instances.length > 0 ? this.instances : (this.primaryInstance ? [this.primaryInstance] : []);
  }

  /**
   * Matches an incoming alert against a rule trigger.
   */
  public matchTrigger(alert: AlertRecord, trigger: PlaybookTrigger): { matched: boolean; reasons: string[] } {
    const reasons: string[] = [];

    // Simulated alerts check
    const isSimulated = Boolean(alert.simulated);
    if (isSimulated && !trigger.include_simulated) {
      return { matched: false, reasons: ['Alert is simulated and trigger excludes simulated alerts'] };
    }

    // Scenario matching
    const alertScenario = alert.scenario || (alert as any).record_scenario || '';
    let scenarioMatched = false;

    if (trigger.scenario && alertScenario) {
      if (matchScenario(alertScenario, trigger.scenario)) {
        scenarioMatched = true;
        reasons.push(`Matched exact scenario "${trigger.scenario}"`);
      }
    }

    if (!scenarioMatched && trigger.scenario_pattern && alertScenario) {
      if (matchScenario(alertScenario, trigger.scenario_pattern)) {
        scenarioMatched = true;
        reasons.push(`Matched scenario pattern "${trigger.scenario_pattern}"`);
      }
    }

    if (!scenarioMatched && Array.isArray(trigger.scenarios) && alertScenario) {
      for (const pattern of trigger.scenarios) {
        if (matchScenario(alertScenario, pattern)) {
          scenarioMatched = true;
          reasons.push(`Matched scenario list item "${pattern}"`);
          break;
        }
      }
    }

    if (!scenarioMatched) {
      return { matched: false, reasons: [`Scenario "${alertScenario}" did not match any trigger criteria`] };
    }

    // Events count threshold check
    const alertEventsCount = typeof alert.events_count === 'number'
      ? alert.events_count
      : (Array.isArray(alert.events) ? alert.events.length : 1);

    const threshold = trigger.events_count_threshold || 1;
    if (alertEventsCount < threshold) {
      return {
        matched: false,
        reasons: [`Alert event count (${alertEventsCount}) below threshold (${threshold})`],
      };
    }
    reasons.push(`Event count ${alertEventsCount} meets threshold >= ${threshold}`);

    // Origins filter (optional)
    if (Array.isArray(trigger.origins) && trigger.origins.length > 0) {
      const alertOrigins = Array.isArray(alert.origins) ? alert.origins : (alert as any).origin ? [(alert as any).origin] : [];
      const hasOriginMatch = trigger.origins.some((orig) => alertOrigins.includes(orig));
      if (!hasOriginMatch) {
        return { matched: false, reasons: [`Alert origins [${alertOrigins.join(',')}] do not match required [${trigger.origins.join(',')}]`] };
      }
      reasons.push(`Matched origin criteria`);
    }

    return { matched: true, reasons };
  }

  /**
   * Evaluates an alert against all enabled playbook rules.
   * Runs safety guardrails and either executes remediation or simulates it.
   */
  public async evaluateAlert(
    alert: AlertRecord,
    options: { simulation?: boolean; dryRun?: boolean; specificRuleId?: string } = {},
  ): Promise<PlaybookEvaluationResult[]> {
    const rawIp = getAlertSourceValue(alert.source) || (alert as any).source_ip || (alert as any).source_value;
    if (!rawIp || !isValidIpOrRange(rawIp)) {
      return [];
    }

    const ip = rawIp.trim();
    const rules = this.listRules().filter((r) => {
      if (options.specificRuleId) return r.id === options.specificRuleId;
      return r.enabled;
    });

    const results: PlaybookEvaluationResult[] = [];
    const now = new Date();
    const nowIso = now.toISOString();
    const nowMs = now.getTime();

    for (const rule of rules) {
      const triggerResult = this.matchTrigger(alert, rule.trigger);
      if (!triggerResult.matched) {
        continue;
      }

      const targets = this.resolveTargets(rule.action);
      const isSimulatedMode = Boolean(
        options.simulation ||
        options.dryRun ||
        this.simulationMode ||
        rule.guardrails?.simulation_mode
      );

      // --- Safety Guardrail 1: Never Ban Allowlisted IPs ---
      if (rule.guardrails?.never_ban_allowlisted !== false) {
        const allowlistCheck = await this.isAllowlisted(ip, targets);
        if (allowlistCheck.allowlisted) {
          const message = `Safety guardrail: IP ${ip} is allowlisted (${allowlistCheck.reason}). Automatic ban blocked.`;
          if (!options.dryRun) {
            await this.recordExecution({
              id: crypto.randomUUID(),
              playbook_id: rule.id,
              playbook_name: rule.name,
              alert_id: alert.id,
              ip,
              scenario: alert.scenario || 'unknown',
              events_count: alert.events_count || 1,
              action_type: rule.action.type,
              action_duration: rule.action.duration,
              scope: rule.action.scope || 'fleet',
              status: 'blocked_by_allowlist',
              message,
              executed_at: nowIso,
            });
          }

          results.push({
            rule_id: rule.id,
            rule_name: rule.name,
            alert_id: alert.id,
            ip,
            matched: true,
            match_reasons: triggerResult.reasons,
            status: 'blocked_by_allowlist',
            error: message,
          });
          continue;
        }
      }

      // --- Safety Guardrail 2: Rate Limit / Cooldown per IP ---
      const cooldownCheck = this.isCoolingDown(ip, rule, nowMs);
      if (cooldownCheck.inCooldown) {
        const message = `Safety guardrail: IP ${ip} is in cooldown (${cooldownCheck.reason}). Action blocked.`;
        if (!options.dryRun) {
          await this.recordExecution({
            id: crypto.randomUUID(),
            playbook_id: rule.id,
            playbook_name: rule.name,
            alert_id: alert.id,
            ip,
            scenario: alert.scenario || 'unknown',
            events_count: alert.events_count || 1,
            action_type: rule.action.type,
            action_duration: rule.action.duration,
            scope: rule.action.scope || 'fleet',
            status: 'blocked_by_cooldown',
            message,
            executed_at: nowIso,
          });
        }

        results.push({
          rule_id: rule.id,
          rule_name: rule.name,
          alert_id: alert.id,
          ip,
          matched: true,
          match_reasons: triggerResult.reasons,
          status: 'blocked_by_cooldown',
          error: message,
        });
        continue;
      }

      // Action parameters
      const decisionScenario = rule.action.scenario || alert.scenario || 'playbook-remediation';
      const reason = rule.action.reason || `Automated remediation: ${rule.name}`;
      const actionSummary = {
        type: rule.action.type,
        duration: rule.action.duration,
        scope: rule.action.scope || 'fleet',
        reason,
        scenario: decisionScenario,
        instances: targets.map((t) => t.name || t.id),
      };

      // --- Safety Guardrail 3: Simulation Mode Support ---
      if (isSimulatedMode) {
        const message = `[SIMULATION] Would issue automatic ${rule.action.type} for IP ${ip} (${rule.action.duration}) across ${targets.length} instance(s)`;
        if (!options.dryRun) {
          await this.recordExecution({
            id: crypto.randomUUID(),
            playbook_id: rule.id,
            playbook_name: rule.name,
            alert_id: alert.id,
            ip,
            scenario: alert.scenario || 'unknown',
            events_count: alert.events_count || 1,
            action_type: rule.action.type,
            action_duration: rule.action.duration,
            scope: rule.action.scope || 'fleet',
            status: 'simulated',
            message,
            details: { action: actionSummary, targets: targets.map((t) => t.id) },
            executed_at: nowIso,
          });
        }

        results.push({
          rule_id: rule.id,
          rule_name: rule.name,
          alert_id: alert.id,
          ip,
          matched: true,
          match_reasons: triggerResult.reasons,
          status: 'simulated',
          action: actionSummary,
        });
        continue;
      }

      // --- Live Execution: Issue Automatic Ban Across Fleet ---
      try {
        const instanceResults: Array<{ instance_id: string; instance_name: string; success: boolean; error?: string }> = [];
        let anySuccess = false;

        for (const target of targets) {
          const client = this.lapiClients.get(target.id);
          if (!client) {
            instanceResults.push({
              instance_id: target.id,
              instance_name: target.name,
              success: false,
              error: `No LAPI client configured for instance ${target.id}`,
            });
            continue;
          }

          try {
            await client.addDecision(ip, rule.action.type, rule.action.duration, reason.slice(0, 256), decisionScenario);
            instanceResults.push({
              instance_id: target.id,
              instance_name: target.name,
              success: true,
            });
            anySuccess = true;
          } catch (err: any) {
            instanceResults.push({
              instance_id: target.id,
              instance_name: target.name,
              success: false,
              error: err?.message || String(err),
            });
          }
        }

        const status: PlaybookExecutionStatus = anySuccess ? 'executed' : 'failed';
        const message = anySuccess
          ? `Automatically issued ${rule.action.type} for ${ip} (${rule.action.duration}) across ${instanceResults.filter((r) => r.success).length}/${targets.length} instance(s)`
          : `Failed to issue ${rule.action.type} for ${ip}: all instances failed`;

        // Record execution in audit log and DB
        if (this.auditLog && anySuccess) {
          this.auditLog.record(null, {
            action: 'decision.add',
            ip,
            type: rule.action.type,
            scenario: decisionScenario,
            duration: rule.action.duration,
            reason: reason.slice(0, 256),
            instances: targets.map((t) => t.name),
            outcome: anySuccess ? 'success' : 'failure',
          });
        }

        await this.recordExecution({
          id: crypto.randomUUID(),
          playbook_id: rule.id,
          playbook_name: rule.name,
          alert_id: alert.id,
          ip,
          scenario: alert.scenario || 'unknown',
          events_count: alert.events_count || 1,
          action_type: rule.action.type,
          action_duration: rule.action.duration,
          scope: rule.action.scope || 'fleet',
          status,
          message,
          details: { instance_results: instanceResults },
          executed_at: nowIso,
        });

        // Trigger cache delta update so the decision is visible immediately
        if (anySuccess && this.updateCacheDelta) {
          void this.updateCacheDelta({ publishUnchanged: true }).catch((e) => {
            console.warn('[playbooks] Cache delta update failed after ban:', e.message);
          });
        }

        results.push({
          rule_id: rule.id,
          rule_name: rule.name,
          alert_id: alert.id,
          ip,
          matched: true,
          match_reasons: triggerResult.reasons,
          status,
          action: actionSummary,
          error: status === 'failed' ? message : undefined,
        });
      } catch (err: any) {
        const message = `Execution error: ${err.message || String(err)}`;
        await this.recordExecution({
          id: crypto.randomUUID(),
          playbook_id: rule.id,
          playbook_name: rule.name,
          alert_id: alert.id,
          ip,
          scenario: alert.scenario || 'unknown',
          events_count: alert.events_count || 1,
          action_type: rule.action.type,
          action_duration: rule.action.duration,
          scope: rule.action.scope || 'fleet',
          status: 'failed',
          message,
          executed_at: nowIso,
        });

        results.push({
          rule_id: rule.id,
          rule_name: rule.name,
          alert_id: alert.id,
          ip,
          matched: true,
          match_reasons: triggerResult.reasons,
          status: 'failed',
          error: message,
        });
      }
    }

    return results;
  }

  /**
   * Evaluates a batch of alerts against playbook rules.
   */
  public async evaluateAlerts(
    alerts: AlertRecord[],
    options: { simulation?: boolean; dryRun?: boolean } = {},
  ): Promise<PlaybookEvaluationResult[]> {
    const allResults: PlaybookEvaluationResult[] = [];
    for (const alert of alerts) {
      const res = await this.evaluateAlert(alert, options);
      allResults.push(...res);
    }
    return allResults;
  }

  /**
   * Evaluates recent alerts from the database against playbook rules.
   */
  public async evaluateRecentAlerts(
    options: { since?: string; limit?: number; simulation?: boolean } = {},
  ): Promise<PlaybookEvaluationResult[]> {
    if (!this.database) return [];
    const cutoff = options.since || new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const now = new Date().toISOString();
    const rows = this.database.getAlertsBetween(cutoff, now);
    const alerts: AlertRecord[] = [];
    for (const row of rows) {
      try {
        if (row.raw_data) {
          alerts.push(JSON.parse(row.raw_data));
        }
      } catch {
        // ignore unparseable row
      }
    }
    const limited = options.limit ? alerts.slice(0, options.limit) : alerts;
    return this.evaluateAlerts(limited, { simulation: options.simulation });
  }

  /**
   * Dry-run simulation of an alert against rules without modifying database or upstream.
   */
  public async simulateAlert(alert: AlertRecord): Promise<PlaybookEvaluationResult[]> {
    return this.evaluateAlert(alert, { dryRun: true, simulation: true });
  }

  /**
   * Returns remaining cooldown in milliseconds for an IP, or 0 if not cooling down.
   */
  public getCooldownMs(ip: string): number {
    const tracked = this.ipCooldowns.get(ip);
    if (!tracked) return 0;
    const elapsed = Date.now() - tracked.lastActionMs;
    const remaining = this.defaultCooldownSeconds * 1000 - elapsed;
    return remaining > 0 ? remaining : 0;
  }

  /**
   * Clears cooldown for an IP (or all IPs if omitted).
   */
  public clearCooldown(ip?: string): void {
    if (ip) {
      this.ipCooldowns.delete(ip);
    } else {
      this.ipCooldowns.clear();
    }
  }
}

export function createPlaybookService(options: PlaybookServiceOptions = {}): PlaybookService {
  return new PlaybookService(options);
}

/**
 * Registers REST API routes for Automated Remediation Playbooks.
 */
export function registerPlaybookRoutes(options: {
  app: Hono;
  basePath: string;
  service: PlaybookService;
  ensureAuth: (context: HonoContext, next: () => Promise<void>) => Promise<Response | void>;
  ensureCanManageEnforcement: (context: HonoContext) => Response | null;
}): void {
  const { app, basePath, service, ensureAuth, ensureCanManageEnforcement } = options;
  const root = `${basePath}/api/playbooks`;

  // GET /api/playbooks - List all playbook rules
  app.get(root, ensureAuth, async (context) => {
    const rules = service.listRules();
    const response: PlaybookListResponse = {
      rules,
      total: rules.length,
    };
    return context.json(response);
  });

  // GET /api/playbooks/executions - List execution logs with filters
  app.get(`${root}/executions`, ensureAuth, async (context) => {
    const query = context.req.query();
    const playbook_id = query.playbook_id ? String(query.playbook_id) : undefined;
    const ip = query.ip ? String(query.ip) : undefined;
    const status = query.status ? String(query.status) : undefined;
    const limit = query.limit ? Number.parseInt(String(query.limit), 10) : 50;
    const offset = query.offset ? Number.parseInt(String(query.offset), 10) : 0;

    const result = service.listExecutions({
      playbook_id,
      ip,
      status,
      limit,
      offset,
    });

    return context.json(result);
  });

  // POST /api/playbooks/simulate (or /evaluate) - Dry-run evaluation
  const handleSimulate = async (context: HonoContext) => {
    const body = await context.req.json().catch(() => null);
    if (!body || typeof body !== 'object') {
      return context.json({ error: 'Request body must be a valid JSON object' }, 400);
    }

    const alert: AlertRecord = body.alert || body;
    if (!alert.scenario) {
      return context.json({ error: 'Alert must contain a valid scenario' }, 400);
    }

    const results = await service.simulateAlert(alert);
    return context.json({ results, alert });
  };

  app.post(`${root}/simulate`, ensureAuth, handleSimulate);
  app.post(`${root}/evaluate`, ensureAuth, handleSimulate);

  // POST /api/playbooks - Create a new rule
  app.post(root, ensureAuth, async (context) => {
    const permissionError = ensureCanManageEnforcement(context);
    if (permissionError) return permissionError;

    const body = await context.req.json().catch(() => null);
    const validation = validatePlaybookRule(body);
    if (!validation.valid) {
      return context.json({ error: validation.errors.join('; '), errors: validation.errors }, 400);
    }

    try {
      const created = await service.createRule(body as UpsertPlaybookRuleRequest);
      return context.json(created, 201);
    } catch (err: any) {
      return context.json({ error: err.message }, 400);
    }
  });

  // GET /api/playbooks/:id - Get a single rule
  app.get(`${root}/:id`, ensureAuth, async (context) => {
    const id = context.req.param('id');
    const rule = service.getRule(id);
    if (!rule) {
      return context.json({ error: 'Playbook rule not found' }, 404);
    }
    return context.json(rule);
  });

  // PUT /api/playbooks/:id - Update an existing rule
  app.put(`${root}/:id`, ensureAuth, async (context) => {
    const permissionError = ensureCanManageEnforcement(context);
    if (permissionError) return permissionError;

    const id = context.req.param('id');
    const body = await context.req.json().catch(() => null);
    const validation = validatePlaybookRule(body);
    if (!validation.valid) {
      return context.json({ error: validation.errors.join('; '), errors: validation.errors }, 400);
    }

    try {
      const updated = await service.updateRule(id, body as UpsertPlaybookRuleRequest);
      if (!updated) {
        return context.json({ error: 'Playbook rule not found' }, 404);
      }
      return context.json(updated);
    } catch (err: any) {
      return context.json({ error: err.message }, 400);
    }
  });

  // DELETE /api/playbooks/:id - Delete a rule
  app.delete(`${root}/:id`, ensureAuth, async (context) => {
    const permissionError = ensureCanManageEnforcement(context);
    if (permissionError) return permissionError;

    const id = context.req.param('id');
    const deleted = await service.deleteRule(id);
    if (!deleted) {
      return context.json({ error: 'Playbook rule not found' }, 404);
    }
    return context.json({ success: true, message: 'Playbook rule deleted' });
  });

  // POST or PATCH /api/playbooks/:id/toggle - Toggle rule enabled
  const handleToggle = async (context: HonoContext) => {
    const permissionError = ensureCanManageEnforcement(context);
    if (permissionError) return permissionError;

    const id = context.req.param('id');
    const body = await context.req.json().catch(() => ({}));
    const enabled = typeof body?.enabled === 'boolean' ? body.enabled : undefined;

    const updated = await service.toggleRule(id, enabled);
    if (!updated) {
      return context.json({ error: 'Playbook rule not found' }, 404);
    }
    return context.json(updated);
  };

  app.post(`${root}/:id/toggle`, ensureAuth, handleToggle);
  app.patch(`${root}/:id/toggle`, ensureAuth, handleToggle);
}
