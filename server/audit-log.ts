import fs from 'node:fs';
import path from 'node:path';

type HonoContext = any;

export type AuditAction =
  | 'decision.add'
  | 'decision.delete'
  | 'alert.delete'
  | 'cleanup.by-ip'
  | 'user.create'
  | 'user.update'
  | 'user.password-reset'
  | 'user.mfa-reset'
  | 'user.oidc-link'
  | 'user.oidc-unlink'
  | 'user.delete'
  | 'user.login'
  | 'user.logout'
  | 'allowlist.bypass'
  | string;

export type AuditOutcome = 'success' | 'partial' | 'failure' | 'queued' | string;

export interface AuditActor {
  username: string;
  role?: string;
}

export interface AuditEvent {
  action: AuditAction;
  outcome: AuditOutcome;
  [detail: string]: unknown;
}

export interface AuditLogEntry {
  time: string;
  user: string;
  role?: string;
  action: string;
  outcome: string;
  ip?: string;
  values?: string[];
  type?: string;
  scenario?: string;
  duration?: string;
  reason?: string;
  instances?: string[];
  instance_results?: Array<{ instance?: string; instance_name?: string; outcome?: string; error?: string }>;
  target_results?: Array<{ id?: string; value?: string; outcome?: string; error?: string }>;
  alert_ids?: string[];
  decision_ids?: string[];
  target_user_id?: number;
  target_username?: string;
  auth_method?: string;
  bypass_allowlist?: boolean;
  [detail: string]: unknown;
}

export interface AuditLogQueryFilters {
  action?: string;
  user?: string;
  ip?: string;
  outcome?: string;
  from?: string;
  to?: string;
  q?: string;
}

export interface AuditLogQueryParams extends AuditLogQueryFilters {
  page?: number;
  pageSize?: number;
}

export interface AuditLogQueryResult {
  data: AuditLogEntry[];
  pagination: {
    page: number;
    page_size: number;
    total: number;
    total_pages: number;
    unfiltered_total: number;
  };
}

export interface AuditLogger {
  enabled: boolean;
  record: (context: HonoContext, event: AuditEvent) => void;
  query: (params?: AuditLogQueryParams) => AuditLogQueryResult;
  exportEntries: (filters?: AuditLogQueryFilters) => AuditLogEntry[];
  getLogFilePath: () => string | undefined;
}

export interface CreateAuditLoggerOptions {
  enabled: boolean;
  logFile?: string;
  getActor: (context: HonoContext) => AuditActor | null;
}

export function escapeCsvField(value: unknown): string {
  if (value === null || value === undefined) return '';
  const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function formatAuditLogsAsCsv(entries: AuditLogEntry[]): string {
  const headers = ['Time', 'User', 'Role', 'Action', 'Outcome', 'Target', 'Details'];
  const lines = [headers.join(',')];
  for (const entry of entries) {
    const { time, user, role = '', action, outcome, ip, values, target_username, alert_ids, decision_ids, ...rest } = entry;
    const target =
      ip ||
      (Array.isArray(values) && values.length > 0 ? values.join('; ') : '') ||
      target_username ||
      (Array.isArray(alert_ids) && alert_ids.length > 0 ? `Alerts: ${alert_ids.join('; ')}` : '') ||
      (Array.isArray(decision_ids) && decision_ids.length > 0 ? `Decisions: ${decision_ids.join('; ')}` : '') ||
      '';
    const details = Object.keys(rest).length > 0 ? JSON.stringify(rest) : '';
    lines.push([time, user, role, action, outcome, target, details].map(escapeCsvField).join(','));
  }
  return lines.join('\r\n');
}

export function matchesAuditFilter(entry: AuditLogEntry, filters: AuditLogQueryFilters): boolean {
  if (filters.action && filters.action.trim()) {
    const actions = filters.action.split(',').map((a) => a.trim().toLowerCase()).filter(Boolean);
    if (actions.length > 0 && !actions.includes(entry.action?.toLowerCase() || '')) {
      return false;
    }
  }

  if (filters.outcome && filters.outcome.trim()) {
    const outcomes = filters.outcome.split(',').map((o) => o.trim().toLowerCase()).filter(Boolean);
    if (outcomes.length > 0 && !outcomes.includes(entry.outcome?.toLowerCase() || '')) {
      return false;
    }
  }

  if (filters.user && filters.user.trim()) {
    const userFilter = filters.user.trim().toLowerCase();
    const username = entry.user?.toLowerCase() || '';
    const targetUsername = String(entry.target_username || '').toLowerCase();
    if (!username.includes(userFilter) && !targetUsername.includes(userFilter)) {
      return false;
    }
  }

  if (filters.ip && filters.ip.trim()) {
    const ipFilter = filters.ip.trim().toLowerCase();
    let matches = false;
    if (entry.ip && String(entry.ip).toLowerCase().includes(ipFilter)) {
      matches = true;
    } else if (Array.isArray(entry.values) && entry.values.some((v) => String(v).toLowerCase().includes(ipFilter))) {
      matches = true;
    } else if (
      Array.isArray(entry.target_results) &&
      entry.target_results.some(
        (tr) =>
          (tr.id && String(tr.id).toLowerCase().includes(ipFilter)) ||
          (tr.value && String(tr.value).toLowerCase().includes(ipFilter)),
      )
    ) {
      matches = true;
    } else {
      const detailStr = JSON.stringify(entry).toLowerCase();
      if (detailStr.includes(ipFilter)) {
        matches = true;
      }
    }
    if (!matches) return false;
  }

  if (filters.from && filters.from.trim()) {
    const fromTime = Date.parse(filters.from.trim());
    if (!Number.isNaN(fromTime)) {
      const entryTime = Date.parse(entry.time);
      if (!Number.isNaN(entryTime) && entryTime < fromTime) {
        return false;
      }
    }
  }

  if (filters.to && filters.to.trim()) {
    const toTime = Date.parse(filters.to.trim());
    if (!Number.isNaN(toTime)) {
      const entryTime = Date.parse(entry.time);
      if (!Number.isNaN(entryTime) && entryTime > toTime) {
        return false;
      }
    }
  }

  if (filters.q && filters.q.trim()) {
    const q = filters.q.trim().toLowerCase();
    const searchFields = [
      entry.user,
      entry.role,
      entry.action,
      entry.outcome,
      entry.ip,
      entry.reason,
      entry.scenario,
      entry.duration,
      entry.target_username,
      Array.isArray(entry.instances) ? entry.instances.join(' ') : '',
      Array.isArray(entry.values) ? entry.values.join(' ') : '',
      Array.isArray(entry.alert_ids) ? entry.alert_ids.join(' ') : '',
      Array.isArray(entry.decision_ids) ? entry.decision_ids.join(' ') : '',
    ];
    let found = searchFields.some((field) => field && String(field).toLowerCase().includes(q));
    if (!found) {
      found = JSON.stringify(entry).toLowerCase().includes(q);
    }
    if (!found) return false;
  }

  return true;
}

export function createAuditLogger(options: CreateAuditLoggerOptions): AuditLogger {
  const { enabled, logFile, getActor } = options;
  let fileWritable = Boolean(logFile);
  const memoryEntries: AuditLogEntry[] = [];
  const MAX_MEMORY_ENTRIES = 10000;

  if (enabled && logFile) {
    try {
      fs.mkdirSync(path.dirname(logFile), { recursive: true });
    } catch (error) {
      fileWritable = false;
      console.error(`Audit log file directory for "${logFile}" could not be created: ${(error as Error).message}`);
    }
  }

  function readAllEntries(): AuditLogEntry[] {
    if (logFile && fs.existsSync(logFile)) {
      try {
        const stat = fs.statSync(logFile);
        if (stat.isFile()) {
          const content = fs.readFileSync(logFile, 'utf8');
          const lines = content.split('\n');
          const fileEntries: AuditLogEntry[] = [];
          for (const rawLine of lines) {
            const trimmed = rawLine.trim();
            if (!trimmed) continue;
            try {
              fileEntries.push(JSON.parse(trimmed));
            } catch {
              // skip malformed line
            }
          }
          if (fileEntries.length > 0) {
            return fileEntries;
          }
        }
      } catch {
        // Fall back to memoryEntries
      }
    }
    return [...memoryEntries];
  }

  function record(context: HonoContext, event: AuditEvent): void {
    if (!enabled) return;

    // Audit logging must never break the user action it describes.
    try {
      const actor = getActor(context);
      const entry: AuditLogEntry = {
        time: new Date().toISOString(),
        user: actor?.username || 'unknown',
        ...(actor?.role ? { role: actor.role } : {}),
        ...event,
      };
      const line = JSON.stringify(entry);
      console.log(`[audit] ${line}`);
      if (logFile && fileWritable) {
        fs.appendFileSync(logFile, `${line}\n`, 'utf8');
      }
      memoryEntries.push(entry);
      if (memoryEntries.length > MAX_MEMORY_ENTRIES) {
        memoryEntries.splice(0, memoryEntries.length - MAX_MEMORY_ENTRIES);
      }
    } catch (error) {
      console.error(`Failed to write audit log entry: ${(error as Error).message}`);
    }
  }

  function getSortedFilteredEntries(filters: AuditLogQueryFilters = {}): { filtered: AuditLogEntry[]; totalUnfiltered: number } {
    const all = readAllEntries();
    all.sort((a, b) => {
      const timeA = Date.parse(a.time) || 0;
      const timeB = Date.parse(b.time) || 0;
      return timeB - timeA;
    });
    const filtered = all.filter((entry) => matchesAuditFilter(entry, filters));
    return { filtered, totalUnfiltered: all.length };
  }

  function query(params: AuditLogQueryParams = {}): AuditLogQueryResult {
    const { page = 1, pageSize = 50, ...filters } = params;
    const { filtered, totalUnfiltered } = getSortedFilteredEntries(filters);
    const safePage = Math.max(1, page);
    const safePageSize = Math.min(500, Math.max(1, pageSize));
    const total = filtered.length;
    const totalPages = Math.ceil(total / safePageSize);
    const offset = (safePage - 1) * safePageSize;
    const data = filtered.slice(offset, offset + safePageSize);

    return {
      data,
      pagination: {
        page: safePage,
        page_size: safePageSize,
        total,
        total_pages: totalPages,
        unfiltered_total: totalUnfiltered,
      },
    };
  }

  function exportEntries(filters: AuditLogQueryFilters = {}): AuditLogEntry[] {
    const { filtered } = getSortedFilteredEntries(filters);
    return filtered.slice(0, 10000);
  }

  return {
    enabled,
    record,
    query,
    exportEntries,
    getLogFilePath: () => logFile,
  };
}
