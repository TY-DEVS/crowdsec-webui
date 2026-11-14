import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { createAuditLogger, type AuditActor } from '../../audit-log';

const tempDirs: string[] = [];

function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'crowdsec-web-ui-audit-test-'));
  tempDirs.push(dir);
  return dir;
}

function createLogger(options: { enabled?: boolean; logFile?: string; actor?: AuditActor | null } = {}) {
  return createAuditLogger({
    enabled: options.enabled ?? true,
    logFile: options.logFile,
    getActor: () => (options.actor === undefined ? { username: 'tommy', role: 'admin' } : options.actor),
  });
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('createAuditLogger', () => {
  test('writes a structured console line and appends the entry to the log file', () => {
    const logFile = join(createTempDir(), 'logs', 'audit.log');
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const auditLog = createLogger({ logFile });
      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', type: 'ban', outcome: 'success' });

      expect(log).toHaveBeenCalledTimes(1);
      const line = String(log.mock.calls[0][0]);
      expect(line.startsWith('[audit] ')).toBe(true);
      const entry = JSON.parse(line.slice('[audit] '.length));
      expect(entry).toMatchObject({
        user: 'tommy',
        role: 'admin',
        action: 'decision.add',
        ip: '1.2.3.4',
        type: 'ban',
        outcome: 'success',
      });
      expect(Number.isNaN(Date.parse(entry.time))).toBe(false);
      expect(readFileSync(logFile, 'utf8')).toBe(`${line.slice('[audit] '.length)}\n`);
    } finally {
      log.mockRestore();
    }
  });

  test('appends one line per recorded entry', () => {
    const logFile = join(createTempDir(), 'audit.log');
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const auditLog = createLogger({ logFile });
      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', outcome: 'success' });
      auditLog.record({}, { action: 'decision.delete', decision_ids: ['10'], outcome: 'success' });

      const lines = readFileSync(logFile, 'utf8').trimEnd().split('\n');
      expect(lines).toHaveLength(2);
      expect(JSON.parse(lines[0]).action).toBe('decision.add');
      expect(JSON.parse(lines[1]).action).toBe('decision.delete');
    } finally {
      log.mockRestore();
    }
  });

  test('stays silent when disabled', () => {
    const logFile = join(createTempDir(), 'audit.log');
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const auditLog = createLogger({ enabled: false, logFile });
      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', outcome: 'success' });

      expect(log).not.toHaveBeenCalled();
      expect(() => readFileSync(logFile, 'utf8')).toThrow();
    } finally {
      log.mockRestore();
    }
  });

  test('records unknown when no actor is available', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      const auditLog = createLogger({ actor: null });
      auditLog.record({}, { action: 'alert.delete', alert_ids: ['1'], outcome: 'success' });

      const entry = JSON.parse(String(log.mock.calls[0][0]).slice('[audit] '.length));
      expect(entry.user).toBe('unknown');
      expect(entry.role).toBeUndefined();
    } finally {
      log.mockRestore();
    }
  });

  test('keeps console logging when the log file cannot be written', () => {
    const logFile = join(createTempDir(), 'audit.log');
    mkdirSync(logFile);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const auditLog = createLogger({ logFile });
      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', outcome: 'success' });

      expect(log).toHaveBeenCalledWith(expect.stringContaining('[audit] '));
      expect(error).toHaveBeenCalledWith(expect.stringContaining('Failed to write audit log entry'));
    } finally {
      error.mockRestore();
      log.mockRestore();
    }
  });

  test('warns once when the log file directory cannot be created', () => {
    const blockingFile = join(createTempDir(), 'not-a-directory');
    writeFileSync(blockingFile, 'occupied', 'utf8');
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const auditLog = createLogger({ logFile: join(blockingFile, 'audit.log') });
      expect(error).toHaveBeenCalledWith(expect.stringContaining('could not be created'));

      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', outcome: 'success' });
      expect(log).toHaveBeenCalledWith(expect.stringContaining('[audit] '));
      expect(error).toHaveBeenCalledTimes(1);
    } finally {
      error.mockRestore();
      log.mockRestore();
    }
  });

  test('queries entries with pagination and reverse-chronological ordering', () => {
    const auditLog = createLogger();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'user.login', outcome: 'success', time: '2026-01-01T10:00:00.000Z' });
      auditLog.record({}, { action: 'decision.add', ip: '1.1.1.1', outcome: 'success', time: '2026-01-01T11:00:00.000Z' });
      auditLog.record({}, { action: 'decision.delete', outcome: 'success', time: '2026-01-01T12:00:00.000Z' });

      const page1 = auditLog.query({ page: 1, pageSize: 2 });
      expect(page1.pagination.total).toBe(3);
      expect(page1.pagination.total_pages).toBe(2);
      expect(page1.pagination.page).toBe(1);
      expect(page1.pagination.page_size).toBe(2);
      expect(page1.data).toHaveLength(2);
      expect(page1.data[0].action).toBe('decision.delete');
      expect(page1.data[1].action).toBe('decision.add');

      const page2 = auditLog.query({ page: 2, pageSize: 2 });
      expect(page2.data).toHaveLength(1);
      expect(page2.data[0].action).toBe('user.login');
    } finally {
      log.mockRestore();
    }
  });

  test('filters entries by action, outcome, user, ip, date range, and search query', () => {
    const auditLog = createLogger();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'decision.add', ip: '10.0.0.1', outcome: 'success', reason: 'ssh brute force', time: '2026-03-01T10:00:00.000Z' });
      auditLog.record({}, { action: 'decision.add', ip: '10.0.0.2', outcome: 'failure', reason: 'network error', time: '2026-03-02T10:00:00.000Z' });
      auditLog.record({}, { action: 'user.login', outcome: 'success', target_username: 'alice', time: '2026-03-03T10:00:00.000Z' });
      auditLog.record({}, { action: 'alert.delete', outcome: 'queued', alert_ids: ['100', '101'], time: '2026-03-04T10:00:00.000Z' });

      // Action filter
      expect(auditLog.query({ action: 'decision.add' }).pagination.total).toBe(2);
      expect(auditLog.query({ action: 'decision.add,alert.delete' }).pagination.total).toBe(3);

      // Outcome filter
      expect(auditLog.query({ outcome: 'failure' }).pagination.total).toBe(1);
      expect(auditLog.query({ outcome: 'success' }).pagination.total).toBe(2);

      // IP filter
      expect(auditLog.query({ ip: '10.0.0.1' }).pagination.total).toBe(1);
      expect(auditLog.query({ ip: '10.0.0' }).pagination.total).toBe(2);

      // Date range filter
      const dateFiltered = auditLog.query({ from: '2026-03-02T00:00:00.000Z', to: '2026-03-03T23:59:59.999Z' });
      expect(dateFiltered.pagination.total).toBe(2);

      // Free text search query q
      expect(auditLog.query({ q: 'brute force' }).pagination.total).toBe(1);
      expect(auditLog.query({ q: 'alice' }).pagination.total).toBe(1);
    } finally {
      log.mockRestore();
    }
  });

  test('exportEntries returns filtered entries and formats valid CSV', async () => {
    const auditLog = createLogger();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'decision.add', ip: '192.168.1.1', type: 'ban', outcome: 'success', reason: 'port scan, web', time: '2026-05-01T12:00:00.000Z' });
      auditLog.record({}, { action: 'user.login', outcome: 'success', auth_method: 'password', time: '2026-05-01T13:00:00.000Z' });

      const exported = auditLog.exportEntries({ action: 'decision.add' });
      expect(exported).toHaveLength(1);
      expect(exported[0].ip).toBe('192.168.1.1');

      const { formatAuditLogsAsCsv } = await import('../../audit-log');
      const csv = formatAuditLogsAsCsv(exported);
      expect(csv).toContain('Time,User,Role,Action,Outcome,Target,Details');
      expect(csv).toContain('192.168.1.1');
      expect(csv).toContain('decision.add');
      expect(csv).toContain('success');
      // Commas inside reasons/details must be escaped in quotes
      expect(csv).toMatch(/"port scan, web"/);
    } finally {
      log.mockRestore();
    }
  });
});
