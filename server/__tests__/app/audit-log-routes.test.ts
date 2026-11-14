import { describe, expect, test, vi } from 'vitest';
import { Hono } from 'hono';
import { createAuditLogger } from '../../audit-log';
import { registerAuditLogRoutes } from '../../app/audit-log-routes';

describe('registerAuditLogRoutes', () => {
  function setupTestApp() {
    const app = new Hono();
    const auditLog = createAuditLogger({
      enabled: true,
      getActor: () => ({ username: 'admin-user', role: 'admin' }),
    });

    const ensureAuth = async (context: any, next: any) => {
      const authHeader = context.req.header('Authorization');
      if (authHeader === 'Bearer denied') {
        return context.json({ error: 'Unauthorized' }, 401);
      }
      await next();
    };

    registerAuditLogRoutes({
      app,
      basePath: '',
      auditLog,
      ensureAuth,
    });

    return { app, auditLog };
  }

  test('blocks unauthenticated requests when ensureAuth fails', async () => {
    const { app } = setupTestApp();
    const response = await app.request('/api/audit-logs', {
      headers: { Authorization: 'Bearer denied' },
    });
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error).toBe('Unauthorized');
  });

  test('returns paginated audit logs', async () => {
    const { app, auditLog } = setupTestApp();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', type: 'ban', outcome: 'success', time: '2026-06-01T10:00:00.000Z' });
      auditLog.record({}, { action: 'user.login', outcome: 'success', time: '2026-06-01T11:00:00.000Z' });
      auditLog.record({}, { action: 'alert.delete', outcome: 'queued', alert_ids: ['1'], time: '2026-06-01T12:00:00.000Z' });

      const response = await app.request('/api/audit-logs?page=1&page_size=2');
      expect(response.status).toBe(200);
      const json = await response.json();

      expect(json.pagination).toMatchObject({
        page: 1,
        page_size: 2,
        total: 3,
        total_pages: 2,
        unfiltered_total: 3,
      });
      expect(json.data).toHaveLength(2);
      expect(json.data[0].action).toBe('alert.delete');
      expect(json.data[1].action).toBe('user.login');
    } finally {
      log.mockRestore();
    }
  });

  test('applies filters for action, user, ip, outcome, and q', async () => {
    const { app, auditLog } = setupTestApp();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'decision.add', ip: '192.168.1.50', type: 'ban', reason: 'bad bot', outcome: 'success', time: '2026-06-01T10:00:00.000Z' });
      auditLog.record({}, { action: 'decision.add', ip: '10.0.0.5', type: 'ban', outcome: 'failure', time: '2026-06-01T11:00:00.000Z' });
      auditLog.record({}, { action: 'user.login', outcome: 'success', target_username: 'bob', time: '2026-06-01T12:00:00.000Z' });

      // Action filter
      const actionRes = await app.request('/api/audit-logs?action=decision.add');
      const actionData = await actionRes.json();
      expect(actionData.pagination.total).toBe(2);

      // Outcome filter
      const outcomeRes = await app.request('/api/audit-logs?outcome=failure');
      const outcomeData = await outcomeRes.json();
      expect(outcomeData.pagination.total).toBe(1);
      expect(outcomeData.data[0].ip).toBe('10.0.0.5');

      // IP filter
      const ipRes = await app.request('/api/audit-logs?ip=192.168.1.50');
      const ipData = await ipRes.json();
      expect(ipData.pagination.total).toBe(1);

      // Search query q
      const qRes = await app.request('/api/audit-logs?q=bad+bot');
      const qData = await qRes.json();
      expect(qData.pagination.total).toBe(1);
    } finally {
      log.mockRestore();
    }
  });

  test('exports filtered logs as CSV via format=csv or /export', async () => {
    const { app, auditLog } = setupTestApp();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'decision.add', ip: '1.2.3.4', type: 'ban', reason: 'test, with comma', outcome: 'success', time: '2026-06-01T10:00:00.000Z' });

      // Via query param format=csv
      const response = await app.request('/api/audit-logs?format=csv');
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('text/csv');
      expect(response.headers.get('Content-Disposition')).toContain('attachment; filename="audit-logs-');
      const text = await response.text();
      expect(text).toContain('Time,User,Role,Action,Outcome,Target,Details');
      expect(text).toContain('decision.add');
      expect(text).toContain('1.2.3.4');
      expect(text).toMatch(/"test, with comma"/);

      // Via /export route
      const exportRes = await app.request('/api/audit-logs/export');
      expect(exportRes.status).toBe(200);
      expect(exportRes.headers.get('Content-Type')).toContain('text/csv');
    } finally {
      log.mockRestore();
    }
  });

  test('exports filtered logs as JSON via export=true or /export?format=json', async () => {
    const { app, auditLog } = setupTestApp();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      auditLog.record({}, { action: 'user.login', outcome: 'success', time: '2026-06-01T10:00:00.000Z' });

      const response = await app.request('/api/audit-logs?export=true');
      expect(response.status).toBe(200);
      expect(response.headers.get('Content-Type')).toContain('application/json');
      expect(response.headers.get('Content-Disposition')).toContain('attachment; filename="audit-logs-');
      const data = await response.json();
      expect(Array.isArray(data)).toBe(true);
      expect(data).toHaveLength(1);
      expect(data[0].action).toBe('user.login');

      const exportRouteRes = await app.request('/api/audit-logs/export?format=json');
      expect(exportRouteRes.status).toBe(200);
      expect(exportRouteRes.headers.get('Content-Type')).toContain('application/json');
    } finally {
      log.mockRestore();
    }
  });
});
