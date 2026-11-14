import type { Hono } from 'hono';
import { formatAuditLogsAsCsv, type AuditLogQueryFilters, type AuditLogger } from '../audit-log';

type HonoContext = any;
type HonoMiddleware = (context: HonoContext, next: () => Promise<void>) => Promise<Response | void>;

export interface RegisterAuditLogRoutesOptions {
  app: Hono;
  basePath: string;
  auditLog: AuditLogger;
  ensureAuth: HonoMiddleware;
}

export function registerAuditLogRoutes(options: RegisterAuditLogRoutesOptions): void {
  const { app, basePath, auditLog, ensureAuth } = options;

  function extractFilters(context: HonoContext): AuditLogQueryFilters {
    const action = context.req.query('action')?.trim() || undefined;
    const user = context.req.query('user')?.trim() || undefined;
    const ip = context.req.query('ip')?.trim() || undefined;
    const outcome = context.req.query('outcome')?.trim() || undefined;
    const from = context.req.query('from')?.trim() || context.req.query('start')?.trim() || undefined;
    const to = context.req.query('to')?.trim() || context.req.query('end')?.trim() || undefined;
    const q = context.req.query('q')?.trim() || undefined;

    return { action, user, ip, outcome, from, to, q };
  }

  function handleExport(filters: AuditLogQueryFilters, format: 'csv' | 'json') {
    const entries = auditLog.exportEntries(filters);
    const dateStr = new Date().toISOString().slice(0, 10);

    if (format === 'csv') {
      const csv = formatAuditLogsAsCsv(entries);
      return new Response(csv, {
        status: 200,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="audit-logs-${dateStr}.csv"`,
          'Cache-Control': 'no-store',
        },
      });
    }

    return new Response(JSON.stringify(entries, null, 2), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="audit-logs-${dateStr}.json"`,
        'Cache-Control': 'no-store',
      },
    });
  }

  app.get(`${basePath}/api/audit-logs`, ensureAuth, async (context) => {
    const filters = extractFilters(context);
    const format = context.req.query('format')?.toLowerCase();
    const exportParam = context.req.query('export')?.toLowerCase();
    const download = context.req.query('download')?.toLowerCase();

    if (format === 'csv' || exportParam === 'csv' || download === 'csv') {
      return handleExport(filters, 'csv');
    }

    if (exportParam === 'true' || exportParam === 'json' || download === 'json' || (format === 'json' && (exportParam || download))) {
      return handleExport(filters, 'json');
    }

    const page = Math.max(1, Number.parseInt(context.req.query('page') || '1', 10) || 1);
    const pageSize = Math.min(
      500,
      Math.max(1, Number.parseInt(context.req.query('page_size') || context.req.query('limit') || '50', 10) || 50),
    );

    const result = auditLog.query({ page, pageSize, ...filters });
    return context.json(result);
  });

  app.get(`${basePath}/api/audit-logs/export`, ensureAuth, async (context) => {
    const filters = extractFilters(context);
    const format =
      context.req.query('format')?.toLowerCase() === 'json' || context.req.query('type')?.toLowerCase() === 'json'
        ? 'json'
        : 'csv';
    return handleExport(filters, format);
  });
}
