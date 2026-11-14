import { useCallback, useEffect, useState, type FormEvent } from 'react';
import {
  AlertCircle,
  Check,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  Eye,
  Filter,
  RefreshCw,
  RotateCcw,
  ScrollText,
  Search,
  X,
} from 'lucide-react';

import { fetchAuditLogs, getAuditLogsExportUrl } from '../lib/api';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/Card';
import { Badge } from '../components/ui/Badge';
import { Modal } from '../components/ui/Modal';
import { useI18n } from '../lib/i18n';
import { useDateTime } from '../lib/dateTime';
import type { AuditLogItem, AuditLogQueryFilters, PaginationMeta } from '../types';

const OUTCOME_VARIANTS: Record<string, 'success' | 'warning' | 'danger' | 'info' | 'secondary'> = {
  success: 'success',
  partial: 'warning',
  failure: 'danger',
  queued: 'info',
};

const ACTION_VARIANTS: Record<string, 'success' | 'warning' | 'danger' | 'info' | 'secondary'> = {
  'decision.add': 'danger',
  'decision.delete': 'info',
  'alert.delete': 'secondary',
  'cleanup.by-ip': 'warning',
  'user.create': 'info',
  'user.update': 'secondary',
  'user.password-reset': 'warning',
  'user.mfa-reset': 'warning',
  'user.oidc-link': 'info',
  'user.oidc-unlink': 'warning',
  'user.delete': 'danger',
  'user.login': 'success',
  'user.logout': 'secondary',
};

const COMMON_ACTIONS = [
  'decision.add',
  'decision.delete',
  'alert.delete',
  'cleanup.by-ip',
  'user.login',
  'user.create',
  'user.update',
  'user.delete',
  'user.password-reset',
];

const COMMON_OUTCOMES = ['success', 'partial', 'failure', 'queued'];

function formatTarget(log: AuditLogItem): string {
  if (log.ip) return String(log.ip);
  if (Array.isArray(log.values) && log.values.length > 0) {
    if (log.values.length === 1) return String(log.values[0]);
    return `${log.values[0]} (+${log.values.length - 1} more)`;
  }
  if (log.target_username) return `@${log.target_username}`;
  if (Array.isArray(log.decision_ids) && log.decision_ids.length > 0) {
    return `${log.decision_ids.length} decision${log.decision_ids.length === 1 ? '' : 's'}`;
  }
  if (Array.isArray(log.alert_ids) && log.alert_ids.length > 0) {
    return `${log.alert_ids.length} alert${log.alert_ids.length === 1 ? '' : 's'}`;
  }
  return '-';
}

export function AuditLogs() {
  const { t } = useI18n();
  const { formatDateTime } = useDateTime();

  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters state
  const [q, setQ] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [ipFilter, setIpFilter] = useState('');
  const [fromFilter, setFromFilter] = useState('');
  const [toFilter, setToFilter] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  // Modal details
  const [selectedLog, setSelectedLog] = useState<AuditLogItem | null>(null);
  const [copied, setCopied] = useState(false);
  const [exportDropdownOpen, setExportDropdownOpen] = useState(false);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const activeFilters: AuditLogQueryFilters = {
    action: actionFilter || undefined,
    outcome: outcomeFilter || undefined,
    user: userFilter || undefined,
    ip: ipFilter || undefined,
    from: fromFilter ? new Date(fromFilter).toISOString() : undefined,
    to: toFilter ? new Date(toFilter).toISOString() : undefined,
    q: q.trim() || undefined,
  };

  const loadLogs = useCallback(() => {
    setRefreshTrigger((prev) => prev + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    const timeoutId = window.setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchAuditLogs({
          page,
          pageSize,
          action: actionFilter || undefined,
          outcome: outcomeFilter || undefined,
          user: userFilter || undefined,
          ip: ipFilter || undefined,
          from: fromFilter ? new Date(fromFilter).toISOString() : undefined,
          to: toFilter ? new Date(toFilter).toISOString() : undefined,
          q: q.trim() || undefined,
        });
        if (!cancelled) {
          setLogs(response.data);
          setPagination(response.pagination);
          setLoading(false);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : t('pages.auditLogs.loadFailed'));
          setLoading(false);
        }
      }
    }, 0);

    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
    };
  }, [page, pageSize, actionFilter, outcomeFilter, userFilter, ipFilter, fromFilter, toFilter, q, t, refreshTrigger]);

  const handleSearchSubmit = (e: FormEvent) => {
    e.preventDefault();
    setPage(1);
    void loadLogs();
  };

  const handleResetFilters = () => {
    setQ('');
    setActionFilter('');
    setOutcomeFilter('');
    setUserFilter('');
    setIpFilter('');
    setFromFilter('');
    setToFilter('');
    setPage(1);
  };

  const hasActiveFilters = Boolean(
    q || actionFilter || outcomeFilter || userFilter || ipFilter || fromFilter || toFilter,
  );

  const handleCopyJson = async () => {
    if (!selectedLog) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(selectedLog, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Ignore clipboard error
    }
  };

  const handleDownload = (format: 'csv' | 'json') => {
    const url = getAuditLogsExportUrl(activeFilters, format);
    window.location.assign(url);
    setExportDropdownOpen(false);
  };

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <ScrollText className="h-6 w-6 text-primary-600 dark:text-primary-400" aria-hidden="true" />
            <h2 className="text-xl font-bold tracking-tight text-gray-900 dark:text-white">
              {t('pages.auditLogs.title')}
            </h2>
          </div>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            {t('pages.auditLogs.subtitle')}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => void loadLogs()}
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
            aria-label={t('pages.auditLogs.refresh')}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span className="hidden sm:inline">{t('pages.auditLogs.refresh')}</span>
          </button>

          {/* Export Buttons */}
          <div className="relative inline-block text-left">
            <button
              type="button"
              onClick={() => setExportDropdownOpen((prev) => !prev)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 shadow-sm hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
              aria-expanded={exportDropdownOpen}
              aria-haspopup="true"
            >
              <Download className="h-4 w-4" aria-hidden="true" />
              <span>{t('pages.auditLogs.exportCsv')} / JSON</span>
            </button>

            {exportDropdownOpen && (
              <div
                className="absolute right-0 z-20 mt-2 w-44 origin-top-right rounded-md border border-gray-200 bg-white shadow-lg ring-1 ring-black/5 dark:border-gray-700 dark:bg-gray-800"
                role="menu"
              >
                <div className="py-1">
                  <button
                    type="button"
                    onClick={() => handleDownload('csv')}
                    className="flex w-full items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700"
                    role="menuitem"
                  >
                    <Download className="mr-2 h-4 w-4 text-gray-400" aria-hidden="true" />
                    {t('pages.auditLogs.exportCsv')}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDownload('json')}
                    className="flex w-full items-center px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-700"
                    role="menuitem"
                  >
                    <Download className="mr-2 h-4 w-4 text-gray-400" aria-hidden="true" />
                    {t('pages.auditLogs.exportJson')}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Filter and Search Bar Card */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base font-semibold flex items-center gap-2">
            <Filter className="h-4 w-4 text-gray-500" aria-hidden="true" />
            Filters & Search
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSearchSubmit} className="space-y-4">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {/* Free Text Search */}
              <div className="sm:col-span-2">
                <label htmlFor="audit-search-q" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  Search
                </label>
                <div className="relative mt-1">
                  <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" aria-hidden="true" />
                  <input
                    id="audit-search-q"
                    type="text"
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder={t('pages.auditLogs.searchPlaceholder')}
                    className="w-full rounded-md border border-gray-300 bg-white py-1.5 pl-9 pr-8 text-sm text-gray-900 placeholder:text-gray-400 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                  />
                  {q && (
                    <button
                      type="button"
                      onClick={() => setQ('')}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"
                    >
                      <X className="h-4 w-4" aria-hidden="true" />
                    </button>
                  )}
                </div>
              </div>

              {/* Action Filter */}
              <div>
                <label htmlFor="audit-filter-action" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  Action
                </label>
                <select
                  id="audit-filter-action"
                  value={actionFilter}
                  onChange={(e) => {
                    setActionFilter(e.target.value);
                    setPage(1);
                  }}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                >
                  <option value="">{t('pages.auditLogs.filterAction')}</option>
                  {COMMON_ACTIONS.map((action) => (
                    <option key={action} value={action}>
                      {action}
                    </option>
                  ))}
                </select>
              </div>

              {/* Outcome Filter */}
              <div>
                <label htmlFor="audit-filter-outcome" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  Outcome
                </label>
                <select
                  id="audit-filter-outcome"
                  value={outcomeFilter}
                  onChange={(e) => {
                    setOutcomeFilter(e.target.value);
                    setPage(1);
                  }}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                >
                  <option value="">{t('pages.auditLogs.filterOutcome')}</option>
                  {COMMON_OUTCOMES.map((outcome) => (
                    <option key={outcome} value={outcome}>
                      {outcome}
                    </option>
                  ))}
                </select>
              </div>

              {/* User Filter */}
              <div>
                <label htmlFor="audit-filter-user" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  User
                </label>
                <input
                  id="audit-filter-user"
                  type="text"
                  value={userFilter}
                  onChange={(e) => {
                    setUserFilter(e.target.value);
                    setPage(1);
                  }}
                  placeholder={t('pages.auditLogs.filterUser')}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 placeholder:text-gray-400 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                />
              </div>

              {/* IP Filter */}
              <div>
                <label htmlFor="audit-filter-ip" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  IP / Target
                </label>
                <input
                  id="audit-filter-ip"
                  type="text"
                  value={ipFilter}
                  onChange={(e) => {
                    setIpFilter(e.target.value);
                    setPage(1);
                  }}
                  placeholder={t('pages.auditLogs.filterIp')}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 placeholder:text-gray-400 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                />
              </div>

              {/* From Date */}
              <div>
                <label htmlFor="audit-filter-from" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  {t('pages.auditLogs.dateFrom')}
                </label>
                <input
                  id="audit-filter-from"
                  type="datetime-local"
                  value={fromFilter}
                  onChange={(e) => {
                    setFromFilter(e.target.value);
                    setPage(1);
                  }}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                />
              </div>

              {/* To Date */}
              <div>
                <label htmlFor="audit-filter-to" className="block text-xs font-medium text-gray-700 dark:text-gray-300">
                  {t('pages.auditLogs.dateTo')}
                </label>
                <input
                  id="audit-filter-to"
                  type="datetime-local"
                  value={toFilter}
                  onChange={(e) => {
                    setToFilter(e.target.value);
                    setPage(1);
                  }}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-1.5 text-sm text-gray-900 focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500 dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                />
              </div>
            </div>

            {hasActiveFilters && (
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={handleResetFilters}
                  className="inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" />
                  {t('pages.auditLogs.resetFilters')}
                </button>
              </div>
            )}
          </form>
        </CardContent>
      </Card>

      {/* Error Notice */}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-900 dark:border-red-900/50 dark:bg-red-950/30 dark:text-red-100">
          <AlertCircle className="h-5 w-5 shrink-0" aria-hidden="true" />
          <div className="flex-1">{error}</div>
          <button
            type="button"
            onClick={() => void loadLogs()}
            className="rounded bg-red-100 px-2 py-1 text-xs font-medium text-red-800 hover:bg-red-200 dark:bg-red-900/50 dark:text-red-200 dark:hover:bg-red-800"
          >
            {t('pages.auditLogs.retry')}
          </button>
        </div>
      )}

      {/* Main Table Card */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-gray-200 bg-gray-50 text-xs uppercase text-gray-600 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-400">
                <tr>
                  <th scope="col" className="px-4 py-3 sm:px-6">{t('pages.auditLogs.table.time')}</th>
                  <th scope="col" className="px-4 py-3 sm:px-6">{t('pages.auditLogs.table.user')}</th>
                  <th scope="col" className="px-4 py-3 sm:px-6">{t('pages.auditLogs.table.action')}</th>
                  <th scope="col" className="px-4 py-3 sm:px-6">{t('pages.auditLogs.table.target')}</th>
                  <th scope="col" className="px-4 py-3 sm:px-6">{t('pages.auditLogs.table.outcome')}</th>
                  <th scope="col" className="px-4 py-3 sm:px-6 text-right">{t('pages.auditLogs.table.details')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
                {loading && logs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-gray-500 dark:text-gray-400">
                      <RefreshCw className="mx-auto mb-2 h-6 w-6 animate-spin text-gray-400" aria-hidden="true" />
                      Loading audit logs...
                    </td>
                  </tr>
                ) : logs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-gray-500 dark:text-gray-400">
                      {hasActiveFilters ? t('pages.auditLogs.empty') : t('pages.auditLogs.noLogsYet')}
                    </td>
                  </tr>
                ) : (
                  logs.map((log, index) => {
                    const outcomeVariant = OUTCOME_VARIANTS[log.outcome] || 'secondary';
                    const actionVariant = ACTION_VARIANTS[log.action] || 'secondary';

                    return (
                      <tr
                        key={`${log.time}-${index}`}
                        onClick={() => setSelectedLog(log)}
                        className="cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-900/50 transition-colors"
                      >
                        <td className="whitespace-nowrap px-4 py-3 sm:px-6 text-xs text-gray-500 dark:text-gray-400">
                          {formatDateTime(log.time)}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 sm:px-6">
                          <div className="flex items-center gap-1.5">
                            <span className="font-medium text-gray-900 dark:text-white">{log.user}</span>
                            {log.role && (
                              <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                                {log.role}
                              </Badge>
                            )}
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 sm:px-6">
                          <Badge variant={actionVariant}>
                            {log.action}
                          </Badge>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 sm:px-6 font-mono text-xs text-gray-700 dark:text-gray-300">
                          {formatTarget(log)}
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 sm:px-6">
                          <Badge variant={outcomeVariant}>
                            {log.outcome}
                          </Badge>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 sm:px-6 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedLog(log);
                            }}
                            className="inline-flex items-center gap-1 rounded p-1 text-gray-500 hover:bg-gray-100 hover:text-gray-700 dark:text-gray-400 dark:hover:bg-gray-800 dark:hover:text-gray-200"
                            aria-label={t('pages.auditLogs.viewDetails')}
                          >
                            <Eye className="h-4 w-4" aria-hidden="true" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls Footer */}
          {pagination && pagination.total > 0 && (
            <div className="flex flex-col gap-3 border-t border-gray-200 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6 dark:border-gray-800">
              <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400">
                <span>{t('pages.auditLogs.pageSize')}</span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setPage(1);
                  }}
                  className="rounded border border-gray-300 bg-white px-2 py-1 text-xs text-gray-900 focus:border-primary-500 focus:outline-none dark:border-gray-700 dark:bg-gray-900 dark:text-white"
                >
                  <option value={25}>25</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
                <span>
                  {t('pages.auditLogs.showing', {
                    start: (pagination.page - 1) * pagination.page_size + 1,
                    end: Math.min(pagination.page * pagination.page_size, pagination.total),
                    total: pagination.total,
                  })}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={pagination.page <= 1 || loading}
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  className="inline-flex items-center gap-1 rounded-md border border-gray-300 bg-white px-2.5 py-1.5 text-xs font-medium text-gray-700 shadow-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden="true" />
                  {t('pages.auditLogs.prev')}
                </button>
                <span className="text-xs text-gray-600 dark:text-gray-400">
                  {t('pages.auditLogs.page', { current: pagination.page, total: pagination.total_pages || 1 })}
                </span>
                <button
                  type="button"
                  disabled={pagination.page >= pagination.total_pages || loading}
                  onClick={() => setPage((p) => p + 1)}
                  className="inline-flex items-center gap-1 rounded-md border border-gray-300 bg-white px-2.5 py-1.5 text-xs font-medium text-gray-700 shadow-sm hover:bg-gray-50 disabled:opacity-50 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
                >
                  {t('pages.auditLogs.next')}
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                </button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Details View Modal */}
      {selectedLog && (
        <Modal
          isOpen={Boolean(selectedLog)}
          onClose={() => setSelectedLog(null)}
          title={t('pages.auditLogs.modal.title')}
          maxWidth="max-w-2xl"
        >
          <div className="space-y-4">
            {/* Summary Grid */}
            <div className="grid grid-cols-2 gap-3 rounded-lg border border-gray-200 bg-gray-50 p-4 text-xs dark:border-gray-800 dark:bg-gray-900/50">
              <div>
                <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.table.time')}:</span>{' '}
                <span className="text-gray-900 dark:text-white">{formatDateTime(selectedLog.time)}</span>
              </div>
              <div>
                <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.table.user')}:</span>{' '}
                <span className="text-gray-900 dark:text-white">
                  {selectedLog.user} {selectedLog.role ? `(${selectedLog.role})` : ''}
                </span>
              </div>
              <div>
                <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.table.action')}:</span>{' '}
                <Badge variant={ACTION_VARIANTS[selectedLog.action] || 'secondary'}>
                  {selectedLog.action}
                </Badge>
              </div>
              <div>
                <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.table.outcome')}:</span>{' '}
                <Badge variant={OUTCOME_VARIANTS[selectedLog.outcome] || 'secondary'}>
                  {selectedLog.outcome}
                </Badge>
              </div>

              {selectedLog.ip && (
                <div>
                  <span className="font-semibold text-gray-500 dark:text-gray-400">IP:</span>{' '}
                  <span className="font-mono text-gray-900 dark:text-white">{String(selectedLog.ip)}</span>
                </div>
              )}

              {selectedLog.type && (
                <div>
                  <span className="font-semibold text-gray-500 dark:text-gray-400">Type:</span>{' '}
                  <span className="text-gray-900 dark:text-white">{String(selectedLog.type)}</span>
                </div>
              )}

              {selectedLog.duration && (
                <div>
                  <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.modal.duration')}:</span>{' '}
                  <span className="text-gray-900 dark:text-white">{String(selectedLog.duration)}</span>
                </div>
              )}

              {selectedLog.scenario && (
                <div>
                  <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.modal.scenario')}:</span>{' '}
                  <span className="text-gray-900 dark:text-white">{String(selectedLog.scenario)}</span>
                </div>
              )}

              {selectedLog.reason && (
                <div className="col-span-2">
                  <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.modal.reason')}:</span>{' '}
                  <span className="text-gray-900 dark:text-white">{String(selectedLog.reason)}</span>
                </div>
              )}

              {Array.isArray(selectedLog.instances) && selectedLog.instances.length > 0 && (
                <div className="col-span-2">
                  <span className="font-semibold text-gray-500 dark:text-gray-400">{t('pages.auditLogs.modal.instances')}:</span>{' '}
                  <span className="text-gray-900 dark:text-white">{selectedLog.instances.join(', ')}</span>
                </div>
              )}

              {selectedLog.bypass_allowlist !== undefined && (
                <div className="col-span-2">
                  <span className="font-semibold text-gray-500 dark:text-gray-400">Bypass Allowlist:</span>{' '}
                  <Badge variant={selectedLog.bypass_allowlist ? 'warning' : 'secondary'}>
                    {String(selectedLog.bypass_allowlist)}
                  </Badge>
                </div>
              )}
            </div>

            {/* Raw JSON viewer */}
            <div>
              <div className="mb-1 flex items-center justify-between">
                <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                  {t('pages.auditLogs.modal.rawJson')}
                </span>
                <button
                  type="button"
                  onClick={handleCopyJson}
                  className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs text-gray-600 hover:bg-gray-100 dark:text-gray-400 dark:hover:bg-gray-800"
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-green-500" aria-hidden="true" />
                      <span className="text-green-500">{t('pages.auditLogs.modal.copied')}</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" aria-hidden="true" />
                      <span>{t('pages.auditLogs.modal.copyJson')}</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="max-h-64 overflow-auto rounded-lg border border-gray-200 bg-gray-900 p-3 font-mono text-xs text-green-400 dark:border-gray-800">
                {JSON.stringify(selectedLog, null, 2)}
              </pre>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="button"
                onClick={() => setSelectedLog(null)}
                className="rounded-lg bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-200 dark:hover:bg-gray-700"
              >
                {t('pages.auditLogs.modal.close')}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
