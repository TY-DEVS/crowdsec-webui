import type {
  CrowdsecMetricsResponse,
  CrowdsecMetricsSource,
  StatsAlert,
  StatsDecision,
} from '../../../shared/contracts';
import type { PrometheusSample } from '../../metrics';
import type { ApiRouteDependencies } from '../api-routes';

export function registerMetricsRoutes(dependencies: ApiRouteDependencies): void {
  const {
    app,
    config,
    options,
    state,
    analyticsQueryWorker,
    createSqlWhere,
    ensureAuth,
    ensurePublishedRevisionRead,
    prepareOnDemandRefresh,
    prepareReadCache,
    fetchCrowdsecMetrics,
    fetchCrowdsecMetricsSamples,
    summarizeCrowdsecMetrics,
    primaryInstance,
    QueryWorkerTimeoutError,
    getDashboardStatsFilters,
    noteDashboardStatsRequest,
    createEmptyDashboardStatsResponse,
    isDashboardStatsBuildInProgress,
    warmDashboardStatsCache,
    getStaleDashboardStatsResponseCacheKey,
    buildDashboardStats,
  } = dependencies;

  app.get(`${config.basePath}/api/metrics/crowdsec`, ensureAuth, async (context) => {
    const endpoint = primaryInstance.prometheus[0];
    if (!endpoint) {
      return context.json({ error: 'CrowdSec Prometheus metrics are not enabled' }, 404);
    }

    try {
      const payload: CrowdsecMetricsResponse = await fetchCrowdsecMetrics({
        url: endpoint.url,
        timeoutMs: endpoint.requestTimeoutMs || config.prometheusRequestTimeoutMs,
        auth: endpoint.auth,
        tls: endpoint.tls,
        fetchImpl: options.metricsFetchImpl,
      });

      return context.json(payload);
    } catch (error: any) {
      const message = error?.message || 'Failed to read CrowdSec Prometheus metrics';
      console.error('Error fetching CrowdSec Prometheus metrics:', message);
      return context.json({ error: message }, 502);
    }
  });

  app.get(`${config.basePath}/api/metrics/crowdsec/combined`, ensureAuth, async (context) => {
    const requestedScope = context.req.query('instance') || primaryInstance.id;
    const selectedInstances = requestedScope === 'all'
      ? config.instances
      : config.instances.filter((instance) => instance.id === requestedScope);
    if (selectedInstances.length === 0) {
      return context.json({ error: `Unknown CrowdSec instance scope "${requestedScope}"` }, 404);
    }

    const configuredSources = selectedInstances.flatMap((instance) => instance.prometheus.map((endpoint) => ({
      instance,
      endpoint,
      id: `${instance.id}:${endpoint.id}`,
    })));
    if (configuredSources.length === 0) {
      return context.json({ error: 'No CrowdSec Prometheus metrics endpoints are configured for this scope' }, 404);
    }

    const results = await Promise.allSettled(configuredSources.map(async ({ instance, endpoint, id }) => {
      const samples = await fetchCrowdsecMetricsSamples({
        url: endpoint.url,
        timeoutMs: endpoint.requestTimeoutMs || config.prometheusRequestTimeoutMs,
        auth: endpoint.auth,
        tls: endpoint.tls,
        fetchImpl: options.metricsFetchImpl,
      });
      const sourceSummary = summarizeCrowdsecMetrics(samples);
      return {
        samples: samples.map((sample: PrometheusSample) => ({ ...sample, source_id: id })),
        source: {
          id,
          instance_id: instance.id,
          instance_name: instance.name,
          ...(instance.icon ? { instance_icon: instance.icon } : {}),
          endpoint_id: endpoint.id,
          endpoint_name: endpoint.name,
          ...(endpoint.icon ? { endpoint_icon: endpoint.icon } : {}),
          status: 'available' as const,
          fetched_at: sourceSummary.fetched_at,
          crowdsecVersion: sourceSummary.crowdsecVersion,
          crowdsecStartedAt: sourceSummary.crowdsecStartedAt,
        },
      };
    }));

    const sources: CrowdsecMetricsSource[] = results.map((result, index) => {
      if (result.status === 'fulfilled') return result.value.source;
      const { instance, endpoint, id } = configuredSources[index];
      return {
        id,
        instance_id: instance.id,
        instance_name: instance.name,
        ...(instance.icon ? { instance_icon: instance.icon } : {}),
        endpoint_id: endpoint.id,
        endpoint_name: endpoint.name,
        ...(endpoint.icon ? { endpoint_icon: endpoint.icon } : {}),
        status: 'unavailable',
        error: result.reason instanceof Error ? result.reason.message : String(result.reason),
      };
    });
    const successfulResults = results.flatMap((result) => (result.status === 'fulfilled' ? [result.value] : []));

    if (successfulResults.length === 0) {
      return context.json({
        error: 'Failed to read every CrowdSec Prometheus metrics endpoint in this scope',
        sources,
      }, 502);
    }

    const summary = summarizeCrowdsecMetrics(successfulResults.flatMap((result) => result.samples));
    const { crowdsecVersion: _combinedVersion, crowdsecStartedAt: _combinedStartedAt, ...combinedSummary } = summary;
    return context.json({
      ...combinedSummary,
      aggregation: {
        partial: successfulResults.length !== configuredSources.length,
        sources,
      },
    });
  });

  app.get(`${config.basePath}/api/instances/:instanceId/metrics/:endpointId`, ensureAuth, async (context) => {
    const instance = config.instances.find((candidate) => candidate.id === context.req.param('instanceId'));
    const endpoint = instance?.prometheus.find((candidate) => candidate.id === context.req.param('endpointId'));
    if (!instance || !endpoint) return context.json({ error: 'Unknown CrowdSec instance or Prometheus endpoint' }, 404);
    try {
      return context.json(await fetchCrowdsecMetrics({
        url: endpoint.url,
        timeoutMs: endpoint.requestTimeoutMs || config.prometheusRequestTimeoutMs,
        auth: endpoint.auth,
        tls: endpoint.tls,
        fetchImpl: options.metricsFetchImpl,
      }));
    } catch (error: any) {
      return context.json({ error: error?.message || 'Failed to read CrowdSec Prometheus metrics' }, 502);
    }
  });

  app.get(`${config.basePath}/api/stats/alerts`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    try {
      await prepareOnDemandRefresh(context);

      await prepareReadCache('stats alerts request');

      const where = createSqlWhere();
      where.add('created_at >= ?', new Date(Date.now() - config.lookbackMs).toISOString());
      if (!config.simulationsEnabled) {
        where.add('simulated = 0');
      }
      const alerts = (await analyticsQueryWorker.all<{
        created_at: string;
        scenario?: string | null;
        kind?: string | null;
        source_ip?: string | null;
        country?: string | null;
        as_name?: string | null;
        target?: string | null;
        simulated?: number | null;
      }>(`
        SELECT created_at, scenario, kind, source_ip, country, as_name, target, simulated
        FROM alerts
        ${where.toSql()}
        ORDER BY created_at DESC, id DESC
      `, where.params, { label: 'alert statistics' })).map((row): StatsAlert => ({
        created_at: row.created_at,
        scenario: row.scenario || undefined,
        kind: row.kind || undefined,
        source: row.source_ip || row.country || row.as_name
          ? {
              ip: row.source_ip && !row.source_ip.includes('/') ? row.source_ip : undefined,
              value: row.source_ip || undefined,
              range: row.source_ip && row.source_ip.includes('/') ? row.source_ip : undefined,
              cn: row.country || undefined,
              as_name: row.as_name || undefined,
            }
          : null,
        target: row.target || undefined,
        simulated: row.simulated === 1,
      }));

      return context.json(alerts);
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out serving stats alerts from database:', error.message);
        return context.json({ error: 'Alert statistics query timed out' }, 504);
      }
      console.error('Error serving stats alerts from database:', error.message);
      return context.json({ error: 'Failed to retrieve alert statistics' }, 500);
    }
  });

  app.get(`${config.basePath}/api/stats/decisions`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    try {
      await prepareOnDemandRefresh(context);

      await prepareReadCache('stats decisions request');

      const now = new Date().toISOString();
      const where = createSqlWhere();
      where.add('(created_at >= ? OR stop_at > ?)', new Date(Date.now() - config.lookbackMs).toISOString(), now);
      if (!config.simulationsEnabled) {
        where.add('simulated = 0');
      }
      const decisions = (await analyticsQueryWorker.all<{
        id: string | number;
        created_at: string;
        scenario?: string | null;
        value?: string | null;
        stop_at?: string | null;
        target?: string | null;
        simulated?: number | null;
      }>(`
        SELECT id, created_at, scenario, value, stop_at, target, simulated
        FROM decisions
        ${where.toSql()}
        ORDER BY created_at DESC, id DESC
      `, where.params, { label: 'decision statistics' })).map((row): StatsDecision => ({
        id: row.id,
        created_at: row.created_at,
        scenario: row.scenario || undefined,
        value: row.value || undefined,
        stop_at: row.stop_at || undefined,
        target: row.target || undefined,
        simulated: row.simulated === 1,
      }));

      return context.json(decisions);
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out serving stats decisions from database:', error.message);
        return context.json({ error: 'Decision statistics query timed out' }, 504);
      }
      console.error('Error serving stats decisions from database:', error.message);
      return context.json({ error: 'Failed to retrieve decision statistics' }, 500);
    }
  });

  app.get(`${config.basePath}/api/dashboard/stats`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    try {
      await prepareOnDemandRefresh(context);

      await prepareReadCache('dashboard stats request');
      const filters = getDashboardStatsFilters(context, config.timeZone);
      noteDashboardStatsRequest(filters);
      state.lastDashboardStatsFilters = { ...filters };
      state.lastDashboardStatsRequestedAt = Date.now();
      const initialScopePending = filters.instanceId === 'all'
        ? state.historicalInstanceSyncPending.size > 0
        : state.historicalInstanceSyncPending.has(filters.instanceId);
      if (initialScopePending) {
        return context.json(createEmptyDashboardStatsResponse({ pending: true }));
      }
      if (isDashboardStatsBuildInProgress(filters)) {
        warmDashboardStatsCache(filters);
        const staleResponse = state.staleDashboardStatsResponseCache.get(getStaleDashboardStatsResponseCacheKey(filters));
        if (staleResponse) {
          return context.json({
            ...staleResponse,
            pending: true,
            stale: true,
            retryAfterMs: 1_500,
          });
        }
        return context.json(createEmptyDashboardStatsResponse({ pending: true }));
      }

      return context.json(await buildDashboardStats(filters, context.req.raw.signal));
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out serving dashboard statistics from database:', error.message);
        return context.json({ error: 'Dashboard statistics query timed out' }, 504);
      }
      console.error('Error serving dashboard statistics from database:', error.message);
      return context.json({ error: 'Failed to retrieve dashboard statistics' }, 500);
    }
  });
}
