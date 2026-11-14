import type { AlertRecord, BulkDeleteRequest, InstanceEntityRef } from '../../../shared/contracts';
import type { ApiRouteDependencies } from '../api-routes';
import { capAuditEntries, type AnyError } from './common';

export function registerAlertRoutes(dependencies: ApiRouteDependencies): void {
  const {
    app,
    config,
    database,
    lapiClient,
    lapiClients,
    auditLog,
    ensureAuth,
    ensurePublishedRevisionRead,
    ensureCanManageEnforcement,
    handleApiError,
    prepareOnDemandRefresh,
    prepareReadCache,
    getPageRequest,
    getAlertListFilters,
    getFacetRequest,
    ALERT_FACET_FIELDS,
    compileAlertSearch,
    toSearchErrorResponse,
    queryPaginatedAlerts,
    queryAlertFacet,
    queryAlertSessions,
    QueryWorkerTimeoutError,
    hydrateAlertsBatch,
    hydrateAlertWithDecisions,
    applySimulationModeToAlert,
    toSlimAlert,
    enrichAlertLocations,
    validateInstanceEntityRefs,
    deleteAlertsByRefs,
    deleteAlertsByIds,
    normalizeDeleteIds,
    normalizeAlertDetail,
    withAlertTargetSummary,
    withInstanceName,
    runNotificationEvaluation,
  } = dependencies;

  app.get(`${config.basePath}/api/alerts`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    try {
      await prepareOnDemandRefresh(context);

      await prepareReadCache('alerts request');

      const pageRequest = getPageRequest(context);
      if (pageRequest) {
        const filters = getAlertListFilters(context, config.timeZone);
        const compiledSearch = compileAlertSearch(filters.q, {
          machineEnabled: true,
          originEnabled: true,
        }, {
          timezoneOffsetMinutes: filters.timezoneOffsetMinutes,
          timeZone: filters.timeZone,
        });
        if (!compiledSearch.ok) {
          return context.json(toSearchErrorResponse(compiledSearch.error), 400);
        }
        return context.json(await queryPaginatedAlerts(
          pageRequest,
          filters,
          compiledSearch.ast,
          context.req.query('include_decisions') !== 'false',
        ));
      }

      const since = new Date(Date.now() - config.lookbackMs).toISOString();
      const alerts = hydrateAlertsBatch(database.getAlertsSince(since))
        .map((alert: AlertRecord) => applySimulationModeToAlert(alert, config.simulationsEnabled))
        .filter((alert: AlertRecord | null): alert is AlertRecord => alert !== null)
        .map((alert: AlertRecord) => toSlimAlert(alert))
        .sort((left: { created_at: string }, right: { created_at: string }) =>
          new Date(right.created_at).getTime() - new Date(left.created_at).getTime());

      return context.json(await enrichAlertLocations(alerts));
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out serving alerts from database:', error.message);
        return context.json({ error: 'Alert query timed out' }, 504);
      }
      console.error('Error serving alerts from database:', error.message);
      return context.json({ error: 'Failed to retrieve alerts' }, 500);
    }
  });

  app.get(`${config.basePath}/api/alerts/facets`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    const request = getFacetRequest(context, ALERT_FACET_FIELDS);
    if ('error' in request) {
      return context.json({ error: request.error }, 400);
    }

    try {
      await prepareOnDemandRefresh(context);
      await prepareReadCache('alert facets request');

      const filters = getAlertListFilters(context, config.timeZone);
      const compiledSearch = compileAlertSearch(filters.q, {
        machineEnabled: true,
        originEnabled: true,
      }, {
        timezoneOffsetMinutes: filters.timezoneOffsetMinutes,
        timeZone: filters.timeZone,
      });
      if (!compiledSearch.ok) {
        return context.json(toSearchErrorResponse(compiledSearch.error), 400);
      }

      return context.json(await queryAlertFacet(request, filters, compiledSearch.ast));
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        return context.json({ error: 'Facet query timed out' }, 504);
      }
      console.error('Error serving alert facets from database:', error.message);
      return context.json({ error: 'Failed to retrieve alert facets' }, 500);
    }
  });

  app.get(`${config.basePath}/api/alerts/sessions`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    try {
      await prepareOnDemandRefresh(context);
      await prepareReadCache('alert sessions request');

      const filters = getAlertListFilters(context, config.timeZone);
      const compiledSearch = compileAlertSearch(filters.q, {
        machineEnabled: true,
        originEnabled: true,
      }, {
        timezoneOffsetMinutes: filters.timezoneOffsetMinutes,
        timeZone: filters.timeZone,
      });
      if (!compiledSearch.ok) {
        return context.json(toSearchErrorResponse(compiledSearch.error), 400);
      }

      return context.json(await queryAlertSessions(
        getPageRequest(context) ?? { page: 1, pageSize: 50 },
        filters,
        compiledSearch.ast,
      ));
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out serving alert sessions from database:', error.message);
        return context.json({ error: 'Alert session query timed out' }, 504);
      }
      console.error('Error serving alert sessions from database:', error.message);
      return context.json({ error: 'Failed to retrieve alert sessions' }, 500);
    }
  });

  app.post(`${config.basePath}/api/alerts/bulk-delete`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const doRequest = async () => {
      const body = await context.req.json<BulkDeleteRequest>();
      if (Array.isArray(body.refs) && body.refs.length > 0) {
        const validated = validateInstanceEntityRefs(body.refs);
        if ('error' in validated) return context.json({ error: validated.error }, 400);
        const result = await deleteAlertsByRefs(validated);
        const failedIds = new Set(result.failed.map((failure: { id: string }) => failure.id));
        const alertIds = capAuditEntries(validated.map((ref: InstanceEntityRef) => `${ref.instance_id}:${ref.id}`));
        const targetResults = capAuditEntries(validated.map((ref: InstanceEntityRef) => {
          const id = `${ref.instance_id}:${ref.id}`;
          return { id, outcome: failedIds.has(id) ? 'failure' as const : 'queued' as const };
        }));
        auditLog.record(context, {
          action: 'alert.delete',
          alert_ids: alertIds.entries,
          target_results: targetResults.entries,
          ...(alertIds.truncated || targetResults.truncated ? { truncated: true } : {}),
          requested_alerts: result.requested_alerts,
          deleted_alerts: result.deleted_alerts,
          requested_decisions: result.requested_decisions,
          deleted_decisions: result.deleted_decisions,
          outcome: result.failed.length === 0 ? 'queued' : result.deleted_alerts > 0 ? 'partial' : 'failure',
        });
        if (result.deleted_decisions > 0) {
          void runNotificationEvaluation('bulk alert delete');
        }
        return context.json(result);
      }
      if (!Array.isArray(body.ids) || body.ids.length === 0) {
        return context.json({ error: 'At least one alert ID is required' }, 400);
      }
      if (config.instances.length > 1) {
        return context.json({ error: 'Structured instance refs are required when multiple CrowdSec instances are configured' }, 400);
      }
      const ids = normalizeDeleteIds(body.ids);
      if (ids.length !== body.ids.length) {
        return context.json({ error: 'Alert IDs must be numeric' }, 400);
      }

      const result = await deleteAlertsByIds(ids);
      const alertIds = capAuditEntries(ids);
      const targetResults = capAuditEntries(ids.map((id: string) => ({ id, outcome: 'queued' as const })));
      auditLog.record(context, {
        action: 'alert.delete',
        alert_ids: alertIds.entries,
        target_results: targetResults.entries,
        ...(alertIds.truncated || targetResults.truncated ? { truncated: true } : {}),
        requested_alerts: result.requested_alerts,
        requested_decisions: result.requested_decisions,
        deleted_alerts: result.deleted_alerts,
        deleted_decisions: result.deleted_decisions,
        outcome: 'queued',
      });
      if (result.deleted_decisions > 0) {
        void runNotificationEvaluation('bulk alert delete');
      }
      return context.json(result);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'bulk deleting alerts', doRequest);
    }
  });

  app.get(`${config.basePath}/api/alerts/:id`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    if (config.instances.length > 1) return context.json({ error: 'instance_id is required when multiple CrowdSec instances are configured' }, 400);
    const alertId = String(context.req.param('id'));
    if (!/^\d+$/.test(alertId)) {
      return context.json({ error: 'Invalid alert ID' }, 400);
    }

    const doRequest = async () => {
      if (context.req.query('include_decisions') === 'false') {
        const snapshot = database.getAlertDecisionSnapshot(alertId);
        let alert = snapshot ? normalizeAlertDetail(JSON.parse(snapshot.raw_data), alertId) : null;
        if (!alert) {
          alert = normalizeAlertDetail(await lapiClient.getAlertById(alertId), alertId);
        }
        if (!alert) {
          return context.json({ error: 'Alert not found' }, 404);
        }
        const payload = applySimulationModeToAlert({ ...withAlertTargetSummary(alert), decisions: [] }, config.simulationsEnabled);
        return payload ? context.json(payload) : context.json({ error: 'Alert not found' }, 404);
      }

      const alertData = await lapiClient.getAlertById(alertId);
      const normalizedAlert = normalizeAlertDetail(alertData, alertId);
      if (!normalizedAlert) {
        return context.json({ error: 'Alert not found' }, 404);
      }

      const payload = applySimulationModeToAlert(hydrateAlertWithDecisions(withAlertTargetSummary(normalizedAlert)), config.simulationsEnabled);
      if (!payload) {
        return context.json({ error: 'Alert not found' }, 404);
      }
      return context.json(payload);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'fetching alert details', doRequest);
    }
  });

  app.delete(`${config.basePath}/api/alerts/:id`, ensureAuth, async (context) => {
    if (config.instances.length > 1) return context.json({ error: 'instance_id is required when multiple CrowdSec instances are configured' }, 400);
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const alertId = String(context.req.param('id'));
    if (!/^\d+$/.test(alertId)) {
      return context.json({ error: 'Invalid alert ID' }, 400);
    }

    const doRequest = async () => {
      const result = await deleteAlertsByIds([alertId]);
      auditLog.record(context, {
        action: 'alert.delete',
        alert_ids: [alertId],
        target_results: [{ id: alertId, outcome: 'queued' }],
        requested_alerts: result.requested_alerts,
        requested_decisions: result.requested_decisions,
        deleted_alerts: result.deleted_alerts,
        deleted_decisions: result.deleted_decisions,
        outcome: 'queued',
      });
      if (result.deleted_decisions > 0) {
        void runNotificationEvaluation('alert decision delete');
      }
      return context.json(result);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'deleting alert', doRequest);
    }
  });

  app.get(`${config.basePath}/api/instances/:instanceId/alerts/:id`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    const instanceId = String(context.req.param('instanceId'));
    const instance = config.instances.find((candidate) => candidate.id === instanceId);
    if (!instance) return context.json({ error: 'Unknown CrowdSec instance' }, 404);
    try {
      const alert = normalizeAlertDetail(await lapiClients.get(instanceId)!.getAlertById(context.req.param('id')), context.req.param('id'));
      return alert
        ? context.json(withInstanceName({ ...withAlertTargetSummary(alert), instance_id: instanceId }))
        : context.json({ error: 'Alert not found' }, 404);
    } catch (error: any) {
      return context.json({ error: error?.message || 'Failed to retrieve alert' }, error?.status === 404 ? 404 : 502);
    }
  });

  app.delete(`${config.basePath}/api/instances/:instanceId/alerts/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;
    const instanceId = String(context.req.param('instanceId'));
    const instance = config.instances.find((candidate) => candidate.id === instanceId);
    if (!instance) return context.json({ error: 'Unknown CrowdSec instance' }, 404);
    try {
      const alertId = String(context.req.param('id'));
      if (!/^\d+$/.test(alertId)) return context.json({ error: 'Invalid alert ID' }, 400);
      const result = await deleteAlertsByRefs([{ instance_id: instanceId, id: alertId }]);
      if (result.failed.length > 0) return context.json({ error: result.failed[0].error }, 502);
      auditLog.record(context, {
        action: 'alert.delete',
        alert_ids: [alertId],
        target_results: [{ id: `${instanceId}:${alertId}`, outcome: 'queued' }],
        instance: instance.name,
        instance_id: instance.id,
        outcome: 'queued',
      });
      if (result.deleted_decisions > 0) {
        void runNotificationEvaluation('alert decision delete');
      }
      return context.json(result);
    } catch (error: any) {
      return context.json({ error: error?.message || 'Failed to delete alert' }, 502);
    }
  });
}
