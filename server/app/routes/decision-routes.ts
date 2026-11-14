import {
  BULK_ADD_DECISIONS_MAX,
  MANUAL_DECISION_LOOKUP_MAX,
  type AddDecisionRequest,
  type AllowlistMatch,
  type AllowlistedDecisionResponse,
  type BulkAddDecisionRequest,
  type BulkAddDecisionResponse,
  type BulkDeleteRequest,
  type CleanupByIpRequest,
  type InstanceEntityRef,
  type ManualDecisionLookupRequest,
  type ManualDecisionLookupResponse,
} from '../../../shared/contracts';
import type { AuditOutcome } from '../../audit-log';
import type { RuntimeConfig } from '../../config';
import type { ApiRouteDependencies } from '../api-routes';
import {
  BULK_ALLOWLIST_CHECK_CONCURRENCY,
  MANUAL_DECISION_ORIGINS,
  auditTargetOutcome,
  capAuditEntries,
  decisionAuditValues,
  parseDecisionSettings,
  resolveDecisionAuditTargets,
  type AnyError,
} from './common';

export function registerDecisionRoutes(dependencies: ApiRouteDependencies): void {
  const {
    app,
    config,
    database,
    lapiClients,
    syncWorker,
    analyticsQueryWorker,
    allowlistService,
    auditLog,
    ensureAuth,
    ensurePublishedRevisionRead,
    ensureCanManageEnforcement,
    handleApiError,
    prepareOnDemandRefresh,
    prepareReadCache,
    getPageRequest,
    getDecisionListFilters,
    getFacetRequest,
    DECISION_FACET_FIELDS,
    compileDecisionSearch,
    toSearchErrorResponse,
    queryPaginatedDecisions,
    queryDecisionFacet,
    QueryWorkerTimeoutError,
    getAlertCoordinatesByIds,
    getAlertKindsByIds,
    decisionFromRow,
    markDuplicateDecisions,
    enrichDecisionLocations,
    toDecisionListItem,
    resolveOperationInstances,
    isValidIpOrRange,
    primaryInstance,
    deleteEntriesByIp,
    deleteEntriesByIpOnInstance,
    updateCacheDelta,
    syncInstanceDelta,
    validateInstanceEntityRefs,
    createDeleteResult,
    groupInstanceEntityRefs,
    toFailure,
    deleteDecisionsByIdsInChunks,
    deleteDecisionFromLapi,
    normalizeDeleteIds,
    invalidateDashboardStatsCache,
    runNotificationEvaluation,
  } = dependencies;

  app.get(`${config.basePath}/api/decisions`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    try {
      await prepareOnDemandRefresh(context);

      await prepareReadCache('decisions request');

      const pageRequest = getPageRequest(context);
      const includeExpired = context.req.query('include_expired') === 'true';
      if (pageRequest) {
        const filters = getDecisionListFilters(context, config.timeZone);
        const compiledSearch = compileDecisionSearch(filters.q, {
          machineEnabled: true,
          originEnabled: true,
        }, {
          timezoneOffsetMinutes: filters.timezoneOffsetMinutes,
          timeZone: filters.timeZone,
        });
        if (!compiledSearch.ok) {
          return context.json(toSearchErrorResponse(compiledSearch.error), 400);
        }
        return context.json(await queryPaginatedDecisions(pageRequest, filters, compiledSearch.ast, includeExpired));
      }

      const now = new Date().toISOString();
      const since = new Date(Date.now() - config.lookbackMs).toISOString();
      const rows = includeExpired
        ? database.getDecisionsSince(since, now)
        : database.getActiveDecisions(now);

      const [alertCoordinates, alertKinds] = await Promise.all([
        getAlertCoordinatesByIds(rows.map((row: { alert_id?: string | number | null }) => row.alert_id)),
        getAlertKindsByIds(rows.map((row: { alert_id?: string | number | null }) => row.alert_id)),
      ]);

      let decisions = rows.map((row: any) => {
        const decision = decisionFromRow(row);
        const kind = row.alert_id === undefined || row.alert_id === null
          ? undefined
          : alertKinds.get(String(row.alert_id));
        if (kind) decision.kind = kind;
        return toDecisionListItem(decision, includeExpired);
      });
      if (!config.simulationsEnabled) {
        decisions = decisions.filter((decision: any) => !decision.simulated);
      }
      decisions = markDuplicateDecisions(decisions);
      decisions.sort((left: any, right: any) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime());
      decisions = await enrichDecisionLocations(decisions, alertCoordinates);

      return context.json(decisions);
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out serving decisions from database:', error.message);
        return context.json({ error: 'Decision query timed out' }, 504);
      }
      console.error('Error serving decisions from database:', error.message);
      return context.json({ error: 'Failed to retrieve decisions' }, 500);
    }
  });

  app.get(`${config.basePath}/api/decisions/facets`, ensureAuth, ensurePublishedRevisionRead, async (context) => {
    const request = getFacetRequest(context, DECISION_FACET_FIELDS);
    if ('error' in request) {
      return context.json({ error: request.error }, 400);
    }

    try {
      await prepareOnDemandRefresh(context);
      await prepareReadCache('decision facets request');

      const filters = getDecisionListFilters(context, config.timeZone);
      const compiledSearch = compileDecisionSearch(filters.q, {
        machineEnabled: true,
        originEnabled: true,
      }, {
        timezoneOffsetMinutes: filters.timezoneOffsetMinutes,
        timeZone: filters.timeZone,
      });
      if (!compiledSearch.ok) {
        return context.json(toSearchErrorResponse(compiledSearch.error), 400);
      }

      return context.json(await queryDecisionFacet(
        request,
        filters,
        compiledSearch.ast,
        context.req.query('include_expired') === 'true',
      ));
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        return context.json({ error: 'Facet query timed out' }, 504);
      }
      console.error('Error serving decision facets from database:', error.message);
      return context.json({ error: 'Failed to retrieve decision facets' }, 500);
    }
  });

  app.delete(`${config.basePath}/api/instances/:instanceId/decisions/:id`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;
    const instanceId = String(context.req.param('instanceId'));
    const instance = config.instances.find((candidate) => candidate.id === instanceId);
    if (!instance) return context.json({ error: 'Unknown CrowdSec instance' }, 404);
    try {
      const decisionId = String(context.req.param('id'));
      const targets = resolveDecisionAuditTargets(database, [{ id: decisionId, instance_id: instanceId }]);
      const values = decisionAuditValues(targets);
      await lapiClients.get(instanceId)!.deleteDecision(decisionId);
      try {
        await syncWorker.runExclusive(() => {
          database.deleteDecisionByInstanceId(instanceId, decisionId);
          database.refreshDecisionDuplicateFlags(new Date().toISOString());
        });
      } catch (error) {
        auditLog.record(context, {
          action: 'decision.delete',
          decision_ids: [decisionId],
          target_results: targets.map((target) => ({ ...target, outcome: 'partial' })),
          ...(values.length > 0 ? { values } : {}),
          instance: instance.name,
          instance_id: instance.id,
          remote_deleted: true,
          local_cache_updated: false,
          outcome: 'partial',
        });
        throw error;
      }
      invalidateDashboardStatsCache();
      auditLog.record(context, {
        action: 'decision.delete',
        decision_ids: [decisionId],
        target_results: targets.map((target) => ({ ...target, outcome: 'success' })),
        ...(values.length > 0 ? { values } : {}),
        instance: instance.name,
        instance_id: instance.id,
        outcome: 'success',
      });
      return context.json({ message: 'Deleted' });
    } catch (error: any) {
      return context.json({ error: error?.message || 'Failed to delete decision' }, 502);
    }
  });

  app.post(`${config.basePath}/api/cleanup/by-ip`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const doRequest = async () => {
      const body = await context.req.json<CleanupByIpRequest>();
      const ip = String(body.ip || '').trim();
      if (!isValidIpOrRange(ip)) {
        return context.json({ error: 'Invalid IP address format' }, 400);
      }

      const targets = resolveOperationInstances(body.scope, body.instance_id, body.instance_ids);
      if ('error' in targets) return context.json({ error: targets.error }, 400);
      const results = await Promise.all(targets.map(async (instance: RuntimeConfig['instances'][number]) => {
        try {
          const result = instance.id === primaryInstance.id && body.scope === undefined
            ? await deleteEntriesByIp(ip)
            : await deleteEntriesByIpOnInstance(instance.id, ip);
          return {
            instance_id: instance.id,
            instance_name: instance.name,
            success: result.failed.length === 0,
            ...(result.failed.length > 0 ? { error: `${result.failed.length} item(s) failed` } : {}),
            result,
          };
        } catch (error: any) {
          return { instance_id: instance.id, instance_name: instance.name, success: false, error: error?.message || String(error) };
        }
      }));
      const succeeded = results.filter((result) => result.success).length;
      const payload = { results, succeeded, failed: results.length - succeeded };
      const instanceResultEntries = results.map((result) => ({
        instance_id: result.instance_id,
        instance: result.instance_name,
        outcome: result.success
          ? ('result' in result && result.result?.deleted_alerts > 0 ? 'queued' as const : 'success' as const)
          : ('result' in result && result.result
            && result.result.deleted_alerts + result.result.deleted_decisions > 0 ? 'partial' as const : 'failure' as const),
      }));
      const instanceResults = capAuditEntries(instanceResultEntries);
      auditLog.record(context, {
        action: 'cleanup.by-ip',
        ip,
        instances: results.map((result) => result.instance_name),
        instance_results: instanceResults.entries,
        ...(instanceResults.truncated ? { truncated: true } : {}),
        deleted_alerts: results.reduce((total, entry) => total + ('result' in entry && entry.result ? entry.result.deleted_alerts : 0), 0),
        deleted_decisions: results.reduce((total, entry) => total + ('result' in entry && entry.result ? entry.result.deleted_decisions : 0), 0),
        outcome: auditTargetOutcome(instanceResultEntries.map((result) => result.outcome)),
      });
      if (succeeded > 0) void runNotificationEvaluation('cleanup by ip');
      if (results.length === 1 && body.scope === undefined && results[0].success && 'result' in results[0]) {
        return context.json(results[0].result);
      }
      return context.json(payload, succeeded === results.length ? 200 : succeeded > 0 ? 207 : 502);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'deleting entries by IP', doRequest);
    }
  });

  app.post(`${config.basePath}/api/decisions/manual-lookup`, ensureAuth, async (context) => {
    let body: ManualDecisionLookupRequest;
    try {
      body = await context.req.json<ManualDecisionLookupRequest>();
    } catch {
      return context.json({ error: 'Invalid JSON body' }, 400);
    }
    if (!Array.isArray(body?.values) || !body.values.every((value: unknown) => typeof value === 'string')) {
      return context.json({ error: 'values must be an array of strings' }, 400);
    }
    const rawValues = body.values as string[];
    const values = [...new Set(rawValues.map((value) => value.trim()).filter(Boolean))];
    if (values.length > MANUAL_DECISION_LOOKUP_MAX) {
      return context.json({ error: `At most ${MANUAL_DECISION_LOOKUP_MAX} values can be looked up at once` }, 400);
    }
    if (values.length === 0) return context.json({ decisions: [] } satisfies ManualDecisionLookupResponse);
    try {
      await prepareReadCache('manual decision lookup');
      const rows = await analyticsQueryWorker.all<{ value: string; instance_id: string; stop_at: string }>(`
        SELECT value, instance_id, MAX(stop_at) AS stop_at
        FROM decisions
        WHERE value IN (${values.map(() => '?').join(', ')})
          AND stop_at > ?
          AND simulated = 0
          AND origin IN (${MANUAL_DECISION_ORIGINS.map(() => '?').join(', ')})
        GROUP BY value, instance_id
      `, [...values, new Date().toISOString(), ...MANUAL_DECISION_ORIGINS], { label: 'manual decision lookup' });
      return context.json({ decisions: rows } satisfies ManualDecisionLookupResponse);
    } catch (error: any) {
      if (error instanceof QueryWorkerTimeoutError) {
        console.warn('Timed out looking up manual decisions:', error.message);
        return context.json({ error: 'Manual decision lookup timed out' }, 504);
      }
      console.error('Error looking up manual decisions:', error.message);
      return context.json({ error: 'Failed to look up manual decisions' }, 500);
    }
  });

  app.post(`${config.basePath}/api/decisions`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const doRequest = async () => {
      const body = await context.req.json<AddDecisionRequest>();
      const ip = body.ip;

      if (!ip) {
        return context.json({ error: 'IP address is required' }, 400);
      }

      if (!isValidIpOrRange(ip)) {
        return context.json({ error: 'Invalid IP address format' }, 400);
      }

      const settings = parseDecisionSettings(body);
      if ('error' in settings) return context.json({ error: settings.error }, 400);
      const { duration, reason, type, scenario } = settings;

      const targets = resolveOperationInstances(body.scope, body.instance_id, body.instance_ids);
      if ('error' in targets) return context.json({ error: targets.error }, 400);
      const bypassAllowlist = body.bypass_allowlist === true;
      if (!bypassAllowlist) {
        const check = await allowlistService.checkValue(targets, ip);
        for (const result of check.results) {
          if (result.status === 'unavailable') {
            console.warn(`[decisions] Allowlist check for ${ip} failed on ${result.instance_name}: ${result.error}`);
          }
        }
        const allowlisted: AllowlistMatch[] = check.results.flatMap((result) => (result.allowlisted
          ? [{ instance_id: result.instance_id, instance_name: result.instance_name, ...(result.reason ? { reason: result.reason } : {}) }]
          : []));
        if (allowlisted.length > 0) {
          const response: AllowlistedDecisionResponse = { error: `${ip} is allowlisted`, code: 'ALLOWLISTED', allowlisted };
          return context.json(response, 409);
        }
      }
      const targetOutcomes = new Map<string, AuditOutcome>();
      const results = await Promise.all(targets.map(async (instance: RuntimeConfig['instances'][number]) => {
        const client = lapiClients.get(instance.id)!;
        let upstreamAdded = false;
        try {
          const result = await client.addDecision(ip, type, duration, reason.slice(0, 256), scenario);
          upstreamAdded = true;
          if (instance.id === primaryInstance.id) await updateCacheDelta({ publishUnchanged: true });
          else await syncInstanceDelta(instance.id);
          targetOutcomes.set(instance.id, 'success');
          return { instance_id: instance.id, instance_name: instance.name, success: true, result };
        } catch (error: any) {
          targetOutcomes.set(instance.id, upstreamAdded ? 'partial' : 'failure');
          return { instance_id: instance.id, instance_name: instance.name, success: false, error: error?.message || String(error) };
        }
      }));
      const succeeded = results.filter((result) => result.success).length;
      const payload = { results, succeeded, failed: results.length - succeeded };
      for (const result of results) {
        if (result.success) console.log(`[decisions] Added ${type} decision for ${ip} (${duration}, ${scenario}). Instance: ${result.instance_name}.`);
      }
      const instanceResultEntries = results.map((result) => ({
        instance_id: result.instance_id,
        instance: result.instance_name,
        outcome: targetOutcomes.get(result.instance_id) || 'failure',
      }));
      const instanceResults = capAuditEntries(instanceResultEntries);
      auditLog.record(context, {
        action: 'decision.add',
        ip,
        type,
        scenario,
        duration,
        reason: reason.slice(0, 256),
        ...(bypassAllowlist ? { bypass_allowlist: true } : {}),
        instances: results.map((result) => result.instance_name),
        instance_results: instanceResults.entries,
        ...(instanceResults.truncated ? { truncated: true } : {}),
        outcome: auditTargetOutcome(instanceResultEntries.map((result) => result.outcome)),
      });
      if (succeeded > 0) void runNotificationEvaluation('manual decision add');
      if (results.length === 1 && body.scope === undefined && results[0].success) {
        return context.json({ message: 'Decision added (via Alert)', result: results[0].result });
      }
      return context.json(payload, succeeded === results.length ? 200 : succeeded > 0 ? 207 : 502);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'adding decision', doRequest);
    }
  });

  app.post(`${config.basePath}/api/decisions/bulk-add`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const doRequest = async () => {
      const body = await context.req.json<BulkAddDecisionRequest>();
      if (!Array.isArray(body.values) || body.values.length === 0) {
        return context.json({ error: 'At least one value is required' }, 400);
      }
      const rawValues = body.values as unknown[];
      const values: string[] = [...new Set(rawValues.map((value) => (typeof value === 'string' ? value.trim() : '')))];
      if (values.length > BULK_ADD_DECISIONS_MAX) {
        return context.json({ error: `At most ${BULK_ADD_DECISIONS_MAX} values can be added at once` }, 400);
      }
      const invalid = values.find((value) => !value || !isValidIpOrRange(value));
      if (invalid !== undefined) return context.json({ error: `Invalid IP address format: ${invalid}` }, 400);
      const settings = parseDecisionSettings(body);
      if ('error' in settings) return context.json({ error: settings.error }, 400);
      const { duration, reason, type, scenario } = settings;

      const targets = resolveOperationInstances(body.scope, body.instance_id, body.instance_ids);
      if ('error' in targets) return context.json({ error: targets.error }, 400);
      const bypassAllowlist = body.bypass_allowlist === true;
      const allowlisted: BulkAddDecisionResponse['allowlisted'] = [];
      if (!bypassAllowlist) {
        let next = 0;
        await Promise.all(Array.from({ length: Math.min(BULK_ALLOWLIST_CHECK_CONCURRENCY, values.length) }, async () => {
          while (next < values.length) {
            const value = values[next++];
            const check = await allowlistService.checkValue(targets, value);
            const matches: AllowlistMatch[] = check.results.flatMap((result) => {
              if (result.status === 'unavailable') console.warn(`[decisions] Allowlist check for ${value} failed on ${result.instance_name}: ${result.error}`);
              return result.allowlisted
                ? [{ instance_id: result.instance_id, instance_name: result.instance_name, ...(result.reason ? { reason: result.reason } : {}) }]
                : [];
            });
            if (matches.length > 0) allowlisted.push({ value, allowlisted: matches });
          }
        }));
      }
      const skipped = new Set(allowlisted.map((entry: { value: string }) => entry.value));
      const added = values.filter((value: string) => !skipped.has(value));
      allowlisted.sort((a: { value: string }, b: { value: string }) => values.indexOf(a.value) - values.indexOf(b.value));
      if (added.length === 0) {
        const response: BulkAddDecisionResponse = { added, allowlisted, results: [], succeeded: 0, failed: 0 };
        return context.json(response);
      }

      const targetOutcomes = new Map<string, AuditOutcome>();
      const results = await Promise.all(targets.map(async (instance: RuntimeConfig['instances'][number]) => {
        const client = lapiClients.get(instance.id)!;
        let upstreamAdded = false;
        try {
          const result = await client.addDecisions(added, type, duration, reason.slice(0, 256), scenario);
          upstreamAdded = true;
          if (instance.id === primaryInstance.id) await updateCacheDelta({ publishUnchanged: true });
          else await syncInstanceDelta(instance.id);
          targetOutcomes.set(instance.id, 'success');
          return { instance_id: instance.id, instance_name: instance.name, success: true, result };
        } catch (error: any) {
          targetOutcomes.set(instance.id, upstreamAdded ? 'partial' : 'failure');
          return { instance_id: instance.id, instance_name: instance.name, success: false, error: error?.message || String(error) };
        }
      }));
      const succeeded = results.filter((result) => result.success).length;
      for (const result of results) {
        if (result.success) console.log(`[decisions] Added ${added.length} ${type} decisions (${duration}, ${scenario}). Instance: ${result.instance_name}.`);
      }
      const instanceResultEntries = results.map((result) => ({
        instance_id: result.instance_id,
        instance: result.instance_name,
        outcome: targetOutcomes.get(result.instance_id) || 'failure',
      }));
      const instanceResults = capAuditEntries(instanceResultEntries);
      const auditValues = capAuditEntries(added);
      auditLog.record(context, {
        action: 'decision.add',
        values: auditValues.entries,
        type,
        scenario,
        duration,
        reason: reason.slice(0, 256),
        ...(bypassAllowlist ? { bypass_allowlist: true } : {}),
        instances: results.map((result) => result.instance_name),
        instance_results: instanceResults.entries,
        ...(instanceResults.truncated || auditValues.truncated ? { truncated: true } : {}),
        outcome: auditTargetOutcome(instanceResultEntries.map((result) => result.outcome)),
      });
      if (succeeded > 0) void runNotificationEvaluation('manual decision add');
      const response: BulkAddDecisionResponse = { added, allowlisted, results, succeeded, failed: results.length - succeeded };
      return context.json(response, succeeded === results.length ? 200 : succeeded > 0 ? 207 : 502);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'adding decisions', doRequest);
    }
  });

  app.post(`${config.basePath}/api/decisions/bulk-delete`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const doRequest = async () => {
      const body = await context.req.json<BulkDeleteRequest>();
      if (Array.isArray(body.refs) && body.refs.length > 0) {
        const validated = validateInstanceEntityRefs(body.refs);
        if ('error' in validated) return context.json({ error: validated.error }, 400);
        const resolvedTargets = resolveDecisionAuditTargets(database, validated);
        const auditValues = capAuditEntries(decisionAuditValues(resolvedTargets));
        const result = createDeleteResult({ requested_decisions: validated.length });
        const groups = groupInstanceEntityRefs(validated);
        const targetOutcomes = new Map<string, AuditOutcome>();
        await Promise.all(Array.from(groups, async ([instanceId, ids]) => {
          const client = lapiClients.get(instanceId)!;
          for (const id of ids) {
            const targetId = `${instanceId}:${id}`;
            let upstreamDeleted = false;
            try {
              await client.deleteDecision(id);
              upstreamDeleted = true;
              await syncWorker.runExclusive(() => database.deleteDecisionByInstanceId(instanceId, id));
              result.deleted_decisions += 1;
              targetOutcomes.set(targetId, 'success');
            } catch (error) {
              result.failed.push(toFailure('decision', targetId, error as AnyError));
              targetOutcomes.set(targetId, upstreamDeleted ? 'partial' : 'failure');
            }
          }
        }));
        await syncWorker.runExclusive(() => database.refreshDecisionDuplicateFlags(new Date().toISOString()));
        invalidateDashboardStatsCache();
        const decisionIds = capAuditEntries(validated.map((ref: InstanceEntityRef) => `${ref.instance_id}:${ref.id}`));
        const targetResults = capAuditEntries(resolvedTargets.map((target) => ({
          ...target,
          outcome: targetOutcomes.get(target.id) || 'failure',
        })));
        auditLog.record(context, {
          action: 'decision.delete',
          decision_ids: decisionIds.entries,
          target_results: targetResults.entries,
          ...(auditValues.entries.length > 0 ? { values: auditValues.entries } : {}),
          ...(decisionIds.truncated || auditValues.truncated || targetResults.truncated ? { truncated: true } : {}),
          requested_decisions: result.requested_decisions,
          deleted_decisions: result.deleted_decisions,
          outcome: auditTargetOutcome(Array.from(targetOutcomes.values())),
        });
        if (result.deleted_decisions > 0) void runNotificationEvaluation('bulk decision delete');
        return context.json(result);
      }
      if (!Array.isArray(body.ids) || body.ids.length === 0) {
        return context.json({ error: 'At least one decision ID is required' }, 400);
      }
      if (config.instances.length > 1) {
        return context.json({ error: 'Structured instance refs are required when multiple CrowdSec instances are configured' }, 400);
      }
      const ids = normalizeDeleteIds(body.ids);
      if (ids.length !== body.ids.length) {
        return context.json({ error: 'Decision IDs must be numeric' }, 400);
      }

      const resolvedTargets = resolveDecisionAuditTargets(database, ids.map((id: string) => ({ id })));
      const auditValues = capAuditEntries(decisionAuditValues(resolvedTargets));
      const result = await deleteDecisionsByIdsInChunks(ids);
      const decisionIds = capAuditEntries(ids);
      const failedIds = new Set(result.failed.map((failure: { id: string }) => failure.id));
      const targetResultEntries = resolvedTargets.map((target) => ({
        ...target,
        outcome: failedIds.has(target.id) ? 'failure' as const : 'success' as const,
      }));
      const targetResults = capAuditEntries(targetResultEntries);
      auditLog.record(context, {
        action: 'decision.delete',
        decision_ids: decisionIds.entries,
        target_results: targetResults.entries,
        ...(auditValues.entries.length > 0 ? { values: auditValues.entries } : {}),
        ...(decisionIds.truncated || auditValues.truncated || targetResults.truncated ? { truncated: true } : {}),
        requested_decisions: result.requested_decisions,
        deleted_decisions: result.deleted_decisions,
        outcome: auditTargetOutcome(targetResultEntries.map((target) => target.outcome)),
      });
      if (result.deleted_decisions > 0) {
        void runNotificationEvaluation('bulk decision delete');
      }
      return context.json(result);
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'bulk deleting decisions', doRequest);
    }
  });

  app.delete(`${config.basePath}/api/decisions/:id`, ensureAuth, async (context) => {
    if (config.instances.length > 1) return context.json({ error: 'instance_id is required when multiple CrowdSec instances are configured' }, 400);
    const readOnlyResponse = ensureCanManageEnforcement(context);
    if (readOnlyResponse) return readOnlyResponse;

    const decisionId = String(context.req.param('id'));
    if (!/^\d+$/.test(decisionId)) {
      return context.json({ error: 'Invalid decision ID' }, 400);
    }

    const doRequest = async () => {
      const targets = resolveDecisionAuditTargets(database, [{ id: decisionId }]);
      const values = decisionAuditValues(targets);
      const result = await deleteDecisionFromLapi(decisionId);
      console.log(`Removing decision ${decisionId} from local cache...`);
      try {
        await syncWorker.runExclusive(() => {
          database.deleteDecision(decisionId);
          database.refreshDecisionDuplicateFlags(new Date().toISOString());
        });
      } catch (error) {
        auditLog.record(context, {
          action: 'decision.delete',
          decision_ids: [decisionId],
          target_results: targets.map((target) => ({ ...target, outcome: 'partial' })),
          ...(values.length > 0 ? { values } : {}),
          remote_deleted: true,
          local_cache_updated: false,
          outcome: 'partial',
        });
        throw error;
      }
      invalidateDashboardStatsCache();
      auditLog.record(context, {
        action: 'decision.delete',
        decision_ids: [decisionId],
        target_results: targets.map((target) => ({ ...target, outcome: 'success' })),
        ...(values.length > 0 ? { values } : {}),
        outcome: 'success',
      });
      void runNotificationEvaluation('decision delete');
      return context.json((result as object) || { message: 'Deleted' });
    };

    try {
      return await doRequest();
    } catch (error) {
      return handleApiError(error as AnyError, context, 'deleting decision', doRequest);
    }
  });
}
