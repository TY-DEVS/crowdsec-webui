import net from 'node:net';
import type {
  ConfigResponse,
  ManagedConfigSetting,
  ManagedSettingSource,
  UpdateAllowlistsSidebarPreferenceRequest,
  UpdateManualDecisionScenariosRequest,
  UpdateManualRefreshSettingRequest,
  UpdateMetricsSidebarPreferenceRequest,
  UpdateStatisticsSidebarPreferenceRequest,
} from '../../../shared/contracts';
import { DEFAULT_MANUAL_DECISION_SCENARIO, isValidDecisionScenario } from '../../../shared/contracts';
import { resolveManagedSettingSource, type RuntimeConfig } from '../../config';
import { ThreatIntelService } from '../../threat-intel';
import type { ApiRouteDependencies } from '../api-routes';
import type { HonoContext } from './common';

const MAX_CUSTOM_MANUAL_DECISION_SCENARIOS = 100;
const FONT_PREFERENCE_PATTERN = /^[a-z0-9-]{1,64}$/;
const SIDEBAR_PREFERENCE_KEYS = ['metrics_sidebar_visible', 'allowlists_sidebar_visible', 'statistics_sidebar_visible'] as const;

export function registerConfigRoutes(dependencies: ApiRouteDependencies): void {
  const {
    app,
    config,
    database,
    lapiClient,
    lapiClients,
    syncWorker,
    state,
    dashboardAuth,
    ensureAuth,
    ensureCanManageSettings,
    lookbackHours,
    getIntervalName,
    aggregateLapiStatus,
    aggregateHistoricalSyncStatus,
    instanceSyncStatuses,
    syncStatus,
    saveAllowlistsSidebarVisible,
    saveStatisticsSidebarVisible,
    saveMetricsSidebarVisible,
    saveManualDecisionScenarios,
    parseRefreshInterval,
    savePersistedConfig,
    startRefreshScheduler,
    updateCache,
    refreshLatestWindow,
    refreshFullHistory,
    normalizeLanguagePreference,
    saveLanguagePreference,
    resetReconcileWindowState,
    invalidateDashboardStatsCache,
    ensureBootstrapReady,
    checkForUpdates,
    readUpdateCheckOverrides,
    threatIntelService: customThreatIntelService,
  } = dependencies;

  const threatIntelService = customThreatIntelService || new ThreatIntelService(config.threatIntel);

  const manualDecisionScenarios = (instance: RuntimeConfig['instances'][number]): string[] => [
    ...new Set([
      DEFAULT_MANUAL_DECISION_SCENARIO,
      ...(instance.manualDecisionScenarios ?? config.manualDecisionScenarios),
      ...state.manualDecisionScenarios,
    ]),
  ];

  const configuredManualDecisionScenarios = (): string[] => [
    ...new Set([
      ...config.manualDecisionScenarios,
      ...config.instances.flatMap((instance) => instance.manualDecisionScenarios ?? []),
    ]),
  ];

  const managedConfigSettings: Partial<Record<ManagedConfigSetting, ManagedSettingSource>> = {
    ...(config.metricsSidebarVisibleManaged
      ? { metrics_sidebar_visible: resolveManagedSettingSource(config.configEnvironmentOverrides, 'ui.metricsSidebarVisible') }
      : {}),
    ...(config.allowlistsSidebarVisibleManaged
      ? { allowlists_sidebar_visible: resolveManagedSettingSource(config.configEnvironmentOverrides, 'ui.allowlistsSidebarVisible') }
      : {}),
    ...(config.statisticsSidebarVisibleManaged
      ? { statistics_sidebar_visible: resolveManagedSettingSource(config.configEnvironmentOverrides, 'ui.statisticsSidebarVisible') }
      : {}),
    ...(config.refreshIntervalManaged
      ? { refresh_interval: resolveManagedSettingSource(config.configEnvironmentOverrides, 'crowdsec.sync.refreshInterval') }
      : {}),
    ...(config.manualRefreshEnabledManaged
      ? { manual_refresh_enabled: resolveManagedSettingSource(config.configEnvironmentOverrides, 'crowdsec.sync.manualRefreshEnabled') }
      : {}),
  };

  const preferenceUserId = (context: HonoContext): number | null => {
    if (!dashboardAuth.enabled) return null;
    const userId = dashboardAuth.getSession(context)?.userId;
    return userId && userId > 0 ? userId : null;
  };

  const resolveSidebarVisibility = (context: HonoContext) => {
    const userId = preferenceUserId(context);
    const preferences = userId ? database.getUserPreferences(userId) : {};
    const [metricsKey, allowlistsKey, statisticsKey] = SIDEBAR_PREFERENCE_KEYS;
    return {
      metrics_sidebar_visible: !config.metricsSidebarVisibleManaged && preferences[metricsKey] !== undefined
        ? preferences[metricsKey] === 'true'
        : state.metricsSidebarVisible,
      allowlists_sidebar_visible: !config.allowlistsSidebarVisibleManaged && preferences[allowlistsKey] !== undefined
        ? preferences[allowlistsKey] === 'true'
        : state.allowlistsSidebarVisible,
      statistics_sidebar_visible: !config.statisticsSidebarVisibleManaged && preferences[statisticsKey] !== undefined
        ? preferences[statisticsKey] === 'true'
        : state.statisticsSidebarVisible,
    };
  };

  const managedByConfigResponse = (context: HonoContext, setting: string) => context.json({
    error: `${setting} is managed by the application configuration`,
    code: 'MANAGED_BY_CONFIG',
  }, 409);

  app.get(`${config.basePath}/api/config`, ensureAuth, (context) => {
    const hours = lookbackHours(config.lookbackPeriod);
    const payload: ConfigResponse = {
      statistics: dependencies.statistics.configuration(),
      lookback_period: config.lookbackPeriod,
      lookback_hours: hours,
      lookback_days: Math.max(1, Math.round(hours / 24)),
      refresh_interval: state.refreshIntervalMs,
      manual_refresh_enabled: state.manualRefreshEnabled,
      managed_settings: managedConfigSettings,
      current_interval_name: getIntervalName(state.refreshIntervalMs),
      lapi_status: lapiClient.getStatus(),
      instances: config.instances.map((instance) => ({
        id: instance.id,
        name: instance.name,
        icon: instance.icon,
        lapi_status: lapiClients.get(instance.id)!.getStatus(),
        sync_status: { ...(instanceSyncStatuses.get(instance.id) || syncStatus) },
        prometheus: instance.prometheus.map((endpoint) => ({ id: endpoint.id, name: endpoint.name, icon: endpoint.icon })),
        sync_overrides: { ...instance.sync },
        manual_decision_scenarios: manualDecisionScenarios(instance),
      })),
      aggregate_lapi_status: aggregateLapiStatus(),
      sync_status: aggregateHistoricalSyncStatus(),
      cache_last_update: state.cacheRefreshCompletedAt,
      next_refresh_at: state.nextRefreshAt,
      simulations_enabled: config.simulationsEnabled,
      machine_features_enabled: true,
      origin_features_enabled: true,
      time_zone: config.timeZone,
      time_format: config.timeFormat,
      date_format: config.dateFormat,
      metrics_enabled: config.instances.some((instance) => instance.prometheus.length > 0),
      ...resolveSidebarVisibility(context),
      manual_decision_scenario_settings: {
        configured: configuredManualDecisionScenarios(),
        custom: [...state.manualDecisionScenarios],
      },
      ...(config.deploymentMode === 'load-test' ? { deployment_mode: config.deploymentMode } : {}),
      ...(config.loadTestProfile ? { load_test_profile: config.loadTestProfile } : {}),
      permissions: dashboardAuth.getPermissions(context),
    };

    return context.json(payload);
  });

  app.get(`${config.basePath}/api/instances`, ensureAuth, (context) => context.json({
    data: config.instances.map((instance) => ({
      id: instance.id,
      name: instance.name,
      icon: instance.icon,
      lapi_status: lapiClients.get(instance.id)!.getStatus(),
      sync_status: { ...(instanceSyncStatuses.get(instance.id) || syncStatus) },
      prometheus: instance.prometheus.map((endpoint) => ({ id: endpoint.id, name: endpoint.name, icon: endpoint.icon })),
      sync_overrides: { ...instance.sync },
      manual_decision_scenarios: manualDecisionScenarios(instance),
    })),
    aggregate_status: aggregateLapiStatus(),
  }));

  app.put(`${config.basePath}/api/config/allowlists-sidebar`, ensureAuth, async (context) => {
    const userId = preferenceUserId(context);
    if (config.allowlistsSidebarVisibleManaged) return managedByConfigResponse(context, 'Allowlists sidebar visibility');

    try {
      const body = await context.req.json<UpdateAllowlistsSidebarPreferenceRequest>();
      if (typeof body.visible !== 'boolean') {
        return context.json({ error: 'visible must be a boolean' }, 400);
      }

      if (userId) {
        await syncWorker.runExclusive(() => database.setUserPreference(userId, 'allowlists_sidebar_visible', String(body.visible)));
      } else {
        await syncWorker.runExclusive(() => saveAllowlistsSidebarVisible(database, body.visible));
        state.allowlistsSidebarVisible = body.visible;
      }

      return context.json({ success: true, allowlists_sidebar_visible: body.visible });
    } catch (error: any) {
      console.error('Error updating allowlists sidebar preference:', error.message);
      return context.json({ error: 'Failed to update allowlists sidebar preference' }, 500);
    }
  });

  app.put(`${config.basePath}/api/config/statistics-sidebar`, ensureAuth, async (context) => {
    const userId = preferenceUserId(context);
    if (config.statisticsSidebarVisibleManaged) return managedByConfigResponse(context, 'Statistics sidebar visibility');

    try {
      const body = await context.req.json<UpdateStatisticsSidebarPreferenceRequest>();
      if (typeof body.visible !== 'boolean') {
        return context.json({ error: 'visible must be a boolean' }, 400);
      }

      if (userId) {
        await syncWorker.runExclusive(() => database.setUserPreference(userId, 'statistics_sidebar_visible', String(body.visible)));
      } else {
        await syncWorker.runExclusive(() => saveStatisticsSidebarVisible(database, body.visible));
        state.statisticsSidebarVisible = body.visible;
      }

      return context.json({ success: true, statistics_sidebar_visible: body.visible });
    } catch (error: any) {
      console.error('Error updating statistics sidebar preference:', error.message);
      return context.json({ error: 'Failed to update statistics sidebar preference' }, 500);
    }
  });

  app.put(`${config.basePath}/api/config/metrics-sidebar`, ensureAuth, async (context) => {
    if (config.metricsSidebarVisibleManaged) return managedByConfigResponse(context, 'Metrics sidebar visibility');

    try {
      const body = await context.req.json<UpdateMetricsSidebarPreferenceRequest>();
      if (typeof body.visible !== 'boolean') {
        return context.json({ error: 'visible must be a boolean' }, 400);
      }

      const userId = preferenceUserId(context);
      if (userId) {
        await syncWorker.runExclusive(() => database.setUserPreference(userId, 'metrics_sidebar_visible', String(body.visible)));
      } else {
        await syncWorker.runExclusive(() => saveMetricsSidebarVisible(database, body.visible));
        state.metricsSidebarVisible = body.visible;
      }

      return context.json({
        success: true,
        metrics_sidebar_visible: body.visible,
      });
    } catch (error: any) {
      console.error('Error updating metrics sidebar preference:', error.message);
      return context.json({ error: 'Failed to update metrics sidebar preference' }, 500);
    }
  });

  app.put(`${config.basePath}/api/config/manual-decision-scenarios`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      const body = await context.req.json<UpdateManualDecisionScenariosRequest>();
      if (!Array.isArray(body?.scenarios) || body.scenarios.some((scenario: unknown) => typeof scenario !== 'string')) {
        return context.json({ error: 'scenarios must be an array of strings' }, 400);
      }
      const rawScenarios = body.scenarios as string[];
      const configured = new Set([DEFAULT_MANUAL_DECISION_SCENARIO, ...configuredManualDecisionScenarios()]);
      const scenarios: string[] = [...new Set(rawScenarios.map((scenario) => scenario.trim()))]
        .filter((scenario) => Boolean(scenario) && !configured.has(scenario));
      const invalid = scenarios.find((scenario) => !isValidDecisionScenario(scenario));
      if (invalid) {
        return context.json({ error: `Invalid scenario format: "${invalid}". Use e.g. "${DEFAULT_MANUAL_DECISION_SCENARIO}"` }, 400);
      }
      if (scenarios.length > MAX_CUSTOM_MANUAL_DECISION_SCENARIOS) {
        return context.json({ error: `At most ${MAX_CUSTOM_MANUAL_DECISION_SCENARIOS} scenarios can be added` }, 400);
      }

      await syncWorker.runExclusive(() => saveManualDecisionScenarios(database, scenarios));
      state.manualDecisionScenarios = scenarios;
      console.log(`Manual decision scenarios updated: ${scenarios.join(', ') || '(none)'}`);

      return context.json({
        success: true,
        manual_decision_scenario_settings: {
          configured: configuredManualDecisionScenarios(),
          custom: scenarios,
        },
      });
    } catch (error: any) {
      console.error('Error updating manual decision scenarios:', error.message);
      return context.json({ error: 'Failed to update manual decision scenarios' }, 500);
    }
  });

  app.put(`${config.basePath}/api/config/refresh-interval`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;
    if (config.refreshIntervalManaged) return managedByConfigResponse(context, 'Refresh interval');

    try {
      const body = await context.req.json<{ interval?: string }>();
      const interval = body.interval;

      if (!interval) {
        return context.json({ error: 'interval is required' }, 400);
      }

      const validIntervals = ['manual', '0', '5s', '30s', '1m', '5m'];
      if (!validIntervals.includes(interval)) {
        return context.json({ error: `Invalid interval. Must be one of: ${validIntervals.join(', ')}` }, 400);
      }

      const nextInterval = parseRefreshInterval(interval);
      const previous = getIntervalName(state.refreshIntervalMs);
      state.refreshIntervalMs = nextInterval;
      await syncWorker.runExclusive(() => savePersistedConfig(database, { refresh_interval_ms: nextInterval }));
      startRefreshScheduler();
      console.log(`Refresh interval changed: ${previous} -> ${interval} (${nextInterval}ms)`);

      return context.json({
        success: true,
        old_interval: previous,
        new_interval: interval,
        new_interval_ms: nextInterval,
        next_refresh_at: state.nextRefreshAt,
        message: `Refresh interval updated to ${interval}`,
      });
    } catch (error: any) {
      console.error('Error updating refresh interval:', error.message);
      return context.json({ error: 'Failed to update refresh interval' }, 500);
    }
  });

  app.put(`${config.basePath}/api/config/manual-refresh`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;
    if (config.manualRefreshEnabledManaged) return managedByConfigResponse(context, 'Manual refresh');

    try {
      const body = await context.req.json<UpdateManualRefreshSettingRequest>();
      if (typeof body.enabled !== 'boolean') {
        return context.json({ error: 'enabled must be a boolean' }, 400);
      }

      state.manualRefreshEnabled = body.enabled;
      await syncWorker.runExclusive(() => savePersistedConfig(database, {
        manual_refresh_enabled: state.manualRefreshEnabled,
      }));
      console.log(`Manual refresh ${state.manualRefreshEnabled ? 'enabled' : 'disabled'}`);

      return context.json({
        success: true,
        manual_refresh_enabled: state.manualRefreshEnabled,
      });
    } catch (error: any) {
      console.error('Error updating manual refresh setting:', error.message);
      return context.json({ error: 'Failed to update manual refresh setting' }, 500);
    }
  });

  app.post(`${config.basePath}/api/cache/refresh`, ensureAuth, async (context) => {
    if (!state.manualRefreshEnabled) {
      return context.json({
        error: 'Manual refresh is disabled',
        code: 'MANUAL_REFRESH_DISABLED',
      }, 403);
    }

    let body: { mode?: string };
    try {
      body = await context.req.json<{ mode?: string }>();
    } catch {
      return context.json({ error: 'A JSON request body is required' }, 400);
    }

    if (body.mode !== 'delta' && body.mode !== 'latest' && body.mode !== 'full') {
      return context.json({ error: 'mode must be one of: delta, latest, full' }, 400);
    }
    if (state.cacheRefreshPromise || state.initializationPromise || state.bootstrapPromise) {
      return context.json({ error: 'A cache refresh is already in progress', code: 'REFRESH_IN_PROGRESS' }, 409);
    }

    try {
      if (body.mode === 'delta') {
        await updateCache({ throwOnError: true, reconcile: false, publishUnchanged: true });
      } else if (body.mode === 'latest') {
        await refreshLatestWindow();
      } else {
        await refreshFullHistory();
      }
      return context.json({ success: true, mode: body.mode, completed_at: state.cacheRefreshCompletedAt });
    } catch (error: any) {
      const message = error?.message || 'Cache refresh failed';
      console.error(`Manual ${body.mode} refresh failed:`, message);
      return context.json({ error: message }, 502);
    }
  });

  app.put(`${config.basePath}/api/config/language`, ensureAuth, async (context) => {
    try {
      const body = await context.req.json<{ language?: string }>();
      const language = body.language;
      const normalizedLanguage = normalizeLanguagePreference(language);
      if (language !== normalizedLanguage && normalizedLanguage === 'browser') {
        return context.json({ error: 'Invalid language preference' }, 400);
      }

      const userId = preferenceUserId(context);
      await syncWorker.runExclusive(() => {
        if (userId) database.setUserPreference(userId, 'language', normalizedLanguage);
        if (!userId || dashboardAuth.getPermissions(context).can_manage_settings) {
          saveLanguagePreference(database, normalizedLanguage);
        }
      });
      return context.json({
        success: true,
        language: normalizedLanguage,
      });
    } catch (error: any) {
      console.error('Error updating language preference:', error.message);
      return context.json({ error: 'Failed to update language preference' }, 500);
    }
  });

  app.put(`${config.basePath}/api/config/font`, ensureAuth, async (context) => {
    const body = await context.req.json<{ font?: unknown }>().catch(() => null);
    const font = body?.font;
    if (typeof font !== 'string' || !FONT_PREFERENCE_PATTERN.test(font)) {
      return context.json({ error: 'Invalid font preference' }, 400);
    }
    const userId = preferenceUserId(context);
    if (userId) await syncWorker.runExclusive(() => database.setUserPreference(userId, 'font', font));
    return context.json({ success: true, font });
  });

  app.post(`${config.basePath}/api/cache/clear`, ensureAuth, async (context) => {
    const readOnlyResponse = ensureCanManageSettings(context);
    if (readOnlyResponse) return readOnlyResponse;

    try {
      state.initialHistorySyncs.clear();
      for (const instance of config.instances) {
        state.initialHistorySyncs.add(instance.id);
        state.instanceLastUpdates.set(instance.id, null);
        resetReconcileWindowState(instance.id);
      }
      await syncWorker.runExclusive(() => {
        database.clearSyncData();
      });
      state.cache.isInitialized = false;
      state.cache.isComplete = false;
      state.cache.lastUpdate = null;
      state.cacheRefreshCompletedAt = null;
      state.staleDashboardStatsResponseCache.clear();
      invalidateDashboardStatsCache();
      await ensureBootstrapReady('manual cache clear');

      return context.json({
        success: true,
        message: 'Cache cleared and re-synced',
        alert_count: database.countAlerts(),
      });
    } catch (error: any) {
      console.error('Error clearing cache:', error.message);
      return context.json({ error: 'Failed to clear cache' }, 500);
    }
  });

  app.get(`${config.basePath}/api/update-check`, ensureAuth, async (context) => {
    try {
      const status = await checkForUpdates(readUpdateCheckOverrides(context.req.query()));
      context.header('Cache-Control', 'no-store, no-cache, must-revalidate');
      context.header('Pragma', 'no-cache');
      return context.json(status);
    } catch (error: any) {
      console.error('Error checking for updates:', error.message);
      context.header('Cache-Control', 'no-store, no-cache, must-revalidate');
      context.header('Pragma', 'no-cache');
      return context.json({ error: 'Update check failed' }, 500);
    }
  });

  app.get(`${config.basePath}/api/threat-intel/lookup`, ensureAuth, async (context) => {
    const ip = context.req.query('ip')?.trim();
    if (!ip) {
      return context.json({ error: 'Missing required "ip" query parameter' }, 400);
    }
    if (net.isIP(ip) === 0) {
      return context.json({ error: `Invalid IP address: "${ip}"` }, 400);
    }
    try {
      const result = await threatIntelService.lookup(ip);
      return context.json(result);
    } catch (error: any) {
      console.error('Threat intelligence lookup error:', error);
      return context.json({ error: error?.message || 'Threat intelligence lookup failed' }, 500);
    }
  });
}
