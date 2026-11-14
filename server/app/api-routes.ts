import type { Hono } from 'hono';
import type { RuntimeConfig } from '../config';
import type { CrowdsecDatabase } from '../database';
import type { LapiClient } from '../lapi';
import type { ThreatIntelService } from '../threat-intel';
import type { AllowlistService } from './allowlists';
import type { DatabaseQueryWorker } from '../query-worker-client';
import type { DashboardStatsFilters } from './types';
import {
  registerAlertRoutes,
  registerDecisionRoutes,
  registerNotificationRoutes,
  registerConfigRoutes,
  registerMetricsRoutes,
} from './routes';

export interface ApiRouteState {
  refreshIntervalMs: number;
  manualRefreshEnabled: boolean;
  metricsSidebarVisible: boolean;
  allowlistsSidebarVisible: boolean;
  statisticsSidebarVisible: boolean;
  manualDecisionScenarios: string[];
  cacheRefreshCompletedAt: string | null;
  cache: { isInitialized: boolean; isComplete: boolean; lastUpdate: string | null };
  initialHistorySyncs: Set<string>;
  instanceLastUpdates: Map<string, string | null>;
  staleDashboardStatsResponseCache: Map<string, unknown>;
  lastDashboardStatsFilters: DashboardStatsFilters | null;
  lastDashboardStatsRequestedAt: number;
  historicalInstanceSyncPending: Set<string>;
  nextRefreshAt: string | null;
  cacheRefreshPromise: Promise<void> | null;
  initializationPromise: Promise<unknown> | null;
  bootstrapPromise: Promise<unknown> | null;
}

export interface ApiRouteDependencies extends Record<string, any> {
  app: Hono;
  config: RuntimeConfig;
  database: CrowdsecDatabase;
  lapiClient: LapiClient;
  lapiClients: Map<string, LapiClient>;
  analyticsQueryWorker: DatabaseQueryWorker;
  allowlistService: AllowlistService;
  threatIntelService?: ThreatIntelService;
  state: ApiRouteState;
}

export function registerApiRoutes(dependencies: ApiRouteDependencies): void {
  registerAlertRoutes(dependencies);
  registerDecisionRoutes(dependencies);
  registerNotificationRoutes(dependencies);
  registerConfigRoutes(dependencies);
  registerMetricsRoutes(dependencies);
}

export * from './routes';
