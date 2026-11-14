import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test, vi } from 'vitest';
import { createApp } from '../../app';
import { createRuntimeConfig } from '../../config';
import { CrowdsecDatabase } from '../../database';

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Ignore Windows temp lock
    }
  }
});

function fakeClient(name: string) {
  const status = { isConnected: true, lastCheck: null, lastError: null, offline_since: null };
  return {
    hasAuthConfig: () => true,
    hasToken: () => true,
    login: vi.fn(async () => true),
    updateStatus: vi.fn(),
    getStatus: () => ({ ...status }),
    heartbeat: vi.fn(async () => {}),
    sendUsageMetrics: vi.fn(async () => {}),
    fetchAlerts: vi.fn(async (): Promise<any[]> => []),
    getAlertById: vi.fn(async (id: string) => ({ id: Number(id), created_at: new Date().toISOString(), decisions: [] })),
    addDecision: vi.fn(async () => ({ message: `${name} added` })),
    addDecisions: vi.fn(async () => ({ message: `${name} bulk added` })),
    fetchAllowlists: vi.fn(async (): Promise<any[]> => []),
    checkAllowlist: vi.fn(async (): Promise<{ allowlisted: boolean; reason?: string }> => ({ allowlisted: false })),
    deleteAlert: vi.fn(async () => ({ message: `${name} alert deleted` })),
    deleteDecision: vi.fn(async () => ({ message: `${name} decision deleted` })),
  };
}

function createTestController() {
  const dir = mkdtempSync(path.join(tmpdir(), 'crowdsec-web-ui-selected-scope-test-'));
  tempDirs.push(dir);
  const config = createRuntimeConfig({
    DB_DIR: dir,
    CROWDSEC_USER: 'watcher',
    CROWDSEC_PASSWORD: 'secret',
    CROWDSEC_REFRESH_INTERVAL: '1h',
    AUTH_ENABLED: 'false',
  }, { defaultConfigFile: path.join(dir, 'config.yaml') });
  const base = config.instances[0];
  config.instances = [
    { ...base, id: 'inst-1', name: 'Instance 1', lapiUrl: 'http://inst1:8080' },
    { ...base, id: 'inst-2', name: 'Instance 2', lapiUrl: 'http://inst2:8080' },
    { ...base, id: 'inst-3', name: 'Instance 3', lapiUrl: 'http://inst3:8080' },
  ];
  const database = new CrowdsecDatabase({ dataDir: dir });
  const client1 = fakeClient('inst-1');
  const client2 = fakeClient('inst-2');
  const client3 = fakeClient('inst-3');

  const controller = createApp({
    config,
    database,
    lapiClients: new Map([
      ['inst-1', client1 as never],
      ['inst-2', client2 as never],
      ['inst-3', client3 as never],
    ]),
    startBackgroundTasks: false,
    initialCacheState: { isInitialized: true, isComplete: true, lastUpdate: new Date().toISOString() },
    updateChecker: async () => ({ update_available: false, current_version: 'test', remote_version: 'test', tag: 'test', release_url: '', checked_at: new Date().toISOString() }),
  });

  return { controller, database, client1, client2, client3 };
}

describe('selected scope decision targeting', () => {
  test('POST /api/decisions targets only the selected instances when scope is selected', async () => {
    const { controller, database, client1, client2, client3 } = createTestController();
    try {
      const response = await controller.fetch(new Request('http://localhost/api/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: '198.51.100.1',
          duration: '4h',
          type: 'ban',
          reason: 'manual fleet test',
          scope: 'selected',
          instance_ids: ['inst-2', 'inst-3'],
        }),
      }));

      expect(response.status).toBe(200);
      expect(client1.addDecision).not.toHaveBeenCalled();
      expect(client2.addDecision).toHaveBeenCalledTimes(1);
      expect(client3.addDecision).toHaveBeenCalledTimes(1);

      const json = await response.json() as any;
      expect(json.succeeded).toBe(2);
      expect(json.results.map((r: any) => r.instance_id)).toEqual(['inst-2', 'inst-3']);
    } finally {
      controller.stopBackgroundTasks();
      database.close();
    }
  });

  test('POST /api/decisions fails when scope is selected but instance_ids is empty or invalid', async () => {
    const { controller, database, client1, client2, client3 } = createTestController();
    try {
      const emptyResponse = await controller.fetch(new Request('http://localhost/api/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: '198.51.100.2',
          scope: 'selected',
          instance_ids: [],
        }),
      }));
      expect(emptyResponse.status).toBe(400);

      const invalidResponse = await controller.fetch(new Request('http://localhost/api/decisions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip: '198.51.100.2',
          scope: 'selected',
          instance_ids: ['non-existent'],
        }),
      }));
      expect(invalidResponse.status).toBe(400);

      expect(client1.addDecision).not.toHaveBeenCalled();
      expect(client2.addDecision).not.toHaveBeenCalled();
      expect(client3.addDecision).not.toHaveBeenCalled();
    } finally {
      controller.stopBackgroundTasks();
      database.close();
    }
  });

  test('POST /api/decisions/bulk-add targets only selected instances', async () => {
    const { controller, database, client1, client2, client3 } = createTestController();
    try {
      const response = await controller.fetch(new Request('http://localhost/api/decisions/bulk-add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          values: ['198.51.100.10', '198.51.100.11'],
          duration: '4h',
          type: 'ban',
          reason: 'bulk fleet test',
          scope: 'selected',
          instance_ids: ['inst-1'],
        }),
      }));

      expect(response.status).toBe(200);
      expect(client1.addDecisions).toHaveBeenCalledTimes(1);
      expect(client2.addDecisions).not.toHaveBeenCalled();
      expect(client3.addDecisions).not.toHaveBeenCalled();
    } finally {
      controller.stopBackgroundTasks();
      database.close();
    }
  });
});
