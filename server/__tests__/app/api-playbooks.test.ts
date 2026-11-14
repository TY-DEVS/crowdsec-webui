import { describe, expect, test, afterEach } from 'vitest';
import { createAuthSessionCookie, createController, tempDir, destroyTempDir } from './harness';
import type { PlaybookListResponse, PlaybookRule } from '../../../shared/contracts';

describe('Playbooks API (/api/playbooks)', () => {
  const controllers: Array<ReturnType<typeof createController>['controller']> = [];

  function makeController(options?: Parameters<typeof createController>[0]) {
    const res = createController(options);
    controllers.push(res.controller);
    return res;
  }

  afterEach(() => {
    while (controllers.length > 0) {
      const c = controllers.pop();
      if (c) {
        try {
          c.stopBackgroundTasks();
          c.database.close();
        } catch {}
      }
    }
    try {
      destroyTempDir();
    } catch {}
  });

  const getUrl = (controller: ReturnType<typeof createController>['controller'], endpoint: string) =>
    `http://localhost${controller.config.basePath}/api/playbooks${endpoint}`;

  test('lists, creates, retrieves, updates, toggles, and deletes playbook rules', async () => {
    const { controller } = makeController();
    const url = getUrl(controller, '');

    // 1. Initial list should be empty
    const listRes1 = await controller.fetch(new Request(url));
    expect(listRes1.status).toBe(200);
    const listData1 = (await listRes1.json()) as PlaybookListResponse;
    expect(listData1.rules).toHaveLength(0);
    expect(listData1.total).toBe(0);

    // 2. Create rule
    const validRule = {
      name: 'Auto-Ban SSH Brute Force',
      description: 'Mitigate repeat SSH attackers across fleet',
      priority: 10,
      trigger: {
        scenario: 'crowdsecurity/ssh-bf',
        events_count_threshold: 5,
      },
      action: {
        type: 'ban',
        duration: '4h',
        scope: 'fleet',
      },
      guardrails: {
        never_ban_allowlisted: true,
        cooldown_seconds: 3600,
        simulation_mode: false,
      },
    };

    const createRes = await controller.fetch(
      new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(validRule),
      }),
    );
    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as PlaybookRule;
    expect(created.id).toBeDefined();
    expect(created.name).toBe('Auto-Ban SSH Brute Force');
    expect(created.action.duration).toBe('4h');
    expect(created.enabled).toBe(true);
    expect(created.execution_count).toBe(0);

    // 3. List rules should contain the new rule
    const listRes2 = await controller.fetch(new Request(url));
    const listData2 = (await listRes2.json()) as PlaybookListResponse;
    expect(listData2.rules).toHaveLength(1);
    expect(listData2.total).toBe(1);
    expect(listData2.rules[0].id).toBe(created.id);

    // 4. Retrieve single rule
    const getRes = await controller.fetch(new Request(getUrl(controller, `/${created.id}`)));
    expect(getRes.status).toBe(200);
    const fetched = (await getRes.json()) as PlaybookRule;
    expect(fetched.id).toBe(created.id);
    expect(fetched.name).toBe('Auto-Ban SSH Brute Force');

    // 5. Update rule
    const updateRes = await controller.fetch(
      new Request(getUrl(controller, `/${created.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...validRule,
          name: 'Updated Auto-Ban SSH Rule',
          action: { ...validRule.action, duration: '24h' },
        }),
      }),
    );
    expect(updateRes.status).toBe(200);
    const updated = (await updateRes.json()) as PlaybookRule;
    expect(updated.name).toBe('Updated Auto-Ban SSH Rule');
    expect(updated.action.duration).toBe('24h');

    // 6. Toggle rule enabled state
    const toggleRes = await controller.fetch(
      new Request(getUrl(controller, `/${created.id}/toggle`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false }),
      }),
    );
    expect(toggleRes.status).toBe(200);
    const toggled = (await toggleRes.json()) as PlaybookRule;
    expect(toggled.enabled).toBe(false);

    // PATCH toggle also supported
    const patchToggleRes = await controller.fetch(
      new Request(getUrl(controller, `/${created.id}/toggle`), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true }),
      }),
    );
    expect(patchToggleRes.status).toBe(200);
    expect(((await patchToggleRes.json()) as PlaybookRule).enabled).toBe(true);

    // 7. Delete rule
    const delRes = await controller.fetch(
      new Request(getUrl(controller, `/${created.id}`), {
        method: 'DELETE',
      }),
    );
    expect(delRes.status).toBe(200);

    // 8. Retrieve deleted rule returns 404
    const get404Res = await controller.fetch(new Request(getUrl(controller, `/${created.id}`)));
    expect(get404Res.status).toBe(404);
  });

  test('validates payload on rule creation and rejection of bad inputs', async () => {
    const { controller } = makeController();
    const url = getUrl(controller, '');

    // Missing name
    const res1 = await controller.fetch(
      new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          trigger: { scenario: 'crowdsecurity/ssh-bf' },
          action: { type: 'ban', duration: '4h' },
        }),
      }),
    );
    expect(res1.status).toBe(400);

    // Invalid duration format
    const res2 = await controller.fetch(
      new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Bad Duration',
          trigger: { scenario: 'crowdsecurity/ssh-bf' },
          action: { type: 'ban', duration: '4hours' },
        }),
      }),
    );
    expect(res2.status).toBe(400);

    // Missing scenario in trigger
    const res3 = await controller.fetch(
      new Request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Missing Scenario',
          trigger: {},
          action: { type: 'ban', duration: '4h' },
        }),
      }),
    );
    expect(res3.status).toBe(400);
  });

  test('returns 404 for operations on unknown rule IDs', async () => {
    const { controller } = makeController();
    const unknownUrl = getUrl(controller, '/non-existent-id');

    expect((await controller.fetch(new Request(unknownUrl))).status).toBe(404);
    expect(
      (
        await controller.fetch(
          new Request(unknownUrl, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: 'Valid Name',
              trigger: { scenario: 'crowdsecurity/ssh-bf' },
              action: { type: 'ban', duration: '4h' },
            }),
          }),
        )
      ).status,
    ).toBe(404);

    expect(
      (
        await controller.fetch(
          new Request(unknownUrl, {
            method: 'DELETE',
          }),
        )
      ).status,
    ).toBe(404);
  });

  test('simulates alert matching without persisting live bans via /simulate and /evaluate', async () => {
    const { controller } = makeController();

    // Create a live playbook rule
    await controller.fetch(
      new Request(getUrl(controller, ''), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'SSH Auto Ban Rule',
          trigger: { scenario: 'crowdsecurity/ssh-bf', events_count_threshold: 3 },
          action: { type: 'ban', duration: '2h', scope: 'fleet' },
          guardrails: { cooldown_seconds: 3600 },
        }),
      }),
    );

    // Call /api/playbooks/simulate with matching alert
    const simRes = await controller.fetch(
      new Request(getUrl(controller, '/simulate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alert: {
            scenario: 'crowdsecurity/ssh-bf',
            events_count: 5,
            source: { ip: '198.51.100.77', value: '198.51.100.77' },
          },
        }),
      }),
    );
    expect(simRes.status).toBe(200);
    const simData = (await simRes.json()) as any;
    expect(simData.results).toHaveLength(1);
    expect(simData.results[0].matched).toBe(true);
    expect(simData.results[0].status).toBe('simulated');
    expect(simData.results[0].action.duration).toBe('2h');

    // Executions log should not be written by simulation endpoint
    const execRes = await controller.fetch(new Request(getUrl(controller, '/executions')));
    expect(execRes.status).toBe(200);
    const execData = (await execRes.json()) as any;
    expect(execData.total).toBe(0);
  });

  test('enforces authentication and authorization when auth is enabled', async () => {
    const { controller } = makeController({ env: { AUTH_ENABLED: 'true' } });
    const url = getUrl(controller, '');

    // Unauthenticated request is rejected
    const unauthRes = await controller.fetch(new Request(url));
    expect(unauthRes.status).toBe(401);

    // Authenticated read-only user can list rules
    const viewerId = controller.database.createAuthUser({
      username: 'viewer',
      passwordHash: 'hash',
      role: 'read-only',
      authProvider: 'password',
    });
    const viewerCookie = createAuthSessionCookie(controller.database, {
      userId: viewerId,
      username: 'viewer',
      role: 'read-only',
      authMethod: 'password',
    });

    const viewerListRes = await controller.fetch(
      new Request(url, { headers: { cookie: viewerCookie } }),
    );
    expect(viewerListRes.status).toBe(200);

    // Read-only user cannot create rules (read-only mode blocks enforcement/settings mutation)
    const viewerCreateRes = await controller.fetch(
      new Request(url, {
        method: 'POST',
        headers: { cookie: viewerCookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Forbidden Rule',
          trigger: { scenario: 'crowdsecurity/ssh-bf' },
          action: { type: 'ban', duration: '1h' },
        }),
      }),
    );
    expect(viewerCreateRes.status).toBe(403);

    // Admin user can create rules
    const adminId = controller.database.createAuthUser({
      username: 'admin',
      passwordHash: 'hash',
      role: 'admin',
      authProvider: 'password',
    });
    const adminCookie = createAuthSessionCookie(controller.database, {
      userId: adminId,
      username: 'admin',
      role: 'admin',
      authMethod: 'password',
    });

    const adminCreateRes = await controller.fetch(
      new Request(url, {
        method: 'POST',
        headers: { cookie: adminCookie, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Admin Rule',
          trigger: { scenario: 'crowdsecurity/ssh-bf' },
          action: { type: 'ban', duration: '1h' },
        }),
      }),
    );
    expect(adminCreateRes.status).toBe(201);
  });
});
