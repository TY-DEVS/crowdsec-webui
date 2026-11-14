import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import type { AlertRecord, UpsertPlaybookRuleRequest } from '../../../shared/contracts';
import { CrowdsecDatabase } from '../../database';
import {
  createPlaybookService,
  PlaybookService,
  validatePlaybookRule,
  isValidIpOrRange,
} from '../../app/playbooks';

describe('Playbooks Engine (SOAR-Lite)', () => {
  let tempDirs: string[] = [];

  function createTestDb(): CrowdsecDatabase {
    const dir = mkdtempSync(path.join(tmpdir(), 'playbooks-test-'));
    tempDirs.push(dir);
    return new CrowdsecDatabase({ cachePath: path.join(dir, 'test.db') });
  }

  afterEach(() => {
    while (tempDirs.length > 0) {
      const dir = tempDirs.pop();
      if (dir) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          // ignore cleanup errors on Windows
        }
      }
    }
  });

  const sampleAlert = (overrides: Partial<AlertRecord> = {}): AlertRecord => ({
    id: 101,
    uuid: 'alert-101',
    created_at: new Date().toISOString(),
    scenario: 'crowdsecurity/ssh-bf',
    message: 'SSH brute force attempt',
    source: {
      ip: '198.51.100.10',
      value: '198.51.100.10',
    },
    target: 'ssh',
    events_count: 10,
    events: [],
    decisions: [],
    simulated: false,
    ...overrides,
  });

  describe('Rule Validation', () => {
    it('accepts a valid playbook rule specification', () => {
      const req: UpsertPlaybookRuleRequest = {
        name: 'Auto-ban SSH Brute Force',
        description: 'Bans IPs with >= 5 ssh-bf events for 4 hours',
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

      const result = validatePlaybookRule(req);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('rejects rules with missing name, invalid duration, or missing trigger', () => {
      expect(validatePlaybookRule({}).valid).toBe(false);
      expect(validatePlaybookRule({ name: '' }).valid).toBe(false);
      expect(
        validatePlaybookRule({
          name: 'Bad rule',
          trigger: {},
          action: { type: 'ban', duration: 'invalid' },
        }).valid,
      ).toBe(false);

      expect(
        validatePlaybookRule({
          name: 'Bad cooldown',
          trigger: { scenario: 'ssh-bf' },
          action: { type: 'ban', duration: '4h' },
          guardrails: { cooldown_seconds: -10 },
        }).valid,
      ).toBe(false);
    });
  });

  describe('IP Validation', () => {
    it('validates IPv4 and IPv6 addresses and ranges', () => {
      expect(isValidIpOrRange('192.0.2.1')).toBe(true);
      expect(isValidIpOrRange('192.0.2.0/24')).toBe(true);
      expect(isValidIpOrRange('2001:db8::1')).toBe(true);
      expect(isValidIpOrRange('2001:db8::/32')).toBe(true);
      expect(isValidIpOrRange('invalid-ip')).toBe(false);
      expect(isValidIpOrRange('999.999.999.999')).toBe(false);
    });
  });

  describe('Rule CRUD operations', () => {
    it('creates, retrieves, updates, toggles, and deletes rules (memory store)', async () => {
      const service = createPlaybookService();

      // Create
      const created = await service.createRule({
        name: 'HTTP Crawlers',
        trigger: { scenario_pattern: 'crowdsecurity/http-*' },
        action: { type: 'ban', duration: '24h', scope: 'fleet' },
      });

      expect(created.id).toBeDefined();
      expect(created.name).toBe('HTTP Crawlers');
      expect(created.enabled).toBe(true);
      expect(service.listRules()).toHaveLength(1);

      // Get
      const fetched = service.getRule(created.id);
      expect(fetched?.id).toBe(created.id);

      // Update
      const updated = await service.updateRule(created.id, {
        name: 'HTTP Crawlers Aggressive',
        trigger: { scenario_pattern: 'crowdsecurity/http-*', events_count_threshold: 15 },
        action: { type: 'ban', duration: '48h', scope: 'fleet' },
      });
      expect(updated?.name).toBe('HTTP Crawlers Aggressive');
      expect(updated?.action.duration).toBe('48h');

      // Toggle
      const disabled = await service.toggleRule(created.id, false);
      expect(disabled?.enabled).toBe(false);

      const toggledBack = await service.toggleRule(created.id);
      expect(toggledBack?.enabled).toBe(true);

      // Delete
      const deleted = await service.deleteRule(created.id);
      expect(deleted).toBe(true);
      expect(service.listRules()).toHaveLength(0);
      expect(service.getRule(created.id)).toBeNull();
    });

    it('persists rules in database across service restarts', async () => {
      const db = createTestDb();
      const service1 = createPlaybookService({ database: db });

      const rule = await service1.createRule({
        name: 'Persistent Rule',
        trigger: { scenario: 'crowdsecurity/ssh-bf', events_count_threshold: 3 },
        action: { type: 'ban', duration: '12h', scope: 'local' },
        guardrails: { never_ban_allowlisted: true, cooldown_seconds: 1800 },
      });

      expect(rule.id).toBeDefined();
      expect(service1.listRules()).toHaveLength(1);

      // Re-initialize service with same db
      const service2 = createPlaybookService({ database: db });
      const rules = service2.listRules();
      expect(rules).toHaveLength(1);
      expect(rules[0].name).toBe('Persistent Rule');
      expect(rules[0].action.duration).toBe('12h');
      expect(rules[0].guardrails.cooldown_seconds).toBe(1800);

      db.close();
    });
  });

  describe('Trigger Evaluation', () => {
    it('matches exact scenario, pattern glob, and scenario lists', async () => {
      const service = createPlaybookService();

      // Rule 1: exact scenario
      const ruleExact = await service.createRule({
        name: 'Exact Match',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '1h' },
      });

      // Rule 2: pattern
      const rulePattern = await service.createRule({
        name: 'Pattern Match',
        trigger: { scenario_pattern: 'crowdsecurity/http-*' },
        action: { type: 'ban', duration: '2h' },
      });

      // Rule 3: list
      const ruleList = await service.createRule({
        name: 'List Match',
        trigger: { scenarios: ['custom/exploit-1', 'custom/exploit-2'] },
        action: { type: 'ban', duration: '3h' },
      });

      const sshAlert = sampleAlert({ scenario: 'crowdsecurity/ssh-bf' });
      expect(service.matchTrigger(sshAlert, ruleExact.trigger).matched).toBe(true);
      expect(service.matchTrigger(sshAlert, rulePattern.trigger).matched).toBe(false);

      const httpAlert = sampleAlert({ scenario: 'crowdsecurity/http-generic-bf' });
      expect(service.matchTrigger(httpAlert, rulePattern.trigger).matched).toBe(true);

      const exploitAlert = sampleAlert({ scenario: 'custom/exploit-2' });
      expect(service.matchTrigger(exploitAlert, ruleList.trigger).matched).toBe(true);
    });

    it('respects event count threshold', async () => {
      const service = createPlaybookService();
      const rule = await service.createRule({
        name: 'Threshold Rule',
        trigger: { scenario: 'crowdsecurity/ssh-bf', events_count_threshold: 10 },
        action: { type: 'ban', duration: '4h' },
      });

      // Under threshold: 5 events
      const lowAlert = sampleAlert({ events_count: 5 });
      expect(service.matchTrigger(lowAlert, rule.trigger).matched).toBe(false);

      // At threshold: 10 events
      const exactAlert = sampleAlert({ events_count: 10 });
      expect(service.matchTrigger(exactAlert, rule.trigger).matched).toBe(true);

      // Over threshold: 25 events
      const highAlert = sampleAlert({ events_count: 25 });
      expect(service.matchTrigger(highAlert, rule.trigger).matched).toBe(true);
    });

    it('ignores simulated alerts unless explicitly included in trigger', async () => {
      const service = createPlaybookService();
      const defaultRule = await service.createRule({
        name: 'Ignore Simulated',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '1h' },
      });

      const includeSimRule = await service.createRule({
        name: 'Include Simulated',
        trigger: { scenario: 'crowdsecurity/ssh-bf', include_simulated: true },
        action: { type: 'ban', duration: '1h' },
      });

      const simulatedAlert = sampleAlert({ simulated: true });
      expect(service.matchTrigger(simulatedAlert, defaultRule.trigger).matched).toBe(false);
      expect(service.matchTrigger(simulatedAlert, includeSimRule.trigger).matched).toBe(true);
    });
  });

  describe('Safety Guardrails', () => {
    it('never bans allowlisted IPs when guardrail is enabled', async () => {
      const addDecisionMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const mockLapiClients = new Map([
        ['primary', { addDecision: addDecisionMock }],
      ]);

      const mockAllowlistService = {
        checkValue: vi.fn().mockResolvedValue({
          value: '198.51.100.10',
          allowlisted: true,
          results: [{ instance_id: 'primary', instance_name: 'Primary', allowlisted: true }],
        }),
      };

      const service = createPlaybookService({
        lapiClients: mockLapiClients,
        allowlistService: mockAllowlistService,
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      await service.createRule({
        name: 'Auto-Ban SSH',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '4h' },
        guardrails: { never_ban_allowlisted: true },
      });

      const alert = sampleAlert({ source: { ip: '198.51.100.10', value: '198.51.100.10' } });
      const results = await service.evaluateAlert(alert);

      expect(results).toHaveLength(1);
      expect(results[0].status).toBe('blocked_by_allowlist');
      expect(addDecisionMock).not.toHaveBeenCalled();

      // Check execution history recorded the block
      const executions = service.listExecutions();
      expect(executions.total).toBe(1);
      expect(executions.executions[0].status).toBe('blocked_by_allowlist');
    });

    it('blocks custom static allowlisted IPs', async () => {
      const addDecisionMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const customAllowlist = new Set(['198.51.100.99']);

      const service = createPlaybookService({
        customAllowlist,
        lapiClients: new Map([['primary', { addDecision: addDecisionMock }]]),
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      await service.createRule({
        name: 'Rule with allowlist guardrail',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '4h' },
      });

      const alert = sampleAlert({ source: { ip: '198.51.100.99', value: '198.51.100.99' } });
      const results = await service.evaluateAlert(alert);

      expect(results[0].status).toBe('blocked_by_allowlist');
      expect(addDecisionMock).not.toHaveBeenCalled();
    });

    it('enforces rate-limit / cooldown per IP to prevent rapid re-banning', async () => {
      const addDecisionMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const service = createPlaybookService({
        lapiClients: new Map([['primary', { addDecision: addDecisionMock }]]),
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      await service.createRule({
        name: 'Rate-limited Rule',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '4h' },
        guardrails: { cooldown_seconds: 60 },
      });

      const alert = sampleAlert({ source: { ip: '198.51.100.20', value: '198.51.100.20' } });

      // First evaluation: successfully executed
      const firstRun = await service.evaluateAlert(alert);
      expect(firstRun[0].status).toBe('executed');
      expect(addDecisionMock).toHaveBeenCalledTimes(1);

      // Second immediate evaluation: blocked by cooldown
      const secondRun = await service.evaluateAlert(alert);
      expect(secondRun[0].status).toBe('blocked_by_cooldown');
      expect(addDecisionMock).toHaveBeenCalledTimes(1); // not called again

      // Clear cooldown manually to simulate time passage
      service.clearCooldown('198.51.100.20');

      // Third evaluation: can execute again
      const thirdRun = await service.evaluateAlert(alert);
      expect(thirdRun[0].status).toBe('executed');
      expect(addDecisionMock).toHaveBeenCalledTimes(2);
    });

    it('supports simulation mode at rule level without issuing upstream bans', async () => {
      const addDecisionMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const service = createPlaybookService({
        lapiClients: new Map([['primary', { addDecision: addDecisionMock }]]),
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      await service.createRule({
        name: 'Simulated Rule',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '4h' },
        guardrails: { simulation_mode: true },
      });

      const alert = sampleAlert();
      const results = await service.evaluateAlert(alert);

      expect(results).toHaveLength(1);
      expect(results[0].status).toBe('simulated');
      expect(results[0].action?.duration).toBe('4h');
      expect(addDecisionMock).not.toHaveBeenCalled();

      // Recorded as simulated in executions
      const executions = service.listExecutions();
      expect(executions.executions[0].status).toBe('simulated');
    });

    it('supports global simulation mode override', async () => {
      const addDecisionMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const service = createPlaybookService({
        simulationMode: true, // global simulation mode
        lapiClients: new Map([['primary', { addDecision: addDecisionMock }]]),
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      await service.createRule({
        name: 'Live Configured Rule',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '4h' },
        guardrails: { simulation_mode: false },
      });

      const alert = sampleAlert();
      const results = await service.evaluateAlert(alert);

      expect(results[0].status).toBe('simulated');
      expect(addDecisionMock).not.toHaveBeenCalled();
    });

    it('supports dry-run testing via simulateAlert() without changing persistent state', async () => {
      const addDecisionMock = vi.fn();
      const service = createPlaybookService({
        lapiClients: new Map([['primary', { addDecision: addDecisionMock }]]),
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      await service.createRule({
        name: 'Dry Run Target',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '1h' },
      });

      const alert = sampleAlert();
      const results = await service.simulateAlert(alert);

      expect(results).toHaveLength(1);
      expect(results[0].status).toBe('simulated');
      expect(addDecisionMock).not.toHaveBeenCalled();
      // Dry-run does not write to execution history
      expect(service.listExecutions().total).toBe(0);
    });
  });

  describe('Remediation & Fleet Propagation', () => {
    it('propagates automatic bans across all fleet instances when scope is fleet', async () => {
      const primaryBanMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const edgeBanMock = vi.fn().mockResolvedValue({ message: 'OK' });

      const instances = [
        { id: 'primary', name: 'Primary Node' },
        { id: 'edge-1', name: 'Edge Node 1' },
      ] as any[];

      const lapiClients = new Map([
        ['primary', { addDecision: primaryBanMock }],
        ['edge-1', { addDecision: edgeBanMock }],
      ]);

      const auditRecordMock = vi.fn();
      const cacheUpdateMock = vi.fn().mockResolvedValue(undefined);

      const service = createPlaybookService({
        instances,
        primaryInstance: instances[0],
        lapiClients,
        auditLog: { record: auditRecordMock },
        updateCacheDelta: cacheUpdateMock,
      });

      await service.createRule({
        name: 'Fleet Wide SSH Remediation',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: {
          type: 'ban',
          duration: '6h',
          scope: 'fleet',
          reason: 'Auto fleet ban',
        },
      });

      const alert = sampleAlert({ source: { ip: '203.0.113.50', value: '203.0.113.50' } });
      const results = await service.evaluateAlert(alert);

      expect(results[0].status).toBe('executed');
      // Called on both fleet instances!
      expect(primaryBanMock).toHaveBeenCalledWith(
        '203.0.113.50',
        'ban',
        '6h',
        'Auto fleet ban',
        'crowdsecurity/ssh-bf',
      );
      expect(edgeBanMock).toHaveBeenCalledWith(
        '203.0.113.50',
        'ban',
        '6h',
        'Auto fleet ban',
        'crowdsecurity/ssh-bf',
      );

      // Audit log called
      expect(auditRecordMock).toHaveBeenCalled();
      // Cache delta update triggered
      expect(cacheUpdateMock).toHaveBeenCalled();
    });

    it('limits ban to primary instance when scope is local', async () => {
      const primaryBanMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const edgeBanMock = vi.fn().mockResolvedValue({ message: 'OK' });

      const instances = [
        { id: 'primary', name: 'Primary Node' },
        { id: 'edge-1', name: 'Edge Node 1' },
      ] as any[];

      const lapiClients = new Map([
        ['primary', { addDecision: primaryBanMock }],
        ['edge-1', { addDecision: edgeBanMock }],
      ]);

      const service = createPlaybookService({
        instances,
        primaryInstance: instances[0],
        lapiClients,
      });

      await service.createRule({
        name: 'Local Only Ban',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: {
          type: 'ban',
          duration: '1h',
          scope: 'local',
        },
      });

      const alert = sampleAlert({ source: { ip: '203.0.113.60', value: '203.0.113.60' } });
      const results = await service.evaluateAlert(alert);

      expect(results[0].status).toBe('executed');
      expect(primaryBanMock).toHaveBeenCalledTimes(1);
      expect(edgeBanMock).not.toHaveBeenCalled();
    });

    it('updates execution count and last_triggered_at on rules', async () => {
      const primaryBanMock = vi.fn().mockResolvedValue({ message: 'OK' });
      const service = createPlaybookService({
        lapiClients: new Map([['primary', { addDecision: primaryBanMock }]]),
        primaryInstance: { id: 'primary', name: 'Primary' } as any,
      });

      const rule = await service.createRule({
        name: 'Counting Rule',
        trigger: { scenario: 'crowdsecurity/ssh-bf' },
        action: { type: 'ban', duration: '1h' },
        guardrails: { cooldown_seconds: 0 }, // no cooldown
      });

      expect(rule.execution_count).toBe(0);
      expect(rule.last_triggered_at).toBeNull();

      await service.evaluateAlert(sampleAlert({ source: { ip: '1.1.1.1', value: '1.1.1.1' } }));
      const updated1 = service.getRule(rule.id);
      expect(updated1?.execution_count).toBe(1);
      expect(updated1?.last_triggered_at).toBeDefined();

      await service.evaluateAlert(sampleAlert({ source: { ip: '1.1.1.2', value: '1.1.1.2' } }));
      const updated2 = service.getRule(rule.id);
      expect(updated2?.execution_count).toBe(2);
    });
  });
});
