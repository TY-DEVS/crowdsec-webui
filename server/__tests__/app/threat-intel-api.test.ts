import { describe, expect, test, vi } from 'vitest';
import { createController } from './harness';
import type { ThreatIntelLookupResponse } from '../../../shared/contracts';
import { ThreatIntelService } from '../../threat-intel';

describe('Threat Intelligence API', () => {
  test('returns 400 when ip query parameter is missing', async () => {
    const { controller } = createController();
    const response = await controller.fetch(
      new Request('http://localhost/crowdsec/api/threat-intel/lookup'),
    );

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain('Missing required "ip"');
  });

  test('returns 400 when ip is invalid', async () => {
    const { controller } = createController();
    const response = await controller.fetch(
      new Request('http://localhost/crowdsec/api/threat-intel/lookup?ip=not-an-ip'),
    );

    expect(response.status).toBe(400);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain('Invalid IP address');
  });

  test('returns 200 with private IP details for private address', async () => {
    const { controller } = createController();
    const response = await controller.fetch(
      new Request('http://localhost/crowdsec/api/threat-intel/lookup?ip=192.168.1.1'),
    );

    expect(response.status).toBe(200);
    const data = (await response.json()) as ThreatIntelLookupResponse;
    expect(data.ip).toBe('192.168.1.1');
    expect(data.score).toBe(0);
    expect(data.reputation).toBe('benign');
    expect(data.badges.some((b) => b.id === 'private')).toBe(true);
  });

  test('returns 200 with threat intelligence data for public IP', async () => {
    const mockFetch = vi.fn().mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        ip: '198.51.100.33',
        reputation: 'malicious',
        confidence: 'high',
        background_noise_score: 8,
        behaviors: [
          { name: 'tcp:scan', label: 'Port Scan' },
        ],
        classifications: {
          classifications: ['vpn'],
        },
      }),
    });

    const threatIntelService = new ThreatIntelService({
      fetchImpl: mockFetch,
    });

    const { controller } = createController({
      threatIntelService,
    });

    const response = await controller.fetch(
      new Request('http://localhost/crowdsec/api/threat-intel/lookup?ip=198.51.100.33'),
    );

    expect(response.status).toBe(200);
    const data = (await response.json()) as ThreatIntelLookupResponse;
    expect(data.ip).toBe('198.51.100.33');
    expect(data.reputation).toBe('malicious');
    expect(data.confidence).toBe('high');
    expect(data.score).toBeGreaterThanOrEqual(75);
    expect(data.badges.some((b) => b.id === 'scanner')).toBe(true);
    expect(data.badges.some((b) => b.id === 'vpn')).toBe(true);
  });

  test('requires authentication when dashboard sign-in is enabled', async () => {
    const { controller } = createController({
      env: {
        AUTH_ENABLED: 'true',
        AUTH_PASSWORD_LOGIN_ENABLED: 'true',
      },
    });

    const response = await controller.fetch(
      new Request('http://localhost/crowdsec/api/threat-intel/lookup?ip=198.51.100.33'),
    );

    expect(response.status).toBe(401);
  });
});
