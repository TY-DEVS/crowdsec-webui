import { describe, expect, test, vi } from 'vitest';
import { ThreatIntelService, isPrivateOrReservedIp } from '../threat-intel';

describe('ThreatIntelService', () => {
  describe('isPrivateOrReservedIp', () => {
    test('identifies IPv4 private, loopback, and link-local ranges', () => {
      expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('10.0.5.1')).toBe(true);
      expect(isPrivateOrReservedIp('172.16.0.1')).toBe(true);
      expect(isPrivateOrReservedIp('172.31.255.255')).toBe(true);
      expect(isPrivateOrReservedIp('192.168.1.100')).toBe(true);
      expect(isPrivateOrReservedIp('169.254.1.1')).toBe(true);
      expect(isPrivateOrReservedIp('0.0.0.0')).toBe(true);
      // Public IPv4
      expect(isPrivateOrReservedIp('1.1.1.1')).toBe(false);
      expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false);
      expect(isPrivateOrReservedIp('198.51.100.1')).toBe(false);
    });

    test('identifies IPv6 loopback, unique local, and link-local ranges', () => {
      expect(isPrivateOrReservedIp('::1')).toBe(true);
      expect(isPrivateOrReservedIp('fc00::1')).toBe(true);
      expect(isPrivateOrReservedIp('fd12:3456:789a::1')).toBe(true);
      expect(isPrivateOrReservedIp('fe80::1')).toBe(true);
      // Public IPv6
      expect(isPrivateOrReservedIp('2001:db8::1')).toBe(false);
      expect(isPrivateOrReservedIp('2606:4700:4700::1111')).toBe(false);
    });
  });

  describe('validation', () => {
    test('rejects invalid or empty IP addresses', async () => {
      const service = new ThreatIntelService();
      await expect(service.lookup('')).rejects.toThrow('Invalid IP address');
      await expect(service.lookup('not-an-ip')).rejects.toThrow('Invalid IP address');
      await expect(service.lookup('256.256.256.256')).rejects.toThrow('Invalid IP address');
      await expect(service.lookup('1.2.3.4.5')).rejects.toThrow('Invalid IP address');
    });

    test('handles private IP addresses without external network calls', async () => {
      const fetchMock = vi.fn();
      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
      });

      const result = await service.lookup('192.168.1.50');
      expect(fetchMock).not.toHaveBeenCalled();
      expect(result.ip).toBe('192.168.1.50');
      expect(result.score).toBe(0);
      expect(result.reputation).toBe('benign');
      expect(result.confidence).toBe('none');
      expect(result.badges.some((b) => b.id === 'private')).toBe(true);
    });
  });

  describe('CrowdSec CTI integration', () => {
    test('fetches reputation from CrowdSec CTI and maps malicious scanner', async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.22',
          reputation: 'malicious',
          confidence: 'high',
          background_noise_score: 9,
          behaviors: [
            { name: 'tcp:scan', label: 'TCP Scan', description: 'Port scanning' },
            { name: 'http:bruteforce', label: 'HTTP Bruteforce', description: 'Brute forcing web' },
          ],
          classifications: {
            false_positives: [],
          },
          history: {
            first_seen: '2026-01-01T00:00:00Z',
            last_seen: '2026-05-01T12:00:00Z',
          },
        }),
      });

      const service = new ThreatIntelService({
        crowdsecCtiApiKey: 'test-crowdsec-key',
        fetchImpl: fetchMock,
      });

      const result = await service.lookup('198.51.100.22');

      expect(fetchMock).toHaveBeenCalledWith(
        'https://cti.api.crowdsec.net/v2/smoke/198.51.100.22',
        expect.objectContaining({
          headers: expect.objectContaining({
            'x-api-key': 'test-crowdsec-key',
          }),
        }),
      );

      expect(result.ip).toBe('198.51.100.22');
      expect(result.reputation).toBe('malicious');
      expect(result.confidence).toBe('high');
      expect(result.score).toBeGreaterThanOrEqual(75);
      expect(result.badges.some((b) => b.id === 'scanner')).toBe(true);
      expect(result.badges.some((b) => b.id === 'bruteforce')).toBe(true);
      expect(result.badges.some((b) => b.id === 'malicious')).toBe(true);
      expect(result.behaviors).toContain('tcp:scan');
      expect(result.behaviors).toContain('http:bruteforce');
      expect(result.providers.crowdsec?.score).toBeGreaterThanOrEqual(75);
    });

    test('detects Tor and VPN badges from CrowdSec CTI', async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.55',
          reputation: 'suspicious',
          confidence: 'medium',
          background_noise_score: 5,
          reverse_dns: 'tor-exit.example.org',
          behaviors: [],
          classifications: {
            classifications: ['vpn', 'tor-exit'],
          },
        }),
      });

      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
      });

      const result = await service.lookup('198.51.100.55');

      expect(result.reputation).toBe('suspicious');
      expect(result.badges.some((b) => b.id === 'tor')).toBe(true);
      expect(result.badges.some((b) => b.id === 'vpn')).toBe(true);
    });

    test('handles 404 unknown IP from CrowdSec CTI cleanly', async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
      });

      const result = await service.lookup('198.51.100.99');
      expect(result.ip).toBe('198.51.100.99');
      expect(result.reputation).toBe('unknown');
      expect(result.score).toBe(0);
      expect(result.confidence).toBe('none');
    });

    test('handles upstream CrowdSec network error gracefully', async () => {
      const fetchMock = vi.fn().mockRejectedValueOnce(new Error('Connection timed out'));

      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
      });

      const result = await service.lookup('198.51.100.100');
      expect(result.ip).toBe('198.51.100.100');
      expect(result.reputation).toBe('unknown');
      expect(result.score).toBe(0);
      expect(result.providers.crowdsec?.error).toContain('Connection timed out');
    });
  });

  describe('AbuseIPDB integration', () => {
    test('queries AbuseIPDB and combines score and badges when configured', async () => {
      const fetchMock = vi.fn((url: string) => {
        if (url.includes('crowdsec.net')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({
              ip: '198.51.100.40',
              reputation: 'malicious',
              confidence: 'high',
              background_noise_score: 8,
              behaviors: [{ name: 'tcp:scan', label: 'Port Scan' }],
            }),
          });
        }
        if (url.includes('abuseipdb.com')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({
              data: {
                ipAddress: '198.51.100.40',
                abuseConfidenceScore: 95,
                totalReports: 120,
                usageType: 'Data Center/Web Hosting/Transit',
                reports: [
                  { categories: [14, 18], comment: 'SSH port scan and brute force' },
                ],
              },
            }),
          });
        }
        return Promise.reject(new Error(`Unexpected URL ${url}`));
      });

      const service = new ThreatIntelService({
        crowdsecCtiApiKey: 'crowdsec-key',
        abuseipdbApiKey: 'abuseipdb-key',
        fetchImpl: fetchMock as any,
      });

      const result = await service.lookup('198.51.100.40');

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(result.providers.crowdsec).toBeDefined();
      expect(result.providers.abuseipdb).toBeDefined();
      expect(result.providers.abuseipdb?.score).toBe(95);
      expect(result.score).toBeGreaterThanOrEqual(80);
      expect(result.badges.some((b) => b.id === 'scanner')).toBe(true);
      expect(result.badges.some((b) => b.id === 'vpn')).toBe(true);
    });

    test('continues with CrowdSec results if AbuseIPDB fails', async () => {
      const fetchMock = vi.fn((url: string) => {
        if (url.includes('crowdsec.net')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({
              ip: '198.51.100.41',
              reputation: 'malicious',
              confidence: 'high',
              background_noise_score: 9,
              behaviors: [{ name: 'tcp:scan', label: 'Port Scan' }],
            }),
          });
        }
        if (url.includes('abuseipdb.com')) {
          return Promise.resolve({
            ok: false,
            status: 429,
            statusText: 'Too Many Requests',
          });
        }
        return Promise.reject(new Error(`Unexpected URL ${url}`));
      });

      const service = new ThreatIntelService({
        crowdsecCtiApiKey: 'crowdsec-key',
        abuseipdbApiKey: 'abuseipdb-key',
        fetchImpl: fetchMock as any,
      });

      const result = await service.lookup('198.51.100.41');
      expect(result.reputation).toBe('malicious');
      expect(result.providers.crowdsec?.score).toBeGreaterThanOrEqual(75);
      expect(result.providers.abuseipdb?.error).toContain('429');
    });
  });

  describe('in-memory caching', () => {
    test('serves repeated lookups from cache within TTL', async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.77',
          reputation: 'benign',
          confidence: 'high',
          background_noise_score: 0,
          behaviors: [],
        }),
      });

      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
        cacheTtlMs: 60_000,
      });

      const first = await service.lookup('198.51.100.77');
      expect(first.cached).toBe(false);
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const second = await service.lookup('198.51.100.77');
      expect(second.cached).toBe(true);
      expect(fetchMock).toHaveBeenCalledTimes(1); // Not called again!
    });

    test('refetches when cache TTL has elapsed', async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.88',
          reputation: 'benign',
          confidence: 'low',
        }),
      });

      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
        cacheTtlMs: 10, // 10ms TTL
      });

      const first = await service.lookup('198.51.100.88');
      expect(first.cached).toBe(false);

      // Wait 20ms for cache to expire
      await new Promise((resolve) => setTimeout(resolve, 20));

      const second = await service.lookup('198.51.100.88');
      expect(second.cached).toBe(false);
      expect(fetchMock).toHaveBeenCalledTimes(2);
    });

    test('handles leading/trailing whitespace in IP parameter', async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.12',
          reputation: 'benign',
          confidence: 'high',
        }),
      });

      const service = new ThreatIntelService({
        fetchImpl: fetchMock,
      });

      const result = await service.lookup('   198.51.100.12   ');
      expect(result.ip).toBe('198.51.100.12');
      expect(fetchMock).toHaveBeenCalledWith(
        'https://cti.api.crowdsec.net/v2/smoke/198.51.100.12',
        expect.anything(),
      );
    });

  });
});
