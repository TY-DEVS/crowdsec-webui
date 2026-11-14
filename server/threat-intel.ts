import net from 'node:net';
import type {
  ThreatIntelBadge,
  ThreatIntelConfidence,
  ThreatIntelLookupResponse,
  ThreatIntelProviderResult,
  ThreatIntelReputation,
} from '../shared/threat-intel';

export interface ThreatIntelServiceOptions {
  crowdsecCtiApiKey?: string;
  abuseipdbApiKey?: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
      return false;
    }
    const [b0, b1] = parts;
    // 0.0.0.0/8
    if (b0 === 0) return true;
    // 10.0.0.0/8
    if (b0 === 10) return true;
    // 127.0.0.0/8 (loopback)
    if (b0 === 127) return true;
    // 169.254.0.0/16 (link-local)
    if (b0 === 169 && b1 === 254) return true;
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
    // 192.168.0.0/16
    if (b0 === 192 && b1 === 168) return true;
    // 224.0.0.0/4 (multicast)
    if (b0 >= 224 && b0 <= 239) return true;
    // 240.0.0.0/4 (reserved / broadcast)
    if (b0 >= 240) return true;
    return false;
  }

  if (family === 6) {
    const lower = ip.toLowerCase();
    // Loopback
    if (lower === '::1') return true;
    // Unspecified
    if (lower === '::') return true;
    // Unique local address (fc00::/7)
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
    // Link-local (fe80::/10)
    if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
    // Multicast (ff00::/8)
    if (lower.startsWith('ff')) return true;
    return false;
  }

  return false;
}

interface CacheEntry {
  data: ThreatIntelLookupResponse;
  expiresAt: number;
}

export class ThreatIntelService {
  private readonly crowdsecCtiApiKey?: string;
  private readonly abuseipdbApiKey?: string;
  private readonly cacheTtlMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: ThreatIntelServiceOptions = {}) {
    this.crowdsecCtiApiKey = options.crowdsecCtiApiKey?.trim() || undefined;
    this.abuseipdbApiKey = options.abuseipdbApiKey?.trim() || undefined;
    this.cacheTtlMs = options.cacheTtlMs ?? 60 * 60 * 1000; // 1 hour default
    this.timeoutMs = options.timeoutMs ?? 10_000;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
  }

  async lookup(rawIp: string): Promise<ThreatIntelLookupResponse> {
    const ip = rawIp?.trim();
    if (!ip || net.isIP(ip) === 0) {
      throw new Error(`Invalid IP address: "${rawIp}"`);
    }

    if (isPrivateOrReservedIp(ip)) {
      return {
        ip,
        score: 0,
        confidence: 'none',
        reputation: 'benign',
        badges: [
          {
            id: 'private',
            label: 'Private IP',
            variant: 'outline',
            description: 'Internal or reserved network address',
          },
        ],
        behaviors: [],
        providers: {},
        cached: false,
        cachedAt: new Date().toISOString(),
      };
    }

    // Check cache
    const cached = this.cache.get(ip);
    if (cached && cached.expiresAt > Date.now()) {
      return {
        ...cached.data,
        cached: true,
      };
    }

    // Run lookups in parallel
    const [crowdsecResult, abuseipdbResult] = await Promise.all([
      this.fetchCrowdsecCti(ip),
      this.abuseipdbApiKey ? this.fetchAbuseIpDb(ip) : Promise.resolve(null),
    ]);

    const aggregated = this.aggregateResults(ip, crowdsecResult, abuseipdbResult);

    // Cache the result
    this.cache.set(ip, {
      data: aggregated,
      expiresAt: Date.now() + this.cacheTtlMs,
    });

    return {
      ...aggregated,
      cached: false,
    };
  }

  private async fetchCrowdsecCti(ip: string): Promise<ThreatIntelProviderResult> {
    const url = `https://cti.api.crowdsec.net/v2/smoke/${encodeURIComponent(ip)}`;
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };
    if (this.crowdsecCtiApiKey) {
      headers['x-api-key'] = this.crowdsecCtiApiKey;
    }

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const response = await this.fetchImpl(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));

      if (response.status === 404) {
        return {
          name: 'crowdsec',
          score: 0,
          confidence: 'none',
          reputation: 'unknown',
          behaviors: [],
          badges: [],
        };
      }

      if (!response.ok) {
        return {
          name: 'crowdsec',
          score: 0,
          confidence: 'none',
          reputation: 'unknown',
          error: `CrowdSec CTI responded with HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const body = (await response.json()) as any;
      const reputation = this.normalizeReputation(body.reputation);
      const confidence = this.normalizeConfidence(body.confidence);
      const noiseScore = typeof body.background_noise_score === 'number' ? body.background_noise_score : 0;

      let score = 0;
      if (reputation === 'malicious') {
        score = Math.max(75, Math.min(100, Math.round((noiseScore || 8) * 10)));
      } else if (reputation === 'suspicious') {
        score = Math.max(40, Math.min(74, Math.round((noiseScore || 5) * 10)));
      } else if (reputation === 'benign') {
        score = 0;
      } else {
        score = Math.min(30, Math.round(noiseScore * 10));
      }

      const behaviors: string[] = Array.isArray(body.behaviors)
        ? body.behaviors.map((b: any) => b?.name || String(b)).filter(Boolean)
        : [];

      const badges: ThreatIntelBadge[] = [];

      // Malicious / Suspicious badges
      if (reputation === 'malicious') {
        badges.push({ id: 'malicious', label: 'Malicious', variant: 'danger' });
      } else if (reputation === 'suspicious') {
        badges.push({ id: 'suspicious', label: 'Suspicious', variant: 'warning' });
      } else if (reputation === 'benign') {
        badges.push({ id: 'benign', label: 'Clean', variant: 'success' });
      }

      // Scanner badge
      const isScanner = behaviors.some((b) => /scan|crawler|probe/i.test(b)) ||
        (Array.isArray(body.behaviors) && body.behaviors.some((b: any) => /scan|crawler/i.test(b?.label || '')));
      if (isScanner) {
        badges.push({ id: 'scanner', label: 'Known Scanner', variant: 'warning' });
      }

      // Brute force badge
      const isBruteforce = behaviors.some((b) => /bruteforce/i.test(b)) ||
        (Array.isArray(body.behaviors) && body.behaviors.some((b: any) => /bruteforce/i.test(b?.label || '')));
      if (isBruteforce) {
        badges.push({ id: 'bruteforce', label: 'Brute Force', variant: 'danger' });
      }

      // Tor badge
      const reverseDns = String(body.reverse_dns || '').toLowerCase();
      const classifications = Array.isArray(body.classifications?.classifications)
        ? body.classifications.classifications.map((c: any) => String(c).toLowerCase())
        : [];
      if (reverseDns.includes('tor') || classifications.some((c: string) => c.includes('tor'))) {
        badges.push({ id: 'tor', label: 'Tor Node', variant: 'info' });
      }

      // VPN / Proxy badge
      if (classifications.some((c: string) => /vpn|proxy|hosting/i.test(c))) {
        badges.push({ id: 'vpn', label: 'VPN / Proxy', variant: 'secondary' });
      }

      return {
        name: 'crowdsec',
        score,
        confidence,
        reputation,
        lastSeen: body.history?.last_seen || null,
        behaviors,
        badges,
        rawSummary: {
          background_noise_score: noiseScore,
          reverse_dns: body.reverse_dns,
          as_name: body.as_name,
          as_num: body.as_num,
        },
      };
    } catch (err: any) {
      return {
        name: 'crowdsec',
        score: 0,
        confidence: 'none',
        reputation: 'unknown',
        error: err.message || 'Failed to query CrowdSec CTI',
      };
    }
  }

  private async fetchAbuseIpDb(ip: string): Promise<ThreatIntelProviderResult> {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const headers: Record<string, string> = {
      Accept: 'application/json',
      Key: this.abuseipdbApiKey!,
    };

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const response = await this.fetchImpl(url, {
        method: 'GET',
        headers,
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));

      if (!response.ok) {
        return {
          name: 'abuseipdb',
          score: 0,
          confidence: 'none',
          reputation: 'unknown',
          error: `AbuseIPDB responded with HTTP ${response.status}: ${response.statusText}`,
        };
      }

      const body = (await response.json()) as any;
      const data = body.data || {};
      const abuseConfidenceScore = typeof data.abuseConfidenceScore === 'number' ? data.abuseConfidenceScore : 0;
      const totalReports = typeof data.totalReports === 'number' ? data.totalReports : 0;
      const isWhitelisted = Boolean(data.isWhitelisted);

      let reputation: ThreatIntelReputation = 'unknown';
      if (isWhitelisted) {
        reputation = 'benign';
      } else if (abuseConfidenceScore >= 75) {
        reputation = 'malicious';
      } else if (abuseConfidenceScore >= 25) {
        reputation = 'suspicious';
      } else if (totalReports === 0) {
        reputation = 'benign';
      }

      let confidence: ThreatIntelConfidence = 'none';
      if (totalReports >= 10 || isWhitelisted) {
        confidence = 'high';
      } else if (totalReports > 0) {
        confidence = 'medium';
      } else if (abuseConfidenceScore > 0) {
        confidence = 'low';
      }

      const badges: ThreatIntelBadge[] = [];
      const usageType = String(data.usageType || '').toLowerCase();
      const domain = String(data.domain || '').toLowerCase();

      if (usageType.includes('data center') || usageType.includes('hosting') || usageType.includes('transit') || usageType.includes('vpn')) {
        badges.push({ id: 'vpn', label: 'VPN / Hosting', variant: 'secondary' });
      }

      if (domain.includes('tor') || usageType.includes('tor')) {
        badges.push({ id: 'tor', label: 'Tor Node', variant: 'info' });
      }

      // Check report categories (14: port scan, 18: brute force)
      if (Array.isArray(data.reports)) {
        for (const report of data.reports) {
          const categories: number[] = Array.isArray(report.categories) ? report.categories : [];
          if (categories.includes(14) && !badges.some((b) => b.id === 'scanner')) {
            badges.push({ id: 'scanner', label: 'Known Scanner', variant: 'warning' });
          }
          if (categories.includes(18) && !badges.some((b) => b.id === 'bruteforce')) {
            badges.push({ id: 'bruteforce', label: 'Brute Force', variant: 'danger' });
          }
        }
      }

      return {
        name: 'abuseipdb',
        score: isWhitelisted ? 0 : abuseConfidenceScore,
        confidence,
        reputation,
        lastSeen: data.lastReportedAt || null,
        badges,
        rawSummary: {
          totalReports,
          usageType: data.usageType,
          isp: data.isp,
          isWhitelisted,
        },
      };
    } catch (err: any) {
      return {
        name: 'abuseipdb',
        score: 0,
        confidence: 'none',
        reputation: 'unknown',
        error: err.message || 'Failed to query AbuseIPDB',
      };
    }
  }

  private aggregateResults(
    ip: string,
    crowdsec: ThreatIntelProviderResult,
    abuseipdb: ThreatIntelProviderResult | null,
  ): ThreatIntelLookupResponse {
    const providers: ThreatIntelLookupResponse['providers'] = {};
    const badgesMap = new Map<string, ThreatIntelBadge>();
    const behaviorsSet = new Set<string>();

    if (crowdsec) {
      providers.crowdsec = crowdsec;
      for (const badge of crowdsec.badges || []) {
        badgesMap.set(badge.id, badge);
      }
      for (const b of crowdsec.behaviors || []) {
        behaviorsSet.add(b);
      }
    }

    if (abuseipdb) {
      providers.abuseipdb = abuseipdb;
      for (const badge of abuseipdb.badges || []) {
        badgesMap.set(badge.id, badge);
      }
    }

    // Determine overall score: take highest confidence / maximum risk score
    let score = 0;
    if (abuseipdb && !abuseipdb.error && !crowdsec.error) {
      score = Math.max(crowdsec.score, abuseipdb.score);
    } else if (crowdsec && !crowdsec.error) {
      score = crowdsec.score;
    } else if (abuseipdb && !abuseipdb.error) {
      score = abuseipdb.score;
    }

    // Determine reputation
    let reputation: ThreatIntelReputation = 'unknown';
    if (score >= 70) {
      reputation = 'malicious';
    } else if (score >= 25) {
      reputation = 'suspicious';
    } else if (crowdsec.reputation === 'benign' || abuseipdb?.reputation === 'benign') {
      reputation = 'benign';
    } else if (crowdsec.reputation === 'unknown' && (!abuseipdb || abuseipdb.reputation === 'unknown')) {
      reputation = 'unknown';
    }

    // Add reputation badge if not already added
    if (reputation === 'malicious' && !badgesMap.has('malicious')) {
      badgesMap.set('malicious', { id: 'malicious', label: 'Malicious', variant: 'danger' });
    } else if (reputation === 'suspicious' && !badgesMap.has('suspicious')) {
      badgesMap.set('suspicious', { id: 'suspicious', label: 'Suspicious', variant: 'warning' });
    }

    // Determine confidence
    let confidence: ThreatIntelConfidence = 'none';
    if (crowdsec.confidence === 'high' || abuseipdb?.confidence === 'high') {
      confidence = 'high';
    } else if (crowdsec.confidence === 'medium' || abuseipdb?.confidence === 'medium') {
      confidence = 'medium';
    } else if (crowdsec.confidence === 'low' || abuseipdb?.confidence === 'low') {
      confidence = 'low';
    }

    return {
      ip,
      score,
      confidence,
      reputation,
      badges: Array.from(badgesMap.values()),
      behaviors: Array.from(behaviorsSet),
      providers,
      cached: false,
      cachedAt: new Date().toISOString(),
    };
  }

  private normalizeReputation(val: unknown): ThreatIntelReputation {
    const s = String(val || '').toLowerCase();
    if (s === 'malicious') return 'malicious';
    if (s === 'suspicious') return 'suspicious';
    if (s === 'benign') return 'benign';
    return 'unknown';
  }

  private normalizeConfidence(val: unknown): ThreatIntelConfidence {
    const s = String(val || '').toLowerCase();
    if (s === 'high') return 'high';
    if (s === 'medium') return 'medium';
    if (s === 'low') return 'low';
    return 'none';
  }
}
