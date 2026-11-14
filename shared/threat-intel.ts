export type ThreatIntelReputation = 'malicious' | 'suspicious' | 'benign' | 'unknown';

export type ThreatIntelConfidence = 'high' | 'medium' | 'low' | 'none';

export type ThreatIntelBadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'secondary' | 'outline';

export interface ThreatIntelBadge {
  id: string;
  label: string;
  variant: ThreatIntelBadgeVariant;
  description?: string;
}

export interface ThreatIntelProviderResult {
  name: 'crowdsec' | 'abuseipdb';
  score: number;
  confidence?: ThreatIntelConfidence;
  reputation?: ThreatIntelReputation;
  lastSeen?: string | null;
  behaviors?: string[];
  badges?: ThreatIntelBadge[];
  rawSummary?: Record<string, unknown>;
  error?: string;
}

export interface ThreatIntelLookupResponse {
  ip: string;
  score: number;
  confidence: ThreatIntelConfidence;
  reputation: ThreatIntelReputation;
  badges: ThreatIntelBadge[];
  behaviors: string[];
  providers: {
    crowdsec?: ThreatIntelProviderResult;
    abuseipdb?: ThreatIntelProviderResult;
  };
  cached: boolean;
  cachedAt: string;
}

export interface ThreatIntelConfig {
  crowdsecCtiApiKey?: string;
  abuseipdbApiKey?: string;
  cacheTtlMs?: number;
  timeoutMs?: number;
}
