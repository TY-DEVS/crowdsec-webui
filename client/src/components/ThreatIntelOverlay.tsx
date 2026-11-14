import { useEffect, useState } from 'react';
import { Shield, ExternalLink, Loader2 } from 'lucide-react';
import { Badge } from './ui/Badge';
import { fetchThreatIntelLookup } from '../lib/api';
import type { ThreatIntelLookupResponse } from '../types';
import { useI18n } from '../lib/i18n';

interface ThreatIntelOverlayProps {
  ip: string | undefined | null;
  className?: string;
}

interface ThreatIntelState {
  key: string;
  data: ThreatIntelLookupResponse | null;
  loading: boolean;
  error: string | null;
}

export function ThreatIntelOverlay({ ip, className }: ThreatIntelOverlayProps) {
  const { t } = useI18n();
  const targetIp = ip?.trim() || '';

  const [state, setState] = useState<ThreatIntelState>({
    key: '',
    data: null,
    loading: false,
    error: null,
  });

  useEffect(() => {
    if (!targetIp) return;
    let cancelled = false;

    void (async () => {
      try {
        const res = await fetchThreatIntelLookup(targetIp);
        if (cancelled) return;
        setState({
          key: targetIp,
          data: res,
          loading: false,
          error: null,
        });
      } catch (err: unknown) {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : 'Threat intelligence lookup failed';
        setState({
          key: targetIp,
          data: null,
          loading: false,
          error: message,
        });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [targetIp]);

  if (!targetIp) return null;

  const isCurrent = state.key === targetIp;
  const loading = !isCurrent || state.loading;
  const data = isCurrent ? state.data : null;
  const error = isCurrent ? state.error : null;

  const score = data?.score ?? 0;
  const reputation = data?.reputation ?? 'unknown';
  const confidence = data?.confidence ?? 'none';

  const scoreColorClass =
    score >= 70 || reputation === 'malicious'
      ? 'text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
      : score >= 25 || reputation === 'suspicious'
        ? 'text-yellow-700 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
        : reputation === 'benign'
          ? 'text-green-700 dark:text-green-400 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
          : 'text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-800 border-gray-200 dark:border-gray-700';

  return (
    <div
      className={`rounded-lg border border-gray-200 bg-white p-4 shadow-sm dark:border-gray-700 dark:bg-gray-800 ${className || ''}`}
      data-testid="threat-intel-overlay"
    >
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-primary-600 dark:text-primary-400 shrink-0" />
          <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">
            {t('pages.alerts.threatIntelTitle', { defaultValue: 'Threat Intelligence Reputation' })}
          </h4>
        </div>
        <a
          href={`https://app.crowdsec.net/cti/${encodeURIComponent(targetIp)}`}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1 text-xs text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 transition-colors"
          title={t('pages.alerts.viewOnCti', { defaultValue: 'View on CrowdSec CTI' })}
        >
          <span>{t('pages.alerts.viewOnCti', { defaultValue: 'View on CrowdSec CTI' })}</span>
          <ExternalLink size={12} className="shrink-0" />
        </a>
      </div>

      {loading && (
        <div className="flex items-center gap-2 py-3 text-sm text-gray-500 dark:text-gray-400">
          <Loader2 size={16} className="animate-spin text-primary-500 shrink-0" />
          <span>{t('pages.alerts.threatIntelLoading', { defaultValue: 'Loading threat intelligence reputation...' })}</span>
        </div>
      )}

      {error && !loading && (
        <div className="py-2 text-xs text-gray-500 dark:text-gray-400">
          {t('pages.alerts.threatIntelUnavailable', { defaultValue: 'Threat intelligence reputation unavailable' })}
        </div>
      )}

      {data && !loading && !error && (
        <div className="space-y-3">
          {/* Score & Confidence Banner */}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className={`inline-flex items-center gap-2.5 px-3 py-1.5 rounded-lg border ${scoreColorClass}`}>
              <div className="flex items-baseline gap-1">
                <span className="text-lg font-bold font-mono leading-none">{data.score}</span>
                <span className="text-[10px] opacity-70 leading-none">/ 100</span>
              </div>
              <span className="h-3 w-px bg-current opacity-30" />
              <span className="text-xs font-semibold uppercase tracking-wider">
                {reputation}
              </span>
            </div>

            <div className="flex items-center gap-1.5 text-xs text-gray-600 dark:text-gray-300">
              <span className="text-xs">Confidence: {confidence}</span>
            </div>
          </div>

          {/* Badges */}
          {data.badges && data.badges.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 pt-1" data-testid="threat-intel-badges">
              {data.badges.map((badge) => (
                <Badge key={badge.id} variant={badge.variant}>
                  {badge.label}
                </Badge>
              ))}
            </div>
          )}

          {/* Behaviors */}
          {data.behaviors && data.behaviors.length > 0 && (
            <div className="flex flex-wrap items-center gap-1 pt-1 text-xs text-gray-500 dark:text-gray-400">
              <span className="font-semibold uppercase tracking-wider text-[10px]">Behaviors:</span>
              {data.behaviors.map((behavior) => (
                <span
                  key={behavior}
                  className="font-mono bg-gray-100 dark:bg-gray-700/60 px-1.5 py-0.5 rounded text-[11px] text-gray-700 dark:text-gray-300"
                >
                  {behavior}
                </span>
              ))}
            </div>
          )}

          {/* Provider consensus footer */}
          <div className="pt-2 border-t border-gray-100 dark:border-gray-700/60 flex items-center justify-between text-[11px] text-gray-500 dark:text-gray-400">
            <div className="flex items-center gap-2">
              <span>CrowdSec CTI</span>
              {data.providers.abuseipdb && !data.providers.abuseipdb.error && (
                <>
                  <span>·</span>
                  <span>AbuseIPDB ({data.providers.abuseipdb.score}%)</span>
                </>
              )}
            </div>
            {data.cached && (
              <span className="text-[10px] text-gray-400 uppercase tracking-wider">cached</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
