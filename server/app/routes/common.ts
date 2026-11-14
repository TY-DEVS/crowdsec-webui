import type { AddDecisionRequest } from '../../../shared/contracts';
import { DEFAULT_MANUAL_DECISION_SCENARIO, isValidDecisionScenario } from '../../../shared/contracts';
import type { AuditOutcome } from '../../audit-log';
import type { CrowdsecDatabase } from '../../database';

export type HonoContext = any;

export type AnyError = Error & {
  code?: string;
  response?: { data?: unknown; status: number };
  request?: unknown;
  helpLink?: string;
  helpText?: string;
};

export const AUDIT_LIST_LIMIT = 100;
export const BULK_ALLOWLIST_CHECK_CONCURRENCY = 8;
export const MANUAL_DECISION_ORIGINS = ['cscli', 'cscli-import', 'console'];

export function capAuditEntries<T>(entries: T[]): { entries: T[]; truncated: boolean } {
  return entries.length > AUDIT_LIST_LIMIT
    ? { entries: entries.slice(0, AUDIT_LIST_LIMIT), truncated: true }
    : { entries, truncated: false };
}

export function auditTargetOutcome(outcomes: AuditOutcome[]): AuditOutcome {
  if (outcomes.length === 0) return 'success';
  if (outcomes.every((outcome) => outcome === 'success' || outcome === 'queued')) {
    return outcomes.includes('queued') ? 'queued' : 'success';
  }
  if (outcomes.every((outcome) => outcome === 'failure')) return 'failure';
  return 'partial';
}

export function resolveDecisionAuditTargets(
  database: CrowdsecDatabase,
  refs: Array<{ id: string | number; instance_id?: string }>,
): Array<{ id: string; value?: string }> {
  const targets: Array<{ id: string; value?: string }> = [];
  for (const ref of refs) {
    const internalId = ref.instance_id ? database.getDecisionInternalId(ref.instance_id, ref.id) : String(ref.id);
    const value = internalId === null ? undefined : database.getDecisionById(internalId)?.value;
    targets.push({
      id: ref.instance_id ? `${ref.instance_id}:${ref.id}` : String(ref.id),
      ...(typeof value === 'string' && value ? { value } : {}),
    });
  }
  return targets;
}

export function decisionAuditValues(targets: Array<{ value?: string }>): string[] {
  return Array.from(new Set(targets.flatMap((target) => (target.value ? [target.value] : []))));
}

export function parseDecisionSettings(
  body: Omit<AddDecisionRequest, 'ip'>,
): { error: string } | { duration: string; reason: string; type: string; scenario: string } {
  const duration = body.duration || '4h';
  const reason = body.reason || 'manual';
  const type = body.type || 'ban';
  const scenario = typeof body.scenario === 'string' && body.scenario.trim()
    ? body.scenario.trim()
    : DEFAULT_MANUAL_DECISION_SCENARIO;
  const validTypes = ['ban', 'captcha'];
  if (!validTypes.includes(type)) return { error: `Invalid type. Must be one of: ${validTypes.join(', ')}` };
  if (!/^\d+[smhd]$/.test(duration)) return { error: 'Invalid duration format. Use e.g. "4h", "30m", "1d"' };
  if ((body.scenario != null && typeof body.scenario !== 'string') || !isValidDecisionScenario(scenario)) {
    return { error: `Invalid scenario format. Use e.g. "${DEFAULT_MANUAL_DECISION_SCENARIO}"` };
  }
  return { duration, reason, type, scenario };
}
