import type { RiskAcceptance } from '../types/config.js';
import type { Finding } from '../types/finding.js';

/** Check whether a risk acceptance entry is still active (not expired) */
export function isAcceptanceActive(acceptance: RiskAcceptance): boolean {
  if (!acceptance.expires) return true;
  try {
    return new Date(acceptance.expires) > new Date();
  } catch {
    return true; // Invalid date format — treat as non-expiring
  }
}

/** Build a lookup set of active risk-accepted rule IDs */
export function buildAcceptanceSet(acceptances: RiskAcceptance[]): Map<string, RiskAcceptance> {
  const map = new Map<string, RiskAcceptance>();
  for (const a of acceptances) {
    if (isAcceptanceActive(a)) {
      map.set(a.rule, a);
    }
  }
  return map;
}

/** Mark findings that match risk-accepted rules. Returns the same array, mutated. */
export function applyRiskAcceptance(
  findings: Finding[],
  acceptances: RiskAcceptance[],
): { findings: Finding[]; acceptedCount: number } {
  if (acceptances.length === 0) return { findings, acceptedCount: 0 };

  const acceptedSet = buildAcceptanceSet(acceptances);
  let acceptedCount = 0;

  for (const finding of findings) {
    const ruleId = finding.ruleId ?? finding.id;
    // Match against the rule ID (e.g., "AA-CE-012") — strip any instance suffix
    const baseRuleId = ruleId.replace(/-\d+$/, '');
    const acceptance = acceptedSet.get(baseRuleId) ?? acceptedSet.get(ruleId);
    if (acceptance) {
      finding.accepted = true;
      finding.acceptedReason = acceptance.reason;
      acceptedCount++;
    }
  }

  return { findings, acceptedCount };
}

/**
 * Check if a hardening check ID is risk-accepted.
 * Returns the acceptance entry if found and active, null otherwise.
 */
export function isCheckAccepted(
  checkId: string,
  acceptances: RiskAcceptance[],
): RiskAcceptance | null {
  for (const a of acceptances) {
    if (a.rule === checkId && isAcceptanceActive(a)) {
      return a;
    }
  }
  return null;
}
