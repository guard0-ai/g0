import type { SecurityDomain } from '../types/common.js';
import type { Finding } from '../types/finding.js';
import type { ScanScore, DomainScore } from '../types/score.js';
import { DOMAIN_WEIGHTS, DOMAIN_LABELS, SEVERITY_DEDUCTIONS, REACHABILITY_MULTIPLIERS, EXPLOITABILITY_MULTIPLIERS } from './weights.js';
import { scoreToGrade } from './grades.js';

const ALL_DOMAINS: SecurityDomain[] = [
  'goal-integrity',
  'tool-safety',
  'identity-access',
  'supply-chain',
  'code-execution',
  'memory-context',
  'data-leakage',
  'cascading-failures',
  'human-oversight',
  'inter-agent',
  'reliability-bounds',
  'rogue-agent',
];

/** Check types that indicate absence-based rules (hardening recommendations) */
const ABSENCE_CHECK_TYPES = new Set([
  'prompt_missing',
  'tool_missing_property',
]);

/**
 * Classify a finding as presence-based (security) or absence-based (hardening).
 * Presence-based: something bad IS there (code pattern, taint flow, dangerous config).
 * Absence-based: something good is MISSING (no guarding, no validation, no boundary).
 */
function isAbsenceBased(finding: Finding): boolean {
  if (finding.checkType && ABSENCE_CHECK_TYPES.has(finding.checkType)) return true;
  // agent_property with "missing" in the title/description is absence-based
  if (finding.checkType === 'agent_property' &&
      (finding.title.toLowerCase().includes('missing') || finding.title.toLowerCase().includes('no '))) {
    return true;
  }
  return false;
}

function computeDomainScore(domainFindings: Finding[]): number {
  let totalDeduction = 0;
  for (const f of domainFindings) {
    const base = SEVERITY_DEDUCTIONS[f.severity] ?? 0;
    const reachMult = REACHABILITY_MULTIPLIERS[f.reachability ?? 'unknown'] ?? 0.6;
    const exploitMult = EXPLOITABILITY_MULTIPLIERS[f.exploitability ?? 'not-assessed'] ?? 0.7;
    totalDeduction += base * reachMult * exploitMult;
  }
  return Math.max(0, Math.round(100 - totalDeduction));
}

export function calculateScore(findings: Finding[]): ScanScore {
  const domains: DomainScore[] = ALL_DOMAINS.map(domain => {
    const domainFindings = findings.filter(f => f.domain === domain);
    const critical = domainFindings.filter(f => f.severity === 'critical').length;
    const high = domainFindings.filter(f => f.severity === 'high').length;
    const medium = domainFindings.filter(f => f.severity === 'medium').length;
    const low = domainFindings.filter(f => f.severity === 'low').length;

    const score = computeDomainScore(domainFindings);

    return {
      domain,
      label: DOMAIN_LABELS[domain],
      score,
      weight: DOMAIN_WEIGHTS[domain],
      findings: domainFindings.length,
      critical,
      high,
      medium,
      low,
    };
  });

  const totalWeight = domains.reduce((sum, d) => sum + d.weight, 0);
  const weightedSum = domains.reduce((sum, d) => sum + d.score * d.weight, 0);
  const overall = Math.round(weightedSum / totalWeight);

  // Split scoring: separate presence-based (security) from absence-based (hardening)
  const securityFindings = findings.filter(f => !isAbsenceBased(f));
  const hardeningFindings = findings.filter(f => isAbsenceBased(f));

  const securityScore = securityFindings.length > 0
    ? computeWeightedScore(securityFindings)
    : 100;
  const hardeningScore = hardeningFindings.length > 0
    ? computeWeightedScore(hardeningFindings)
    : 100;

  return {
    overall,
    grade: scoreToGrade(overall),
    domains,
    securityScore,
    hardeningScore,
  };
}

/**
 * Compute a weighted score from a subset of findings across all domains.
 */
function computeWeightedScore(findings: Finding[]): number {
  const domainScores = ALL_DOMAINS.map(domain => {
    const domainFindings = findings.filter(f => f.domain === domain);
    return {
      score: computeDomainScore(domainFindings),
      weight: DOMAIN_WEIGHTS[domain],
    };
  });

  const totalWeight = domainScores.reduce((sum, d) => sum + d.weight, 0);
  const weightedSum = domainScores.reduce((sum, d) => sum + d.score * d.weight, 0);
  return Math.round(weightedSum / totalWeight);
}
