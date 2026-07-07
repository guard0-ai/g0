import type { SecurityDomain } from '../types/common.js';
import type { Finding } from '../types/finding.js';
import type { ScanScore, DomainScore } from '../types/score.js';
import type { ModuleGraph } from '../analyzers/ast/module-graph.js';
import { DOMAIN_WEIGHTS, DOMAIN_LABELS, SEVERITY_DEDUCTIONS, REACHABILITY_MULTIPLIERS, EXPLOITABILITY_MULTIPLIERS } from './weights.js';
import { scoreToGrade } from './grades.js';
import { correlateFindings } from './correlation.js';

export interface ScoringThresholds {
  max_findings_per_rule?: number;
  low_severity_cap?: number;
  medium_severity_cap?: number;
}

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

/** Default max deduction from low-severity findings per domain */
const DEFAULT_LOW_SEVERITY_CAP = 10;
/** Default max deduction from medium-severity findings per domain */
const DEFAULT_MEDIUM_SEVERITY_CAP = 30;

/** Score ceilings that correspond to the top of each letter grade. */
const GRADE_CEILING = { F: 55, D: 69, C: 79, B: 89 } as const;

/**
 * A finding is "material" if it is not risk-accepted and not clearly discounted.
 * A critical that is BOTH utility-code AND judged unlikely to be exploited is the
 * only critical we treat as non-material — everything else counts against the grade.
 */
function isMaterial(f: Finding): boolean {
  if (f.accepted) return false;
  if (f.reachability === 'utility-code' && f.exploitability === 'unlikely') return false;
  return true;
}

/**
 * Cap the overall score so the letter grade can never contradict the finding
 * counts a user can see. A scanner that reports critical findings must not
 * present a healthy grade — per-domain averaging otherwise dilutes a handful of
 * criticals across twelve domains and yields a misleadingly high score.
 *
 * Returns the score ceiling to apply and a human-readable reason (or null when
 * no cap is warranted).
 */
function computeGradeCap(findings: Finding[]): { ceiling: number; reason: string } | null {
  const active = findings.filter(f => !f.accepted);
  const criticals = active.filter(f => f.severity === 'critical');
  const highs = active.filter(f => f.severity === 'high');
  const materialCriticals = criticals.filter(isMaterial).length;
  const materialHighs = highs.filter(isMaterial).length;
  const rawCriticals = criticals.length;
  const rawHighs = highs.length;

  // Exploitable ("material") criticals are the strongest signal.
  if (materialCriticals >= 3) {
    return { ceiling: GRADE_CEILING.F, reason: `${materialCriticals} exploitable critical findings` };
  }
  if (materialCriticals >= 1) {
    return {
      ceiling: GRADE_CEILING.D,
      reason: `${materialCriticals} exploitable critical finding${materialCriticals === 1 ? '' : 's'}`,
    };
  }
  // Reachability is a best-effort heuristic (see analyzability), so a large number
  // of criticals caps the grade even when they currently read as low-reachability —
  // "unreachable" is not the same as "safe".
  if (rawCriticals >= 5) {
    return { ceiling: GRADE_CEILING.D, reason: `${rawCriticals} critical findings present` };
  }
  if (rawCriticals >= 1) {
    return {
      ceiling: GRADE_CEILING.C,
      reason: `${rawCriticals} critical finding${rawCriticals === 1 ? '' : 's'} present`,
    };
  }
  if (materialHighs >= 5) {
    return { ceiling: GRADE_CEILING.C, reason: `${materialHighs} exploitable high-severity findings` };
  }
  if (rawHighs >= 8) {
    return { ceiling: GRADE_CEILING.B, reason: `${rawHighs} high-severity findings present` };
  }
  return null;
}

function computeDomainScore(domainFindings: Finding[], thresholds?: ScoringThresholds): number {
  let lowDeduction = 0;
  let mediumDeduction = 0;
  let otherDeduction = 0;
  for (const f of domainFindings) {
    const base = SEVERITY_DEDUCTIONS[f.severity] ?? 0;
    const reachMult = REACHABILITY_MULTIPLIERS[f.reachability ?? 'unknown'] ?? 0.6;
    const exploitMult = EXPLOITABILITY_MULTIPLIERS[f.exploitability ?? 'not-assessed'] ?? 0.7;
    const deduction = base * reachMult * exploitMult;
    if (f.severity === 'low') {
      lowDeduction += deduction;
    } else if (f.severity === 'medium') {
      mediumDeduction += deduction;
    } else {
      otherDeduction += deduction;
    }
  }
  const lowCap = thresholds?.low_severity_cap ?? DEFAULT_LOW_SEVERITY_CAP;
  const medCap = thresholds?.medium_severity_cap ?? DEFAULT_MEDIUM_SEVERITY_CAP;
  const totalDeduction = otherDeduction
    + Math.min(mediumDeduction, medCap)
    + Math.min(lowDeduction, lowCap);
  return Math.max(0, Math.round(100 - totalDeduction));
}

export function calculateScore(
  findings: Finding[],
  moduleGraph?: ModuleGraph,
  thresholds?: ScoringThresholds,
  domainWeightOverrides?: Partial<Record<SecurityDomain, number>>,
): ScanScore {
  // Detect cross-domain attack chains
  const correlation = correlateFindings(findings, moduleGraph);
  const chainBonus = new Map<SecurityDomain, number>();
  for (const detected of correlation.chains) {
    for (const link of detected.chain.links) {
      const current = chainBonus.get(link.domain) ?? 0;
      chainBonus.set(link.domain, current + detected.chain.bonusDeduction);
    }
  }

  const domains: DomainScore[] = ALL_DOMAINS.map(domain => {
    const domainFindings = findings.filter(f => f.domain === domain);
    const critical = domainFindings.filter(f => f.severity === 'critical').length;
    const high = domainFindings.filter(f => f.severity === 'high').length;
    const medium = domainFindings.filter(f => f.severity === 'medium').length;
    const low = domainFindings.filter(f => f.severity === 'low').length;

    let score = computeDomainScore(domainFindings, thresholds);

    // Apply attack chain bonus deduction
    const bonus = chainBonus.get(domain) ?? 0;
    if (bonus > 0) {
      score = Math.max(0, score - bonus);
    }

    const weight = domainWeightOverrides?.[domain] ?? DOMAIN_WEIGHTS[domain];

    return {
      domain,
      label: DOMAIN_LABELS[domain],
      score,
      weight,
      findings: domainFindings.length,
      critical,
      high,
      medium,
      low,
    };
  });

  const totalWeight = domains.reduce((sum, d) => sum + d.weight, 0);
  const weightedSum = domains.reduce((sum, d) => sum + d.score * d.weight, 0);
  const rawOverall = Math.round(weightedSum / totalWeight);

  // Cap the grade so it can never contradict visible critical/high counts.
  const cap = computeGradeCap(findings);
  const overall = cap ? Math.min(rawOverall, cap.ceiling) : rawOverall;
  const capReason = cap && overall < rawOverall ? cap.reason : undefined;

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
    capReason,
    domains,
    securityScore,
    hardeningScore,
    correlations: correlation.chains.length > 0
      ? {
          chains: correlation.chains.map(c => ({
            name: c.chain.name,
            description: c.chain.description,
            findingIds: c.matchedFindings.map(f => f.id),
            amplifier: c.chain.bonusDeduction,
          })),
        }
      : undefined,
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
