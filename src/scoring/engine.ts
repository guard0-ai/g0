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

export function calculateScore(findings: Finding[]): ScanScore {
  const domains: DomainScore[] = ALL_DOMAINS.map(domain => {
    const domainFindings = findings.filter(f => f.domain === domain);
    const critical = domainFindings.filter(f => f.severity === 'critical').length;
    const high = domainFindings.filter(f => f.severity === 'high').length;
    const medium = domainFindings.filter(f => f.severity === 'medium').length;
    const low = domainFindings.filter(f => f.severity === 'low').length;

    // Calculate deductions with reachability and exploitability multipliers
    let totalDeduction = 0;
    for (const f of domainFindings) {
      const base = SEVERITY_DEDUCTIONS[f.severity] ?? 0;
      const reachMult = REACHABILITY_MULTIPLIERS[f.reachability ?? 'unknown'] ?? 0.6;
      const exploitMult = EXPLOITABILITY_MULTIPLIERS[f.exploitability ?? 'not-assessed'] ?? 0.7;
      totalDeduction += base * reachMult * exploitMult;
    }

    const score = Math.max(0, Math.round(100 - totalDeduction));

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

  return {
    overall,
    grade: scoreToGrade(overall),
    domains,
  };
}
