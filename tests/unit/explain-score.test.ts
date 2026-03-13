import { describe, it, expect } from 'vitest';
import { buildExplainScoreData } from '../../src/reporters/explain-score.js';
import type { ScanScore, DomainScore } from '../../src/types/score.js';

function makeDomain(domain: string, label: string, score: number, weight: number): DomainScore {
  return { domain: domain as any, label, score, weight, findings: score < 100 ? 1 : 0, critical: 0, high: 0, medium: score < 100 ? 1 : 0, low: 0 };
}

describe('buildExplainScoreData', () => {
  const domains: DomainScore[] = [
    makeDomain('goal-integrity', 'Goal Integrity', 80, 1.5),
    makeDomain('tool-safety', 'Tool Safety', 60, 1.5),
    makeDomain('identity-access', 'Identity & Access', 100, 1.2),
    makeDomain('supply-chain', 'Supply Chain', 90, 1.0),
    makeDomain('code-execution', 'Code Execution', 50, 1.3),
    makeDomain('memory-context', 'Memory & Context', 100, 1.1),
    makeDomain('data-leakage', 'Data Leakage', 70, 1.3),
    makeDomain('cascading-failures', 'Cascading Failures', 100, 1.2),
    makeDomain('human-oversight', 'Human Oversight', 100, 1.0),
    makeDomain('inter-agent', 'Inter-Agent', 100, 1.1),
    makeDomain('reliability-bounds', 'Reliability Bounds', 100, 1.2),
    makeDomain('rogue-agent', 'Rogue Agent', 100, 1.4),
  ];
  const totalWeight = domains.reduce((s, d) => s + d.weight, 0);
  const overall = Math.round(domains.reduce((s, d) => s + d.score * d.weight, 0) / totalWeight);
  const score: ScanScore = { overall, grade: 'B', domains };

  it('returns correct number of rows', () => { expect(buildExplainScoreData(score).rows).toHaveLength(12); });
  it('calculates weighted contribution', () => { expect(buildExplainScoreData(score).rows.find(r => r.domain === 'goal-integrity')!.weightedContribution).toBe(120); });
  it('identifies lowest-scoring domains', () => {
    const data = buildExplainScoreData(score);
    expect(data.topImprovements[0].domain).toBe('code-execution');
    expect(data.topImprovements[1].domain).toBe('tool-safety');
  });
  it('calculates potential gain', () => {
    expect(buildExplainScoreData(score).topImprovements[0].potentialGain).toBe(Math.round((50 * 1.3) / totalWeight));
  });
  it('overall matches', () => { expect(buildExplainScoreData(score).overall).toBe(overall); });
  it('perfect scores have zero gain', () => {
    const p: ScanScore = { overall: 100, grade: 'A', domains: domains.map(d => ({ ...d, score: 100 })) };
    expect(buildExplainScoreData(p).topImprovements.every(i => i.potentialGain === 0)).toBe(true);
  });
});
