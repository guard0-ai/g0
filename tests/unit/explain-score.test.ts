import { describe, it, expect } from 'vitest';
import { buildExplainScoreData } from '../../src/reporters/explain-score.js';
import type { ScanScore, DomainScore } from '../../src/types/score.js';

function makeDomain(domain: string, label: string, score: number, weight: number): DomainScore {
  return {
    domain: domain as any,
    label,
    score,
    weight,
    findings: score < 100 ? 1 : 0,
    critical: 0,
    high: 0,
    medium: score < 100 ? 1 : 0,
    low: 0,
  };
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
  const weightedSum = domains.reduce((s, d) => s + d.score * d.weight, 0);
  const overall = Math.round(weightedSum / totalWeight);

  const score: ScanScore = {
    overall,
    grade: 'B',
    domains,
  };

  it('returns correct number of rows', () => {
    const data = buildExplainScoreData(score);
    expect(data.rows).toHaveLength(12);
  });

  it('calculates weighted contribution correctly', () => {
    const data = buildExplainScoreData(score);
    const goalRow = data.rows.find(r => r.domain === 'goal-integrity')!;
    expect(goalRow.weightedContribution).toBe(80 * 1.5);
  });

  it('identifies lowest-scoring domains as top improvements', () => {
    const data = buildExplainScoreData(score);
    expect(data.topImprovements).toHaveLength(3);
    expect(data.topImprovements[0].domain).toBe('code-execution');
    expect(data.topImprovements[0].score).toBe(50);
    expect(data.topImprovements[1].domain).toBe('tool-safety');
    expect(data.topImprovements[1].score).toBe(60);
  });

  it('calculates potential gain correctly', () => {
    const data = buildExplainScoreData(score);
    const codeExec = data.topImprovements[0];
    const expectedGain = Math.round((50 * 1.3) / totalWeight);
    expect(codeExec.potentialGain).toBe(expectedGain);
  });

  it('overall matches input score', () => {
    const data = buildExplainScoreData(score);
    expect(data.overall).toBe(overall);
  });

  it('handles perfect scores with no improvements', () => {
    const perfectDomains = domains.map(d => ({ ...d, score: 100 }));
    const perfectScore: ScanScore = {
      overall: 100,
      grade: 'A',
      domains: perfectDomains,
    };
    const data = buildExplainScoreData(perfectScore);
    expect(data.topImprovements.every(i => i.potentialGain === 0)).toBe(true);
  });
});
