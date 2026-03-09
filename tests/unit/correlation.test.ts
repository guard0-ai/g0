import { describe, it, expect } from 'vitest';
import { correlateFindings } from '../../src/scoring/correlation.js';
import { calculateScore } from '../../src/scoring/engine.js';
import type { Finding } from '../../src/types/finding.js';

function makeFinding(
  ruleId: string,
  severity: Finding['severity'],
  domain: Finding['domain'],
  file = 'test.py',
): Finding {
  return {
    id: `finding-${ruleId}`,
    ruleId,
    title: `Test finding ${ruleId}`,
    description: 'Test',
    severity,
    confidence: 'high',
    domain,
    location: { file, line: 1 },
    remediation: 'Fix it',
    standards: { owaspAgentic: ['ASI01'] },
  };
}

describe('correlateFindings', () => {
  it('detects injection-to-rce chain', () => {
    const findings = [
      makeFinding('AA-GI-022', 'high', 'goal-integrity'),
      makeFinding('AA-CE-002', 'critical', 'code-execution'),
    ];
    const result = correlateFindings(findings);
    expect(result.chains.length).toBeGreaterThanOrEqual(1);
    expect(result.chains[0].chain.id).toBe('injection-to-rce');
    expect(result.amplifiedFindingIds.size).toBe(2);
  });

  it('detects prompt-injection-to-tool-abuse chain', () => {
    const findings = [
      makeFinding('AA-GI-051', 'high', 'goal-integrity'),
      makeFinding('AA-TS-007', 'critical', 'tool-safety'),
    ];
    const result = correlateFindings(findings);
    expect(result.chains.some(c => c.chain.id === 'prompt-injection-to-tool-abuse')).toBe(true);
  });

  it('does not detect chain when severity too low', () => {
    const findings = [
      makeFinding('AA-GI-022', 'low', 'goal-integrity'), // below medium threshold
      makeFinding('AA-CE-002', 'critical', 'code-execution'),
    ];
    const result = correlateFindings(findings);
    expect(result.chains.filter(c => c.chain.id === 'injection-to-rce').length).toBe(0);
  });

  it('does not detect chain when only one domain matches', () => {
    const findings = [
      makeFinding('AA-GI-022', 'high', 'goal-integrity'),
      // No code-execution finding
    ];
    const result = correlateFindings(findings);
    expect(result.chains.filter(c => c.chain.id === 'injection-to-rce').length).toBe(0);
  });

  it('returns empty for clean findings', () => {
    const findings = [
      makeFinding('AA-SC-001', 'low', 'supply-chain'),
    ];
    const result = correlateFindings(findings);
    expect(result.chains.length).toBe(0);
    expect(result.amplifiedFindingIds.size).toBe(0);
  });

  it('detects multiple chains simultaneously', () => {
    const findings = [
      makeFinding('AA-GI-022', 'high', 'goal-integrity'),
      makeFinding('AA-CE-002', 'critical', 'code-execution'),
      makeFinding('AA-TS-007', 'critical', 'tool-safety'),
      makeFinding('AA-DL-023', 'high', 'data-leakage'),
      makeFinding('AA-CE-043', 'high', 'code-execution'),
    ];
    const result = correlateFindings(findings);
    expect(result.chains.length).toBeGreaterThanOrEqual(2);
  });
});

describe('calculateScore with correlation', () => {
  it('applies bonus deduction for detected chains', () => {
    const chainFindings = [
      makeFinding('AA-GI-022', 'high', 'goal-integrity'),
      makeFinding('AA-CE-002', 'critical', 'code-execution'),
    ];
    const singleFindings = [
      makeFinding('AA-GI-022', 'high', 'goal-integrity'),
    ];

    const chainScore = calculateScore(chainFindings);
    const singleScore = calculateScore(singleFindings);

    // Chain findings should produce a lower score due to correlation bonus
    expect(chainScore.overall).toBeLessThan(singleScore.overall + 10);
    expect(chainScore.correlations).toBeDefined();
    expect(chainScore.correlations!.chains.length).toBeGreaterThanOrEqual(1);
  });

  it('includes correlations in score output', () => {
    const findings = [
      makeFinding('AA-GI-022', 'high', 'goal-integrity'),
      makeFinding('AA-CE-002', 'critical', 'code-execution'),
    ];
    const score = calculateScore(findings);
    expect(score.correlations).toBeDefined();
    expect(score.correlations!.chains[0].name).toContain('Injection');
  });

  it('does not include correlations when no chains detected', () => {
    const findings = [
      makeFinding('AA-SC-001', 'low', 'supply-chain'),
    ];
    const score = calculateScore(findings);
    expect(score.correlations).toBeUndefined();
  });
});
