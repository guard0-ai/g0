import { describe, it, expect } from 'vitest';
import { calculateScore } from '../../src/scoring/engine.js';
import { scoreToGrade } from '../../src/scoring/grades.js';
import type { Finding } from '../../src/types/finding.js';

describe('scoreToGrade', () => {
  it('returns A for scores >= 90', () => {
    expect(scoreToGrade(90)).toBe('A');
    expect(scoreToGrade(100)).toBe('A');
    expect(scoreToGrade(95)).toBe('A');
  });

  it('returns B for scores 80-89', () => {
    expect(scoreToGrade(80)).toBe('B');
    expect(scoreToGrade(89)).toBe('B');
  });

  it('returns C for scores 70-79', () => {
    expect(scoreToGrade(70)).toBe('C');
    expect(scoreToGrade(79)).toBe('C');
  });

  it('returns D for scores 60-69', () => {
    expect(scoreToGrade(60)).toBe('D');
    expect(scoreToGrade(69)).toBe('D');
  });

  it('returns F for scores < 60', () => {
    expect(scoreToGrade(59)).toBe('F');
    expect(scoreToGrade(0)).toBe('F');
    expect(scoreToGrade(30)).toBe('F');
  });
});

describe('calculateScore', () => {
  it('returns perfect score with no findings', () => {
    const score = calculateScore([]);
    expect(score.overall).toBe(100);
    expect(score.grade).toBe('A');
    expect(score.domains).toHaveLength(12);
    score.domains.forEach(d => {
      expect(d.score).toBe(100);
      expect(d.findings).toBe(0);
    });
  });

  it('deducts points for critical findings', () => {
    const findings: Finding[] = [
      makeFinding('AA-TS-001', 'critical', 'tool-safety'),
    ];
    const score = calculateScore(findings);
    expect(score.overall).toBeLessThan(100);
    const toolDomain = score.domains.find(d => d.domain === 'tool-safety');
    expect(toolDomain!.score).toBeLessThan(100);
    expect(toolDomain!.critical).toBe(1);
  });

  it('deducts more for critical than for medium', () => {
    const critFindings: Finding[] = [
      makeFinding('AA-TS-001', 'critical', 'tool-safety'),
    ];
    const medFindings: Finding[] = [
      makeFinding('AA-TS-002', 'medium', 'tool-safety'),
    ];
    const critScore = calculateScore(critFindings);
    const medScore = calculateScore(medFindings);
    expect(critScore.overall).toBeLessThan(medScore.overall);
  });

  it('score never goes below 0', () => {
    const findings: Finding[] = [];
    for (let i = 0; i < 50; i++) {
      findings.push(makeFinding(`AA-TS-${i}`, 'critical', 'tool-safety'));
    }
    const score = calculateScore(findings);
    expect(score.overall).toBeGreaterThanOrEqual(0);
    score.domains.forEach(d => {
      expect(d.score).toBeGreaterThanOrEqual(0);
    });
  });

  it('counts findings by severity correctly', () => {
    const findings: Finding[] = [
      makeFinding('AA-GI-001', 'critical', 'goal-integrity'),
      makeFinding('AA-GI-002', 'high', 'goal-integrity'),
      makeFinding('AA-GI-003', 'medium', 'goal-integrity'),
      makeFinding('AA-GI-004', 'low', 'goal-integrity'),
    ];
    const score = calculateScore(findings);
    const gi = score.domains.find(d => d.domain === 'goal-integrity')!;
    expect(gi.critical).toBe(1);
    expect(gi.high).toBe(1);
    expect(gi.medium).toBe(1);
    expect(gi.low).toBe(1);
    expect(gi.findings).toBe(4);
  });

  it('caps low-severity deductions per domain', () => {
    // 50 low findings in one domain should not collapse the score
    const findings: Finding[] = [];
    for (let i = 0; i < 50; i++) {
      findings.push(makeFinding(`AA-GI-${i}`, 'low', 'goal-integrity'));
    }
    const score = calculateScore(findings);
    const gi = score.domains.find(d => d.domain === 'goal-integrity')!;
    // With cap of 10, domain score should be >= 90
    expect(gi.score).toBeGreaterThanOrEqual(90);
  });

  it('caps medium-severity deductions per domain', () => {
    const findings: Finding[] = [];
    for (let i = 0; i < 30; i++) {
      findings.push(makeFinding(`AA-GI-${i}`, 'medium', 'goal-integrity'));
    }
    const score = calculateScore(findings);
    const gi = score.domains.find(d => d.domain === 'goal-integrity')!;
    // With cap of 30, domain score should be >= 70
    expect(gi.score).toBeGreaterThanOrEqual(70);
  });

  it('never grades a project with many criticals better than D', () => {
    // 16 criticals spread across domains must not present as a B, no matter how
    // healthy the other domains look.
    const findings: Finding[] = [];
    for (let i = 0; i < 16; i++) {
      findings.push(makeMaterialFinding(`AA-X-${i}`, 'critical', 'tool-safety'));
    }
    const score = calculateScore(findings);
    expect(score.overall).toBeLessThanOrEqual(69);
    expect(['D', 'F']).toContain(score.grade);
    expect(score.capReason).toBeTruthy();
  });

  it('caps a single exploitable critical at grade D', () => {
    const score = calculateScore([makeMaterialFinding('AA-X-1', 'critical', 'tool-safety')]);
    expect(score.overall).toBeLessThanOrEqual(69);
    expect(score.capReason).toContain('critical');
  });

  it('does not let any critical earn an A grade', () => {
    // Even a discounted (utility-code + unlikely) critical blocks a high grade.
    const f = makeFinding('AA-X-1', 'critical', 'supply-chain');
    f.reachability = 'utility-code';
    f.exploitability = 'unlikely';
    const score = calculateScore([f]);
    expect(score.overall).toBeLessThanOrEqual(79);
    expect(['C', 'D', 'F']).toContain(score.grade);
  });

  it('caps many low-reachability criticals at D', () => {
    // 16 utility-code criticals (the discovery-blind case) must not read as a B.
    const findings: Finding[] = [];
    for (let i = 0; i < 16; i++) {
      const f = makeFinding(`AA-U-${i}`, 'critical', 'code-execution');
      f.reachability = 'utility-code';
      f.exploitability = 'unlikely';
      findings.push(f);
    }
    const score = calculateScore(findings);
    expect(score.overall).toBeLessThanOrEqual(69);
    expect(['D', 'F']).toContain(score.grade);
  });

  it('does not cap when a critical is risk-accepted', () => {
    const f = makeMaterialFinding('AA-X-1', 'critical', 'tool-safety');
    f.accepted = true;
    const score = calculateScore([f]);
    // Accepted findings do not drag the grade; no cap reason expected.
    expect(score.capReason).toBeUndefined();
  });
});

function makeFinding(
  ruleId: string,
  severity: Finding['severity'],
  domain: Finding['domain'],
): Finding {
  return {
    id: `finding-${ruleId}`,
    ruleId,
    title: `Test finding ${ruleId}`,
    description: 'Test',
    severity,
    confidence: 'high',
    domain,
    location: { file: 'test.py', line: 1 },
    remediation: 'Fix it',
    owaspAgentic: ['ASI01'],
  };
}

/** A finding that is reachable and plausibly exploitable ("material"). */
function makeMaterialFinding(
  ruleId: string,
  severity: Finding['severity'],
  domain: Finding['domain'],
): Finding {
  const f = makeFinding(ruleId, severity, domain);
  f.reachability = 'agent-reachable';
  f.exploitability = 'likely';
  return f;
}
