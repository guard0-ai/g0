import { describe, it, expect } from 'vitest';
import { evaluateGate, type GateEvalInput } from '../../src/ci/thresholds.js';
import type { Finding } from '../../src/types/finding.js';
import type { ScanResult } from '../../src/types/score.js';
import type { Severity } from '../../src/types/common.js';

function makeFinding(severity: Severity, overrides: Partial<Finding> = {}): Finding {
  return {
    id: overrides.id ?? `f-${severity}-${Math.random().toString(36).slice(2)}`,
    ruleId: overrides.ruleId ?? 'AA-TEST-001',
    title: overrides.title ?? `${severity} finding`,
    description: overrides.description ?? 'test finding',
    severity,
    confidence: overrides.confidence ?? 'high',
    domain: overrides.domain ?? 'tool-safety',
    location: overrides.location ?? { file: 'src/app.py', line: 10 },
    remediation: overrides.remediation ?? 'fix it',
    standards: overrides.standards ?? { owaspAgentic: ['ASI02'] },
    ...overrides,
  };
}

function makeResult(overallScore: number, grade: ScanResult['score']['grade'], findings: Finding[]): ScanResult {
  return {
    score: {
      overall: overallScore,
      grade,
      domains: [],
    },
    findings,
    graph: {
      rootPath: '.',
      primaryFramework: 'generic',
      agents: [],
      tools: [],
      prompts: [],
      models: [],
      vectorDBs: [],
      apiEndpoints: [],
      apiCalls: [],
      moduleGraph: { nodes: [], edges: [] },
    } as unknown as ScanResult['graph'],
    duration: 100,
    timestamp: new Date().toISOString(),
  };
}

function baseInput(overrides: Partial<GateEvalInput> = {}): GateEvalInput {
  const result = overrides.result ?? makeResult(85, 'A', []);
  return {
    result,
    evalFindings: overrides.evalFindings ?? result.findings,
    inBaselineMode: overrides.inBaselineMode ?? false,
    ...overrides,
  };
}

describe('evaluateGate', () => {
  it('fails when score is below minScore', () => {
    const result = makeResult(60, 'C', []);
    const { passed, failures } = evaluateGate(baseInput({ result, minScore: 70 }));
    expect(passed).toBe(false);
    expect(failures).toEqual(['Score 60 is below minimum 70']);
  });

  it('passes when score meets minScore', () => {
    const result = makeResult(75, 'B', []);
    const { passed, failures } = evaluateGate(baseInput({ result, minScore: 70 }));
    expect(passed).toBe(true);
    expect(failures).toEqual([]);
  });

  it('fails when grade is below minGrade', () => {
    const result = makeResult(90, 'D', []);
    const { passed, failures } = evaluateGate(baseInput({ result, minGrade: 'B' }));
    expect(passed).toBe(false);
    expect(failures[0]).toContain('Grade D is below minimum B');
  });

  it('passes when grade meets minGrade', () => {
    const result = makeResult(90, 'A', []);
    const { passed } = evaluateGate(baseInput({ result, minGrade: 'B' }));
    expect(passed).toBe(true);
  });

  it('fails on any critical finding when failCritical is set', () => {
    const findings = [makeFinding('critical'), makeFinding('low')];
    const result = makeResult(50, 'D', findings);
    const { passed, failures } = evaluateGate(baseInput({ result, failCritical: true }));
    expect(passed).toBe(false);
    expect(failures).toEqual(['1 critical finding(s) detected']);
  });

  it('does not fail on critical findings when failCritical is not set', () => {
    const findings = [makeFinding('critical')];
    const result = makeResult(90, 'A', findings);
    const { passed } = evaluateGate(baseInput({ result }));
    expect(passed).toBe(true);
  });

  it('fails on high or critical findings when failHigh is set', () => {
    const findings = [makeFinding('high'), makeFinding('medium')];
    const result = makeResult(80, 'B', findings);
    const { passed, failures } = evaluateGate(baseInput({ result, failHigh: true }));
    expect(passed).toBe(false);
    expect(failures).toEqual(['1 high/critical finding(s) detected']);
  });

  it('failHigh also counts critical findings', () => {
    const findings = [makeFinding('critical'), makeFinding('high'), makeFinding('low')];
    const result = makeResult(80, 'B', findings);
    const { failures } = evaluateGate(baseInput({ result, failHigh: true }));
    expect(failures).toEqual(['2 high/critical finding(s) detected']);
  });

  it('fails based on failOn severity threshold', () => {
    const findings = [makeFinding('medium'), makeFinding('low')];
    const result = makeResult(80, 'B', findings);
    const { passed, failures } = evaluateGate(baseInput({ result, failOn: 'medium' }));
    expect(passed).toBe(false);
    expect(failures).toEqual(['1 finding(s) at or above medium severity']);
  });

  it('failOn does not flag findings below the threshold', () => {
    const findings = [makeFinding('low'), makeFinding('info')];
    const result = makeResult(80, 'B', findings);
    const { passed } = evaluateGate(baseInput({ result, failOn: 'high' }));
    expect(passed).toBe(true);
  });

  it('baseline mode skips absolute score/grade gates even when they would otherwise fail', () => {
    const result = makeResult(10, 'F', []);
    const { passed, failures } = evaluateGate(baseInput({
      result,
      minScore: 70,
      minGrade: 'B',
      inBaselineMode: true,
    }));
    expect(passed).toBe(true);
    expect(failures).toEqual([]);
  });

  it('baseline mode still evaluates finding-count gates against evalFindings', () => {
    const findings = [makeFinding('critical')];
    const result = makeResult(10, 'F', findings);
    const { passed, failures } = evaluateGate(baseInput({
      result,
      evalFindings: findings,
      failCritical: true,
      inBaselineMode: true,
    }));
    expect(passed).toBe(false);
    expect(failures).toEqual(['1 new critical finding(s) detected']);
  });

  it('baseline mode defaults to failing on new critical/high when no explicit finding gate is set', () => {
    const allFindings = [makeFinding('critical'), makeFinding('low')];
    const newFindings = [makeFinding('critical')];
    const result = makeResult(40, 'D', allFindings);
    const { passed, failures } = evaluateGate(baseInput({
      result,
      evalFindings: newFindings,
      inBaselineMode: true,
    }));
    expect(passed).toBe(false);
    expect(failures).toEqual(['1 new high/critical finding(s) introduced']);
  });

  it('baseline mode default-fail-on-new-severe is suppressed by an explicit failOn', () => {
    const newFindings = [makeFinding('critical')];
    const result = makeResult(40, 'D', newFindings);
    const { failures } = evaluateGate(baseInput({
      result,
      evalFindings: newFindings,
      inBaselineMode: true,
      failOn: 'critical',
    }));
    // Only the explicit failOn failure fires, not the default-severe rule too.
    expect(failures).toEqual(['1 new finding(s) at or above critical severity']);
  });

  it('baseline mode with zero new critical/high findings passes when relying on the default rule', () => {
    const newFindings = [makeFinding('low'), makeFinding('medium')];
    const result = makeResult(90, 'A', newFindings);
    const { passed } = evaluateGate(baseInput({
      result,
      evalFindings: newFindings,
      inBaselineMode: true,
    }));
    expect(passed).toBe(true);
  });
});
