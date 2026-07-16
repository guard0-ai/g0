import { describe, it, expect } from 'vitest';
import {
  fingerprintFinding,
  buildBaseline,
  diffAgainstBaseline,
} from '../../src/ci/baseline.js';
import type { Finding } from '../../src/types/finding.js';

function makeFinding(ruleId: string, file: string, title: string, line = 1): Finding {
  return {
    id: `f-${ruleId}-${line}`,
    ruleId,
    title,
    description: 'x',
    severity: 'high',
    confidence: 'high',
    domain: 'tool-safety',
    location: { file, line },
    remediation: 'fix',
    standards: { owaspAgentic: ['ASI01'] },
  } as Finding;
}

describe('baseline fingerprinting', () => {
  it('is stable across line-number changes', () => {
    const a = makeFinding('AA-TS-007', 'agent.py', 'subprocess with shell=True', 10);
    const b = makeFinding('AA-TS-007', 'agent.py', 'subprocess with shell=True', 42);
    expect(fingerprintFinding(a)).toBe(fingerprintFinding(b));
  });

  it('normalizes numeric noise in titles', () => {
    const a = makeFinding('AA-DL-046', 'm.py', 'Shared memory across 3 users');
    const b = makeFinding('AA-DL-046', 'm.py', 'Shared memory across 7 users');
    expect(fingerprintFinding(a)).toBe(fingerprintFinding(b));
  });

  it('differs by rule and by file', () => {
    const base = makeFinding('AA-TS-007', 'a.py', 'shell');
    expect(fingerprintFinding(base)).not.toBe(fingerprintFinding(makeFinding('AA-TS-008', 'a.py', 'shell')));
    expect(fingerprintFinding(base)).not.toBe(fingerprintFinding(makeFinding('AA-TS-007', 'b.py', 'shell')));
  });
});

describe('diffAgainstBaseline', () => {
  const existing = [
    makeFinding('AA-TS-007', 'a.py', 'shell injection'),
    makeFinding('AA-DL-023', 'b.py', 'credentials in response'),
  ];

  it('reports zero new findings against its own baseline', () => {
    const baseline = buildBaseline(existing, '2.0.0', '2026-01-01T00:00:00Z');
    const diff = diffAgainstBaseline(existing, baseline);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.knownCount).toBe(2);
  });

  it('detects a newly introduced finding while ignoring known ones', () => {
    const baseline = buildBaseline(existing, '2.0.0', '2026-01-01T00:00:00Z');
    const withNew = [...existing, makeFinding('AA-IA-001', 'c.py', 'hardcoded api key')];
    const diff = diffAgainstBaseline(withNew, baseline);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].ruleId).toBe('AA-IA-001');
    expect(diff.knownCount).toBe(2);
  });

  it('treats a known finding at a shifted line as known', () => {
    const baseline = buildBaseline(existing, '2.0.0', '2026-01-01T00:00:00Z');
    const shifted = [makeFinding('AA-TS-007', 'a.py', 'shell injection', 99)];
    const diff = diffAgainstBaseline(shifted, baseline);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.knownCount).toBe(1);
  });
});
