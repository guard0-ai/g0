import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { formatScanResult } from '../../src/mcp/server/format.js';
import { appendCta } from '../../src/mcp/server/cta.js';
import { resetSessionForTests } from '../../src/mcp/server/session.js';
import type { ScanResult } from '../../src/types/score.js';
import type { Finding } from '../../src/types/finding.js';
import type { Severity, Confidence } from '../../src/types/common.js';

function makeFinding(overrides: Partial<Finding> & { id: string }): Finding {
  return {
    id: overrides.id,
    ruleId: overrides.ruleId ?? 'AA-TEST-001',
    title: overrides.title ?? `Finding ${overrides.id}`,
    description: overrides.description ?? 'A test finding.',
    severity: overrides.severity ?? 'medium',
    confidence: overrides.confidence ?? 'medium',
    domain: overrides.domain ?? 'tool-safety',
    location: overrides.location ?? { file: 'agent.py', line: 1 },
    remediation: overrides.remediation ?? 'Fix it.',
    standards: overrides.standards ?? { owaspAgentic: [] },
  };
}

function makeScanResult(findings: Finding[], overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    score: {
      overall: 42,
      grade: 'D',
      domains: [],
      ...overrides.score,
    },
    findings,
    graph: {} as ScanResult['graph'],
    duration: 123,
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('formatScanResult', () => {
  it('sorts findings critical -> low, then by confidence within a severity', () => {
    const findings: Finding[] = [
      makeFinding({ id: 'f-low', severity: 'low', confidence: 'high' }),
      makeFinding({ id: 'f-crit-low-conf', severity: 'critical', confidence: 'low' }),
      makeFinding({ id: 'f-crit-high-conf', severity: 'critical', confidence: 'high' }),
      makeFinding({ id: 'f-high', severity: 'high', confidence: 'medium' }),
    ];
    const result = makeScanResult(findings);

    const { structured } = formatScanResult(result);
    const ids = structured.topFindings.map(f => f.id);

    expect(ids).toEqual(['f-crit-high-conf', 'f-crit-low-conf', 'f-high', 'f-low']);
  });

  it('counts findings by severity', () => {
    const findings = [
      makeFinding({ id: '1', severity: 'critical' }),
      makeFinding({ id: '2', severity: 'critical' }),
      makeFinding({ id: '3', severity: 'high' }),
      makeFinding({ id: '4', severity: 'low' }),
    ];
    const result = makeScanResult(findings);

    const { structured } = formatScanResult(result);
    expect(structured.countsBySeverity.critical).toBe(2);
    expect(structured.countsBySeverity.high).toBe(1);
    expect(structured.countsBySeverity.medium).toBe(0);
    expect(structured.countsBySeverity.low).toBe(1);
    expect(structured.totalFindings).toBe(4);
  });

  it('caps the finding list at maxFindings and sets truncated', () => {
    const findings = Array.from({ length: 50 }, (_, i) =>
      makeFinding({ id: `f-${i}`, severity: 'high' }),
    );
    const result = makeScanResult(findings);

    const { markdown, structured } = formatScanResult(result, { maxFindings: 10 });

    expect(structured.topFindings.length).toBe(10);
    expect(structured.truncated).toBe(true);
    expect(markdown).toContain('…and 40 more findings');
    expect(markdown).toContain("Run 'g0 scan .' locally for the full list.");
  });

  it('does not truncate when findings fit under maxFindings', () => {
    const findings = [makeFinding({ id: '1' }), makeFinding({ id: '2' })];
    const result = makeScanResult(findings);

    const { structured, markdown } = formatScanResult(result, { maxFindings: 30 });
    expect(structured.truncated).toBe(false);
    expect(structured.topFindings.length).toBe(2);
    expect(markdown).not.toContain('more findings');
  });

  it('enforces a byte cap on markdown even under maxFindings', () => {
    // Findings with a huge remediation blob so even a handful blow the ~20KB budget.
    const bigRemediation = 'x'.repeat(5000);
    const findings = Array.from({ length: 10 }, (_, i) =>
      makeFinding({ id: `big-${i}`, severity: 'critical', remediation: bigRemediation }),
    );
    const result = makeScanResult(findings);

    const { markdown, structured } = formatScanResult(result, { maxFindings: 30 });

    expect(structured.truncated).toBe(true);
    expect(structured.topFindings.length).toBeLessThan(10);
    expect(Buffer.byteLength(markdown, 'utf-8')).toBeLessThan(25 * 1024);
  });

  it('includes score, grade, capReason, suppressedCount, and duration in structured output', () => {
    const result = makeScanResult([], {
      score: { overall: 55, grade: 'C', capReason: '2 exploitable criticals', domains: [] },
      suppressedCount: 3,
      duration: 987,
    });

    const { structured } = formatScanResult(result);
    expect(structured.score).toBe(55);
    expect(structured.grade).toBe('C');
    expect(structured.capReason).toBe('2 exploitable criticals');
    expect(structured.suppressedCount).toBe(3);
    expect(structured.duration).toBe(987);
  });
});

describe('appendCta', () => {
  beforeEach(() => {
    resetSessionForTests();
    vi.resetModules();
  });

  afterEach(() => {
    vi.doUnmock('../../src/platform/cta.js');
    vi.restoreAllMocks();
  });

  it('appends the CTA line when maybeGetCta returns a string', async () => {
    vi.doMock('../../src/platform/cta.js', () => ({
      maybeGetCta: vi.fn(() => 'Sign up at https://guard0.ai/signup?utm_source=g0'),
    }));
    const { appendCta: appendCtaMocked } = await import('../../src/mcp/server/cta.js');

    const out = await appendCtaMocked('# result', 'scan-complete');
    expect(out).toContain('# result');
    expect(out).toContain('Sign up at https://guard0.ai/signup?utm_source=g0');
  });

  it('returns markdown unchanged when maybeGetCta returns null (suppressed)', async () => {
    vi.doMock('../../src/platform/cta.js', () => ({
      maybeGetCta: vi.fn(() => null),
    }));
    const { appendCta: appendCtaMocked } = await import('../../src/mcp/server/cta.js');

    const out = await appendCtaMocked('# result', 'scan-complete');
    expect(out).toBe('# result');
  });

  it('only appends once per session even across multiple qualifying calls', async () => {
    vi.doMock('../../src/platform/cta.js', () => ({
      maybeGetCta: vi.fn(() => 'CTA line'),
    }));
    const { appendCta: appendCtaMocked } = await import('../../src/mcp/server/cta.js');

    const first = await appendCtaMocked('# first', 'scan-complete');
    const second = await appendCtaMocked('# second', 'criticals-found');

    expect(first).toContain('CTA line');
    expect(second).toBe('# second');
  });

  it('never throws even if platform/cta.js import fails', async () => {
    vi.doMock('../../src/platform/cta.js', () => {
      throw new Error('module load failure');
    });
    const { appendCta: appendCtaMocked } = await import('../../src/mcp/server/cta.js');

    await expect(appendCtaMocked('# result', 'scan-complete')).resolves.toBe('# result');
  });
});
