import { describe, it, expect } from 'vitest';
import {
  REPORT_MARKER,
  STATIC_CTA_LINE,
  countBySeverity,
  renderSeverityTable,
  renderScoreLine,
  renderFindingsSection,
  renderVerdict,
  renderCtaLine,
  renderReportBody,
} from '../../action/src/render.js';
import type { Finding } from '../../src/types/finding.js';
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

describe('countBySeverity', () => {
  it('tallies findings correctly by severity', () => {
    const findings = [
      makeFinding('critical'),
      makeFinding('critical'),
      makeFinding('high'),
      makeFinding('medium'),
      makeFinding('medium'),
      makeFinding('medium'),
      makeFinding('low'),
      makeFinding('info'),
    ];
    expect(countBySeverity(findings)).toEqual({ critical: 2, high: 1, medium: 3, low: 1, info: 1 });
  });

  it('returns all zeros for no findings', () => {
    expect(countBySeverity([])).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });
});

describe('renderSeverityTable', () => {
  it('renders a markdown table with the correct counts', () => {
    const table = renderSeverityTable({ critical: 3, high: 5, medium: 2, low: 1, info: 0 });
    expect(table).toContain('| Critical | 3 |');
    expect(table).toContain('| High | 5 |');
    expect(table).toContain('| Medium | 2 |');
    expect(table).toContain('| Low | 1 |');
  });
});

describe('renderFindingsSection', () => {
  it('lists all findings when at or under the limit', () => {
    const findings = [makeFinding('critical'), makeFinding('high')];
    const out = renderFindingsSection(findings, 10);
    expect(out).toContain('CRITICAL');
    expect(out).toContain('HIGH');
    expect(out).not.toContain('<details>');
  });

  it('truncates to the limit and puts the rest in a <details> block', () => {
    const findings = Array.from({ length: 15 }, (_, i) =>
      makeFinding('medium', { title: `finding-${i}`, location: { file: 'a.py', line: i } }),
    );
    const out = renderFindingsSection(findings, 10);

    // First 10 appear outside the details block.
    for (let i = 0; i < 10; i++) {
      expect(out).toContain(`finding-${i}`);
    }
    expect(out).toContain('<details>');
    expect(out).toContain('<summary>5 more findings</summary>');
    // The remaining 5 are present (inside the details block).
    for (let i = 10; i < 15; i++) {
      expect(out).toContain(`finding-${i}`);
    }
  });

  it('sorts by severity (most severe first) before truncating', () => {
    const findings = [
      makeFinding('low', { title: 'low-1' }),
      makeFinding('critical', { title: 'critical-1' }),
      makeFinding('medium', { title: 'medium-1' }),
    ];
    const out = renderFindingsSection(findings, 2);
    // Only the 2 most severe should be visible (outside <details>).
    const beforeDetails = out.split('<details>')[0];
    expect(beforeDetails).toContain('critical-1');
    expect(beforeDetails).toContain('medium-1');
    expect(beforeDetails).not.toContain('low-1');
  });

  it('returns a placeholder for zero findings', () => {
    expect(renderFindingsSection([], 10)).toContain('No findings');
  });
});

describe('renderScoreLine', () => {
  it('renders plain score/grade with no base diff', () => {
    expect(renderScoreLine(78, 'B', null)).toBe('Score 78/100 (B)');
  });

  it('renders the delta line format when a base diff is present', () => {
    const line = renderScoreLine(78, 'B', { scoreDelta: 4, newFindingsCount: 2 });
    expect(line).toContain('▲ +4');
    expect(line).toContain('vs base');
    expect(line).toContain('2 new findings');
  });

  it('renders a negative delta with a down arrow', () => {
    const line = renderScoreLine(60, 'C', { scoreDelta: -10, newFindingsCount: 1 });
    expect(line).toContain('▼ -10');
    expect(line).toContain('1 new finding');
    expect(line).not.toContain('1 new findings');
  });

  it('renders a zero delta distinctly', () => {
    const line = renderScoreLine(70, 'B', { scoreDelta: 0, newFindingsCount: 0 });
    expect(line).toContain('± 0');
  });
});

describe('renderVerdict', () => {
  it('renders a passed verdict with no failure reasons', () => {
    const out = renderVerdict(true, []);
    expect(out).toContain('PASSED');
    expect(out).not.toContain('FAILED');
  });

  it('renders a failed verdict with each failure reason listed', () => {
    const out = renderVerdict(false, ['Score 40 is below minimum 70', '3 critical finding(s) detected']);
    expect(out).toContain('FAILED');
    expect(out).toContain('Score 40 is below minimum 70');
    expect(out).toContain('3 critical finding(s) detected');
  });
});

describe('renderCtaLine', () => {
  it('returns the static UTM line when enabled', () => {
    expect(renderCtaLine(true)).toBe(STATIC_CTA_LINE);
  });

  it('returns null when disabled', () => {
    expect(renderCtaLine(false)).toBeNull();
  });
});

describe('renderReportBody', () => {
  it('always includes the sticky-comment marker', () => {
    const body = renderReportBody({
      score: 90,
      grade: 'A',
      passed: true,
      failures: [],
      findings: [],
      signupCta: false,
    });
    expect(body.startsWith(REPORT_MARKER)).toBe(true);
  });

  it('includes the CTA line when signupCta is true', () => {
    const body = renderReportBody({
      score: 90,
      grade: 'A',
      passed: true,
      failures: [],
      findings: [],
      signupCta: true,
    });
    expect(body).toContain(STATIC_CTA_LINE);
  });

  it('omits the CTA line when signupCta is false', () => {
    const body = renderReportBody({
      score: 90,
      grade: 'A',
      passed: true,
      failures: [],
      findings: [],
      signupCta: false,
    });
    expect(body).not.toContain('guard0.ai/signup');
  });

  it('includes the base diff delta line when provided', () => {
    const body = renderReportBody({
      score: 82,
      grade: 'B',
      passed: true,
      failures: [],
      findings: [],
      baseDiff: { scoreDelta: 4, newFindingsCount: 2 },
      signupCta: false,
    });
    expect(body).toContain('▲ +4');
    expect(body).toContain('2 new findings');
  });
});
