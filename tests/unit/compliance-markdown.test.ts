import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { reportComplianceMarkdown } from '../../src/reporters/compliance-markdown.js';
import type { ScanResult } from '../../src/types/score.js';
import type { Finding } from '../../src/types/finding.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1',
    ruleId: 'AA-GI-001',
    title: 'Test finding',
    description: 'A test finding',
    severity: 'critical',
    confidence: 'high',
    domain: 'goal-integrity',
    location: { file: 'agent.py', line: 42, column: 0 },
    remediation: 'Fix it',
    standards: {},
    ...overrides,
  };
}

function makeScanResult(findings: Finding[] = []): ScanResult {
  return {
    score: { overall: 65, grade: 'C', domains: [] },
    findings,
    graph: { agents: [], tools: [], edges: [], models: [] } as any,
    duration: 100,
    timestamp: new Date().toISOString(),
  };
}

describe('compliance-markdown reporter', () => {
  const tmpFiles: string[] = [];

  function tmpPath(): string {
    const p = path.join(os.tmpdir(), `g0-test-${Date.now()}-${Math.random().toString(36).slice(2)}.md`);
    tmpFiles.push(p);
    return p;
  }

  afterEach(() => {
    for (const f of tmpFiles) {
      try { fs.unlinkSync(f); } catch {}
    }
    tmpFiles.length = 0;
  });

  it('generates a valid markdown file for iso42001', () => {
    const out = tmpPath();
    reportComplianceMarkdown(makeScanResult(), 'iso42001', out);
    const md = fs.readFileSync(out, 'utf-8');

    expect(md).toContain('# ISO 42001 AI Management System');
    expect(md).toContain('## Summary');
    expect(md).toContain('## Controls');
    expect(md).toContain('| Status | Control | Name | Findings | Notes |');
    expect(md).toContain('guard0.ai');
  });

  it('shows pass for controls with no findings', () => {
    const out = tmpPath();
    reportComplianceMarkdown(makeScanResult([]), 'iso42001', out);
    const md = fs.readFileSync(out, 'utf-8');

    expect(md).toContain('✅ PASS');
    expect(md).not.toContain('❌ FAIL');
  });

  it('shows fail for controls with critical findings', () => {
    const out = tmpPath();
    const finding = makeFinding({ severity: 'critical', domain: 'goal-integrity' });
    reportComplianceMarkdown(makeScanResult([finding]), 'iso42001', out);
    const md = fs.readFileSync(out, 'utf-8');

    expect(md).toContain('❌ FAIL');
    expect(md).toContain('`AA-GI-001`');
  });

  it('shows partial for controls with medium findings', () => {
    const out = tmpPath();
    const finding = makeFinding({ severity: 'medium', domain: 'data-leakage' });
    reportComplianceMarkdown(makeScanResult([finding]), 'iso42001', out);
    const md = fs.readFileSync(out, 'utf-8');

    expect(md).toContain('⚠️ PARTIAL');
  });

  it('throws for unknown standard', () => {
    const out = tmpPath();
    expect(() => reportComplianceMarkdown(makeScanResult(), 'unknown-standard', out)).toThrow('Unknown standard');
  });

  it('works with all supported standards', () => {
    const standards = ['owasp-agentic', 'iso42001', 'nist-ai-rmf', 'soc2', 'eu-ai-act'];
    for (const std of standards) {
      const out = tmpPath();
      reportComplianceMarkdown(makeScanResult(), std, out);
      const md = fs.readFileSync(out, 'utf-8');
      expect(md).toContain('## Controls');
    }
  });

  it('includes score and grade', () => {
    const out = tmpPath();
    reportComplianceMarkdown(makeScanResult(), 'iso42001', out);
    const md = fs.readFileSync(out, 'utf-8');

    expect(md).toContain('65/100');
    expect(md).toContain('(C)');
  });
});
