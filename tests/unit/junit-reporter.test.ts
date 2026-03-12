import { describe, it, expect } from 'vitest';
import { reportJunit } from '../../src/reporters/junit.js';
import type { ScanResult } from '../../src/types/score.js';
import type { Finding } from '../../src/types/finding.js';

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: 'AA-GI-001-0',
    ruleId: 'AA-GI-001',
    title: 'Test finding',
    description: 'Test description',
    severity: 'high',
    confidence: 'high',
    domain: 'goal-integrity',
    location: { file: 'agent.py', line: 10, snippet: 'some code here' },
    remediation: 'Fix it',
    standards: { owaspAgentic: ['ASI01'] },
    ...overrides,
  };
}

function makeScanResult(findings: Finding[]): ScanResult {
  return {
    findings,
    score: {
      overall: 75,
      grade: 'C' as const,
      domains: [],
    },
    graph: {
      rootPath: '/test',
      primaryFramework: 'langchain',
      secondaryFrameworks: [],
      agents: [],
      tools: [],
      prompts: [],
      files: { all: [], python: [], typescript: [], javascript: [], configs: [] },
      models: [],
      vectorDBs: [],
      mcpServers: [],
    },
    timestamp: '2025-01-01T00:00:00.000Z',
    duration: 1000,
  };
}

describe('JUnit XML Reporter', () => {
  it('generates valid JUnit XML structure', () => {
    const result = makeScanResult([makeFinding()]);
    const xml = reportJunit(result);

    expect(xml).toContain('<?xml version="1.0" encoding="UTF-8"?>');
    expect(xml).toContain('<testsuites name="g0-scan"');
    expect(xml).toContain('tests="1"');
    expect(xml).toContain('failures="1"');
    expect(xml).toContain('<testsuite name="goal-integrity"');
    expect(xml).toContain('<testcase name="AA-GI-001"');
    expect(xml).toContain('classname="goal-integrity"');
  });

  it('marks high/critical/medium as failures, low/info as pass', () => {
    const result = makeScanResult([
      makeFinding({ id: 'f1', ruleId: 'R-001', severity: 'critical', domain: 'tool-safety' }),
      makeFinding({ id: 'f2', ruleId: 'R-002', severity: 'high', domain: 'tool-safety' }),
      makeFinding({ id: 'f3', ruleId: 'R-003', severity: 'medium', domain: 'tool-safety' }),
      makeFinding({ id: 'f4', ruleId: 'R-004', severity: 'low', domain: 'tool-safety' }),
      makeFinding({ id: 'f5', ruleId: 'R-005', severity: 'info', domain: 'tool-safety' }),
    ]);
    const xml = reportJunit(result);

    expect(xml).toContain('tests="5" failures="3"');
    // critical, high, medium have <failure>
    expect((xml.match(/<failure /g) || []).length).toBe(3);
  });

  it('groups findings by domain into testsuites', () => {
    const result = makeScanResult([
      makeFinding({ id: 'f1', ruleId: 'R-001', domain: 'tool-safety' }),
      makeFinding({ id: 'f2', ruleId: 'R-002', domain: 'goal-integrity' }),
      makeFinding({ id: 'f3', ruleId: 'R-003', domain: 'tool-safety' }),
    ]);
    const xml = reportJunit(result);

    expect((xml.match(/<testsuite /g) || []).length).toBe(2);
    expect(xml).toContain('<testsuite name="tool-safety" tests="2"');
    expect(xml).toContain('<testsuite name="goal-integrity" tests="1"');
  });

  it('escapes XML special characters', () => {
    const result = makeScanResult([
      makeFinding({ title: 'Finding with <special> & "chars"' }),
    ]);
    const xml = reportJunit(result);

    expect(xml).toContain('&lt;special&gt;');
    expect(xml).toContain('&amp;');
    expect(xml).toContain('&quot;chars&quot;');
    // Must be valid XML (no unescaped < > & in content)
    expect(xml).not.toMatch(/<failure[^>]*>[^<]*<[^/!][^<]*<\/failure>/);
  });

  it('handles empty findings', () => {
    const result = makeScanResult([]);
    const xml = reportJunit(result);

    expect(xml).toContain('tests="0" failures="0"');
    expect(xml).not.toContain('<testsuite ');
  });

  it('includes file location and remediation in failure body', () => {
    const result = makeScanResult([
      makeFinding({
        ruleId: 'AA-TS-003',
        title: 'Unsandboxed tool call',
        location: { file: 'tools.ts', line: 18 },
        remediation: 'Add sandbox wrapper',
      }),
    ]);
    const xml = reportJunit(result);

    expect(xml).toContain('tools.ts:18');
    expect(xml).toContain('AA-TS-003');
    expect(xml).toContain('Add sandbox wrapper');
  });

  it('writes to file when outputPath is provided', async () => {
    const fs = await import('node:fs');
    const os = await import('node:os');
    const path = await import('node:path');
    const tmpFile = path.join(os.tmpdir(), `junit-test-${Date.now()}.xml`);

    try {
      const result = makeScanResult([makeFinding()]);
      reportJunit(result, tmpFile);

      const content = fs.readFileSync(tmpFile, 'utf-8');
      expect(content).toContain('<?xml version="1.0"');
      expect(content).toContain('<testsuites');
    } finally {
      fs.unlinkSync(tmpFile);
    }
  });
});
