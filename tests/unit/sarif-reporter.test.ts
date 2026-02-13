import { describe, it, expect } from 'vitest';
import { reportSarif } from '../../src/reporters/sarif.js';
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

describe('SARIF Reporter', () => {
  it('generates valid SARIF 2.1.0 structure', () => {
    const result = makeScanResult([makeFinding()]);
    const json = reportSarif(result);
    const sarif = JSON.parse(json);

    expect(sarif.$schema).toContain('sarif-schema-2.1.0');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('g0');
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  it('includes partialFingerprints on results', () => {
    const result = makeScanResult([makeFinding()]);
    const json = reportSarif(result);
    const sarif = JSON.parse(json);
    const sarifResult = sarif.runs[0].results[0];

    expect(sarifResult.partialFingerprints).toBeDefined();
    expect(sarifResult.partialFingerprints.primaryLocationLineHash).toBeDefined();
    expect(typeof sarifResult.partialFingerprints.primaryLocationLineHash).toBe('string');
    expect(sarifResult.partialFingerprints.primaryLocationLineHash.length).toBe(64); // SHA-256 hex
  });

  it('produces deterministic fingerprints', () => {
    const finding = makeFinding();
    const result1 = reportSarif(makeScanResult([finding]));
    const result2 = reportSarif(makeScanResult([finding]));
    const sarif1 = JSON.parse(result1);
    const sarif2 = JSON.parse(result2);

    expect(sarif1.runs[0].results[0].partialFingerprints.primaryLocationLineHash)
      .toBe(sarif2.runs[0].results[0].partialFingerprints.primaryLocationLineHash);
  });

  it('includes helpUri on rule descriptors', () => {
    const result = makeScanResult([makeFinding()]);
    const json = reportSarif(result);
    const sarif = JSON.parse(json);

    // AA-GI-001 maps to ASI01 which should have a helpUri
    const giRule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'AA-GI-001');
    expect(giRule).toBeDefined();
    expect(giRule.helpUri).toContain('owasp.org');
  });

  it('includes standards in rule properties', () => {
    const result = makeScanResult([makeFinding()]);
    const json = reportSarif(result);
    const sarif = JSON.parse(json);

    const giRule = sarif.runs[0].tool.driver.rules.find((r: { id: string }) => r.id === 'AA-GI-001');
    expect(giRule.properties.standards).toBeDefined();
    expect(giRule.properties.standards.owaspAgentic).toContain('ASI01');
  });

  it('writes to file when outputPath provided', () => {
    const result = makeScanResult([makeFinding()]);
    const tmpPath = '/tmp/test-sarif-output.json';
    reportSarif(result, tmpPath);

    const { readFileSync } = require('node:fs');
    const content = readFileSync(tmpPath, 'utf-8');
    const sarif = JSON.parse(content);
    expect(sarif.version).toBe('2.1.0');

    // Cleanup
    require('node:fs').unlinkSync(tmpPath);
  });
});
