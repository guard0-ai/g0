import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';
import { runScan } from '../../src/pipeline.js';
import { reportJson } from '../../src/reporters/json.js';
import { reportHtml } from '../../src/reporters/html.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('End-to-end scan: vulnerable-agent', () => {
  it('finds issues across all domains', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'vulnerable-agent') });

    expect(result.findings.length).toBeGreaterThan(20);
    expect(result.score.grade).toBe('F');
    expect(result.score.overall).toBeLessThan(60);

    const domains = new Set(result.findings.map(f => f.domain));
    expect(domains.has('goal-integrity')).toBe(true);
    expect(domains.has('tool-safety')).toBe(true);
    expect(domains.has('code-execution')).toBe(true);
    expect(domains.has('data-leakage')).toBe(true);
  });

  it('detects LangChain framework', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'vulnerable-agent') });
    expect(result.graph.primaryFramework).toBe('langchain');
  });
});

describe('End-to-end scan: langchain-basic', () => {
  it('produces clean scan for basic agent', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'langchain-basic') });
    expect(result.score.overall).toBeGreaterThanOrEqual(50);
    expect(result.score.grade).toMatch(/^[A-D]$/);
    // No critical findings
    const criticalFindings = result.findings.filter(f => f.severity === 'critical');
    expect(criticalFindings.length).toBe(0);
  });
});

describe('End-to-end scan: crewai-crew', () => {
  it('detects CrewAI framework and finds issues', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'crewai-crew') });
    expect(result.graph.primaryFramework).toBe('crewai');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});

describe('End-to-end scan: mcp-server', () => {
  it('detects MCP framework and finds issues', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'mcp-server') });
    expect(result.graph.primaryFramework).toBe('mcp');
    expect(result.findings.length).toBeGreaterThan(0);

    const tsFindings = result.findings.filter(f => f.domain === 'tool-safety');
    expect(tsFindings.length).toBeGreaterThan(0);
  });
});

describe('End-to-end scan: openai-assistant', () => {
  it('detects OpenAI framework', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'openai-assistant') });
    expect(result.graph.primaryFramework).toBe('openai');
  });
});

describe('JSON reporter', () => {
  it('produces valid JSON with all fields', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'vulnerable-agent') });
    const json = reportJson(result);
    const parsed = JSON.parse(json);

    expect(parsed.version).toBe('1.0.0');
    expect(parsed.timestamp).toBeTruthy();
    expect(parsed.score.overall).toBeTypeOf('number');
    expect(parsed.score.grade).toBeTruthy();
    expect(parsed.score.domains).toBeInstanceOf(Array);
    expect(parsed.findings).toBeInstanceOf(Array);
    expect(parsed.findings[0].ruleId).toBeTruthy();
    expect(parsed.findings[0].severity).toBeTruthy();
    expect(parsed.graph).toBeTruthy();
  });

  it('writes to file when path provided', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'langchain-basic') });
    const tmpFile = path.join(os.tmpdir(), `g0-test-${Date.now()}.json`);
    reportJson(result, tmpFile);
    expect(fs.existsSync(tmpFile)).toBe(true);
    const content = JSON.parse(fs.readFileSync(tmpFile, 'utf-8'));
    expect(content.score.overall).toBeGreaterThanOrEqual(50);
    fs.unlinkSync(tmpFile);
  });
});

describe('HTML reporter', () => {
  it('produces valid HTML file', async () => {
    const result = await runScan({ targetPath: path.join(FIXTURES, 'vulnerable-agent') });
    const tmpFile = path.join(os.tmpdir(), `g0-test-${Date.now()}.html`);
    reportHtml(result, tmpFile);
    expect(fs.existsSync(tmpFile)).toBe(true);
    const content = fs.readFileSync(tmpFile, 'utf-8');
    expect(content).toContain('<!DOCTYPE html>');
    expect(content).toContain('g0 Security Report');
    expect(content).toContain('Goal Integrity');
    fs.unlinkSync(tmpFile);
  });
});
