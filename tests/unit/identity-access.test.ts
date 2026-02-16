import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { runScan } from '../../src/pipeline.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('Identity & Access Rules', () => {
  it('detects hardcoded API keys', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'vulnerable-agent') });
    const iaFindings = result.findings.filter(f => f.domain === 'identity-access');
    const keyFindings = iaFindings.filter(f => f.ruleId === 'AA-IA-001');
    expect(keyFindings.length).toBeGreaterThan(0);
  });

  it('detects secrets in MCP config', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'mcp-server') });
    const iaFindings = result.findings.filter(f => f.domain === 'identity-access');
    expect(iaFindings.length).toBeGreaterThan(0);
  });

  it('does not flag dangerous identity issues in clean code', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'langchain-basic') });
    const iaFindings = result.findings.filter(f =>
      f.domain === 'identity-access' && f.severity === 'critical'
    );
    expect(iaFindings.length).toBe(0);
  });
});
