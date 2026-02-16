import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { runScan } from '../../src/pipeline.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('Cascading failures rules', () => {
  it('detects cascading failure patterns in fixture', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'cascading-failures') });

    const cfFindings = result.findings.filter(f => f.domain === 'cascading-failures');
    expect(cfFindings.length).toBeGreaterThan(5);

    const ruleIds = new Set(cfFindings.map(f => f.ruleId));

    // Retry without max count (infinite while True loop)
    expect(ruleIds.has('AA-CF-003')).toBe(true);

    // Stack trace in error response
    expect(ruleIds.has('AA-CF-004')).toBe(true);

    // No timeout on inter-agent calls (requests.post without timeout)
    expect(ruleIds.has('AA-CF-010')).toBe(true);

    // Bare except: pass
    expect(ruleIds.has('AA-CF-013')).toBe(true);
  });

  it('detects resource exhaustion patterns', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'cascading-failures') });

    const cfFindings = result.findings.filter(f => f.domain === 'cascading-failures');
    // Should detect multiple cascading failure patterns from both hardcoded and YAML rules
    expect(cfFindings.length).toBeGreaterThan(5);
  });

  it('detects error propagation in vulnerable-agent fixture', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'vulnerable-agent') });

    const cfFindings = result.findings.filter(f => f.domain === 'cascading-failures');
    // Should find at least retry-without-max and other CF patterns
    expect(cfFindings.length).toBeGreaterThan(0);
  });
});
