import { describe, it, expect } from 'vitest';
import { runCIGate, formatGitHubAnnotations, formatCIOutput } from '../../src/ci/gate.js';
import { evaluatePolicy, getCIExitCode } from '../../src/governance/policy-engine.js';
import type { SecurityPolicy } from '../../src/governance/policy-engine.js';

// Helper: build a minimal policy with scan spec
function makePolicy(spec: SecurityPolicy['spec']): SecurityPolicy {
  return {
    apiVersion: 'g0/v1',
    kind: 'SecurityPolicy',
    metadata: { name: 'test-policy' },
    spec,
  };
}

describe('CI Gate', () => {
  it('returns pass when no policy is found', () => {
    const result = runCIGate({ policyPath: '/nonexistent/path/.g0-policy.yaml' });

    expect(result.exitCode).toBe(0);
    expect(result.evaluation).toBeNull();
    expect(result.summary).toContain('No policy found');
    expect(result.annotations).toHaveLength(0);
  });

  it('returns pass when policy has no violations', () => {
    const policy = makePolicy({ scan: { maxCritical: 5, maxHigh: 10 } });
    const evaluation = evaluatePolicy(policy, { criticalCount: 0, highCount: 0 });
    const exitCode = getCIExitCode(evaluation);

    expect(exitCode).toBe(0);
    expect(evaluation.passed).toBe(true);
    expect(evaluation.violations).toHaveLength(0);
  });

  it('returns exit code 1 for critical violations', () => {
    const policy = makePolicy({ scan: { maxCritical: 0 } });
    const evaluation = evaluatePolicy(policy, { criticalCount: 3 });

    expect(getCIExitCode(evaluation)).toBe(1);
    expect(evaluation.passed).toBe(false);
    expect(evaluation.violations[0].severity).toBe('critical');
  });

  it('returns exit code 1 for high violations', () => {
    const policy = makePolicy({ scan: { maxHigh: 0 } });
    const evaluation = evaluatePolicy(policy, { highCount: 5 });

    expect(getCIExitCode(evaluation)).toBe(1);
    expect(evaluation.violations[0].severity).toBe('high');
  });

  it('returns exit code 2 for medium-only violations', () => {
    const policy = makePolicy({
      scan: { requiredStandards: ['OWASP-ASVS'] },
    });
    const evaluation = evaluatePolicy(policy, { standards: [] });

    expect(getCIExitCode(evaluation)).toBe(2);
    expect(evaluation.violations.every(v => v.severity === 'medium')).toBe(true);
  });

  it('formats GitHub Actions annotations correctly', () => {
    const result = runCIGate({ policyPath: '/nonexistent/.g0-policy.yaml' });
    // No annotations for missing policy
    expect(formatGitHubAnnotations(result)).toBe('');

    // Test with annotations present
    const resultWithAnnotations = {
      exitCode: 1,
      evaluation: null,
      summary: 'test',
      annotations: [
        { level: 'error' as const, message: 'Too many criticals', rule: 'scan.maxCritical' },
        { level: 'warning' as const, message: 'Missing standard', rule: 'scan.requiredStandards' },
        { level: 'notice' as const, message: 'Minor issue', rule: 'scan.info' },
      ],
    };

    const output = formatGitHubAnnotations(resultWithAnnotations);
    expect(output).toContain('::error::Too many criticals [scan.maxCritical]');
    expect(output).toContain('::warning::Missing standard [scan.requiredStandards]');
    expect(output).toContain('::notice::Minor issue [scan.info]');
  });

  it('formats generic CI output with readable text', () => {
    const passingResult = {
      exitCode: 0,
      evaluation: null,
      summary: 'All policy checks passed',
      annotations: [],
    };
    const passOutput = formatCIOutput(passingResult);
    expect(passOutput).toContain('PASS');
    expect(passOutput).toContain('All policy checks passed');

    const failingResult = {
      exitCode: 1,
      evaluation: null,
      summary: '2 violations (1 critical, 1 high)',
      annotations: [
        { level: 'error' as const, message: 'Critical finding exceeded', rule: 'scan.maxCritical' },
        { level: 'error' as const, message: 'High finding exceeded', rule: 'scan.maxHigh' },
      ],
    };
    const failOutput = formatCIOutput(failingResult);
    expect(failOutput).toContain('FAIL');
    expect(failOutput).toContain('[ERROR] Critical finding exceeded (scan.maxCritical)');
    expect(failOutput).toContain('[ERROR] High finding exceeded (scan.maxHigh)');

    const warnResult = {
      exitCode: 2,
      evaluation: null,
      summary: '1 violation (1 medium)',
      annotations: [
        { level: 'warning' as const, message: 'Missing standard', rule: 'scan.requiredStandards' },
      ],
    };
    const warnOutput = formatCIOutput(warnResult);
    expect(warnOutput).toContain('WARNING');
    expect(warnOutput).toContain('[WARN] Missing standard');
  });

  it('maps violation severities to correct annotation levels', () => {
    const policy = makePolicy({
      scan: { maxCritical: 0, requiredStandards: ['SOC2'] },
    });
    const evaluation = evaluatePolicy(policy, { criticalCount: 1, standards: [] });

    // Build annotations the same way runCIGate does
    const annotations = evaluation.violations.map((v) => {
      const level = v.severity === 'critical' || v.severity === 'high'
        ? 'error'
        : v.severity === 'medium'
          ? 'warning'
          : 'notice';
      return { level, message: v.message, rule: v.rule };
    });

    const criticalAnnotation = annotations.find(a => a.rule === 'scan.maxCritical');
    expect(criticalAnnotation?.level).toBe('error');

    const mediumAnnotation = annotations.find(a => a.rule === 'scan.requiredStandards');
    expect(mediumAnnotation?.level).toBe('warning');
  });
});
