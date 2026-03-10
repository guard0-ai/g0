import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('Policy Engine', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-policy-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('loadPolicy', () => {
    it('loads JSON policy file', async () => {
      const { loadPolicy } = await import('../../src/governance/policy-engine.js');

      const policyPath = path.join(tmpDir, '.g0-policy.yaml');
      fs.writeFileSync(policyPath, JSON.stringify({
        apiVersion: 'guard0.dev/v1',
        kind: 'SecurityPolicy',
        spec: {
          scan: { minGrade: 'B', maxCritical: 0 },
          runtime: { killSwitch: 'required' },
        },
      }));

      const policy = loadPolicy(policyPath);
      expect(policy).not.toBeNull();
      expect(policy!.spec.scan!.minGrade).toBe('B');
      expect(policy!.spec.runtime!.killSwitch).toBe('required');
    });

    it('returns null for missing file', async () => {
      const { loadPolicy } = await import('../../src/governance/policy-engine.js');
      const policy = loadPolicy('/nonexistent');
      expect(policy).toBeNull();
    });
  });

  describe('evaluateScanPolicy', () => {
    it('passes when scan meets requirements', async () => {
      const { evaluateScanPolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateScanPolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { scan: { minGrade: 'B', maxCritical: 0 } } },
        { grade: 'A', criticalCount: 0 },
      );
      expect(violations).toHaveLength(0);
    });

    it('fails when grade too low', async () => {
      const { evaluateScanPolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateScanPolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { scan: { minGrade: 'B' } } },
        { grade: 'D' },
      );
      expect(violations).toHaveLength(1);
      expect(violations[0].rule).toBe('scan.minGrade');
    });

    it('fails when too many criticals', async () => {
      const { evaluateScanPolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateScanPolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { scan: { maxCritical: 0 } } },
        { criticalCount: 3 },
      );
      expect(violations).toHaveLength(1);
      expect(violations[0].severity).toBe('critical');
    });

    it('fails when required standard missing', async () => {
      const { evaluateScanPolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateScanPolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { scan: { requiredStandards: ['owasp-asi', 'nist-ai-rmf'] } } },
        { standards: ['owasp-asi'] },
      );
      expect(violations).toHaveLength(1);
      expect(violations[0].message).toContain('nist-ai-rmf');
    });
  });

  describe('evaluateRuntimePolicy', () => {
    it('fails when kill switch required but missing', async () => {
      const { evaluateRuntimePolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateRuntimePolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { runtime: { killSwitch: 'required' } } },
        { killSwitchAvailable: false },
      );
      expect(violations).toHaveLength(1);
      expect(violations[0].rule).toBe('runtime.killSwitch');
    });

    it('passes when all runtime requirements met', async () => {
      const { evaluateRuntimePolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateRuntimePolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { runtime: { killSwitch: 'required', injectionResponse: 'block', piiResponse: 'redact' } } },
        { killSwitchAvailable: true, injectionBlocking: true, piiRedaction: true },
      );
      expect(violations).toHaveLength(0);
    });
  });

  describe('evaluateHostPolicy', () => {
    it('fails when disk encryption required but missing', async () => {
      const { evaluateHostPolicy } = await import('../../src/governance/policy-engine.js');

      const violations = evaluateHostPolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { host: { diskEncryption: 'required' } } },
        { diskEncrypted: false },
      );
      expect(violations).toHaveLength(1);
      expect(violations[0].severity).toBe('critical');
    });
  });

  describe('evaluatePolicy', () => {
    it('evaluates all contexts together', async () => {
      const { evaluatePolicy } = await import('../../src/governance/policy-engine.js');

      const evaluation = evaluatePolicy(
        {
          apiVersion: 'v1', kind: 'SecurityPolicy',
          spec: {
            scan: { minGrade: 'B', maxCritical: 0 },
            runtime: { killSwitch: 'required' },
            host: { firewall: 'required' },
          },
        },
        { grade: 'A', criticalCount: 0 },
        { killSwitchAvailable: true },
        { firewallEnabled: true },
      );

      expect(evaluation.passed).toBe(true);
      expect(evaluation.violations).toHaveLength(0);
      expect(evaluation.grade).toBe('A');
    });

    it('returns F grade for critical violations', async () => {
      const { evaluatePolicy } = await import('../../src/governance/policy-engine.js');

      const evaluation = evaluatePolicy(
        { apiVersion: 'v1', kind: 'SecurityPolicy', spec: { scan: { maxCritical: 0 } } },
        { criticalCount: 5 },
      );

      expect(evaluation.passed).toBe(false);
      expect(evaluation.grade).toBe('F');
    });
  });

  describe('getCIExitCode', () => {
    it('returns 0 for passing evaluation', async () => {
      const { getCIExitCode } = await import('../../src/governance/policy-engine.js');
      expect(getCIExitCode({ policy: {} as any, violations: [], passed: true, grade: 'A' })).toBe(0);
    });

    it('returns 1 for critical/high violations', async () => {
      const { getCIExitCode } = await import('../../src/governance/policy-engine.js');
      expect(getCIExitCode({
        policy: {} as any,
        violations: [{ rule: 'test', severity: 'critical', message: 'test', actual: 0, expected: 1 }],
        passed: false,
        grade: 'F',
      })).toBe(1);
    });

    it('returns 2 for medium/low violations only', async () => {
      const { getCIExitCode } = await import('../../src/governance/policy-engine.js');
      expect(getCIExitCode({
        policy: {} as any,
        violations: [{ rule: 'test', severity: 'medium', message: 'test', actual: 0, expected: 1 }],
        passed: false,
        grade: 'C',
      })).toBe(2);
    });
  });
});
