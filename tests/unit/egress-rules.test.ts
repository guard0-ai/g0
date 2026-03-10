import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

describe('egress-rules', () => {
  describe('generateIptablesRules', () => {
    it('generates rules for IP addresses', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['142.250.80.46', '8.8.8.8']);

      expect(result.rules.some(r => r.includes('-d 142.250.80.46'))).toBe(true);
      expect(result.rules.some(r => r.includes('-d 8.8.8.8'))).toBe(true);
      expect(result.chain).toBe('DOCKER-USER');
    });

    it('generates rules for CIDR ranges', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['10.0.0.0/8', '172.16.0.0/12']);

      expect(result.rules.some(r => r.includes('-d 10.0.0.0/8'))).toBe(true);
      expect(result.rules.some(r => r.includes('-d 172.16.0.0/12'))).toBe(true);
    });

    it('skips wildcard hostnames with warning', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['*.openai.com']);

      expect(result.unresolved).toContain('*.openai.com');
      expect(result.rules.some(r => r.includes('SKIP: wildcard'))).toBe(true);
    });

    it('includes DNS allowance rule', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8']);

      expect(result.rules.some(r => r.includes('--dport 53'))).toBe(true);
    });

    it('includes RELATED,ESTABLISHED rule by default', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8']);

      expect(result.rules.some(r => r.includes('RELATED,ESTABLISHED'))).toBe(true);
    });

    it('includes default deny rule by default', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8']);

      expect(result.defaultDeny).toBe(true);
      expect(result.rules.some(r => r.includes('-j DROP'))).toBe(true);
    });

    it('omits default deny when disabled', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8'], { defaultDeny: false });

      expect(result.defaultDeny).toBe(false);
      expect(result.rules.some(r => r.includes('-j DROP'))).toBe(false);
    });

    it('uses custom chain name', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8'], { chain: 'FORWARD' });

      expect(result.chain).toBe('FORWARD');
      expect(result.rules.some(r => r.includes('FORWARD'))).toBe(true);
    });

    it('generates OUTPUT chain rules when includeOutputChain is true', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8'], { includeOutputChain: true });

      expect(result.rules.some(r => r.includes('-I OUTPUT'))).toBe(true);
    });

    it('tracks resolved hostnames', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      // Use an IP so it doesn't need DNS, but also test the structure
      const result = await generateIptablesRules(['1.2.3.4']);

      expect(result.resolved).toBeDefined();
      expect(typeof result.resolved).toBe('object');
    });

    it('uses custom comment prefix', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const result = await generateIptablesRules(['8.8.8.8'], { commentPrefix: 'my-egress' });

      expect(result.rules.some(r => r.includes('my-egress'))).toBe(true);
    });
  });

  describe('formatRulesAsScript', () => {
    it('generates a bash script with shebang', async () => {
      const { generateIptablesRules, formatRulesAsScript } = await import('../../src/endpoint/egress-rules.js');

      const ruleSet = await generateIptablesRules(['8.8.8.8']);
      const script = formatRulesAsScript(ruleSet);

      expect(script).toContain('#!/bin/bash');
      expect(script).toContain('set -euo pipefail');
      expect(script).toContain('iptables');
    });
  });

  describe('applyIptablesRules', () => {
    it('returns not-applied on macOS', async () => {
      const { generateIptablesRules, applyIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const ruleSet = await generateIptablesRules(['8.8.8.8']);

      // On macOS (dev), this should return applied: false
      const os = await import('node:os');
      if (os.platform() === 'darwin') {
        const result = applyIptablesRules(ruleSet);
        expect(result.applied).toBe(false);
        expect(result.errors).toContain('iptables rules can only be applied on Linux');
      }
    });

    it('accepts a logger parameter', async () => {
      const { generateIptablesRules, applyIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const ruleSet = await generateIptablesRules(['8.8.8.8']);
      const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };

      // Should not throw regardless of platform
      const result = applyIptablesRules(ruleSet, mockLogger);
      expect(result).toHaveProperty('applied');
      expect(result).toHaveProperty('rulesApplied');
      expect(result).toHaveProperty('errors');
    });
  });

  describe('rule generation for mixed allowlist', () => {
    it('handles a realistic allowlist with IPs, CIDRs, hostnames, and wildcards', async () => {
      const { generateIptablesRules } = await import('../../src/endpoint/egress-rules.js');

      const allowlist = [
        'api.anthropic.com',
        '*.openai.com',
        '8.8.8.8',
        '10.0.0.0/8',
      ];

      const result = await generateIptablesRules(allowlist);

      // IP should be directly in rules
      expect(result.rules.some(r => r.includes('-d 8.8.8.8'))).toBe(true);

      // CIDR should be directly in rules
      expect(result.rules.some(r => r.includes('-d 10.0.0.0/8'))).toBe(true);

      // Wildcard should be in unresolved
      expect(result.unresolved).toContain('*.openai.com');

      // Hostname may or may not resolve — check structure
      if (result.resolved['api.anthropic.com']) {
        expect(result.resolved['api.anthropic.com'].length).toBeGreaterThan(0);
      } else {
        expect(result.unresolved).toContain('api.anthropic.com');
      }
    });
  });
});
