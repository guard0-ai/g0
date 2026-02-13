import { describe, it, expect } from 'vitest';
import { getAllRules, getRuleById, getRulesByDomain } from '../../src/analyzers/rules/index.js';

describe('Rule Registry', () => {
  it('has 475+ rules (hardcoded + builtin YAML)', () => {
    const rules = getAllRules();
    expect(rules.length).toBeGreaterThanOrEqual(475);
  });

  it('has unique rule IDs', () => {
    const rules = getAllRules();
    const ids = rules.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('has correct rule counts per domain (hardcoded + builtin YAML)', () => {
    expect(getRulesByDomain('goal-integrity').length).toBeGreaterThanOrEqual(70);
    expect(getRulesByDomain('tool-safety').length).toBeGreaterThanOrEqual(50);
    expect(getRulesByDomain('identity-access').length).toBeGreaterThanOrEqual(70);
    expect(getRulesByDomain('supply-chain').length).toBeGreaterThanOrEqual(40);
    expect(getRulesByDomain('code-execution').length).toBeGreaterThanOrEqual(65);
    expect(getRulesByDomain('memory-context').length).toBeGreaterThanOrEqual(35);
    expect(getRulesByDomain('data-leakage').length).toBeGreaterThanOrEqual(70);
    expect(getRulesByDomain('cascading-failures').length).toBeGreaterThanOrEqual(60);
  });

  it('can find rules by ID', () => {
    const rule = getRuleById('AA-GI-001');
    expect(rule).toBeDefined();
    expect(rule!.domain).toBe('goal-integrity');
  });

  it('returns undefined for unknown rule ID', () => {
    expect(getRuleById('XX-ZZ-999')).toBeUndefined();
  });

  it('every rule has required fields', () => {
    const rules = getAllRules();
    for (const rule of rules) {
      expect(rule.id).toMatch(/^AA-[A-Z]{2}-\d{3}$/);
      expect(rule.name).toBeTruthy();
      expect(rule.domain).toBeTruthy();
      expect(rule.severity).toMatch(/^(critical|high|medium|low|info)$/);
      expect(rule.confidence).toMatch(/^(high|medium|low)$/);
      expect(typeof rule.check).toBe('function');
    }
  });

  it('every rule maps to OWASP standards', () => {
    const rules = getAllRules();
    for (const rule of rules) {
      expect(rule.owaspAgentic).toBeDefined();
      if (rule.owaspAgentic.length > 0) {
        for (const ref of rule.owaspAgentic) {
          expect(ref).toMatch(/^ASI\d{2}$/);
        }
      }
    }
  });

  it('most rules have OWASP standards mapping', () => {
    const rules = getAllRules();
    const withOwasp = rules.filter(r => r.owaspAgentic.length > 0);
    // At least 90% of rules should have OWASP mapping
    expect(withOwasp.length / rules.length).toBeGreaterThan(0.9);
  });
});
