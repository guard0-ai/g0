import { describe, it, expect } from 'vitest';
import { getAllRules, getRuleById } from '../../src/analyzers/rules/index.js';

describe('rules command', () => {
  describe('getAllRules', () => {
    it('returns a non-empty array of rules', () => {
      expect(getAllRules().length).toBeGreaterThan(0);
    });

    it('every rule has required fields', () => {
      for (const rule of getAllRules()) {
        expect(rule.id).toBeTruthy();
        expect(rule.name).toBeTruthy();
        expect(rule.domain).toBeTruthy();
        expect(rule.severity).toBeTruthy();
        expect(rule.description).toBeTruthy();
        expect(typeof rule.check).toBe('function');
      }
    });

    it('every rule has a valid severity', () => {
      const valid = ['critical', 'high', 'medium', 'low', 'info'];
      for (const rule of getAllRules()) expect(valid).toContain(rule.severity);
    });
  });

  describe('getRuleById', () => {
    it('finds a known rule', () => {
      const rule = getRuleById('AA-GI-001');
      expect(rule).toBeDefined();
      expect(rule!.id).toBe('AA-GI-001');
    });

    it('returns undefined for unknown rule', () => {
      expect(getRuleById('NONEXISTENT-999')).toBeUndefined();
    });
  });

  describe('filtering', () => {
    it('filters by domain', () => {
      const rules = getAllRules().filter(r => r.domain === 'goal-integrity');
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.every(r => r.domain === 'goal-integrity')).toBe(true);
    });

    it('filters by severity', () => {
      const rules = getAllRules().filter(r => r.severity === 'critical');
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.every(r => r.severity === 'critical')).toBe(true);
    });

    it('searches by text', () => {
      const rules = getAllRules().filter(r =>
        r.name.toLowerCase().includes('injection') || r.description.toLowerCase().includes('injection')
      );
      expect(rules.length).toBeGreaterThan(0);
    });

    it('returns empty for non-matching domain', () => {
      expect(getAllRules().filter(r => r.domain === 'nonexistent').length).toBe(0);
    });
  });

  describe('standards', () => {
    it('some rules have standards mapping', () => {
      expect(getAllRules().filter(r => r.standards && Object.keys(r.standards).length > 0).length).toBeGreaterThan(0);
    });
  });
});
