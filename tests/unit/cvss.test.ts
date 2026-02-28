import { describe, it, expect } from 'vitest';
import { computeCVSSScore, vectorToString, deriveVector, cvssRating } from '../../src/testing/scoring/cvss.js';
import type { CVSSVector } from '../../src/testing/scoring/cvss.js';

describe('CVSS 3.1 Scoring', () => {
  describe('computeCVSSScore', () => {
    it('computes maximum score for worst-case vector', () => {
      const vector: CVSSVector = {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'C',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'H',
      };
      expect(computeCVSSScore(vector)).toBe(10.0);
    });

    it('returns 0 for no-impact vector', () => {
      const vector: CVSSVector = {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'N',
        integrityImpact: 'N',
        availabilityImpact: 'N',
      };
      expect(computeCVSSScore(vector)).toBe(0);
    });

    it('computes a mid-range score', () => {
      // AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N = 6.5
      const vector: CVSSVector = {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'L',
        integrityImpact: 'L',
        availabilityImpact: 'N',
      };
      const score = computeCVSSScore(vector);
      expect(score).toBeGreaterThan(5);
      expect(score).toBeLessThan(8);
    });

    it('scope changed increases score', () => {
      const base: CVSSVector = {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'N',
      };
      const changed = { ...base, scope: 'C' as const };
      expect(computeCVSSScore(changed)).toBeGreaterThan(computeCVSSScore(base));
    });

    it('high complexity reduces score', () => {
      const low: CVSSVector = {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'U',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'N',
      };
      const high = { ...low, attackComplexity: 'H' as const };
      expect(computeCVSSScore(high)).toBeLessThan(computeCVSSScore(low));
    });
  });

  describe('vectorToString', () => {
    it('formats CVSS 3.1 vector string', () => {
      const vector: CVSSVector = {
        attackVector: 'N',
        attackComplexity: 'L',
        privilegesRequired: 'N',
        userInteraction: 'N',
        scope: 'C',
        confidentialityImpact: 'H',
        integrityImpact: 'H',
        availabilityImpact: 'H',
      };
      expect(vectorToString(vector)).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
    });
  });

  describe('deriveVector', () => {
    it('sets low AC for few turns', () => {
      const vector = deriveVector('prompt-injection', 'high', 3);
      expect(vector.attackComplexity).toBe('L');
    });

    it('sets high AC for many turns', () => {
      const vector = deriveVector('prompt-injection', 'high', 8);
      expect(vector.attackComplexity).toBe('H');
    });

    it('sets scope changed for tool-abuse', () => {
      const vector = deriveVector('tool-abuse', 'critical', 3);
      expect(vector.scope).toBe('C');
    });

    it('sets scope unchanged for jailbreak', () => {
      const vector = deriveVector('jailbreak', 'high', 3);
      expect(vector.scope).toBe('U');
    });

    it('sets high confidentiality for data-exfiltration', () => {
      const vector = deriveVector('data-exfiltration', 'critical', 3);
      expect(vector.confidentialityImpact).toBe('H');
    });

    it('sets high integrity for tool-abuse', () => {
      const vector = deriveVector('tool-abuse', 'critical', 3);
      expect(vector.integrityImpact).toBe('H');
    });

    it('always sets AV to Network', () => {
      const vector = deriveVector('jailbreak', 'medium', 1);
      expect(vector.attackVector).toBe('N');
    });

    it('always sets PR to None', () => {
      const vector = deriveVector('jailbreak', 'medium', 1);
      expect(vector.privilegesRequired).toBe('N');
    });
  });

  describe('cvssRating', () => {
    it('returns None for 0', () => {
      expect(cvssRating(0)).toBe('None');
    });

    it('returns Low for 3.9', () => {
      expect(cvssRating(3.9)).toBe('Low');
    });

    it('returns Medium for 5.0', () => {
      expect(cvssRating(5.0)).toBe('Medium');
    });

    it('returns High for 8.0', () => {
      expect(cvssRating(8.0)).toBe('High');
    });

    it('returns Critical for 9.0+', () => {
      expect(cvssRating(9.0)).toBe('Critical');
      expect(cvssRating(10.0)).toBe('Critical');
    });
  });
});
