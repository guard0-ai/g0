import { describe, it, expect } from 'vitest';
import { majorityVoteFP } from '../../src/ai/consensus.js';

describe('AI Meta-Analyzer & Consensus', () => {
  describe('Majority Vote FP', () => {
    it('marks as FP only when majority agrees', () => {
      const results = [
        new Map([['f1', { falsePositive: true, reason: 'dead code' }]]),
        new Map([['f1', { falsePositive: true, reason: 'dead code' }]]),
        new Map([['f1', { falsePositive: false }]]),
      ];
      const merged = majorityVoteFP(results);
      expect(merged.get('f1')?.falsePositive).toBe(true);
    });

    it('keeps as TP when majority says TP', () => {
      const results = [
        new Map([['f1', { falsePositive: false }]]),
        new Map([['f1', { falsePositive: false }]]),
        new Map([['f1', { falsePositive: true, reason: 'maybe FP' }]]),
      ];
      const merged = majorityVoteFP(results);
      expect(merged.get('f1')?.falsePositive).toBe(false);
    });

    it('handles findings present in only some rounds', () => {
      const results = [
        new Map([['f1', { falsePositive: true, reason: 'r1' }], ['f2', { falsePositive: false }]]),
        new Map([['f1', { falsePositive: false }]]),
        new Map([['f2', { falsePositive: true, reason: 'r2' }]]),
      ];
      const merged = majorityVoteFP(results);
      expect(merged.get('f1')?.falsePositive).toBe(false); // 1 FP, 1 TP -> TP
      expect(merged.get('f2')?.falsePositive).toBe(false); // 1 TP, 1 FP -> tie goes to TP
    });

    it('handles empty results', () => {
      const merged = majorityVoteFP([]);
      expect(merged.size).toBe(0);
    });
  });
});
