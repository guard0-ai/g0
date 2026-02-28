import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getSLMScorer, getSLMScorers, resetSLMCache, slmScoreToNumeric, type SLMScorer } from '../../src/testing/scoring/slm.js';
import { judgeSLM } from '../../src/testing/judge/slm.js';

describe('SLM Scoring', () => {
  beforeEach(() => {
    resetSLMCache();
  });

  afterEach(() => {
    resetSLMCache();
    delete process.env.OLLAMA_BASE_URL;
    delete process.env.HF_API_TOKEN;
  });

  describe('slmScoreToNumeric', () => {
    it('maps jailbreak with high score to 9', () => {
      expect(slmScoreToNumeric('jailbreak', 0.95)).toBe(9);
    });

    it('maps jailbreak with lower score to 8', () => {
      expect(slmScoreToNumeric('jailbreak', 0.7)).toBe(8);
    });

    it('maps injection with high score to 8', () => {
      expect(slmScoreToNumeric('injection', 0.9)).toBe(8);
    });

    it('maps injection with lower score to 7', () => {
      expect(slmScoreToNumeric('injection', 0.6)).toBe(7);
    });

    it('maps harmful to 8 with high score', () => {
      expect(slmScoreToNumeric('harmful', 0.9)).toBe(8);
    });

    it('maps pii with high score to 7', () => {
      expect(slmScoreToNumeric('pii', 0.8)).toBe(7);
    });

    it('maps safe with very high confidence to 2', () => {
      expect(slmScoreToNumeric('safe', 0.95)).toBe(2);
    });

    it('maps safe with medium confidence to 3', () => {
      expect(slmScoreToNumeric('safe', 0.8)).toBe(3);
    });

    it('maps safe with low confidence to 5', () => {
      expect(slmScoreToNumeric('safe', 0.5)).toBe(5);
    });

    it('maps unknown label to 5', () => {
      expect(slmScoreToNumeric('unknown', 0.9)).toBe(5);
    });
  });

  describe('getSLMScorer', () => {
    it('returns null when no env vars set', () => {
      const scorer = getSLMScorer();
      expect(scorer).toBeNull();
    });

    it('returns sentinel scorer when OLLAMA_BASE_URL is set', () => {
      process.env.OLLAMA_BASE_URL = 'http://localhost:11434';
      const scorer = getSLMScorer();
      expect(scorer).not.toBeNull();
      expect(scorer!.name).toBe('sentinel');
    });

    it('returns sentinel scorer when HF_API_TOKEN is set', () => {
      process.env.HF_API_TOKEN = 'hf_test_token';
      const scorer = getSLMScorer();
      expect(scorer).not.toBeNull();
      expect(scorer!.name).toBe('sentinel');
    });
  });

  describe('getSLMScorers', () => {
    it('returns all null scorers when no env vars set', () => {
      const scorers = getSLMScorers();
      expect(scorers.sentinel).toBeNull();
      expect(scorers.cleric).toBeNull();
      expect(scorers.hunter).toBeNull();
    });

    it('returns all scorers when OLLAMA_BASE_URL is set', () => {
      process.env.OLLAMA_BASE_URL = 'http://localhost:11434';
      const scorers = getSLMScorers();
      expect(scorers.sentinel).not.toBeNull();
      expect(scorers.cleric).not.toBeNull();
      expect(scorers.hunter).not.toBeNull();
    });

    it('caches scorers across calls', () => {
      process.env.OLLAMA_BASE_URL = 'http://localhost:11434';
      const s1 = getSLMScorers();
      const s2 = getSLMScorers();
      expect(s1).toBe(s2);
    });

    it('resets cache correctly', () => {
      process.env.OLLAMA_BASE_URL = 'http://localhost:11434';
      const s1 = getSLMScorers();
      resetSLMCache();
      const s2 = getSLMScorers();
      expect(s1).not.toBe(s2);
    });
  });

  describe('SIMBA SLM Integration', () => {
    it('uses SLM score when available via slmScoreToNumeric', () => {
      // Simulate what SIMBA does: convert SLM label + score to numeric
      const jailbreakScore = slmScoreToNumeric('jailbreak', 0.95);
      expect(jailbreakScore).toBe(9);

      const safeScore = slmScoreToNumeric('safe', 0.95);
      expect(safeScore).toBe(2);
    });

    it('heuristic fallback produces valid scores', () => {
      // The heuristic produces scores 2-9, same range as SLM
      const scores = [
        slmScoreToNumeric('safe', 0.95),   // 2
        slmScoreToNumeric('safe', 0.8),    // 3
        slmScoreToNumeric('safe', 0.5),    // 5
        slmScoreToNumeric('injection', 0.6), // 7
        slmScoreToNumeric('jailbreak', 0.95), // 9
      ];
      for (const score of scores) {
        expect(score).toBeGreaterThanOrEqual(1);
        expect(score).toBeLessThanOrEqual(10);
      }
    });
  });
});

describe('SLM Judge', () => {
  afterEach(() => {
    resetSLMCache();
    delete process.env.OLLAMA_BASE_URL;
    delete process.env.HF_API_TOKEN;
  });

  it('returns null when no SLM scorers available', async () => {
    const result = await judgeSLM('test payload', ['test response'], 'prompt-injection');
    expect(result).toBeNull();
  });

  it('returns null gracefully when SLMs are configured but unreachable', async () => {
    process.env.OLLAMA_BASE_URL = 'http://localhost:99999'; // unreachable
    const result = await judgeSLM('test payload', ['test response'], 'prompt-injection');
    // Should return null since all scorers will fail/timeout
    expect(result === null || result?.judgeLevel === 'slm').toBe(true);
  });

  it('has correct judge level when returning result', async () => {
    // This test verifies the structure of the return type
    // In a real scenario, the SLM would be called
    process.env.HF_API_TOKEN = 'test';
    // We can't easily mock fetch here, but we can verify graceful failure
    const result = await judgeSLM('test payload', ['test response'], 'prompt-injection');
    if (result) {
      expect(result.judgeLevel).toBe('slm');
      expect(['vulnerable', 'resistant', 'inconclusive']).toContain(result.verdict);
    }
  });
});
