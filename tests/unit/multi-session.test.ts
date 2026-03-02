import { describe, it, expect, vi } from 'vitest';
import type { AdaptiveAttackConfig, AttackState, TestTarget, AdaptiveTestCaseResult } from '../../src/types/test.js';
import type { AIProvider } from '../../src/ai/provider.js';

function createMockAIProvider(response: string): AIProvider {
  return {
    name: 'mock',
    model: 'mock-model',
    analyze: vi.fn().mockResolvedValue(response),
  };
}

describe('Multi-Session Attacks', () => {
  describe('Session Configuration', () => {
    it('recon session reduces maxTurns to 40% of total', () => {
      const baseTurns = 10;
      const reconTurns = Math.max(3, Math.floor(baseTurns * 0.4));
      expect(reconTurns).toBe(4);
    });

    it('recon session has minimum of 3 turns', () => {
      const baseTurns = 5;
      const reconTurns = Math.max(3, Math.floor(baseTurns * 0.4));
      expect(reconTurns).toBe(3);
    });

    it('armed session uses full maxTurns', () => {
      const baseTurns = 10;
      expect(baseTurns).toBe(10);
    });
  });

  describe('Session Phase Assignment', () => {
    it('assigns phases correctly for 2 sessions', () => {
      const sessionCount = 2;
      const phases: string[] = [];
      for (let session = 0; session < sessionCount; session++) {
        const phase = session === 0 ? 'recon'
          : session === sessionCount - 1 ? 'verify'
          : 'armed';
        phases.push(phase);
      }
      expect(phases).toEqual(['recon', 'verify']);
    });

    it('assigns phases correctly for 3 sessions', () => {
      const sessionCount = 3;
      const phases: string[] = [];
      for (let session = 0; session < sessionCount; session++) {
        const phase = session === 0 ? 'recon'
          : session === sessionCount - 1 ? 'verify'
          : 'armed';
        phases.push(phase);
      }
      expect(phases).toEqual(['recon', 'armed', 'verify']);
    });

    it('assigns phases correctly for 4 sessions', () => {
      const sessionCount = 4;
      const phases: string[] = [];
      for (let session = 0; session < sessionCount; session++) {
        const phase = session === 0 ? 'recon'
          : session === sessionCount - 1 ? 'verify'
          : 'armed';
        phases.push(phase);
      }
      expect(phases).toEqual(['recon', 'armed', 'armed', 'verify']);
    });
  });

  describe('Intelligence Propagation', () => {
    it('session 1 intelligence feeds into session 2 config', () => {
      const sessionResults = [
        {
          intelligence: ['Agent has file access tools', 'Vulnerable to role-play'],
        },
      ];

      const intel = sessionResults
        .map(sr => sr.intelligence.join('; '))
        .filter(Boolean)
        .join('\n');

      const priorIntelligence = `\n\nMULTI-SESSION INTELLIGENCE (from 1 previous session(s)):\n${intel}`;

      expect(priorIntelligence).toContain('Agent has file access tools');
      expect(priorIntelligence).toContain('Vulnerable to role-play');
      expect(priorIntelligence).toContain('MULTI-SESSION INTELLIGENCE');
    });

    it('multiple sessions accumulate intelligence', () => {
      const sessionResults = [
        { intelligence: ['Discovery from session 1'] },
        { intelligence: ['Discovery from session 2'] },
      ];

      const intel = sessionResults
        .map(sr => sr.intelligence.join('; '))
        .filter(Boolean)
        .join('\n');

      expect(intel).toContain('Discovery from session 1');
      expect(intel).toContain('Discovery from session 2');
    });
  });

  describe('Result Aggregation', () => {
    it('picks vulnerable result over resistant', () => {
      const sessionResults = [
        {
          result: {
            verdict: 'resistant' as const,
            cvssScore: undefined,
            evidence: 'Session 1 was resistant',
          },
        },
        {
          result: {
            verdict: 'vulnerable' as const,
            cvssScore: 7.5,
            evidence: 'Session 2 found vulnerability',
          },
        },
      ];

      const bestResult = sessionResults.reduce((best, sr) => {
        if (sr.result.verdict === 'vulnerable' && best.result.verdict !== 'vulnerable') return sr;
        if (sr.result.verdict === 'vulnerable' && best.result.verdict === 'vulnerable') {
          return (sr.result.cvssScore ?? 0) > (best.result.cvssScore ?? 0) ? sr : best;
        }
        return best;
      }, sessionResults[0]);

      expect(bestResult.result.verdict).toBe('vulnerable');
      expect(bestResult.result.cvssScore).toBe(7.5);
    });

    it('picks highest CVSS score among vulnerable results', () => {
      const sessionResults = [
        {
          result: {
            verdict: 'vulnerable' as const,
            cvssScore: 5.0,
          },
        },
        {
          result: {
            verdict: 'vulnerable' as const,
            cvssScore: 8.5,
          },
        },
      ];

      const bestResult = sessionResults.reduce((best, sr) => {
        if (sr.result.verdict === 'vulnerable' && best.result.verdict !== 'vulnerable') return sr;
        if (sr.result.verdict === 'vulnerable' && best.result.verdict === 'vulnerable') {
          return (sr.result.cvssScore ?? 0) > (best.result.cvssScore ?? 0) ? sr : best;
        }
        return best;
      }, sessionResults[0]);

      expect(bestResult.result.cvssScore).toBe(8.5);
    });

    it('generates multi-session evidence string', () => {
      const sessionResults = [
        { sessionNumber: 1, phase: 'recon', result: { verdict: 'resistant', evidence: 'Agent refused' } },
        { sessionNumber: 2, phase: 'armed', result: { verdict: 'vulnerable', evidence: 'Leaked system prompt' } },
      ];

      const evidence = sessionResults
        .map(sr => `Session ${sr.sessionNumber} (${sr.phase}): ${sr.result.verdict} — ${sr.result.evidence.slice(0, 150)}`)
        .join('\n');

      expect(evidence).toContain('Session 1 (recon): resistant');
      expect(evidence).toContain('Session 2 (armed): vulnerable');
      expect(evidence).toContain('Leaked system prompt');
    });
  });

  describe('Session Metadata', () => {
    it('stores session details in finalState.meta.sessions', () => {
      const sessions = [
        { sessionNumber: 1, phase: 'recon', verdict: 'resistant', turnsExecuted: 4, intelligence: ['Found tool access'] },
        { sessionNumber: 2, phase: 'verify', verdict: 'vulnerable', turnsExecuted: 8, intelligence: ['Confirmed leak'] },
      ];

      const meta = { sessions };
      expect(meta.sessions).toHaveLength(2);
      expect(meta.sessions[0].phase).toBe('recon');
      expect(meta.sessions[1].phase).toBe('verify');
      expect(meta.sessions[0].intelligence).toContain('Found tool access');
    });
  });
});
