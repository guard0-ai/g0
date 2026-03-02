import type { AIProvider } from '../../ai/provider.js';
import type { AttackCategory, JudgeCriteria, JudgeResult } from '../../types/test.js';
import { judgeDeterministic } from './deterministic.js';
import { judgeHeuristic } from './heuristic.js';
import { judgeLLM } from './llm.js';
import { judgeSLM } from './slm.js';
import { scoreVulnerableResponse } from './scoring.js';

export async function judge(
  payloadText: string,
  responses: string[],
  criteria: JudgeCriteria,
  aiProvider?: AIProvider | null,
  category?: AttackCategory,
): Promise<JudgeResult> {
  // Level 1: Deterministic pattern matching
  const deterministicResult = judgeDeterministic(responses, criteria);
  if (deterministicResult) return attachGraduatedScore(deterministicResult, responses);

  // Level 2: Heuristic scoring
  const heuristicResult = judgeHeuristic(responses, criteria);
  if (heuristicResult) return attachGraduatedScore(heuristicResult, responses);

  // Level 2.5: SLM scoring (Sentinel + Cleric + Hunter)
  if (category) {
    const slmResult = await judgeSLM(payloadText, responses, category);
    if (slmResult) return attachGraduatedScore(slmResult, responses);
  }

  // Level 3: LLM-as-judge (optional)
  if (aiProvider) {
    const llmResult = await judgeLLM(payloadText, responses, criteria, aiProvider, category);
    if (llmResult) return attachGraduatedScore(llmResult, responses);
  }

  // Fallback: inconclusive
  return {
    verdict: 'inconclusive',
    confidence: 'low',
    evidence: 'No judge level could determine a verdict',
    judgeLevel: 'heuristic',
  };
}

/**
 * Attach StrongREJECT-inspired graduated scores to vulnerable results.
 * Only computes scores when the verdict is 'vulnerable'.
 */
function attachGraduatedScore(result: JudgeResult, responses: string[]): JudgeResult {
  if (result.verdict !== 'vulnerable') return result;

  const { specificity, convincingness, qualityScore } = scoreVulnerableResponse(responses);
  return {
    ...result,
    specificity,
    convincingness,
    qualityScore,
  };
}
