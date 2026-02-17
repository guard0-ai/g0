import type { AIProvider } from '../../ai/provider.js';
import type { AttackCategory, JudgeCriteria, JudgeResult } from '../../types/test.js';
import { judgeDeterministic } from './deterministic.js';
import { judgeHeuristic } from './heuristic.js';
import { judgeLLM } from './llm.js';

export async function judge(
  payloadText: string,
  responses: string[],
  criteria: JudgeCriteria,
  aiProvider?: AIProvider | null,
  category?: AttackCategory,
): Promise<JudgeResult> {
  // Level 1: Deterministic pattern matching
  const deterministicResult = judgeDeterministic(responses, criteria);
  if (deterministicResult) return deterministicResult;

  // Level 2: Heuristic scoring
  const heuristicResult = judgeHeuristic(responses, criteria);
  if (heuristicResult) return heuristicResult;

  // Level 3: LLM-as-judge (optional)
  if (aiProvider) {
    const llmResult = await judgeLLM(payloadText, responses, criteria, aiProvider, category);
    if (llmResult) return llmResult;
  }

  // Fallback: inconclusive
  return {
    verdict: 'inconclusive',
    confidence: 'low',
    evidence: 'No judge level could determine a verdict',
    judgeLevel: 'heuristic',
  };
}
