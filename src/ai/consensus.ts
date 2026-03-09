import type { AIProvider } from './provider.js';

export interface ConsensusResult<T> {
  result: T;
  agreementRate: number;
  rounds: number;
}

/**
 * Run a function N times and merge results via majority vote.
 * Used for FP detection: only mark as FP if majority of runs agree.
 */
export async function runWithConsensus<T>(
  fn: (provider: AIProvider) => Promise<T>,
  provider: AIProvider,
  n: number,
  mergeFn: (results: T[]) => T,
): Promise<ConsensusResult<T>> {
  if (n <= 1) {
    const result = await fn(provider);
    return { result, agreementRate: 1, rounds: 1 };
  }

  const results: T[] = [];
  for (let i = 0; i < n; i++) {
    try {
      const result = await fn(provider);
      results.push(result);
    } catch {
      // Skip failed rounds
    }
  }

  if (results.length === 0) {
    throw new Error('All consensus rounds failed');
  }

  const merged = mergeFn(results);
  return {
    result: merged,
    agreementRate: results.length / n,
    rounds: results.length,
  };
}

/**
 * Merge FP maps by majority vote: only mark as FP if >50% of rounds agreed.
 */
export function majorityVoteFP(
  results: Map<string, { falsePositive: boolean; reason?: string }>[],
): Map<string, { falsePositive: boolean; reason?: string }> {
  const merged = new Map<string, { falsePositive: boolean; reason?: string }>();
  const allIds = new Set(results.flatMap(r => [...r.keys()]));

  for (const id of allIds) {
    let fpVotes = 0;
    let tpVotes = 0;
    let lastReason: string | undefined;

    for (const r of results) {
      const entry = r.get(id);
      if (!entry) continue;
      if (entry.falsePositive) {
        fpVotes++;
        lastReason = entry.reason;
      } else {
        tpVotes++;
      }
    }

    // Only mark as FP if majority agrees
    merged.set(id, {
      falsePositive: fpVotes > tpVotes,
      reason: fpVotes > tpVotes ? lastReason : undefined,
    });
  }

  return merged;
}
