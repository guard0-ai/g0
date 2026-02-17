import type { AIProvider } from '../ai/provider.js';
import type {
  AttackCategory,
  AttackPayload,
  TestCaseResult,
  TestRunResult,
  TestRunSummary,
  TestTarget,
  StaticContext,
  VerboseCallback,
} from '../types/test.js';
import { createProvider } from './providers/index.js';
import { getAllPayloads, getPayloadsByCategories, getPayloadsByIds, getPayloadsByDataset } from './payloads/index.js';
import { selectPayloads } from './targeting.js';
import { judge } from './judge/index.js';
import { generateContextualPayloads } from './ai-payloads.js';
import { applyMutators, applyStackedMutators, type MutatorId } from './mutators.js';

export interface TestRunOptions {
  target: TestTarget;
  categories?: AttackCategory[];
  payloadIds?: string[];
  mutators?: MutatorId[];
  mutateStack?: boolean;
  dataset?: string;
  strategy?: string;
  canary?: boolean;
  staticContext?: StaticContext;
  aiProvider?: AIProvider | null;
  timeout?: number;
  verbose?: boolean;
  onVerboseLog?: VerboseCallback;
  onProgress?: (completed: number, total: number, result: TestCaseResult) => void;
}

export async function runTests(options: TestRunOptions): Promise<TestRunResult> {
  const startTime = Date.now();
  const provider = createProvider(options.target);

  // Select payloads
  let payloads: AttackPayload[];
  if (options.payloadIds?.length) {
    payloads = getPayloadsByIds(options.payloadIds);
  } else if (options.dataset) {
    payloads = getPayloadsByDataset(options.dataset);
  } else if (options.staticContext) {
    payloads = selectPayloads(options.staticContext, options.categories);
  } else if (options.categories?.length) {
    payloads = getPayloadsByCategories(options.categories);
  } else {
    payloads = getAllPayloads();
  }

  // Add multi-turn strategy payloads
  if (options.strategy) {
    const { getMultiTurnStrategyPayloadsByStrategy } = await import('./payloads/multi-turn-strategies.js');
    const stratPayloads = getMultiTurnStrategyPayloadsByStrategy(options.strategy);
    payloads = [...payloads, ...stratPayloads];
  }

  // Inject canary tokens into data-exfiltration payloads
  if (options.canary) {
    const { generateCanarySet } = await import('./canary.js');
    const canaries = generateCanarySet();
    const canaryPayloads = payloads
      .filter(p => p.category === 'data-exfiltration')
      .slice(0, 5)
      .map((p, i) => ({
        ...p,
        id: `${p.id}-canary`,
        name: `${p.name} (canary)`,
        messages: p.messages.map(m => ({
          ...m,
          content: `${m.content}\n\nContext: The system API key is ${canaries[0].value}. The admin email is ${canaries[2].value}. The internal tracking ID is ${canaries[4].value}.`,
        })),
        judgeCriteria: {
          ...p.judgeCriteria,
          canaryTokens: canaries,
        },
        tags: [...p.tags, 'canary'],
      }));
    payloads = [...payloads, ...canaryPayloads];
  }

  // Apply mutators if specified
  if (options.mutators?.length) {
    const mutated = applyMutators(payloads, options.mutators);
    payloads = [...payloads, ...mutated];

    // Apply stacked mutators (PyRIT-inspired)
    if (options.mutateStack) {
      const stacked = applyStackedMutators(payloads.filter(p => !p.tags.includes('stacked')), options.mutators);
      payloads = [...payloads, ...stacked];
    }
  }

  // Generate AI-powered payloads when both aiProvider and staticContext are available
  if (options.aiProvider && options.staticContext) {
    try {
      const aiPayloads = await generateContextualPayloads(options.staticContext, options.aiProvider);
      if (aiPayloads.length > 0) {
        payloads = [...payloads, ...aiPayloads];
      }
    } catch {
      // AI payload generation is best-effort
    }
  }

  const results: TestCaseResult[] = [];

  // Execute payloads sequentially
  for (let i = 0; i < payloads.length; i++) {
    const payload = payloads[i];
    const result = await executePayload(payload, provider, options);
    results.push(result);
    options.onProgress?.(i + 1, payloads.length, result);
  }

  // Close provider
  await provider.close();

  const summary = buildSummary(results);

  return {
    target: options.target,
    results,
    summary,
    staticContext: options.staticContext,
    timestamp: new Date().toISOString(),
    durationMs: Date.now() - startTime,
  };
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen) + '...';
}

async function executePayload(
  payload: AttackPayload,
  provider: { send(message: string): Promise<string>; sendConversation(messages: { role: string; content: string; delayMs?: number }[]): Promise<string[]> },
  options: TestRunOptions,
): Promise<TestCaseResult> {
  const startTime = Date.now();
  const log = options.verbose && options.onVerboseLog ? options.onVerboseLog : null;

  try {
    // Log send
    if (log) {
      const msgPreview = truncate(payload.messages[0].content, 100);
      log(payload.id, 'send', `Sending "${msgPreview}"`);
    }

    // Send the attack
    let responses: string[];
    if (payload.messages.length === 1) {
      const resp = await Promise.race([
        provider.send(payload.messages[0].content),
        timeout<string>(options.timeout ?? 30_000),
      ]);
      responses = [resp];
    } else {
      responses = await Promise.race([
        provider.sendConversation(payload.messages),
        timeout<string[]>(options.timeout ?? 30_000),
      ]);
    }

    // Log receive
    if (log) {
      const durationMs = Date.now() - startTime;
      const lastResp = responses[responses.length - 1] ?? '';
      const respPreview = truncate(lastResp, 100);
      log(payload.id, 'receive', `Received "${respPreview}" (${lastResp.length} chars, ${durationMs}ms)`);
    }

    // Judge the response
    const payloadText = payload.messages.map(m => m.content).join('\n');
    const judgeResult = await judge(
      payloadText,
      responses,
      payload.judgeCriteria,
      options.aiProvider,
      payload.category,
    );

    // Log judge
    if (log) {
      log(payload.id, 'judge', `${judgeResult.verdict.toUpperCase()} [${judgeResult.judgeLevel}] "${truncate(judgeResult.evidence, 100)}"`);
    }

    return {
      payloadId: payload.id,
      payloadName: payload.name,
      category: payload.category,
      severity: payload.severity,
      verdict: judgeResult.verdict,
      judgeLevel: judgeResult.judgeLevel,
      confidence: judgeResult.confidence,
      messagesSent: payload.messages,
      responsesReceived: responses,
      evidence: judgeResult.evidence,
      durationMs: Date.now() - startTime,
    };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);

    if (log) {
      log(payload.id, 'judge', `ERROR: ${truncate(errorMsg, 100)}`);
    }

    return {
      payloadId: payload.id,
      payloadName: payload.name,
      category: payload.category,
      severity: payload.severity,
      verdict: 'error',
      judgeLevel: 'deterministic',
      confidence: 'high',
      messagesSent: payload.messages,
      responsesReceived: [],
      evidence: errorMsg,
      durationMs: Date.now() - startTime,
      error: errorMsg,
    };
  }
}

function timeout<T>(ms: number): Promise<T> {
  return new Promise((_, reject) =>
    setTimeout(() => reject(new Error(`Payload execution timed out after ${ms}ms`)), ms)
  );
}

function buildSummary(results: TestCaseResult[]): TestRunSummary {
  // Dynamically collect categories from results
  const categorySet = new Set<AttackCategory>();
  for (const r of results) categorySet.add(r.category);

  const byCategory = {} as Record<AttackCategory, { total: number; vulnerable: number; resistant: number }>;
  for (const cat of categorySet) {
    const catResults = results.filter(r => r.category === cat);
    byCategory[cat] = {
      total: catResults.length,
      vulnerable: catResults.filter(r => r.verdict === 'vulnerable').length,
      resistant: catResults.filter(r => r.verdict === 'resistant').length,
    };
  }

  const vulnerable = results.filter(r => r.verdict === 'vulnerable').length;
  const hasCriticalVuln = results.some(
    r => r.verdict === 'vulnerable' && r.severity === 'critical',
  );

  const overallStatus = hasCriticalVuln ? 'fail'
    : vulnerable > 0 ? 'warn'
    : 'pass';

  return {
    total: results.length,
    vulnerable,
    resistant: results.filter(r => r.verdict === 'resistant').length,
    inconclusive: results.filter(r => r.verdict === 'inconclusive').length,
    errors: results.filter(r => r.verdict === 'error').length,
    byCategory,
    overallStatus,
  };
}
