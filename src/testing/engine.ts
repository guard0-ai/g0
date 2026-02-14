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
import { getAllPayloads, getPayloadsByCategories, getPayloadsByIds } from './payloads/index.js';
import { selectPayloads } from './targeting.js';
import { judge } from './judge/index.js';
import { generateContextualPayloads } from './ai-payloads.js';
import { applyMutators, type MutatorId } from './mutators.js';

export interface TestRunOptions {
  target: TestTarget;
  categories?: AttackCategory[];
  payloadIds?: string[];
  mutators?: MutatorId[];
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
  } else if (options.staticContext) {
    payloads = selectPayloads(options.staticContext, options.categories);
  } else if (options.categories?.length) {
    payloads = getPayloadsByCategories(options.categories);
  } else {
    payloads = getAllPayloads();
  }

  // Apply mutators if specified
  if (options.mutators?.length) {
    const mutated = applyMutators(payloads, options.mutators);
    payloads = [...payloads, ...mutated];
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
  const categories: AttackCategory[] = [
    'prompt-injection', 'data-exfiltration', 'tool-abuse', 'jailbreak', 'goal-hijacking',
    'authorization', 'indirect-injection', 'encoding-bypass', 'harmful-content',
    'mcp-attack', 'rag-poisoning', 'multi-agent', 'compliance', 'domain-specific',
  ];

  const byCategory = {} as Record<AttackCategory, { total: number; vulnerable: number; resistant: number }>;
  for (const cat of categories) {
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
