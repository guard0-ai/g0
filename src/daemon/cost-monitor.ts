import * as fs from 'node:fs';
import * as path from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────────

export interface CostConfig {
  hourlyLimitUsd?: number;
  dailyLimitUsd?: number;
  monthlyLimitUsd?: number;
  circuitBreakerEnabled?: boolean;
}

export interface CostSnapshot {
  hourly: number;
  daily: number;
  monthly: number;
  breaker: 'ok' | 'warning' | 'tripped';
  details: CostDetail[];
}

export interface CostDetail {
  model: string;
  inputTokens: number;
  outputTokens: number;
  cost: number;
}

// ── Per-Model Pricing (USD per 1M tokens) ──────────────────────────────────

interface ModelPricing {
  inputPer1M: number;
  outputPer1M: number;
}

const MODEL_PRICING: Record<string, ModelPricing> = {
  // Anthropic
  'claude-opus-4': { inputPer1M: 15, outputPer1M: 75 },
  'claude-sonnet-4': { inputPer1M: 3, outputPer1M: 15 },
  'claude-haiku-3.5': { inputPer1M: 0.80, outputPer1M: 4 },
  'claude-3-opus': { inputPer1M: 15, outputPer1M: 75 },
  'claude-3.5-sonnet': { inputPer1M: 3, outputPer1M: 15 },
  'claude-3-haiku': { inputPer1M: 0.25, outputPer1M: 1.25 },
  // OpenAI
  'gpt-4o': { inputPer1M: 2.50, outputPer1M: 10 },
  'gpt-4o-mini': { inputPer1M: 0.15, outputPer1M: 0.60 },
  'gpt-4-turbo': { inputPer1M: 10, outputPer1M: 30 },
  'gpt-4': { inputPer1M: 30, outputPer1M: 60 },
  'o1': { inputPer1M: 15, outputPer1M: 60 },
  'o1-mini': { inputPer1M: 3, outputPer1M: 12 },
  // Google
  'gemini-1.5-pro': { inputPer1M: 1.25, outputPer1M: 5 },
  'gemini-1.5-flash': { inputPer1M: 0.075, outputPer1M: 0.30 },
  'gemini-2.0-flash': { inputPer1M: 0.10, outputPer1M: 0.40 },
  // Default fallback
  'default': { inputPer1M: 5, outputPer1M: 15 },
};

// ── Token Usage Extraction ─────────────────────────────────────────────────

interface TokenUsage {
  model: string;
  inputTokens: number;
  outputTokens: number;
  timestamp: string;
}

function extractTokenUsageFromLine(line: string): TokenUsage | null {
  try {
    const parsed = JSON.parse(line);

    // OpenClaw session JSONL format
    let model = parsed.model ?? parsed.data?.model ?? 'default';
    let inputTokens = 0;
    let outputTokens = 0;
    const timestamp = parsed.timestamp ?? parsed.ts ?? new Date().toISOString();

    // Anthropic format
    if (parsed.usage) {
      inputTokens = parsed.usage.input_tokens ?? parsed.usage.prompt_tokens ?? 0;
      outputTokens = parsed.usage.output_tokens ?? parsed.usage.completion_tokens ?? 0;
    }

    // OpenAI format
    if (parsed.data?.usage) {
      inputTokens = parsed.data.usage.prompt_tokens ?? parsed.data.usage.input_tokens ?? 0;
      outputTokens = parsed.data.usage.completion_tokens ?? parsed.data.usage.output_tokens ?? 0;
    }

    // Direct token counts
    if (parsed.input_tokens) inputTokens = parsed.input_tokens;
    if (parsed.output_tokens) outputTokens = parsed.output_tokens;

    if (inputTokens === 0 && outputTokens === 0) return null;

    // Normalize model names
    model = normalizeModelName(model);

    return { model, inputTokens, outputTokens, timestamp };
  } catch {
    return null;
  }
}

function normalizeModelName(model: string): string {
  const lower = model.toLowerCase();

  // Match known models
  for (const key of Object.keys(MODEL_PRICING)) {
    if (key === 'default') continue;
    if (lower.includes(key)) return key;
  }

  // Partial matches
  if (lower.includes('opus')) return 'claude-opus-4';
  if (lower.includes('sonnet')) return 'claude-sonnet-4';
  if (lower.includes('haiku')) return 'claude-haiku-3.5';
  if (lower.includes('gpt-4o-mini')) return 'gpt-4o-mini';
  if (lower.includes('gpt-4o')) return 'gpt-4o';
  if (lower.includes('gpt-4')) return 'gpt-4';
  if (lower.includes('gemini')) return 'gemini-1.5-pro';

  return 'default';
}

function calculateCost(usage: TokenUsage): number {
  const pricing = MODEL_PRICING[usage.model] ?? MODEL_PRICING['default'];
  const inputCost = (usage.inputTokens / 1_000_000) * pricing.inputPer1M;
  const outputCost = (usage.outputTokens / 1_000_000) * pricing.outputPer1M;
  return inputCost + outputCost;
}

// ── Public API ─────────────────────────────────────────────────────────────

/**
 * Estimate the total cost from a single session JSONL file
 */
export function estimateSessionCost(sessionFile: string): CostDetail[] {
  const details = new Map<string, CostDetail>();

  let content: string;
  try {
    content = fs.readFileSync(sessionFile, 'utf-8');
  } catch {
    return [];
  }

  for (const line of content.split('\n')) {
    if (!line.trim()) continue;
    const usage = extractTokenUsageFromLine(line);
    if (!usage) continue;

    const cost = calculateCost(usage);
    const existing = details.get(usage.model);
    if (existing) {
      existing.inputTokens += usage.inputTokens;
      existing.outputTokens += usage.outputTokens;
      existing.cost += cost;
    } else {
      details.set(usage.model, {
        model: usage.model,
        inputTokens: usage.inputTokens,
        outputTokens: usage.outputTokens,
        cost,
      });
    }
  }

  return [...details.values()];
}

/**
 * Scan all session files in an events/agent directory and compute cost snapshot
 */
export function getCostSnapshot(
  eventsDir: string,
  config: CostConfig,
): CostSnapshot {
  const now = Date.now();
  const hourAgo = now - 60 * 60 * 1000;
  const dayAgo = now - 24 * 60 * 60 * 1000;
  const monthAgo = now - 30 * 24 * 60 * 60 * 1000;

  let hourly = 0;
  let daily = 0;
  let monthly = 0;
  const modelCosts = new Map<string, CostDetail>();

  // Scan JSONL files in events directory
  const files = findJsonlFiles(eventsDir);

  for (const file of files) {
    let content: string;
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    for (const line of content.split('\n')) {
      if (!line.trim()) continue;
      const usage = extractTokenUsageFromLine(line);
      if (!usage) continue;

      const cost = calculateCost(usage);
      const ts = new Date(usage.timestamp).getTime();

      if (ts >= monthAgo) {
        monthly += cost;
        // Aggregate by model
        const existing = modelCosts.get(usage.model);
        if (existing) {
          existing.inputTokens += usage.inputTokens;
          existing.outputTokens += usage.outputTokens;
          existing.cost += cost;
        } else {
          modelCosts.set(usage.model, {
            model: usage.model,
            inputTokens: usage.inputTokens,
            outputTokens: usage.outputTokens,
            cost,
          });
        }
      }
      if (ts >= dayAgo) daily += cost;
      if (ts >= hourAgo) hourly += cost;
    }
  }

  // Determine breaker state
  let breaker: CostSnapshot['breaker'] = 'ok';

  if (config.circuitBreakerEnabled) {
    const hourlyTripped = config.hourlyLimitUsd !== undefined && hourly >= config.hourlyLimitUsd;
    const dailyTripped = config.dailyLimitUsd !== undefined && daily >= config.dailyLimitUsd;
    const monthlyTripped = config.monthlyLimitUsd !== undefined && monthly >= config.monthlyLimitUsd;

    if (hourlyTripped || dailyTripped || monthlyTripped) {
      breaker = 'tripped';
    } else {
      // Warning at 80%
      const hourlyWarning = config.hourlyLimitUsd !== undefined && hourly >= config.hourlyLimitUsd * 0.8;
      const dailyWarning = config.dailyLimitUsd !== undefined && daily >= config.dailyLimitUsd * 0.8;
      const monthlyWarning = config.monthlyLimitUsd !== undefined && monthly >= config.monthlyLimitUsd * 0.8;

      if (hourlyWarning || dailyWarning || monthlyWarning) {
        breaker = 'warning';
      }
    }
  }

  return {
    hourly: Math.round(hourly * 100) / 100,
    daily: Math.round(daily * 100) / 100,
    monthly: Math.round(monthly * 100) / 100,
    breaker,
    details: [...modelCosts.values()],
  };
}

/**
 * Get model pricing table
 */
export function getModelPricing(): Record<string, ModelPricing> {
  return { ...MODEL_PRICING };
}

// ── Internal helpers ──────────────────────────────────────────────────────

function findJsonlFiles(dir: string): string[] {
  const files: string[] = [];
  try {
    if (!fs.existsSync(dir)) return files;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isFile() && entry.name.endsWith('.jsonl')) {
        files.push(fullPath);
      } else if (entry.isDirectory()) {
        // Recurse one level
        try {
          const subEntries = fs.readdirSync(fullPath);
          for (const sub of subEntries) {
            if (sub.endsWith('.jsonl')) {
              files.push(path.join(fullPath, sub));
            }
          }
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }
  return files;
}
