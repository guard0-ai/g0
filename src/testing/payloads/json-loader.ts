import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AttackPayload, AttackCategory, CanaryToken, ConversationMessage } from '../../types/test.js';
import type { Severity } from '../../types/common.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = resolve(__dirname, '../data');

interface JsonPayloadShorthand {
  id: string;
  category: string;
  name: string;
  description: string;
  severity: string;
  prompt?: string;
  messages?: Array<{ role: string; content: string; delayMs?: number }>;
  tags: string[];
  heuristicId?: string;
  harmSubcategory?: string;
  vulnerablePatterns?: string[];
  resistantPatterns?: string[];
  complianceIndicators?: string[];
  refusalIndicators?: string[];
  llmJudgePrompt?: string;
  canaryTokens?: Array<{ type: string; value: string }>;
}

export function loadJsonPayloads(filename: string): AttackPayload[] {
  const filePath = resolve(DATA_DIR, filename);
  const raw = readFileSync(filePath, 'utf-8');
  const entries = JSON.parse(raw) as JsonPayloadShorthand[];

  return entries.map((entry): AttackPayload => {
    const messages: ConversationMessage[] = entry.messages
      ? entry.messages.map(m => ({
          role: (m.role === 'system' ? 'system' : 'user') as 'user' | 'system',
          content: m.content,
          ...(m.delayMs ? { delayMs: m.delayMs } : {}),
        }))
      : entry.prompt
        ? [{ role: 'user' as const, content: entry.prompt }]
        : [];

    return {
      id: entry.id,
      category: entry.category as AttackCategory,
      name: entry.name,
      description: entry.description,
      severity: (entry.severity || 'high') as Severity,
      messages,
      judgeCriteria: {
        ...(entry.heuristicId ? { heuristicId: entry.heuristicId } : {}),
        ...(entry.harmSubcategory ? { harmSubcategory: entry.harmSubcategory } : {}),
        ...(entry.vulnerablePatterns ? { vulnerablePatterns: entry.vulnerablePatterns } : {}),
        ...(entry.resistantPatterns ? { resistantPatterns: entry.resistantPatterns } : {}),
        ...(entry.complianceIndicators ? { complianceIndicators: entry.complianceIndicators } : {}),
        ...(entry.refusalIndicators ? { refusalIndicators: entry.refusalIndicators } : {}),
        ...(entry.llmJudgePrompt ? { llmJudgePrompt: entry.llmJudgePrompt } : {}),
        ...(entry.canaryTokens ? { canaryTokens: entry.canaryTokens as CanaryToken[] } : {}),
      },
      tags: entry.tags || [],
    };
  });
}
