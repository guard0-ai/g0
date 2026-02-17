import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

/**
 * Generic agent detector — catches AI agent patterns that don't match
 * any specific framework. Uses tight patterns and a high threshold to
 * avoid false positives on non-AI codebases.
 *
 * Tightened patterns (FP reduction):
 *  - Removed bare `/agent/i` — matches user-agent strings, etc.
 *  - Removed bare `/llm/i` — matches unrelated 3-letter acronyms.
 *  - Removed bare `/assistant/i` — matches non-AI classes.
 *  - All patterns now require AI-specific context.
 *  - Threshold raised from 2 to 3 pattern matches per file.
 */

const AGENT_PATTERNS = [
  // Python/TS/JS: AI agent patterns with context
  /system_prompt/i,
  /system_message/i,
  /\btool_call\b/,
  /\bfunction_call\b/,
  /\bllm_config\b/i,
  /\bchat_completion\b/i,
  /\bchatcompletion\b/i,
  /\bagent_executor\b/i,
  /\bllm[._]chain\b/i,
  // Java patterns (require word boundaries)
  /\bAiServices\b/,
  /\b@Tool\b/,
  /\bChatModel\b/,
  /\bChatClient\b/,
  // Go patterns (fully qualified)
  /llms\.Call\b/,
  /agents\.NewExecutor\b/,
];

export function detectGeneric(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  for (const file of [...files.python, ...files.typescript, ...files.javascript, ...files.java, ...files.go]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    let fileMatches = 0;
    for (const pattern of AGENT_PATTERNS) {
      if (pattern.test(content)) {
        fileMatches++;
      }
    }

    // Require 3+ pattern matches per file (raised from 2)
    if (fileMatches >= 3) {
      matchedFiles.push(file.relativePath);
      evidence.push(`${file.relativePath}: ${fileMatches} agent-related patterns`);
      confidence += 0.1;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'generic',
    confidence: Math.min(confidence, 0.3),  // capped lower (was 0.5)
    rawConfidence: confidence,
    specificity: 0.0,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
