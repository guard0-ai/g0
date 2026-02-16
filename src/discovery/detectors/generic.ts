import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const AGENT_PATTERNS = [
  /agent/i,
  /llm/i,
  /chatbot/i,
  /assistant/i,
  /system_prompt/i,
  /system_message/i,
  /tool_call/,
  /function_call/,
  // Java patterns
  /\bAiServices\b/,
  /\b@Tool\b/,
  /\bChatModel\b/,
  /\bChatClient\b/,
  // Go patterns
  /llms\.Call/,
  /agents\.NewExecutor/,
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

    if (fileMatches >= 2) {
      matchedFiles.push(file.relativePath);
      evidence.push(`${file.relativePath}: ${fileMatches} agent-related patterns`);
      confidence += 0.1;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'generic',
    confidence: Math.min(confidence, 0.5),
    rawConfidence: confidence,
    specificity: 0.0,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
