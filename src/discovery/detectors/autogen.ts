import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const AUTOGEN_PATTERNS = [
  /from\s+autogen/,
  /import\s+autogen/,
  /from\s+ag2/,
  /import\s+ag2/,
  /ConversableAgent/,
  /AssistantAgent/,
  /UserProxyAgent/,
  /GroupChat\s*\(/,
  /GroupChatManager/,
  /register_for_llm/,
  /initiate_chat/,
];

const AUTOGEN_DEPS = [
  'pyautogen',
  'autogen-agentchat',
  'autogen',
  'autogen-core',
  'ag2',
  'ag2',
];

export function detectAutoGen(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check Python files
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of AUTOGEN_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check requirements.txt / configs for autogen deps
  for (const file of files.configs) {
    // Skip lock files — transitive deps cause false detection
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of AUTOGEN_DEPS) {
      if (content.includes(dep)) {
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'autogen',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.9,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
