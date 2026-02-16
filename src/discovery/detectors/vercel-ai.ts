import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const VERCEL_AI_DEPS = [
  'ai', '@ai-sdk/openai', '@ai-sdk/anthropic', '@ai-sdk/google', '@ai-sdk/mistral',
];

const VERCEL_AI_PATTERNS = [
  /from\s+['"]ai['"]/,
  /from\s+['"]ai\/rsc['"]/,
  /from\s+['"]@ai-sdk\//,
  /generateText\s*\(/,
  /streamText\s*\(/,
  /generateObject\s*\(/,
  /streamObject\s*\(/,
  /tool\s*\(\s*\{/,
  /createStreamableUI\s*\(/,
  /createStreamableValue\s*\(/,
];

export function detectVercelAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check TS/JS files
  for (const file of [...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of VERCEL_AI_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check package.json configs for Vercel AI SDK deps
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

    for (const dep of VERCEL_AI_DEPS) {
      // Use word-boundary check to avoid substring matches (e.g. 'ai' in 'crewai')
      const depPattern = new RegExp(`["']${dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`);
      if (depPattern.test(content)) {
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'vercel-ai',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.9,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
