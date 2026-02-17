import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const VERCEL_AI_DEPS = [
  'ai', '@ai-sdk/openai', '@ai-sdk/anthropic', '@ai-sdk/google', '@ai-sdk/mistral',
];

// High-confidence: import statements from the Vercel AI SDK
const VERCEL_AI_IMPORT_PATTERNS = [
  /from\s+['"]ai['"]/,
  /from\s+['"]ai\/rsc['"]/,
  /from\s+['"]@ai-sdk\//,
  /require\s*\(\s*['"]ai['"]\s*\)/,
  /require\s*\(\s*['"]@ai-sdk\//,
  /createStreamableUI\s*\(/,
  /createStreamableValue\s*\(/,
];

// Lower-confidence: function calls that are only meaningful with an import
const VERCEL_AI_CODE_PATTERNS = [
  /\bgenerateText\s*\(\s*\{/,
  /\bstreamText\s*\(\s*\{/,
  /\bgenerateObject\s*\(\s*\{/,
  /\bstreamObject\s*\(\s*\{/,
];

export function detectVercelAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  for (const file of [...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Check for import patterns first (high confidence)
    let hasImport = false;
    for (const pattern of VERCEL_AI_IMPORT_PATTERNS) {
      if (pattern.test(content)) {
        hasImport = true;
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }

    // Code patterns only count if the file also has an import
    if (hasImport) {
      for (const pattern of VERCEL_AI_CODE_PATTERNS) {
        if (pattern.test(content)) {
          evidence.push(`${file.relativePath}: matches ${pattern.source}`);
          confidence += 0.1;
          break;
        }
      }
    }
  }

  // Check package.json configs for Vercel AI SDK deps
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of VERCEL_AI_DEPS) {
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
    specificity: 0.6,  // lowered from 0.9 — generic function names
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
