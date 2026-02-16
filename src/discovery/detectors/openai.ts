import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const OPENAI_PATTERNS = [
  /from\s+agents\s+import/,
  /require\s*\(\s*['"]openai['"]\s*\)/,
  /from\s+['"]openai['"]/,
  /client\.beta\.assistants/,
  /assistants\.create/,
  /client\.responses\.create/,
  /Runner\.run/,
  /function_tool/,
  /\.beta\.threads/,
];

// Broader patterns that indicate openai as a provider (not framework)
// Only used when no more specific framework is detected
const OPENAI_PROVIDER_PATTERNS = [
  /from\s+openai\s+import/,
  /import\s+openai/,
];

export function detectOpenAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    let matched = false;
    for (const pattern of OPENAI_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        matched = true;
        break;
      }
    }
    // Provider-only patterns (from openai import / import openai) get lower weight
    // since many frameworks use openai as a provider
    if (!matched) {
      for (const pattern of OPENAI_PROVIDER_PATTERNS) {
        if (pattern.test(content)) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source} (provider)`);
          confidence += 0.1;
          break;
        }
      }
    }
  }

  // Check deps
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

    if (content.includes('"openai"') || content.includes("'openai'") || content.includes('openai-agents')) {
      evidence.push(`${file.relativePath}: depends on openai`);
      confidence += 0.3;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'openai',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.7,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
