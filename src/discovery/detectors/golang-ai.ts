import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const GOLANG_AI_DEPS = [
  'github.com/tmc/langchaingo',
  'github.com/cloudwego/eino',
  'github.com/firebase/genkit',
  'cloud.google.com/go/ai',
  'github.com/google/generative-ai-go',
  'github.com/sashabaranov/go-openai',
];

// High-confidence: fully qualified import paths
const GOLANG_AI_IMPORT_PATTERNS = [
  /\"github\.com\/tmc\/langchaingo/,
  /\"github\.com\/cloudwego\/eino/,
  /\"github\.com\/firebase\/genkit/,
  /\"cloud\.google\.com\/go\/ai/,
  /\"github\.com\/google\/generative-ai-go/,
  /\"github\.com\/sashabaranov\/go-openai/,
];

// Medium-confidence: API patterns — require full package.method form
const GOLANG_AI_CODE_PATTERNS = [
  /\bllms\.Call\b/,
  /\bagents\.NewExecutor\b/,
  /\bchains\.NewLLMChain\b/,
  /\bopenai\.NewClient\b/,
  /\bgenai\.NewClient\b/,
];

export function detectGolangAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  for (const file of files.go) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Check import patterns first (high confidence)
    let matched = false;
    for (const pattern of GOLANG_AI_IMPORT_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.3;
        matched = true;
        break;
      }
    }

    // Code patterns (lower confidence)
    if (!matched) {
      for (const pattern of GOLANG_AI_CODE_PATTERNS) {
        if (pattern.test(content)) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source}`);
          confidence += 0.15;
          break;
        }
      }
    }
  }

  // Check go.mod for AI deps
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename !== 'go.mod') continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of GOLANG_AI_DEPS) {
      if (content.includes(dep)) {
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'golang-ai',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.6,  // raised from 0.3 — import patterns are fully qualified
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
