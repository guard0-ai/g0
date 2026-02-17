import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

// Bedrock-specific deps only — boto3 is too generic (used by all AWS projects)
const BEDROCK_DEPS = [
  'amazon-bedrock',
  'langchain-aws',
  '@aws-sdk/client-bedrock-runtime',
  '@aws-sdk/client-bedrock-agent-runtime',
];

// High-confidence patterns (Bedrock-specific)
const BEDROCK_SPECIFIC_PATTERNS = [
  /boto3\.client\s*\(\s*['"]bedrock/,
  /\bbedrock-runtime\b/,
  /\bBedrockAgentRuntime\b/,
  /\bChatBedrock\b/,
  /from\s+langchain_aws\b/,
  /\bBedrockLLM\b/,
];

// Generic patterns — only count if file also has Bedrock-specific context
const BEDROCK_CONTEXTUAL_PATTERNS = [
  /\binvoke_model\s*\(/,
  /\.converse\s*\([^)]*modelId/,   // .converse() with modelId nearby
];

export function detectBedrock(files: FileInventory): DetectionResult | null {
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

    // Check specific patterns first
    let hasBedrockContext = false;
    for (const pattern of BEDROCK_SPECIFIC_PATTERNS) {
      if (pattern.test(content)) {
        hasBedrockContext = true;
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }

    // Contextual patterns only count if the file mentions 'bedrock'
    if (!hasBedrockContext && content.includes('bedrock')) {
      for (const pattern of BEDROCK_CONTEXTUAL_PATTERNS) {
        if (pattern.test(content)) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source} (with bedrock context)`);
          confidence += 0.15;
          break;
        }
      }
    }
  }

  // Check deps — only Bedrock-specific packages, not boto3
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of BEDROCK_DEPS) {
      if (content.includes(dep)) {
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'bedrock',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.9,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
