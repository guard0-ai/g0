import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

// Framework-level patterns — specific to OpenAI Agents SDK / Assistants API
const OPENAI_FRAMEWORK_PATTERNS = [
  /client\.beta\.assistants/,
  /assistants\.create\s*\(/,
  /client\.responses\.create\s*\(/,
  /\.beta\.threads/,
];

// OpenAI Agents SDK patterns — require corroborating evidence
const OPENAI_AGENTS_PATTERNS = [
  /from\s+agents\s+import/,          // only count if openai-agents dep present
  /\bRunner\.run\s*\(/,              // word boundary + call context
  /\bfunction_tool\s*\(/,            // word boundary + call context
];

// Broader patterns that indicate openai as a provider (not framework)
const OPENAI_PROVIDER_PATTERNS = [
  /from\s+openai\s+import/,
  /import\s+openai/,
  /require\s*\(\s*['"]openai['"]\s*\)/,
  /from\s+['"]openai['"]/,
];

export function detectOpenAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // First check if openai-agents or swarm dep exists
  let hasAgentsDep = false;
  let hasSwarmDep = false;
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (content.includes('openai-agents') || content.includes('@openai/agents')) {
      hasAgentsDep = true;
      evidence.push(`${file.relativePath}: depends on openai-agents`);
      confidence += 0.3;
    } else if (content.includes('openai-swarm') || content.includes('"swarm"') || content.includes("'swarm'")) {
      hasSwarmDep = true;
      evidence.push(`${file.relativePath}: depends on swarm`);
      confidence += 0.3;
    } else if (content.includes('"openai"') || content.includes("'openai'")) {
      evidence.push(`${file.relativePath}: depends on openai`);
      confidence += 0.2;
    }
  }

  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    let matched = false;

    // Check framework-level patterns (high confidence)
    for (const pattern of OPENAI_FRAMEWORK_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        matched = true;
        break;
      }
    }

    // Check Agents SDK patterns — 'from agents import' only counts with dep
    if (!matched) {
      for (const pattern of OPENAI_AGENTS_PATTERNS) {
        if (pattern.test(content)) {
          // 'from agents import' is generic — only count if openai-agents dep is confirmed
          if (pattern.source.includes('from\\s+agents') && !hasAgentsDep) continue;

          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source}`);
          confidence += 0.2;
          matched = true;
          break;
        }
      }
    }

    // Check Swarm patterns (high confidence — specific to OpenAI's Swarm framework)
    if (!matched && /from\s+swarm\s+import|import\s+swarm/.test(content)) {
      matchedFiles.push(file.relativePath);
      evidence.push(`${file.relativePath}: Swarm framework import`);
      confidence += 0.2;
      matched = true;
    }

    // Provider-only patterns get lower weight
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
