import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';
import type { ASTStore } from '../../analyzers/ast/store.js';
import { findImports, findFunctionCalls } from '../../analyzers/ast/queries.js';

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

/** AST-based framework call patterns */
const OPENAI_AST_FRAMEWORK_CALLS = [
  /client\.beta\.assistants/,
  /assistants\.create/,
  /client\.responses\.create/,
];

const OPENAI_AST_AGENT_CALLS = ['Runner.run', 'function_tool'];

export function detectOpenAI(files: FileInventory, astStore?: ASTStore): DetectionResult | null {
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

  const codeFiles = [...files.python, ...files.typescript, ...files.javascript];
  for (const file of codeFiles) {
    const tree = astStore?.getTree(file.path);

    if (tree) {
      // AST path
      let matched = false;
      const imports = findImports(tree);

      // Check for openai framework imports
      for (const imp of imports) {
        const impText = imp.text;
        if (impText.includes('openai') && (impText.includes('beta') || impText.includes('assistants'))) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: framework import (AST)`);
          confidence += 0.2;
          matched = true;
          break;
        }
      }

      // Check Agents SDK calls
      if (!matched && hasAgentsDep) {
        for (const callName of OPENAI_AST_AGENT_CALLS) {
          const calls = findFunctionCalls(tree, callName);
          if (calls.length > 0) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: calls ${callName}() (AST)`);
            confidence += 0.2;
            matched = true;
            break;
          }
        }
      }

      // Check framework-level call patterns
      if (!matched) {
        for (const pattern of OPENAI_AST_FRAMEWORK_CALLS) {
          const calls = findFunctionCalls(tree, pattern);
          if (calls.length > 0) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: framework call (AST)`);
            confidence += 0.2;
            matched = true;
            break;
          }
        }
      }

      // Swarm
      if (!matched) {
        for (const imp of imports) {
          if (imp.text.includes('swarm')) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: Swarm framework import (AST)`);
            confidence += 0.2;
            matched = true;
            break;
          }
        }
      }

      // Provider-only (low weight)
      if (!matched) {
        for (const imp of imports) {
          if (imp.text.includes('openai')) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: openai import (provider) (AST)`);
            confidence += 0.1;
            break;
          }
        }
      }
    } else {
      // Regex fallback
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

      // Check Agents SDK patterns
      if (!matched && hasAgentsDep) {
        for (const pattern of OPENAI_AGENTS_PATTERNS) {
          if (pattern.test(content)) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: matches ${pattern.source}`);
            confidence += 0.2;
            matched = true;
            break;
          }
        }
      }

      // Check Swarm patterns
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
  }

  if (confidence === 0) return null;

  const hasFrameworkEvidence = hasAgentsDep || hasSwarmDep ||
    evidence.some(e => !e.includes('(provider)') && !e.includes('depends on openai'));
  const isProviderOnly = !hasFrameworkEvidence;

  return {
    framework: 'openai',
    confidence: Math.min(confidence, isProviderOnly ? 0.3 : 1),
    rawConfidence: confidence,
    specificity: isProviderOnly ? 0.2 : 0.7,
    evidence,
    files: [...new Set(matchedFiles)],
    isProviderOnly,
  };
}
