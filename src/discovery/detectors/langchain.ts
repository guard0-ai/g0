import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';
import type { ASTStore } from '../../analyzers/ast/store.js';
import { findImports, findFunctionCalls } from '../../analyzers/ast/queries.js';

const LANGCHAIN_IMPORTS = [
  'langchain', 'langchain_core', 'langchain_community', 'langchain_openai',
  'langchain_anthropic', 'langgraph', 'langsmith',
  '@langchain/core', '@langchain/community', '@langchain/openai',
  '@langchain/anthropic', '@langchain/langgraph',
];

const LANGCHAIN_PATTERNS = [
  /from\s+langchain\b/,
  /import\s+.*langchain/,
  /require\s*\(\s*['"]@langchain/,
  /\bAgentExecutor\b/,
  /\bcreate_react_agent\b/,
  /\bcreate_openai_functions_agent\b/,
  /\bStateGraph\s*\(/,     // require call context for StateGraph
  /\bToolNode\s*\(/,       // require call context for ToolNode
];

/** AST-based import names to look for */
const LANGCHAIN_AST_MODULES = [
  'langchain', 'langchain_core', 'langchain_community', 'langchain_openai',
  'langchain_anthropic', 'langgraph', 'langsmith',
  '@langchain/core', '@langchain/community', '@langchain/openai',
  '@langchain/anthropic', '@langchain/langgraph',
];

/** AST-based call patterns — these are LangChain-specific constructors */
const LANGCHAIN_AST_CALLS = [
  'AgentExecutor', 'create_react_agent', 'create_openai_functions_agent',
  'StateGraph', 'ToolNode',
];

export function detectLangChain(files: FileInventory, astStore?: ASTStore): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  const codeFiles = [...files.python, ...files.typescript, ...files.javascript];

  for (const file of codeFiles) {
    const tree = astStore?.getTree(file.path);

    if (tree) {
      // AST path: check imports and function calls structurally
      let matched = false;
      const imports = findImports(tree);
      for (const imp of imports) {
        const impText = imp.text;
        for (const mod of LANGCHAIN_AST_MODULES) {
          if (impText.includes(mod)) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: imports ${mod} (AST)`);
            confidence += 0.2;
            matched = true;
            break;
          }
        }
        if (matched) break;
      }

      if (!matched) {
        for (const callName of LANGCHAIN_AST_CALLS) {
          const calls = findFunctionCalls(tree, callName);
          if (calls.length > 0) {
            matchedFiles.push(file.relativePath);
            evidence.push(`${file.relativePath}: calls ${callName}() (AST)`);
            confidence += 0.2;
            break;
          }
        }
      }
    } else {
      // Regex fallback when AST is not available
      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        continue;
      }

      for (const pattern of LANGCHAIN_PATTERNS) {
        if (pattern.test(content)) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source}`);
          confidence += 0.2;
          break;
        }
      }
    }
  }

  // Check package.json / requirements.txt for langchain deps
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    const seenDeps = new Set<string>();
    for (const dep of LANGCHAIN_IMPORTS) {
      // Use word boundary to avoid double-counting (e.g. 'langchain' inside 'langchain_openai')
      const depPattern = new RegExp(`\\b${dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
      if (depPattern.test(content) && !seenDeps.has(dep)) {
        seenDeps.add(dep);
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'langchain',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.8,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
