import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const LANGCHAIN_IMPORTS = [
  'langchain', 'langchain_core', 'langchain_community', 'langchain_openai',
  'langchain_anthropic', 'langgraph', 'langsmith',
  '@langchain/core', '@langchain/community', '@langchain/openai',
  '@langchain/anthropic', '@langchain/langgraph',
];

const LANGCHAIN_PATTERNS = [
  /from\s+langchain/,
  /import\s+.*langchain/,
  /require\s*\(\s*['"]@langchain/,
  /AgentExecutor/,
  /create_react_agent/,
  /create_openai_functions_agent/,
  /StateGraph/,
  /ToolNode/,
];

export function detectLangChain(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check Python files
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
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

  // Check package.json / requirements.txt for langchain deps
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

    for (const dep of LANGCHAIN_IMPORTS) {
      if (content.includes(dep)) {
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
    specificity: 0.3,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
