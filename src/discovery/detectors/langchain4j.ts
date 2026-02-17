import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const LANGCHAIN4J_DEPS = [
  'dev.langchain4j', 'langchain4j', 'langgraph4j',
];

// High-confidence patterns (import statements)
const LANGCHAIN4J_IMPORT_PATTERNS = [
  /import\s+dev\.langchain4j/,
  /import\s+dev\.langgraph4j/,
];

// Medium-confidence patterns — only count if file has langchain4j import or dep
const LANGCHAIN4J_CODE_PATTERNS = [
  /\bAiServices\b/,
  /\bChatLanguageModel\b/,
  /\bStateGraph\b/,
  /\b@Tool\b/,
  /\b@SystemMessage\b/,
  /\b@UserMessage\b/,
  /\bStreamingChatLanguageModel\b/,
  /\bTokenizer\b.*langchain4j/,
];

export function detectLangChain4j(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check deps first
  let hasLangchain4jDep = false;
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (!['pom.xml', 'build.gradle', 'build.gradle.kts'].includes(basename)) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of LANGCHAIN4J_DEPS) {
      if (content.includes(dep)) {
        hasLangchain4jDep = true;
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  for (const file of files.java) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Check import patterns (always count)
    let hasImport = false;
    for (const pattern of LANGCHAIN4J_IMPORT_PATTERNS) {
      if (pattern.test(content)) {
        hasImport = true;
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }

    // Code patterns only count if file has import OR project has dep
    if (hasImport || hasLangchain4jDep) {
      for (const pattern of LANGCHAIN4J_CODE_PATTERNS) {
        if (pattern.test(content)) {
          if (!hasImport) matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source}`);
          confidence += 0.1;
          break;
        }
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'langchain4j',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.7,  // raised from 0.4 — now requires import/dep corroboration
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
