import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const LANGCHAIN4J_DEPS = [
  'dev.langchain4j', 'langchain4j', 'langgraph4j',
];

const LANGCHAIN4J_PATTERNS = [
  /import\s+dev\.langchain4j/,
  /import\s+dev\.langgraph4j/,
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

  for (const file of files.java) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of LANGCHAIN4J_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check pom.xml / build.gradle for langchain4j deps
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
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'langchain4j',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.4,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
