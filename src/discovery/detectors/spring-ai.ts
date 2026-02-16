import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const SPRING_AI_DEPS = [
  'spring-ai', 'org.springframework.ai',
];

const SPRING_AI_PATTERNS = [
  /import\s+org\.springframework\.ai/,
  /\bChatClient\b/,
  /\b@Advisor\b/,
  /\bFunctionCallback\b/,
  /\bVectorStore\b/,
  /\bChatModel\b/,
  /\bEmbeddingModel\b/,
  /\bPromptTemplate\b/,
  /\bSystemPromptTemplate\b/,
];

export function detectSpringAI(files: FileInventory): DetectionResult | null {
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

    for (const pattern of SPRING_AI_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (!['pom.xml', 'build.gradle', 'build.gradle.kts'].includes(basename)) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const dep of SPRING_AI_DEPS) {
      if (content.includes(dep)) {
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'spring-ai',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.4,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
