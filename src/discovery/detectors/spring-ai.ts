import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const SPRING_AI_DEPS = [
  'spring-ai', 'org.springframework.ai',
];

// High-confidence: import statement
const SPRING_AI_IMPORT_PATTERN = /import\s+org\.springframework\.ai/;

// Medium-confidence: class names — only count with import or dep
const SPRING_AI_CODE_PATTERNS = [
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

  // Check deps first
  let hasSpringAIDep = false;
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
        hasSpringAIDep = true;
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

    // Check import pattern (always count)
    let hasImport = false;
    if (SPRING_AI_IMPORT_PATTERN.test(content)) {
      hasImport = true;
      matchedFiles.push(file.relativePath);
      evidence.push(`${file.relativePath}: matches Spring AI import`);
      confidence += 0.2;
    }

    // Code patterns only count if file has import OR project has dep
    if (hasImport || hasSpringAIDep) {
      for (const pattern of SPRING_AI_CODE_PATTERNS) {
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
    framework: 'spring-ai',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.7,  // raised from 0.4 — now requires import/dep corroboration
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
