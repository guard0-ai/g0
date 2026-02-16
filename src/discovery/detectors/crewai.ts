import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const CREWAI_PATTERNS = [
  /from\s+crewai\s+import/,
  /from\s+crewai\.tools/,
  /from\s+crewai_tools/,
  /@CrewBase/,
  /Crew\s*\(/,
  /Agent\s*\(\s*\n?\s*role\s*=/,
  /Task\s*\(\s*\n?\s*description\s*=/,
];

const CREWAI_FILES = ['agents.yaml', 'tasks.yaml', 'crew.yaml'];

export function detectCrewAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check for CrewAI YAML config files
  for (const file of files.yaml) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (CREWAI_FILES.includes(basename)) {
      evidence.push(`${file.relativePath}: CrewAI config file`);
      matchedFiles.push(file.relativePath);
      confidence += 0.3;
    }
  }

  // Check Python files for CrewAI imports
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of CREWAI_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check deps
  for (const file of files.configs) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (content.includes('crewai')) {
      evidence.push(`${file.relativePath}: depends on crewai`);
      confidence += 0.3;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'crewai',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.8,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
