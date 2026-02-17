import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

// High-confidence patterns: directly reference crewai
const CREWAI_IMPORT_PATTERNS = [
  /from\s+crewai\s+import/,
  /from\s+crewai\.tools/,
  /from\s+crewai_tools/,
  /@CrewBase/,
];

// Lower-confidence patterns: could appear in non-crewai code — only count with corroboration
const CREWAI_GENERIC_PATTERNS = [
  /\bCrew\s*\(/,
  /Agent\s*\(\s*\n?\s*role\s*=/,
  /Task\s*\(\s*\n?\s*description\s*=/,
];

// YAML files only count if they contain CrewAI-specific keys
const CREWAI_YAML_KEYS = ['role', 'backstory', 'goal', 'allow_delegation'];

export function detectCrewAI(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;
  let hasCrewAIDep = false;
  let hasCrewAIImport = false;

  // Check deps first — needed for corroboration
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (content.includes('crewai')) {
      hasCrewAIDep = true;
      evidence.push(`${file.relativePath}: depends on crewai`);
      confidence += 0.3;
    }
  }

  // Check for CrewAI YAML config files — verify content, not just filename
  for (const file of files.yaml) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (!['agents.yaml', 'agents.yml', 'tasks.yaml', 'tasks.yml', 'crew.yaml', 'crew.yml'].includes(basename)) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Verify the YAML has CrewAI-specific keys (not Ansible tasks.yaml, etc.)
    const hasCrewAIKeys = CREWAI_YAML_KEYS.some(key => new RegExp(`\\b${key}\\s*:`).test(content));
    if (hasCrewAIKeys) {
      evidence.push(`${file.relativePath}: CrewAI config file (verified keys)`);
      matchedFiles.push(file.relativePath);
      confidence += 0.3;
    }
  }

  // Check Python files for CrewAI patterns
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // High-confidence: direct crewai import
    let matched = false;
    for (const pattern of CREWAI_IMPORT_PATTERNS) {
      if (pattern.test(content)) {
        hasCrewAIImport = true;
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        matched = true;
        break;
      }
    }

    // Generic patterns only count if we already have crewai dep or import evidence
    if (!matched && (hasCrewAIDep || hasCrewAIImport)) {
      for (const pattern of CREWAI_GENERIC_PATTERNS) {
        if (pattern.test(content)) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source} (corroborated)`);
          confidence += 0.1;
          matched = true;
          break;
        }
      }
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
