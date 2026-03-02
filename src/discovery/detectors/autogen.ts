import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const AUTOGEN_DEPS = [
  'pyautogen',
  'autogen-agentchat',
  'autogen-core',
  'ag2',
];

// Import-level patterns (high confidence — framework-specific)
const AUTOGEN_IMPORT_PATTERNS = [
  /from\s+autogen\b/,
  /import\s+autogen\b/,
  /from\s+ag2\b/,
  /import\s+ag2\b/,
];

// Constructor/API patterns — only count if file also has import or dep is confirmed
const AUTOGEN_CONSTRUCTOR_PATTERNS = [
  /\bConversableAgent\b/,
  /\bAssistantAgent\b/,
  /\bUserProxyAgent\b/,
  /\bGroupChat\s*\(/,
  /\bGroupChatManager\b/,
  /\bregister_for_llm\b/,
  /\binitiate_chat\b/,
];

export function detectAutoGen(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check requirements.txt / configs for autogen deps
  let hasAutogenDep = false;
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

    const seenDeps = new Set<string>();
    for (const dep of AUTOGEN_DEPS) {
      // Use word-boundary check to avoid substring matches (e.g. 'autogen' in 'autogen-core')
      const depPattern = new RegExp(`\\b${dep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
      if (depPattern.test(content) && !seenDeps.has(dep)) {
        seenDeps.add(dep);
        evidence.push(`${file.relativePath}: depends on ${dep}`);
        confidence += 0.3;
        hasAutogenDep = true;
      }
    }
  }

  // Check Python files
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    let matched = false;

    // Import patterns always count (high confidence)
    for (const pattern of AUTOGEN_IMPORT_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        matched = true;
        hasAutogenDep = true; // import is as good as dep evidence
        break;
      }
    }

    // Constructor patterns only count if we have import/dep corroboration
    if (!matched && hasAutogenDep) {
      for (const pattern of AUTOGEN_CONSTRUCTOR_PATTERNS) {
        if (pattern.test(content)) {
          matchedFiles.push(file.relativePath);
          evidence.push(`${file.relativePath}: matches ${pattern.source}`);
          confidence += 0.2;
          break;
        }
      }
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'autogen',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.9,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
