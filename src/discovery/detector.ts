import type { FrameworkId, FileInventory } from '../types/common.js';
import { detectLangChain } from './detectors/langchain.js';
import { detectCrewAI } from './detectors/crewai.js';
import { detectMCP } from './detectors/mcp.js';
import { detectOpenAI } from './detectors/openai.js';
import { detectVercelAI } from './detectors/vercel-ai.js';
import { detectBedrock } from './detectors/bedrock.js';
import { detectAutoGen } from './detectors/autogen.js';
import { detectLangChain4j } from './detectors/langchain4j.js';
import { detectSpringAI } from './detectors/spring-ai.js';
import { detectGolangAI } from './detectors/golang-ai.js';
import { detectGeneric } from './detectors/generic.js';

export interface DetectionResult {
  framework: FrameworkId;
  confidence: number;
  /** Raw confidence before capping at 1.0 — reflects total evidence volume */
  rawConfidence: number;
  specificity: number;
  evidence: string[];
  files: string[];
}

export interface DetectionSummary {
  primary: FrameworkId;
  secondary: FrameworkId[];
  results: DetectionResult[];
}

type Detector = (files: FileInventory) => DetectionResult | null;

const detectors: Detector[] = [
  detectLangChain,
  detectCrewAI,
  detectMCP,
  detectOpenAI,
  detectVercelAI,
  detectBedrock,
  detectAutoGen,
  detectLangChain4j,
  detectSpringAI,
  detectGolangAI,
  detectGeneric,
];

export function detectFrameworks(files: FileInventory): DetectionSummary {
  const results: DetectionResult[] = [];

  for (const detect of detectors) {
    const result = detect(files);
    if (result && result.confidence > 0) {
      results.push(result);
    }
  }

  // Sort by weighted score combining confidence, specificity, and evidence volume.
  // Volume bonus: log2(rawConfidence) gives diminishing returns for massive match counts
  // but still differentiates "4 matches" from "1228 matches".
  // Specificity bonus is small (max 0.135) to break ties, not override volume.
  results.sort((a, b) => {
    const volumeA = Math.log2(1 + a.rawConfidence);
    const volumeB = Math.log2(1 + b.rawConfidence);
    const scoreA = a.confidence + a.specificity * 0.05 + volumeA * 0.1;
    const scoreB = b.confidence + b.specificity * 0.05 + volumeB * 0.1;
    return scoreB - scoreA;
  });

  const primary = results.length > 0 ? results[0].framework : 'generic' as FrameworkId;
  const secondary = results.slice(1)
    .filter(r => r.confidence > 0.3)
    .map(r => r.framework);

  return { primary, secondary, results };
}
