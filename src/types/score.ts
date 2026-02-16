import type { Grade, SecurityDomain } from './common.js';

export interface DomainScore {
  domain: SecurityDomain;
  label: string;
  score: number;       // 0-100
  weight: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ScanScore {
  overall: number;     // 0-100
  grade: Grade;
  domains: DomainScore[];
}

export interface AIFindingEnrichment {
  explanation: string;
  remediation: string;
  falsePositive: boolean;
  falsePositiveReason?: string;
}

export interface AIComplexFinding {
  title: string;
  description: string;
  severity: import('./common.js').Severity;
  confidence: import('./common.js').Confidence;
  location?: import('./common.js').Location;
}

export interface AIAnalysisResult {
  enrichments: Map<string, AIFindingEnrichment>;
  complexFindings: AIComplexFinding[];
  provider: string;
  duration: number;
  excludedCount?: number;
}

export interface ScanResult {
  score: ScanScore;
  findings: import('./finding.js').Finding[];
  graph: import('./agent-graph.js').AgentGraph;
  duration: number;
  timestamp: string;
  aiAnalysis?: AIAnalysisResult;
  suppressedCount?: number;
}
