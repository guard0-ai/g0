import type { Severity, Confidence, SecurityDomain, Location } from './common.js';

export type Reachability = 'agent-reachable' | 'tool-reachable' | 'endpoint-reachable' | 'utility-code' | 'unknown';
export type FindingExploitability = 'confirmed' | 'likely' | 'unlikely' | 'not-assessed';

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  domain: SecurityDomain;
  location: Location;
  remediation: string;
  standards: StandardsMapping;
  reachability?: Reachability;
  exploitability?: FindingExploitability;
  checkType?: string;
  taintFlow?: {
    stages: Array<{ command: string; taintTypes: string[]; line: number }>;
    flowType: string;
  };
  relatedLocations?: Array<{ file: string; line: number; message: string }>;
  /** True if this finding matches a risk_accepted entry in config */
  accepted?: boolean;
  /** Reason provided for risk acceptance */
  acceptedReason?: string;
}

export interface StandardsMapping {
  owaspAgentic: string[];
  aiuc1?: string[];
  iso42001?: string[];
  nistAiRmf?: string[];
  iso23894?: string[];
  owaspAivss?: string[];
  a2asBasic?: string[];
  euAiAct?: string[];
  mitreAtlas?: string[];
  owaspLlmTop10?: string[];
}

export interface FindingSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}
