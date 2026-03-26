import type { Severity, Confidence, SecurityDomain, Location } from './common.js';

export type Reachability = 'agent-reachable' | 'tool-reachable' | 'endpoint-reachable' | 'utility-code' | 'unknown';
export type FindingExploitability = 'confirmed' | 'likely' | 'unlikely' | 'not-assessed';

/**
 * Finding category distinguishes actual vulnerabilities from missing best practices.
 * - vulnerability: dangerous code/config IS present (shell injection, SQL injection, etc.)
 * - hardening: a recommended control is MISSING (no kill switch, no RBAC, etc.)
 * - informational: low-signal observation, no direct security impact
 */
export type FindingCategory = 'vulnerability' | 'hardening' | 'informational';

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
  /** Derived category: vulnerability (bad code present) vs hardening (good practice absent) */
  category?: FindingCategory;
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
  owaspAgenticTop10?: string[];
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
