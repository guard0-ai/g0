import type { Grade, Severity, SecurityDomain } from './common.js';

export type PresetName = 'strict' | 'balanced' | 'permissive' | 'openclaw';

export interface RiskAcceptance {
  /** Rule ID or hardening check ID (e.g., "OC-H-003", "AA-CE-012") */
  rule: string;
  /** Mandatory justification for accepting the risk */
  reason: string;
  /** Optional expiration date (ISO 8601). After this date, the acceptance is ignored. */
  expires?: string;
}

export interface G0Config {
  min_score?: number;
  min_grade?: Grade;
  fail_on?: Severity;
  exclude_rules?: string[];
  exclude_paths?: string[];
  rules_dir?: string;
  preset?: PresetName;
  severity_overrides?: Record<string, Severity>;
  thresholds?: {
    max_findings_per_rule?: number;
    low_severity_cap?: number;
    medium_severity_cap?: number;
  };
  analyzers?: {
    taint_flow?: boolean;
    cross_file?: boolean;
    pipeline_taint?: boolean;
    analyzability?: boolean;
    intelligence?: boolean;
  };
  domain_weights?: Partial<Record<SecurityDomain, number>>;
  /** Findings accepted as known risks — shown as ACCEPTED, excluded from failure counts */
  risk_accepted?: RiskAcceptance[];
}
