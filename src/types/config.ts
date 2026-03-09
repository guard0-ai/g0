import type { Grade, Severity, SecurityDomain } from './common.js';

export type PresetName = 'strict' | 'balanced' | 'permissive';

export interface G0Config {
  min_score?: number;
  min_grade?: Grade;
  fail_on?: Severity;
  exclude_rules?: string[];
  exclude_paths?: string[];
  include_beta?: boolean;
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
  };
  domain_weights?: Partial<Record<SecurityDomain, number>>;
}
