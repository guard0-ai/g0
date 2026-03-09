import type { G0Config } from '../../types/config.js';

export const permissivePreset: G0Config = {
  fail_on: 'critical',
  thresholds: {
    max_findings_per_rule: 100,
    low_severity_cap: 20,
    medium_severity_cap: 50,
  },
  analyzers: {
    taint_flow: false,
    cross_file: false,
    pipeline_taint: false,
    analyzability: false,
  },
};
