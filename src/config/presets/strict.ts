import type { G0Config } from '../../types/config.js';

export const strictPreset: G0Config = {
  fail_on: 'medium',
  min_score: 80,
  thresholds: {
    max_findings_per_rule: 30,
    low_severity_cap: 5,
    medium_severity_cap: 20,
  },
  analyzers: {
    taint_flow: true,
    cross_file: true,
    pipeline_taint: true,
    analyzability: true,
  },
};
