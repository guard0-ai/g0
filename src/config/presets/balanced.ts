import type { G0Config } from '../../types/config.js';

export const balancedPreset: G0Config = {
  thresholds: {
    max_findings_per_rule: 50,
    low_severity_cap: 10,
    medium_severity_cap: 30,
  },
  analyzers: {
    taint_flow: true,
    cross_file: true,
    pipeline_taint: true,
    analyzability: true,
  },
};
