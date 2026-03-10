import type { G0Config } from '../../types/config.js';

/**
 * OpenClaw deployment preset — strictest thresholds with all analyzers enabled.
 * Tuned for OpenClaw self-hosted AI assistant deployments where egress filtering,
 * secret isolation, container hardening, and data privacy are paramount.
 */
export const openclawPreset: G0Config = {
  fail_on: 'medium',
  min_score: 85,
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
  domain_weights: {
    'code-execution': 1.5,
    'data-leakage': 1.5,
    'supply-chain': 1.3,
    'tool-safety': 1.2,
    'identity-access': 1.2,
    'memory-context': 1.0,
    'goal-integrity': 1.0,
    'cascading-failures': 1.0,
    'human-oversight': 1.0,
    'inter-agent': 1.0,
    'reliability-bounds': 0.8,
    'rogue-agent': 1.0,
  },
};
