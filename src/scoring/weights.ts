import type { SecurityDomain } from '../types/common.js';

export const DOMAIN_WEIGHTS: Record<SecurityDomain, number> = {
  'goal-integrity': 1.5,
  'tool-safety': 1.5,
  'identity-access': 1.2,
  'supply-chain': 1.0,
  'code-execution': 1.3,
  'memory-context': 1.1,
  'data-leakage': 1.3,
  'cascading-failures': 1.2,
  'human-oversight': 1.0,
  'inter-agent': 1.1,
  'reliability-bounds': 1.2,
  'rogue-agent': 1.4,
};

export const DOMAIN_LABELS: Record<SecurityDomain, string> = {
  'goal-integrity': 'Goal Integrity',
  'tool-safety': 'Tool Safety',
  'identity-access': 'Identity & Access',
  'supply-chain': 'Supply Chain',
  'code-execution': 'Code Execution',
  'memory-context': 'Memory & Context',
  'data-leakage': 'Data Leakage',
  'cascading-failures': 'Cascading Failures',
  'human-oversight': 'Human Oversight',
  'inter-agent': 'Inter-Agent',
  'reliability-bounds': 'Reliability Bounds',
  'rogue-agent': 'Rogue Agent',
};

/**
 * Base score deductions per finding severity.
 * A single agent-reachable critical should drop a domain to ~60 (grade D).
 * Two agent-reachable criticals should crater a domain to ~20 (grade F).
 */
export const SEVERITY_DEDUCTIONS = {
  critical: 40,
  high: 18,
  medium: 6,
  low: 2,
  info: 0,
} as const;

/**
 * Reachability multipliers — how close the finding is to agent execution.
 * Unknown defaults to 0.85 (assume reachable until proven otherwise).
 * Utility code gets heavy reduction since it's not on the agent execution path.
 */
export const REACHABILITY_MULTIPLIERS: Record<string, number> = {
  'agent-reachable': 1.0,
  'tool-reachable': 1.0,
  'endpoint-reachable': 0.8,
  'utility-code': 0.3,
  'unknown': 0.85,
};

/**
 * Exploitability multipliers — how likely the finding can be exploited.
 * Not-assessed defaults to 0.85 (assume exploitable until proven otherwise).
 * Confirmed issues get amplified above 1.0.
 */
export const EXPLOITABILITY_MULTIPLIERS: Record<string, number> = {
  'confirmed': 1.2,
  'likely': 1.0,
  'unlikely': 0.4,
  'not-assessed': 0.85,
};
