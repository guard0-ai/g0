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

export const SEVERITY_DEDUCTIONS = {
  critical: 20,
  high: 10,
  medium: 4,
  low: 1,
  info: 0,
} as const;

/** Reachability multipliers — utility code gets 70% reduction */
export const REACHABILITY_MULTIPLIERS: Record<string, number> = {
  'agent-reachable': 1.0,
  'tool-reachable': 1.0,
  'endpoint-reachable': 0.8,
  'utility-code': 0.3,
  'unknown': 0.6,
};

/** Exploitability multipliers — confirmed issues get amplified */
export const EXPLOITABILITY_MULTIPLIERS: Record<string, number> = {
  'confirmed': 1.2,
  'likely': 1.0,
  'unlikely': 0.4,
  'not-assessed': 0.7,
};
