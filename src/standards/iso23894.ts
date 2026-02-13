/**
 * ISO/IEC 23894:2023 — AI Risk Management
 * Maps security domains to risk controls R.1-R.8
 */

export const ISO23894_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['R.2', 'R.3', 'R.5'],
  'tool-safety': ['R.3', 'R.5', 'R.6'],
  'identity-access': ['R.3', 'R.4', 'R.6'],
  'supply-chain': ['R.4', 'R.7'],
  'code-execution': ['R.3', 'R.5', 'R.6'],
  'memory-context': ['R.2', 'R.5'],
  'data-leakage': ['R.2', 'R.4', 'R.6'],
  'cascading-failures': ['R.5', 'R.6', 'R.8'],
};

export const ISO23894_CONTROLS: Record<string, string> = {
  'R.1': 'Establish context for AI risk management',
  'R.2': 'Risk identification for AI systems',
  'R.3': 'Risk analysis for AI systems',
  'R.4': 'Risk evaluation for AI systems',
  'R.5': 'Risk treatment for AI systems',
  'R.6': 'Recording and reporting AI risks',
  'R.7': 'Monitoring and review of AI risks',
  'R.8': 'Communication and consultation on AI risks',
};
