/**
 * OWASP AI Vulnerability Scoring System (AIVSS)
 * Maps security domains to AIVSS vulnerability categories
 */

export const OWASP_AIVSS_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['AIVSS-PI', 'AIVSS-GH'],
  'tool-safety': ['AIVSS-TA', 'AIVSS-PI'],
  'identity-access': ['AIVSS-AC', 'AIVSS-PE'],
  'supply-chain': ['AIVSS-SC', 'AIVSS-MP'],
  'code-execution': ['AIVSS-CE', 'AIVSS-SE'],
  'memory-context': ['AIVSS-DP', 'AIVSS-MP'],
  'data-leakage': ['AIVSS-DL', 'AIVSS-IL'],
  'cascading-failures': ['AIVSS-RF', 'AIVSS-DoS'],
};

export const OWASP_AIVSS_CATEGORIES: Record<string, string> = {
  'AIVSS-PI': 'Prompt Injection',
  'AIVSS-GH': 'Goal Hijacking',
  'AIVSS-TA': 'Tool Abuse',
  'AIVSS-AC': 'Access Control',
  'AIVSS-PE': 'Privilege Escalation',
  'AIVSS-SC': 'Supply Chain Compromise',
  'AIVSS-MP': 'Model Poisoning',
  'AIVSS-CE': 'Code Execution',
  'AIVSS-SE': 'Sandbox Escape',
  'AIVSS-DP': 'Data Poisoning',
  'AIVSS-DL': 'Data Leakage',
  'AIVSS-IL': 'Information Leakage',
  'AIVSS-RF': 'Resource Failure',
  'AIVSS-DoS': 'Denial of Service',
};
