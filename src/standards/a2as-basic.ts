/**
 * Agent-to-Agent Security (A2AS) BASIC Profile
 * AUTH, AUTHZ, AUDIT, ISOL, COMM security controls
 */

export const A2AS_BASIC_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['ISOL', 'COMM'],
  'tool-safety': ['AUTHZ', 'AUDIT', 'ISOL'],
  'identity-access': ['AUTH', 'AUTHZ', 'AUDIT'],
  'supply-chain': ['AUTH', 'COMM'],
  'code-execution': ['ISOL', 'AUTHZ'],
  'memory-context': ['ISOL', 'AUDIT'],
  'data-leakage': ['COMM', 'AUDIT', 'ISOL'],
  'cascading-failures': ['ISOL', 'COMM'],
};

export const A2AS_BASIC_CONTROLS: Record<string, string> = {
  AUTH: 'Authentication — verify agent and service identities',
  AUTHZ: 'Authorization — enforce least-privilege access controls',
  AUDIT: 'Audit — log and monitor agent actions and data flows',
  ISOL: 'Isolation — enforce boundaries between agents and resources',
  COMM: 'Communication — secure inter-agent and external communication',
};
