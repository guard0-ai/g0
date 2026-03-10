/**
 * OWASP Agentic AI Top 10
 * AAT-1 through AAT-10 security controls for AI agent systems
 * https://owasp.org/www-project-agentic-ai-top-10/
 */

export const OWASP_AGENTIC_TOP10_MAPPING: Record<string, string[]> = {
  'goal-integrity': ['AAT-5'],
  'tool-safety': ['AAT-1', 'AAT-3'],
  'identity-access': ['AAT-1'],
  'supply-chain': ['AAT-9'],
  'code-execution': ['AAT-3'],
  'memory-context': ['AAT-7'],
  'data-leakage': ['AAT-6'],
  'cascading-failures': ['AAT-6'],
  'human-oversight': ['AAT-10'],
  'inter-agent': ['AAT-8'],
  'reliability-bounds': ['AAT-4'],
  'rogue-agent': ['AAT-4', 'AAT-2'],
};

export const OWASP_AGENTIC_TOP10_CONTROLS: Record<string, string> = {
  'AAT-1': 'Agent Authorization Hijacking — prevent unauthorized control of agent actions',
  'AAT-2': 'Agent Untraceability — ensure agent actions are auditable and traceable',
  'AAT-3': 'Agent Critical Systems Interaction — secure agent access to critical systems',
  'AAT-4': 'Agent Alignment Faking — detect deceptive compliance in agent behavior',
  'AAT-5': 'Agent Goal Manipulation — prevent unauthorized modification of agent objectives',
  'AAT-6': 'Agent Impact Chain / Blast Radius — limit cascading damage from agent failures',
  'AAT-7': 'Agent Memory/Context Manipulation — protect agent memory and context integrity',
  'AAT-8': 'Multi-Agent Exploitation — secure multi-agent coordination and communication',
  'AAT-9': 'Agent Supply Chain / Dependency Attacks — verify agent dependencies and plugins',
  'AAT-10': 'Agent Checker Out of Loop — ensure human oversight is not bypassed',
};
