import type { AttackPayload, AttackCategory } from '../../types/test.js';
import { promptInjectionPayloads } from './prompt-injection.js';
import { dataExfiltrationPayloads } from './data-exfiltration.js';
import { toolAbusePayloads } from './tool-abuse.js';
import { jailbreakPayloads } from './jailbreak.js';
import { goalHijackingPayloads } from './goal-hijacking.js';
import { authorizationPayloads } from './authorization.js';
import { indirectInjectionPayloads } from './indirect-injection.js';
import { encodingBypassPayloads } from './encoding-bypass.js';
import { harmfulContentPayloads } from './harmful-content.js';
import { mcpAttackPayloads } from './mcp-attack.js';
import { ragPoisoningPayloads } from './rag-poisoning.js';
import { multiAgentPayloads } from './multi-agent.js';
import { compliancePayloads } from './compliance.js';
import { domainSpecificPayloads } from './domain-specific.js';
import { contentSafetyPayloads } from './content-safety.js';
import { biasDetectionPayloads } from './bias-detection.js';
import { piiProbingPayloads } from './pii-probing.js';
import { agenticAttackPayloads } from './agentic-attacks.js';
import { jailbreakAdvancedPayloads } from './jailbreak-advanced.js';

const allPayloads: AttackPayload[] = [
  ...promptInjectionPayloads,
  ...dataExfiltrationPayloads,
  ...toolAbusePayloads,
  ...jailbreakPayloads,
  ...goalHijackingPayloads,
  ...authorizationPayloads,
  ...indirectInjectionPayloads,
  ...encodingBypassPayloads,
  ...harmfulContentPayloads,
  ...mcpAttackPayloads,
  ...ragPoisoningPayloads,
  ...multiAgentPayloads,
  ...compliancePayloads,
  ...domainSpecificPayloads,
  ...contentSafetyPayloads,
  ...biasDetectionPayloads,
  ...piiProbingPayloads,
  ...agenticAttackPayloads,
  ...jailbreakAdvancedPayloads,
];

export function getAllPayloads(): AttackPayload[] {
  return allPayloads;
}

export function getPayloadsByCategory(category: AttackCategory): AttackPayload[] {
  return allPayloads.filter(p => p.category === category);
}

export function getPayloadById(id: string): AttackPayload | undefined {
  return allPayloads.find(p => p.id === id);
}

export function getPayloadsByCategories(categories: AttackCategory[]): AttackPayload[] {
  return allPayloads.filter(p => categories.includes(p.category));
}

export function getPayloadsByIds(ids: string[]): AttackPayload[] {
  return allPayloads.filter(p => ids.includes(p.id));
}
