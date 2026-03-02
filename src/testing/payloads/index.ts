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
import { advancedVectorPayloads } from './advanced-vectors.js';
import { loadJsonPayloads } from './json-loader.js';
import { getMultiTurnStrategyPayloads } from './multi-turn-strategies.js';
import { complianceProbePayloads } from './compliance-probes.js';
import { forcefulMultiTurnPayloads } from './forceful-multi-turn.js';
import { contextExhaustionPayloads } from './context-exhaustion.js';
import { hallucinationExfilPayloads } from './hallucination-exfil.js';
import { toctouAttackPayloads } from './toctou-attacks.js';

// ── Static TS payloads ──
const tsPayloads: AttackPayload[] = [
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
  ...advancedVectorPayloads,
  ...complianceProbePayloads,
  ...forcefulMultiTurnPayloads,
  ...contextExhaustionPayloads,
  ...hallucinationExfilPayloads,
  ...toctouAttackPayloads,
];

// ── JSON payload datasets (lazy-loaded) ──
let jsonPayloadsCache: AttackPayload[] | null = null;

function loadAllJsonPayloads(): AttackPayload[] {
  if (jsonPayloadsCache) return jsonPayloadsCache;

  const datasets: AttackPayload[] = [];
  const files = [
    'jailbreaks-wild.json',
    'jailbreaks-dan.json',
    'jailbreaks-pyrit.json',
    'harmful-categories.json',
    'research-datasets.json',
    'brand-trust.json',
    'probes-garak.json',
    'api-security.json',
    'toxicity-prompts.json',
    'donotanswer.json',
  ];

  for (const file of files) {
    try {
      datasets.push(...loadJsonPayloads(file));
    } catch {
      // JSON file may not exist yet — skip gracefully
    }
  }

  jsonPayloadsCache = datasets;
  return datasets;
}

// ── Multi-turn strategy payloads ──
let multiTurnCache: AttackPayload[] | null = null;
function getMultiTurnPayloads(): AttackPayload[] {
  if (multiTurnCache) return multiTurnCache;
  multiTurnCache = getMultiTurnStrategyPayloads();
  return multiTurnCache;
}

// ── Dataset name → file mapping ──
const DATASET_MAP: Record<string, string[]> = {
  wild: ['jailbreaks-wild.json'],
  dan: ['jailbreaks-dan.json'],
  harmful: ['harmful-categories.json'],
  research: ['research-datasets.json'],
  brand: ['brand-trust.json'],
  garak: ['probes-garak.json'],
  'api-security': ['api-security.json'],
  toxicity: ['toxicity-prompts.json'],
  pyrit: ['jailbreaks-pyrit.json'],
  donotanswer: ['donotanswer.json'],
};

function getAllPayloadsInternal(): AttackPayload[] {
  return [...tsPayloads, ...loadAllJsonPayloads(), ...getMultiTurnPayloads()];
}

export function getAllPayloads(): AttackPayload[] {
  return getAllPayloadsInternal();
}

export function getPayloadsByCategory(category: AttackCategory): AttackPayload[] {
  return getAllPayloadsInternal().filter(p => p.category === category);
}

export function getPayloadById(id: string): AttackPayload | undefined {
  return getAllPayloadsInternal().find(p => p.id === id);
}

export function getPayloadsByCategories(categories: AttackCategory[]): AttackPayload[] {
  return getAllPayloadsInternal().filter(p => categories.includes(p.category));
}

export function getPayloadsByIds(ids: string[]): AttackPayload[] {
  return getAllPayloadsInternal().filter(p => ids.includes(p.id));
}

export function getPayloadsByDataset(dataset: string): AttackPayload[] {
  // Check for HuggingFace datasets (async fetch handled separately)
  const hfNames = ['advbench', 'jailbreakbench', 'wildjailbreak', 'anthropic'];
  if (hfNames.includes(dataset) || dataset.startsWith('hf:')) {
    // HF datasets require async fetch — return empty here,
    // they're loaded via getPayloadsByDatasetAsync() in the engine
    return [];
  }

  const files = DATASET_MAP[dataset];
  if (!files) {
    // If not a known dataset, try as direct filename
    try {
      return loadJsonPayloads(`${dataset}.json`);
    } catch {
      return getAllPayloads();
    }
  }

  const payloads: AttackPayload[] = [];
  for (const file of files) {
    try {
      payloads.push(...loadJsonPayloads(file));
    } catch {
      // Skip missing files
    }
  }
  return payloads;
}

export async function getPayloadsByDatasetAsync(dataset: string): Promise<AttackPayload[]> {
  const hfNames = ['advbench', 'jailbreakbench', 'wildjailbreak', 'anthropic'];
  const datasetName = dataset.startsWith('hf:') ? dataset.slice(3) : dataset;

  if (hfNames.includes(datasetName)) {
    const { fetchHFDataset } = await import('./hf-datasets.js');
    return fetchHFDataset(datasetName);
  }

  return getPayloadsByDataset(dataset);
}
