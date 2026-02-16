import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Rule } from '../../types/control.js';
import { goalIntegrityRules } from './goal-integrity.js';
import { toolSafetyRules } from './tool-safety.js';
import { identityAccessRules } from './identity-access.js';
import { supplyChainRules } from './supply-chain.js';
import { codeExecutionRules } from './code-execution.js';
import { memoryContextRules } from './memory-context.js';
import { dataLeakageRules } from './data-leakage.js';
import { cascadingFailuresRules } from './cascading-failures.js';
import { interAgentRules as _interAgentRules } from './inter-agent.js';
import { humanOversightRules } from './human-oversight.js';

// Gate inter-agent TS rules: only fire when 2+ agents are detected
const interAgentRules: Rule[] = _interAgentRules.map(rule => ({
  ...rule,
  check: (graph: import('../../types/agent-graph.js').AgentGraph) =>
    graph.agents.length >= 2 ? rule.check(graph) : [],
}));
import { reliabilityBoundsRules } from './reliability-bounds.js';
import { rogueAgentRules } from './rogue-agent.js';
import { loadYamlRules, mergeRules } from '../../rules/yaml-loader.js';

const hardcodedRules: Rule[] = [
  ...goalIntegrityRules,
  ...toolSafetyRules,
  ...identityAccessRules,
  ...supplyChainRules,
  ...codeExecutionRules,
  ...memoryContextRules,
  ...dataLeakageRules,
  ...cascadingFailuresRules,
  ...interAgentRules,
  ...humanOversightRules,
  ...reliabilityBoundsRules,
  ...rogueAgentRules,
];

// Cache for builtin YAML rules (loaded once)
let builtinCache: Rule[] | null = null;

function getBuiltinRulesDir(): string {
  const thisFile = fileURLToPath(import.meta.url);
  const thisDir = path.dirname(thisFile);

  // Dev mode (tsx/vitest): src/analyzers/rules/index.ts → src/rules/builtin
  const devDir = path.resolve(thisDir, '..', '..', 'rules', 'builtin');
  if (fs.existsSync(devDir)) return devDir;

  // Dist bundled (tsup): dist/src/index.js → project root → src/rules/builtin
  const distDir = path.resolve(thisDir, '..', '..', 'src', 'rules', 'builtin');
  if (fs.existsSync(distDir)) return distDir;

  // Dist unbundled: dist/src/analyzers/rules/index.js → project root → src/rules/builtin
  const unbundledDir = path.resolve(thisDir, '..', '..', '..', '..', 'src', 'rules', 'builtin');
  if (fs.existsSync(unbundledDir)) return unbundledDir;

  return devDir;
}

function loadBuiltinRules(): Rule[] {
  if (builtinCache) return builtinCache;
  const builtinDir = getBuiltinRulesDir();
  const { rules, errors } = loadYamlRules(builtinDir);
  if (errors.length > 0) {
    for (const err of errors) {
      console.error(`[g0] Builtin rule error in ${err.file}: ${err.message}`);
    }
  }
  builtinCache = rules;
  return rules;
}

export function getAllRules(rulesDir?: string): Rule[] {
  // Always merge hardcoded + builtin YAML rules
  const builtin = loadBuiltinRules();
  let rules = mergeRules(hardcodedRules, builtin);

  // If user provides a custom rulesDir, layer those on top
  if (rulesDir) {
    const { rules: userYaml, errors } = loadYamlRules(rulesDir);
    if (errors.length > 0) {
      for (const err of errors) {
        console.error(`[g0] YAML rule error in ${err.file}: ${err.message}`);
      }
    }
    rules = mergeRules(rules, userYaml);
  }

  return rules;
}

/** Reset the builtin rules cache (for testing). */
export function resetBuiltinCache(): void {
  builtinCache = null;
}

export function getRulesByDomain(domain: string): Rule[] {
  return getAllRules().filter(r => r.domain === domain);
}

export function getRuleById(id: string): Rule | undefined {
  return getAllRules().find(r => r.id === id);
}
