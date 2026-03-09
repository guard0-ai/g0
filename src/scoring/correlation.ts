import type { Finding } from '../types/finding.js';
import type { SecurityDomain } from '../types/common.js';
import type { ModuleGraph } from '../analyzers/ast/module-graph.js';

export interface AttackChain {
  id: string;
  name: string;
  description: string;
  links: ChainLink[];
  /** Deduction bonus when chain is detected (added to domain score deductions) */
  bonusDeduction: number;
}

interface ChainLink {
  domain: SecurityDomain;
  rulePattern: RegExp;
  minSeverity: 'critical' | 'high' | 'medium' | 'low';
}

export interface DetectedChain {
  chain: AttackChain;
  matchedFindings: Finding[];
  files: string[];
}

export interface CorrelationResult {
  chains: DetectedChain[];
  /** Finding IDs that participate in attack chains */
  amplifiedFindingIds: Set<string>;
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * Predefined attack chain patterns.
 * Each chain requires findings from multiple domains that together
 * form an exploitable path worse than either finding alone.
 */
const ATTACK_CHAINS: AttackChain[] = [
  {
    id: 'injection-to-rce',
    name: 'Injection → Remote Code Execution',
    description: 'User input reaches code execution without sanitization across domains',
    links: [
      { domain: 'goal-integrity', rulePattern: /AA-GI-(003|019|022|040|051|093)/, minSeverity: 'medium' },
      { domain: 'code-execution', rulePattern: /AA-CE-(002|006|012|015|030|041|042)/, minSeverity: 'high' },
    ],
    bonusDeduction: 10,
  },
  {
    id: 'data-exfiltration',
    name: 'Data Leakage → Exfiltration Path',
    description: 'Exposed data combined with network access enables exfiltration',
    links: [
      { domain: 'data-leakage', rulePattern: /AA-DL-(001|002|023|046|053)/, minSeverity: 'medium' },
      { domain: 'code-execution', rulePattern: /AA-CE-(043|049)/, minSeverity: 'high' },
    ],
    bonusDeduction: 8,
  },
  {
    id: 'privilege-escalation',
    name: 'Weak Auth → Lateral Movement',
    description: 'Insufficient authentication combined with inter-agent delegation',
    links: [
      { domain: 'identity-access', rulePattern: /AA-IA-(001|004|008|058)/, minSeverity: 'medium' },
      { domain: 'inter-agent', rulePattern: /AA-IC/, minSeverity: 'medium' },
    ],
    bonusDeduction: 8,
  },
  {
    id: 'supply-chain-backdoor',
    name: 'Unverified Dependency → Dynamic Execution',
    description: 'Untrusted package combined with dynamic import/execution',
    links: [
      { domain: 'supply-chain', rulePattern: /AA-SC-(001|005|016|028)/, minSeverity: 'medium' },
      { domain: 'code-execution', rulePattern: /AA-CE-(015|024|051)/, minSeverity: 'high' },
    ],
    bonusDeduction: 10,
  },
  {
    id: 'cascading-denial',
    name: 'No Timeout → No Circuit Breaker',
    description: 'Missing timeout combined with missing circuit breaker enables cascading failure',
    links: [
      { domain: 'cascading-failures', rulePattern: /AA-CF-(003|010|013|051)/, minSeverity: 'medium' },
      { domain: 'reliability-bounds', rulePattern: /AA-RB/, minSeverity: 'medium' },
    ],
    bonusDeduction: 5,
  },
  {
    id: 'prompt-injection-to-tool-abuse',
    name: 'Prompt Injection → Tool Exploitation',
    description: 'Indirect injection combined with unvalidated tool use',
    links: [
      { domain: 'goal-integrity', rulePattern: /AA-GI-(019|022|040|051|052)/, minSeverity: 'medium' },
      { domain: 'tool-safety', rulePattern: /AA-TS-(007|021|024|032|034)/, minSeverity: 'high' },
    ],
    bonusDeduction: 10,
  },
  {
    id: 'memory-poisoning',
    name: 'Memory Injection → Goal Hijacking',
    description: 'Unvalidated memory combined with weak goal boundaries enables persistent compromise',
    links: [
      { domain: 'memory-context', rulePattern: /AA-MP-(005|010|017|019|023)/, minSeverity: 'medium' },
      { domain: 'goal-integrity', rulePattern: /AA-GI-(022|030|051|052)/, minSeverity: 'medium' },
    ],
    bonusDeduction: 8,
  },
  {
    id: 'rogue-agent-uncontrollable',
    name: 'Self-Modifying Agent → No Kill Switch',
    description: 'Agent with self-modification capability and no human override',
    links: [
      { domain: 'rogue-agent', rulePattern: /AA-RA/, minSeverity: 'medium' },
      { domain: 'human-oversight', rulePattern: /AA-HO/, minSeverity: 'medium' },
    ],
    bonusDeduction: 8,
  },
];

function meetsSeverity(finding: Finding, minSeverity: string): boolean {
  return (SEVERITY_ORDER[finding.severity] ?? 0) >= (SEVERITY_ORDER[minSeverity] ?? 0);
}

/**
 * Detect attack chains across findings.
 * Checks if findings in connected files (or same project) match chain patterns.
 */
export function correlateFindings(
  findings: Finding[],
  moduleGraph?: ModuleGraph,
): CorrelationResult {
  const chains: DetectedChain[] = [];
  const amplifiedFindingIds = new Set<string>();

  // Group findings by file for proximity checks
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const file = f.location.file;
    if (!byFile.has(file)) byFile.set(file, []);
    byFile.get(file)!.push(f);
  }

  // Build connected file groups (files that import each other)
  const fileGroups = buildConnectedFileGroups(byFile, moduleGraph);

  for (const chain of ATTACK_CHAINS) {
    // For each group of connected files, check if the chain matches
    for (const group of fileGroups) {
      const groupFindings = group.flatMap(file => byFile.get(file) ?? []);
      const matchResult = matchChain(chain, groupFindings);

      if (matchResult) {
        chains.push({
          chain,
          matchedFindings: matchResult,
          files: group,
        });
        for (const f of matchResult) {
          amplifiedFindingIds.add(f.id);
        }
      }
    }
  }

  return { chains, amplifiedFindingIds };
}

/**
 * Check if a set of findings matches all links in an attack chain.
 */
function matchChain(chain: AttackChain, findings: Finding[]): Finding[] | null {
  const matched: Finding[] = [];

  for (const link of chain.links) {
    const match = findings.find(f =>
      f.domain === link.domain &&
      link.rulePattern.test(f.ruleId) &&
      meetsSeverity(f, link.minSeverity),
    );
    if (!match) return null;
    matched.push(match);
  }

  return matched;
}

/**
 * Group files into connected components based on module imports.
 * Files that import each other (directly or transitively) form a group.
 * Without a module graph, each file is its own group + a project-wide group.
 */
function buildConnectedFileGroups(
  byFile: Map<string, Finding[]>,
  moduleGraph?: ModuleGraph,
): string[][] {
  const files = [...byFile.keys()];

  if (!moduleGraph) {
    // Without module graph, treat entire project as one group
    return [files];
  }

  // Build connected components via union-find
  const parent = new Map<string, string>();
  const find = (x: string): string => {
    if (!parent.has(x)) parent.set(x, x);
    if (parent.get(x) !== x) parent.set(x, find(parent.get(x)!));
    return parent.get(x)!;
  };
  const union = (a: string, b: string) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };

  for (const file of files) {
    const deps = moduleGraph.getDependenciesOf(file);
    for (const dep of deps) {
      if (byFile.has(dep)) {
        union(file, dep);
      }
    }
    const importers = moduleGraph.getImportersOf(file);
    for (const imp of importers) {
      if (byFile.has(imp)) {
        union(file, imp);
      }
    }
  }

  // Collect groups
  const groups = new Map<string, string[]>();
  for (const file of files) {
    const root = find(file);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root)!.push(file);
  }

  return [...groups.values()];
}
