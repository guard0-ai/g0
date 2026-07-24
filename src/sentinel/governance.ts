// Governance policy for the sentinel: declare allow/deny/monitor per tool or
// category, evaluate each installed tool, and produce a compliance verdict.

import * as fs from 'node:fs';
import { parse as parseYaml } from 'yaml';
import type { SnapshotGovernance } from './snapshot.js';

export type Verdict = 'allow' | 'deny' | 'monitor';

export interface PolicyRule {
  /** Match a tool by exact name, `category:<cat>`, or a `*` glob on the name. */
  match: string;
  verdict: Verdict;
}

export interface Policy {
  name?: string;
  default: Verdict;
  rules: PolicyRule[];
}

export interface GovToolInput {
  name: string;
  category?: string;
}

/** Parse a policy from YAML text. Missing fields default safely. */
export function parsePolicy(text: string): Policy {
  const raw = (parseYaml(text) ?? {}) as Partial<Policy>;
  return {
    name: raw.name,
    default: (raw.default as Verdict) ?? 'monitor',
    rules: Array.isArray(raw.rules)
      ? raw.rules
          .filter((r): r is PolicyRule => !!r && typeof r.match === 'string' && typeof r.verdict === 'string')
          .map((r) => ({ match: r.match, verdict: r.verdict }))
      : [],
  };
}

export function loadPolicy(file: string): Policy {
  return parsePolicy(fs.readFileSync(file, 'utf-8'));
}

/** Escape a glob string to a RegExp, treating only `*` as a wildcard. */
function globToRe(glob: string): RegExp {
  const esc = glob.replace(/[.*+?^${}()|[\]\\]/g, (c) => (c === '*' ? '.*' : `\\${c}`));
  return new RegExp(`^${esc}$`, 'i');
}

function matchRule(rule: PolicyRule, tool: GovToolInput): boolean {
  if (rule.match.startsWith('category:')) {
    return (tool.category ?? '').toLowerCase() === rule.match.slice('category:'.length).toLowerCase();
  }
  if (rule.match.includes('*')) return globToRe(rule.match).test(tool.name);
  return rule.match.toLowerCase() === tool.name.toLowerCase();
}

/** Evaluate a policy against tools; first matching rule wins, else the default. */
export function evaluatePolicy(policy: Policy, tools: GovToolInput[]): SnapshotGovernance {
  const verdicts = tools.map((t) => {
    const rule = policy.rules.find((r) => matchRule(r, t));
    return { tool: t.name, verdict: rule?.verdict ?? policy.default, rule: rule?.match };
  });
  return {
    policyName: policy.name,
    verdicts,
    compliant: !verdicts.some((v) => v.verdict === 'deny'),
  };
}
