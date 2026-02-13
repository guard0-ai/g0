import type { AgentGraph } from '../types/agent-graph.js';
import type { Finding } from '../types/finding.js';
import type { Severity } from '../types/common.js';
import { getAllRules } from './rules/index.js';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export interface AnalysisOptions {
  excludeRules?: string[];
  onlyRules?: string[];
  severity?: Severity;
  frameworks?: string[];
  rulesDir?: string;
}

export function runAnalysis(graph: AgentGraph, options?: AnalysisOptions): Finding[] {
  let rules = getAllRules(options?.rulesDir);

  // Filter by --rules (only run these)
  if (options?.onlyRules && options.onlyRules.length > 0) {
    const includeSet = new Set(options.onlyRules);
    rules = rules.filter(r => includeSet.has(r.id));
  }

  // Filter by --exclude-rules
  if (options?.excludeRules && options.excludeRules.length > 0) {
    const excludeSet = new Set(options.excludeRules);
    rules = rules.filter(r => !excludeSet.has(r.id));
  }

  // Filter by --frameworks
  if (options?.frameworks && options.frameworks.length > 0) {
    const fwSet = new Set(options.frameworks);
    rules = rules.filter(r =>
      r.frameworks.includes('all') || r.frameworks.some(f => fwSet.has(f)),
    );
  }

  const findings: Finding[] = [];

  for (const rule of rules) {
    const ruleFindings = rule.check(graph);
    findings.push(...ruleFindings);
  }

  let result = deduplicateFindings(findings);

  // Filter by minimum severity
  if (options?.severity) {
    const minLevel = SEVERITY_ORDER[options.severity];
    result = result.filter(f => SEVERITY_ORDER[f.severity] <= minLevel);
  }

  return result;
}

function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.location.file}:${f.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
