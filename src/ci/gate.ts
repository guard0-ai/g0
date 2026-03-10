import { findPolicy, loadPolicy, evaluatePolicy, getCIExitCode } from '../governance/policy-engine.js';
import type { SecurityPolicy, PolicyEvaluation, ScanContext, RuntimeContext, HostContext } from '../governance/policy-engine.js';

// ── Types ──────────────────────────────────────────────────────────────────

export interface CIGateResult {
  exitCode: number; // 0=pass, 1=fail, 2=warning
  evaluation: PolicyEvaluation | null;
  summary: string;
  annotations: CIAnnotation[];
}

export interface CIAnnotation {
  level: 'error' | 'warning' | 'notice';
  message: string;
  rule: string;
}

// ── CI Gate ────────────────────────────────────────────────────────────────

/**
 * Run CI gate evaluation against scan results.
 * Loads policy, evaluates all contexts, and converts violations to annotations.
 */
export function runCIGate(options: {
  scanContext?: ScanContext;
  runtimeContext?: RuntimeContext;
  hostContext?: HostContext;
  policyPath?: string;
  searchPath?: string;
}): CIGateResult {
  const { scanContext, runtimeContext, hostContext, policyPath, searchPath } = options;

  // Load policy — explicit path or search
  const policy: SecurityPolicy | null = policyPath
    ? loadPolicy(policyPath)
    : findPolicy(searchPath);

  if (!policy) {
    return {
      exitCode: 0,
      evaluation: null,
      summary: 'No policy found \u2014 passing by default',
      annotations: [],
    };
  }

  const evaluation = evaluatePolicy(policy, scanContext, runtimeContext, hostContext);
  const exitCode = getCIExitCode(evaluation);

  // Convert violations to CI annotations
  const annotations: CIAnnotation[] = evaluation.violations.map((v) => ({
    level: severityToLevel(v.severity),
    message: v.message,
    rule: v.rule,
  }));

  const summary = buildSummary(exitCode, evaluation);

  return { exitCode, evaluation, summary, annotations };
}

// ── Formatting ─────────────────────────────────────────────────────────────

/**
 * Format CI gate result for GitHub Actions (::error, ::warning, ::notice annotations).
 */
export function formatGitHubAnnotations(result: CIGateResult): string {
  const lines: string[] = [];

  for (const a of result.annotations) {
    lines.push(`::${a.level}::${a.message} [${a.rule}]`);
  }

  return lines.join('\n');
}

/**
 * Format CI gate result for generic CI (plain text).
 */
export function formatCIOutput(result: CIGateResult): string {
  const lines: string[] = [];

  const header = result.exitCode === 0
    ? 'PASS'
    : result.exitCode === 1
      ? 'FAIL'
      : 'WARNING';

  lines.push(`g0 CI Gate: ${header}`);
  lines.push(result.summary);

  if (result.annotations.length > 0) {
    lines.push('');
    lines.push('Violations:');
    for (const a of result.annotations) {
      const prefix = a.level === 'error' ? '[ERROR]' : a.level === 'warning' ? '[WARN]' : '[NOTICE]';
      lines.push(`  ${prefix} ${a.message} (${a.rule})`);
    }
  }

  return lines.join('\n');
}

// ── Helpers ────────────────────────────────────────────────────────────────

function severityToLevel(severity: 'critical' | 'high' | 'medium' | 'low'): CIAnnotation['level'] {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'notice';
  }
}

function buildSummary(exitCode: number, evaluation: PolicyEvaluation): string {
  const total = evaluation.violations.length;
  if (total === 0) {
    return 'All policy checks passed';
  }

  const counts: Record<string, number> = {};
  for (const v of evaluation.violations) {
    counts[v.severity] = (counts[v.severity] ?? 0) + 1;
  }

  const parts: string[] = [];
  for (const sev of ['critical', 'high', 'medium', 'low'] as const) {
    if (counts[sev]) parts.push(`${counts[sev]} ${sev}`);
  }

  return `${total} violation${total === 1 ? '' : 's'} (${parts.join(', ')})`;
}
