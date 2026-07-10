import { z } from 'zod';
import { getRuleById } from '../../../analyzers/rules/index.js';
import { getCachedScanResult } from '../session.js';
import { resolveConfinedPath, textResult, errorResult, PathEscapeError, type ToolContext, type ToolResult } from './util.js';

export const explainFindingInputShape = {
  rule_id: z.string().optional().describe('A g0 rule ID to explain, e.g. "AA-IA-001"'),
  finding_id: z.string().optional().describe('A specific finding ID from a prior scan_project result (looked up in the cached scan for `path`)'),
  path: z.string().optional().describe("Project path whose cached scan_project result to search for finding_id (default: '.'). Ignored when only rule_id is given."),
};

export interface ExplainFindingInput {
  rule_id?: string;
  finding_id?: string;
  path?: string;
}

export const explainFindingDescription =
  'Explain a g0 rule (by rule_id) and/or a specific finding from a prior scan_project call (by ' +
  'finding_id) — description, remediation guidance, and standards mapping (OWASP Agentic, NIST AI RMF, ' +
  'ISO 42001, EU AI Act, MITRE ATLAS, etc). Looking up a finding_id requires having already called ' +
  'scan_project for that path in this session.';

function serializeStandards(standards: Record<string, string[] | undefined>): string[] {
  const out: string[] = [];
  for (const [key, values] of Object.entries(standards)) {
    if (values && values.length > 0) out.push(`- **${key}:** ${values.join(', ')}`);
  }
  return out;
}

/**
 * `explain_finding` tool handler. Resolves rule metadata via `getRuleById`
 * and/or a concrete finding from the session's cached scan result.
 */
export async function explainFinding(args: ExplainFindingInput, ctx: ToolContext = {}): Promise<ToolResult> {
  if (!args.rule_id && !args.finding_id) {
    return errorResult('Provide rule_id and/or finding_id.');
  }

  const lines: string[] = [];
  const structured: Record<string, unknown> = {};
  let resolvedSomething = false;

  if (args.rule_id) {
    const rule = getRuleById(args.rule_id);
    if (rule) {
      resolvedSomething = true;
      lines.push(`# Rule ${rule.id}: ${rule.name}`);
      lines.push('');
      lines.push(`**Domain:** ${rule.domain}   **Severity:** ${rule.severity}   **Confidence:** ${rule.confidence}`);
      lines.push('');
      lines.push(rule.description);
      const standardsLines = serializeStandards(rule.standards as unknown as Record<string, string[] | undefined>);
      if (standardsLines.length > 0) {
        lines.push('');
        lines.push('## Standards mapping');
        lines.push(...standardsLines);
      }
      structured.rule = {
        id: rule.id,
        name: rule.name,
        domain: rule.domain,
        severity: rule.severity,
        confidence: rule.confidence,
        description: rule.description,
        frameworks: rule.frameworks,
        standards: rule.standards,
      };
    } else {
      lines.push(`Rule "${args.rule_id}" not found. Use \`g0 scan --help\` rule listing or check the rule ID spelling.`);
    }
  }

  if (args.finding_id) {
    let resolvedPath: string;
    try {
      resolvedPath = resolveConfinedPath(args.path ?? '.', ctx.projectRoot);
    } catch (err) {
      if (err instanceof PathEscapeError) return errorResult(err.message);
      return errorResult(err instanceof Error ? err.message : String(err));
    }

    const cached = getCachedScanResult(resolvedPath);
    const finding = cached?.findings.find(f => f.id === args.finding_id);

    if (lines.length > 0) lines.push('');

    if (finding) {
      resolvedSomething = true;
      lines.push(`# Finding ${finding.id}`);
      lines.push('');
      lines.push(`**${finding.title}** — [${finding.severity.toUpperCase()}] rule \`${finding.ruleId}\` (confidence: ${finding.confidence})`);
      lines.push('');
      lines.push(finding.description);
      lines.push('');
      lines.push(`**Remediation:** ${finding.remediation}`);
      lines.push(`**Location:** ${finding.location.file}:${finding.location.line}`);
      structured.finding = finding;
    } else if (cached) {
      lines.push(`Finding "${args.finding_id}" was not found in the cached scan for ${resolvedPath}.`);
    } else {
      lines.push(`No cached scan found for ${resolvedPath}. Call scan_project on this path first, then retry with finding_id.`);
    }
  }

  if (!resolvedSomething) {
    return errorResult(
      'Could not resolve a rule or finding. Check the rule_id spelling, or call scan_project first if you are looking up a finding_id.',
    );
  }

  const markdown = lines.join('\n') + '\n';
  return textResult(markdown, structured);
}
