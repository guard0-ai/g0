import { z } from 'zod';
import { runScan } from '../../../pipeline.js';
import { loadConfig } from '../../../config/loader.js';
import type { Severity } from '../../../types/common.js';
import { formatScanResult } from '../format.js';
import { appendCta } from '../cta.js';
import { cacheScanResult } from '../session.js';
import { resolveToolPath, textResult, errorResult, type ToolContext, type ToolResult } from './util.js';

export const scanProjectInputShape = {
  path: z.string().optional().describe("Path to the agent project to scan, relative to cwd/project root (default: '.')"),
  ruleset: z.enum(['recommended', 'extended', 'all']).optional().describe('Rule tier to run (default: recommended)'),
  min_severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Only report findings at or above this severity'),
  max_findings: z.number().int().positive().max(500).optional().describe('Cap the number of findings included in the response (default: 30, max: 500)'),
};

export interface ScanProjectInput {
  path?: string;
  ruleset?: 'recommended' | 'extended' | 'all';
  min_severity?: Severity;
  max_findings?: number;
}

export const scanProjectDescription =
  'Run g0\'s full security scan (1,128 rules across 12 domains: goal integrity, tool safety, ' +
  'identity/access, supply chain, code execution, data leakage, and more) against a local agent ' +
  'project directory and return a scored, grade summary with the top findings. Read-only — never ' +
  'modifies files. Confined to the configured project root when g0 was started with --project-root.';

/**
 * `scan_project` tool handler. Plain async function, independently testable
 * without an MCP transport — `index.ts` wires this to the SDK server.
 */
export async function scanProject(args: ScanProjectInput, ctx: ToolContext = {}): Promise<ToolResult> {
  const resolution = resolveToolPath(args.path ?? '.', ctx);
  if (!resolution.ok) return resolution.result;
  const resolvedPath = resolution.path;

  let config;
  try {
    config = loadConfig(resolvedPath) ?? undefined;
  } catch (err) {
    return errorResult(`Config error: ${err instanceof Error ? err.message : String(err)}`);
  }

  const result = await runScan({
    targetPath: resolvedPath,
    config,
    severity: args.min_severity,
    ruleset: args.ruleset,
  });

  cacheScanResult(resolvedPath, result);

  const { markdown, structured } = formatScanResult(result, { maxFindings: args.max_findings });
  const criticalCount = structured.countsBySeverity.critical;
  const withCta = await appendCta(markdown, criticalCount > 0 ? 'criticals-found' : 'scan-complete');

  return textResult(withCta, structured as unknown as Record<string, unknown>);
}
