import { z } from 'zod';
import * as path from 'node:path';
import { runScan } from '../../../pipeline.js';
import { loadConfig } from '../../../config/loader.js';
import { appendCta } from '../cta.js';
import { cacheScanResult, getCachedScanResult } from '../session.js';
import { resolveConfinedPath, assertPathExists, textResult, errorResult, PathEscapeError, type ToolContext, type ToolResult } from './util.js';

export const getScoreInputShape = {
  path: z.string().optional().describe("Path to the agent project (default: '.')"),
};

export interface GetScoreInput {
  path?: string;
}

export const getScoreDescription =
  'Get the g0 security score, grade, and per-domain breakdown for a local agent project — a ' +
  'lightweight read that reuses the last scan_project result for this path in the current session ' +
  'when available, avoiding a full rescan.';

/**
 * `get_score` tool handler. Reuses the session-cached `ScanResult` from a
 * prior `scan_project` call for this path when present; otherwise runs a
 * full scan (score is computed as part of runScan — never recomputed here).
 */
export async function getScore(args: GetScoreInput, ctx: ToolContext = {}): Promise<ToolResult> {
  let resolvedPath: string;
  try {
    resolvedPath = resolveConfinedPath(args.path ?? '.', ctx.projectRoot);
    assertPathExists(resolvedPath);
  } catch (err) {
    if (err instanceof PathEscapeError) return errorResult(err.message);
    return errorResult(err instanceof Error ? err.message : String(err));
  }

  let result = getCachedScanResult(resolvedPath);
  if (!result) {
    let config;
    try {
      config = loadConfig(resolvedPath) ?? undefined;
    } catch (err) {
      return errorResult(`Config error: ${err instanceof Error ? err.message : String(err)}`);
    }
    result = await runScan({ targetPath: resolvedPath, config });
    cacheScanResult(resolvedPath, result);
  }

  const { score } = result;

  const lines: string[] = [];
  lines.push(`# g0 score: ${path.basename(resolvedPath)}`);
  lines.push('');
  lines.push(`**Overall:** ${score.overall}/100 (${score.grade})`);
  if (score.capReason) lines.push(`**Grade capped:** ${score.capReason}`);
  lines.push('');
  lines.push('## Domain breakdown');
  for (const d of score.domains) {
    lines.push(`- **${d.label}** (${d.domain}): ${d.score}/100 — ${d.findings} finding(s) (${d.critical}c/${d.high}h/${d.medium}m/${d.low}l)`);
  }

  const markdown = lines.join('\n') + '\n';
  const criticalTotal = score.domains.reduce((sum, d) => sum + d.critical, 0);
  const withCta = await appendCta(markdown, criticalTotal > 0 ? 'criticals-found' : 'scan-complete');

  return textResult(withCta, {
    score: score.overall,
    grade: score.grade,
    capReason: score.capReason,
    domains: score.domains,
  });
}
