import { z } from 'zod';
import { scanMCPPath } from '../../scan-path.js';
import { resolveConfinedPath, assertPathExists, textResult, errorResult, PathEscapeError, type ToolContext, type ToolResult } from './util.js';

export const scanMcpServerInputShape = {
  path: z.string().describe('Path to an MCP server project (source directory) to assess'),
};

export interface ScanMcpServerInput {
  path: string;
}

export const scanMcpServerDescription =
  'Assess an MCP server\'s source code for supply-chain and tool-safety risk: unsafe tool ' +
  'implementations, shell/eval execution, missing input validation, and other findings specific ' +
  'to MCP server code. Read-only, local static analysis only — does not start or connect to the server.';

/**
 * `scan_mcp_server` tool handler — reuses `scanMCPPath` (the same code path
 * as `g0 mcp <path>` on the CLI), formatted for MCP tool consumption.
 */
export async function scanMcpServer(args: ScanMcpServerInput, ctx: ToolContext = {}): Promise<ToolResult> {
  let resolvedPath: string;
  try {
    resolvedPath = resolveConfinedPath(args.path, ctx.projectRoot);
    assertPathExists(resolvedPath);
  } catch (err) {
    if (err instanceof PathEscapeError) return errorResult(err.message);
    return errorResult(err instanceof Error ? err.message : String(err));
  }

  const result = await scanMCPPath(resolvedPath);

  const lines: string[] = [];
  lines.push('# g0 MCP server scan');
  lines.push('');
  lines.push(`**Status:** ${result.summary.overallStatus}`);
  lines.push(`**Servers detected:** ${result.summary.totalServers}   **Tools:** ${result.summary.totalTools}`);
  lines.push(
    `**Findings:** ${result.summary.totalFindings} total — ` +
    `${result.summary.findingsBySeverity.critical} critical, ` +
    `${result.summary.findingsBySeverity.high} high, ` +
    `${result.summary.findingsBySeverity.medium} medium, ` +
    `${result.summary.findingsBySeverity.low} low`,
  );

  if (result.findings.length > 0) {
    lines.push('');
    lines.push('## Findings');
    for (const f of result.findings) {
      lines.push('');
      lines.push(`### [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`- ${f.description}`);
      if (f.file) lines.push(`- Location: ${f.file}${f.line ? `:${f.line}` : ''}`);
    }
  }

  const markdown = lines.join('\n') + '\n';

  return textResult(markdown, {
    status: result.summary.overallStatus,
    totalServers: result.summary.totalServers,
    totalTools: result.summary.totalTools,
    findingsBySeverity: result.summary.findingsBySeverity,
    findings: result.findings,
  });
}
