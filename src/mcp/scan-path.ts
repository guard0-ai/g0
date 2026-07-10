import * as path from 'node:path';
import { runDiscovery } from '../pipeline.js';
import { scanMCPSourceDir } from './source-scanner.js';
import type { MCPScanResult, MCPFindingSeverity } from '../types/mcp-scan.js';

/**
 * Path-based MCP scan: discovers MCP source files under `resolvedPath` and
 * source-scans them, assembling an `MCPScanResult`.
 *
 * Extracted from `src/cli/commands/mcp.ts` (pure refactor, no behavior
 * change) so the MCP server's `scan_mcp_server` tool can reuse it in-process
 * without shelling out to the CLI.
 */
export async function scanMCPPath(resolvedPath: string): Promise<MCPScanResult> {
  const discovery = await runDiscovery(resolvedPath);
  const mcpDetection = discovery.detection.results.find(r => r.framework === 'mcp');
  const mcpFiles = mcpDetection?.files ?? [];

  // Source-scan MCP files
  const sourceResult = scanMCPSourceDir(resolvedPath, mcpFiles);

  // Build MCPScanResult from source scanning
  const findingsBySeverity: Record<MCPFindingSeverity, number> = {
    critical: 0, high: 0, medium: 0, low: 0,
  };
  for (const f of sourceResult.findings) {
    findingsBySeverity[f.severity]++;
  }

  const worstSeverity = sourceResult.findings.reduce<MCPFindingSeverity>((worst, f) => {
    const order: MCPFindingSeverity[] = ['critical', 'high', 'medium', 'low'];
    return order.indexOf(f.severity) < order.indexOf(worst) ? f.severity : worst;
  }, 'low');

  return {
    clients: [],
    servers: mcpFiles.map(f => ({
      name: path.basename(f, path.extname(f)),
      command: '',
      args: [],
      env: {},
      client: 'source-code',
      configFile: f,
      status: (worstSeverity === 'critical' ? 'critical' : worstSeverity === 'high' ? 'warn' : 'ok') as 'ok' | 'warn' | 'critical',
    })),
    tools: sourceResult.tools,
    findings: sourceResult.findings,
    summary: {
      totalClients: 0,
      totalServers: mcpFiles.length,
      totalTools: sourceResult.tools.length,
      totalFindings: sourceResult.findings.length,
      findingsBySeverity,
      overallStatus: sourceResult.findings.some(f => f.severity === 'critical')
        ? 'critical'
        : sourceResult.findings.some(f => f.severity === 'high')
          ? 'warn'
          : 'ok',
    },
  };
}
