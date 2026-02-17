import * as os from 'node:os';
import * as fs from 'node:fs';
import { getAllClientDefs, resolveClientPaths } from '../mcp/well-known-paths.js';
import { scanAllMCPConfigs } from '../mcp/analyzer.js';
import { getMachineId } from '../platform/machine-id.js';
import { detectRunningTools } from './process-detector.js';
import type { AITool, EndpointScanResult } from '../types/endpoint.js';
import type { MCPScanResult } from '../types/mcp-scan.js';

export function scanEndpoint(): EndpointScanResult {
  const startTime = Date.now();
  const platform = os.platform() as 'darwin' | 'linux' | 'win32';

  // 1. Discover all known AI tools and check installation
  const allDefs = getAllClientDefs();
  const runningTools = detectRunningTools();

  // 2. Run full MCP security scan
  let mcp: MCPScanResult;
  try {
    mcp = scanAllMCPConfigs();
  } catch {
    mcp = {
      clients: [],
      servers: [],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0,
        totalServers: 0,
        totalTools: 0,
        totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok' as const,
      },
    };
  }

  // 3. Build AI tools list
  const tools: AITool[] = [];
  for (const def of allDefs) {
    const configPath = def.paths[platform];
    if (!configPath) continue;

    const installed = fs.existsSync(configPath);
    const running = runningTools.has(def.name);

    // Count MCP servers for this tool from scan results
    const servers = mcp.servers.filter(s => s.client === def.name);

    tools.push({
      name: def.name,
      configPath,
      installed,
      running,
      mcpServerCount: servers.length,
      servers,
    });
  }

  // 4. Build summary
  const detectedTools = tools.filter(t => t.installed || t.running);
  const runningToolsList = tools.filter(t => t.running);
  const totalFindings = mcp.summary.totalFindings;

  const findingsBySeverity: Record<string, number> = {
    critical: mcp.summary.findingsBySeverity.critical,
    high: mcp.summary.findingsBySeverity.high,
    medium: mcp.summary.findingsBySeverity.medium,
    low: mcp.summary.findingsBySeverity.low,
  };

  let overallStatus: 'ok' | 'warn' | 'critical' = 'ok';
  if (findingsBySeverity.critical > 0) overallStatus = 'critical';
  else if (findingsBySeverity.high > 0 || findingsBySeverity.medium > 0) overallStatus = 'warn';

  const duration = Date.now() - startTime;

  return {
    machineId: getMachineId(),
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    tools,
    mcp,
    summary: {
      totalTools: detectedTools.length,
      runningTools: runningToolsList.length,
      totalServers: mcp.summary.totalServers,
      totalFindings,
      findingsBySeverity,
      overallStatus,
    },
    duration,
  };
}
