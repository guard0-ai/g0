import * as fs from 'node:fs';
import * as path from 'node:path';
import type { MCPClient, MCPScanResult, MCPFindingSeverity, SkillFileInfo, PinCheckResult } from '../types/mcp-scan.js';
import { resolveClientPaths } from './well-known-paths.js';
import { scanMCPConfig } from './config-scanner.js';
import { scanMCPServerSource } from './source-scanner.js';
import { scanSkillFiles } from './skill-scanner.js';
import { scanOpenClawFiles } from './openclaw-scanner.js';
import { loadPinFile, checkPins } from './hash-pinning.js';

const DEFAULT_PIN_FILE = '.g0-pins.json';

export function scanAllMCPConfigs(rootPath?: string): MCPScanResult {
  const clients = resolveClientPaths();
  const result = scanClients(clients);

  // Integrate skill scanning
  const skills = scanSkillFiles(rootPath);
  if (skills.length > 0) {
    result.skills = skills;
    for (const skill of skills) {
      result.findings.push(...skill.findings);
    }
  }

  // Integrate OpenClaw file scanning
  const openClawFiles = scanOpenClawFiles(rootPath);
  if (openClawFiles.length > 0) {
    result.openClaw = openClawFiles;
    for (const f of openClawFiles) {
      result.findings.push(...f.findings);
    }
  }

  // Auto-check pins if .g0-pins.json exists
  const pinPath = rootPath ? path.join(rootPath, DEFAULT_PIN_FILE) : DEFAULT_PIN_FILE;
  if (result.tools.length > 0 && fs.existsSync(pinPath)) {
    const pinFile = loadPinFile(pinPath);
    if (pinFile) {
      const pinCheck = checkPins(result.tools, pinFile);
      result.pinCheck = pinCheck;
      for (const mismatch of pinCheck.mismatches) {
        result.findings.push({
          severity: 'critical',
          type: 'rug-pull',
          title: `Tool description changed: ${mismatch.toolName}`,
          description: `Tool "${mismatch.toolName}" description has changed since pinning. This may indicate a rug pull attack. Previous: "${mismatch.previousDescription.substring(0, 80)}..."`,
          server: mismatch.serverName,
        });
      }
      for (const removed of pinCheck.removedTools) {
        result.findings.push({
          severity: 'high',
          type: 'rug-pull-removed',
          title: `Pinned tool removed: ${removed}`,
          description: `Tool "${removed}" was present when pins were generated but is now missing.`,
        });
      }
    }
  }

  rebuildSummary(result);
  return result;
}

export function scanMCPConfigFile(configPath: string): MCPScanResult {
  const resolvedPath = path.resolve(configPath);
  const client: MCPClient = {
    name: path.basename(configPath),
    configPath: resolvedPath,
    mcpKey: 'mcpServers',
  };
  return scanClients([client]);
}

export function scanMCPServer(serverPath: string): MCPScanResult {
  const resolvedPath = path.resolve(serverPath);
  const serverName = path.basename(serverPath, path.extname(serverPath));

  const { tools, findings } = scanMCPServerSource(resolvedPath, serverName);

  // Scan for skill files in the server directory
  const serverDir = path.dirname(resolvedPath);
  const skills = scanSkillFiles(serverDir);
  const allFindings = [...findings];
  for (const skill of skills) {
    allFindings.push(...skill.findings);
  }

  const result = buildResult([], [], tools, allFindings);
  if (skills.length > 0) result.skills = skills;
  return result;
}

export function listMCPServers(): MCPScanResult {
  const clients = resolveClientPaths();
  return scanClients(clients, true);
}

function scanClients(clients: MCPClient[], listOnly = false): MCPScanResult {
  const allServers: MCPScanResult['servers'] = [];
  const allFindings: MCPScanResult['findings'] = [];
  const allTools: MCPScanResult['tools'] = [];

  for (const client of clients) {
    const { servers, findings } = scanMCPConfig(
      client.configPath,
      client.name,
      client.mcpKey,
    );
    allServers.push(...servers);
    if (!listOnly) {
      allFindings.push(...findings);
    }
  }

  return buildResult(clients, allServers, allTools, allFindings);
}

function buildResult(
  clients: MCPClient[],
  servers: MCPScanResult['servers'],
  tools: MCPScanResult['tools'],
  findings: MCPScanResult['findings'],
): MCPScanResult {
  const result: MCPScanResult = {
    clients,
    servers,
    tools,
    findings,
    summary: {
      totalClients: clients.length,
      totalServers: servers.length,
      totalTools: tools.length,
      totalFindings: findings.length,
      findingsBySeverity: computeSeverityCounts(findings),
      overallStatus: 'ok',
    },
  };
  rebuildSummary(result);
  return result;
}

function computeSeverityCounts(findings: MCPScanResult['findings']): Record<MCPFindingSeverity, number> {
  return {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };
}

function rebuildSummary(result: MCPScanResult): void {
  result.summary.totalFindings = result.findings.length;
  result.summary.findingsBySeverity = computeSeverityCounts(result.findings);
  const sev = result.summary.findingsBySeverity;
  if (sev.critical > 0) result.summary.overallStatus = 'critical';
  else if (sev.high > 0 || sev.medium > 0) result.summary.overallStatus = 'warn';
  else result.summary.overallStatus = 'ok';
}
