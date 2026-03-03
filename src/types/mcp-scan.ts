export interface MCPClient {
  name: string;
  configPath: string;
  mcpKey: string;
}

export interface MCPServerInfo {
  name: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  client: string;
  configFile: string;
  status: 'ok' | 'warn' | 'critical';
}

export type MCPFindingSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface MCPFinding {
  severity: MCPFindingSeverity;
  type: string;
  title: string;
  description: string;
  server?: string;
  client?: string;
  file?: string;
  line?: number;
}

export interface MCPToolInfo {
  name: string;
  description: string;
  capabilities: string[];
  hasSideEffects: boolean;
  file: string;
  line: number;
}

export interface SkillFileInfo {
  path: string;
  findings: MCPFinding[];
  size: number;
}

export interface PinCheckResult {
  matches: number;
  mismatches: {
    toolName: string;
    serverName: string;
    expected: string;
    actual: string;
    previousDescription: string;
    currentDescription: string;
  }[];
  newTools: string[];
  removedTools: string[];
}

export interface OpenClawFileInfo {
  path: string;
  fileType: 'SKILL.md' | 'SOUL.md' | 'MEMORY.md' | 'openclaw.json';
  findings: MCPFinding[];
  size: number;
}

export interface MCPScanResult {
  clients: MCPClient[];
  servers: MCPServerInfo[];
  tools: MCPToolInfo[];
  findings: MCPFinding[];
  skills?: SkillFileInfo[];
  openClaw?: OpenClawFileInfo[];
  pinCheck?: PinCheckResult;
  summary: MCPScanSummary;
}

export interface MCPScanSummary {
  totalClients: number;
  totalServers: number;
  totalTools: number;
  totalFindings: number;
  findingsBySeverity: Record<MCPFindingSeverity, number>;
  overallStatus: 'ok' | 'warn' | 'critical';
}

export type { MCPVerifyResult, MCPVerifyRisk } from '../mcp/npm-verify.js';
