import type { MCPScanResult, MCPServerInfo } from './mcp-scan.js';

export interface AITool {
  name: string;
  configPath: string;
  installed: boolean;
  running: boolean;
  mcpServerCount: number;
  servers: MCPServerInfo[];
}

export interface EndpointScanResult {
  machineId: string;
  hostname: string;
  timestamp: string;
  tools: AITool[];
  mcp: MCPScanResult;
  summary: {
    totalTools: number;
    runningTools: number;
    totalServers: number;
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    overallStatus: 'ok' | 'warn' | 'critical';
  };
  duration: number;
}

export interface EndpointStatusResult {
  machineId: string;
  hostname: string;
  platform: string;
  arch: string;
  nodeVersion: string;
  daemon: { running: boolean; pid?: number };
  auth: { authenticated: boolean };
  watchPaths: string[];
  mcpServers: number;
  daemonConfig: {
    intervalMinutes: number;
    upload: boolean;
    mcpScan: boolean;
  };
}
