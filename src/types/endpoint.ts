import type { ScanResult } from './score.js';
import type { InventoryResult } from './inventory.js';
import type { MCPScanResult } from './mcp-scan.js';

export interface EndpointProjectScan {
  path: string;
  name: string;
  result?: ScanResult;
  error?: string;
}

export interface EndpointScanResult {
  machineId: string;
  hostname: string;
  timestamp: string;
  mcp: MCPScanResult;
  projects: EndpointProjectScan[];
  summary: {
    totalFindings: number;
    totalProjects: number;
    scannedProjects: number;
    failedProjects: number;
    averageScore: number;
    worstProject?: { name: string; path: string; score: number };
    findingsBySeverity: Record<string, number>;
  };
  duration: number;
}

export interface EndpointProjectInventory {
  path: string;
  name: string;
  result?: InventoryResult;
  error?: string;
}

export interface EndpointInventoryResult {
  machineId: string;
  hostname: string;
  timestamp: string;
  mcp: MCPScanResult;
  projects: EndpointProjectInventory[];
  summary: {
    totalProjects: number;
    scannedProjects: number;
    failedProjects: number;
    uniqueModels: number;
    uniqueFrameworks: number;
    uniqueTools: number;
    uniqueAgents: number;
    totalMCPServers: number;
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
