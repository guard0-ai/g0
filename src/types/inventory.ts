import type { ToolCapability } from './agent-graph.js';

export interface InventoryResult {
  models: InventoryModel[];
  frameworks: InventoryFramework[];
  tools: InventoryTool[];
  mcpServers: InventoryMCPServer[];
  agents: InventoryAgent[];
  vectorDBs: InventoryVectorDB[];
  risks: InventoryRisk[];
  summary: InventorySummary;
}

export interface InventoryModel {
  name: string;
  provider: string;
  framework: string;
  file: string;
  line: number;
}

export interface InventoryFramework {
  name: string;
  version?: string;
  file: string;
}

export interface InventoryTool {
  name: string;
  framework: string;
  description: string;
  capabilities: ToolCapability[];
  hasSideEffects: boolean;
  hasValidation: boolean;
  file: string;
  line: number;
}

export interface InventoryMCPServer {
  name: string;
  command: string;
  args: string[];
  hasSecrets: boolean;
  isPinned: boolean;
  file: string;
  tools?: { name: string; description?: string; capabilities?: string[] }[];
  transport?: string;
  source?: 'config' | 'source-code';
}

export interface InventoryAgent {
  name: string;
  framework: string;
  toolCount: number;
  model?: string;
  hasDelegation: boolean;
  file: string;
  line: number;
}

export interface InventoryVectorDB {
  name: string;
  framework: string;
  file: string;
  line: number;
}

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface InventoryRisk {
  level: RiskLevel;
  category: string;
  description: string;
  file?: string;
  line?: number;
}

export interface InventorySummary {
  totalModels: number;
  totalFrameworks: number;
  totalTools: number;
  totalAgents: number;
  totalMCPServers: number;
  totalVectorDBs: number;
  totalRisks: number;
  riskBreakdown: Record<RiskLevel, number>;
}
