import * as path from 'node:path';
import type { AgentGraph } from '../types/agent-graph.js';
import type { DiscoveryResult } from '../pipeline.js'; // type-only: no circular dep
import type {
  InventoryResult,
  InventoryModel,
  InventoryFramework,
  InventoryTool,
  InventoryMCPServer,
  InventoryAgent,
  InventoryVectorDB,
  InventoryRisk,
  RiskLevel,
} from '../types/inventory.js';
import { scanMCPServerSource } from '../mcp/source-scanner.js';

export function buildInventory(graph: AgentGraph, discovery?: DiscoveryResult): InventoryResult {
  const models = extractModels(graph);
  const frameworks = extractFrameworks(graph);
  const tools = extractTools(graph);
  const mcpServers = extractMCPServers(graph, discovery);
  const agents = extractAgents(graph);
  const vectorDBs = extractVectorDBs(graph);
  const risks = assessRisks(graph);

  const riskBreakdown: Record<RiskLevel, number> = {
    critical: risks.filter(r => r.level === 'critical').length,
    high: risks.filter(r => r.level === 'high').length,
    medium: risks.filter(r => r.level === 'medium').length,
    low: risks.filter(r => r.level === 'low').length,
  };

  return {
    models,
    frameworks,
    tools,
    mcpServers,
    agents,
    vectorDBs,
    risks,
    summary: {
      totalModels: models.length,
      totalFrameworks: frameworks.length,
      totalTools: tools.length,
      totalAgents: agents.length,
      totalMCPServers: mcpServers.length,
      totalVectorDBs: vectorDBs.length,
      totalRisks: risks.length,
      riskBreakdown,
    },
  };
}

function extractModels(graph: AgentGraph): InventoryModel[] {
  return graph.models.map(m => ({
    name: m.name,
    provider: m.provider,
    framework: m.framework,
    file: m.file,
    line: m.line,
  }));
}

function extractFrameworks(graph: AgentGraph): InventoryFramework[] {
  return graph.frameworkVersions.map(f => ({
    name: f.name,
    version: f.version,
    file: f.file,
  }));
}

function extractTools(graph: AgentGraph): InventoryTool[] {
  return graph.tools.map(t => ({
    name: t.name,
    framework: t.framework,
    description: t.description,
    capabilities: t.capabilities,
    hasSideEffects: t.hasSideEffects,
    hasValidation: t.hasInputValidation,
    file: t.file,
    line: t.line,
  }));
}

function extractMCPServers(graph: AgentGraph, discovery?: DiscoveryResult): InventoryMCPServer[] {
  const servers: InventoryMCPServer[] = [];

  // Config-based extraction (existing)
  for (const config of graph.configs) {
    if (config.type !== 'json') continue;

    for (const issue of config.issues) {
      if (issue.type === 'npx-auto-install' || issue.type === 'unpinned-mcp-server') {
        const nameMatch = issue.message.match(/"([^"]+)"/);
        if (nameMatch) {
          const existing = servers.find(s => s.name === nameMatch[1]);
          if (!existing) {
            servers.push({
              name: nameMatch[1],
              command: 'npx',
              args: [],
              hasSecrets: config.secrets.length > 0,
              isPinned: issue.type !== 'unpinned-mcp-server',
              file: config.file,
              source: 'config',
            });
          }
        }
      }
    }
  }

  // Source-code extraction: find MCP files from detection results
  if (discovery) {
    const mcpDetection = discovery.detection.results.find(r => r.framework === 'mcp');
    if (mcpDetection) {
      for (const file of mcpDetection.files) {
        const fullPath = path.isAbsolute(file) ? file : path.join(graph.rootPath, file);
        const serverName = path.basename(file, path.extname(file));

        // Deduplicate against config-discovered servers
        if (servers.find(s => s.name === serverName)) continue;

        const result = scanMCPServerSource(fullPath, serverName);
        if (result.tools.length > 0) {
          servers.push({
            name: serverName,
            command: '',
            args: [],
            hasSecrets: false,
            isPinned: false,
            file,
            tools: result.tools.map(t => ({
              name: t.name,
              description: t.description || undefined,
              capabilities: t.capabilities.length > 0 ? t.capabilities : undefined,
            })),
            source: 'source-code',
          });
        }
      }
    }
  }

  return servers;
}

function extractAgents(graph: AgentGraph): InventoryAgent[] {
  return graph.agents.map(a => {
    const model = a.modelId
      ? graph.models.find(m => m.id === a.modelId)
      : undefined;

    return {
      name: a.name,
      framework: a.framework,
      toolCount: a.tools.length,
      model: model?.name,
      hasDelegation: a.delegationEnabled ?? false,
      file: a.file,
      line: a.line,
    };
  });
}

function extractVectorDBs(graph: AgentGraph): InventoryVectorDB[] {
  return graph.vectorDBs.map(v => ({
    name: v.name,
    framework: v.framework,
    file: v.file,
    line: v.line,
  }));
}

function assessRisks(graph: AgentGraph): InventoryRisk[] {
  const risks: InventoryRisk[] = [];

  // Check for hardcoded secrets
  for (const config of graph.configs) {
    for (const secret of config.secrets) {
      if (secret.isHardcoded) {
        risks.push({
          level: 'critical',
          category: 'hardcoded-secret',
          description: `Hardcoded secret "${secret.key}" found in config`,
          file: config.file,
          line: secret.line,
        });
      }
    }

    for (const issue of config.issues) {
      const level: RiskLevel = issue.type === 'npx-auto-install' ? 'high' : 'medium';
      risks.push({
        level,
        category: issue.type,
        description: issue.message,
        file: config.file,
        line: issue.line,
      });
    }
  }

  // Check for dangerous tools without validation
  for (const tool of graph.tools) {
    const dangerousCaps = tool.capabilities.filter(c =>
      ['shell', 'code-execution', 'database'].includes(c),
    );

    if (dangerousCaps.length > 0 && !tool.hasInputValidation) {
      risks.push({
        level: 'high',
        category: 'unvalidated-dangerous-tool',
        description: `Tool "${tool.name}" has ${dangerousCaps.join('/')} capabilities without input validation`,
        file: tool.file,
        line: tool.line,
      });
    }

    if (tool.hasSideEffects && !tool.hasSandboxing) {
      risks.push({
        level: 'medium',
        category: 'unsandboxed-side-effect',
        description: `Tool "${tool.name}" has side effects without sandboxing`,
        file: tool.file,
        line: tool.line,
      });
    }
  }

  // Check for agents without iteration limits
  for (const agent of graph.agents) {
    if (agent.maxIterations === undefined && agent.tools.length > 0) {
      risks.push({
        level: 'medium',
        category: 'unbounded-agent',
        description: `Agent "${agent.name}" has no max_iterations limit`,
        file: agent.file,
        line: agent.line,
      });
    }
  }

  return risks;
}
