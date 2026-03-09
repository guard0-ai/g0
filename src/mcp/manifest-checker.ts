import * as fs from 'node:fs';
import * as path from 'node:path';
import type { MCPToolInfo, MCPFinding } from '../types/mcp-scan.js';

export interface ManifestCheckResult {
  undeclaredTools: string[];  // In code but not in config
  phantomTools: string[];     // In config but not in code
  findings: MCPFinding[];
}

interface MCPConfigEntry {
  tools?: string[];
  command?: string;
  args?: string[];
}

/**
 * Compare tools found by source scanning vs tools declared in MCP config.
 * Flags undeclared tools (in code but not config) and phantom tools (in config but not code).
 */
export function checkManifestConsistency(
  sourceTools: MCPToolInfo[],
  configPath: string,
  serverName: string,
): ManifestCheckResult {
  const result: ManifestCheckResult = {
    undeclaredTools: [],
    phantomTools: [],
    findings: [],
  };

  // Try to read MCP config
  let configTools: string[] = [];
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    const ext = path.extname(configPath).toLowerCase();

    if (ext === '.json') {
      const parsed = JSON.parse(content);
      // Handle various MCP config formats
      const mcpServers = parsed.mcpServers ?? parsed.mcp_servers ?? parsed.servers ?? {};
      for (const server of Object.values(mcpServers) as MCPConfigEntry[]) {
        if (Array.isArray(server.tools)) {
          configTools.push(...server.tools);
        }
      }
      // Also check tools at top level
      if (Array.isArray(parsed.tools)) {
        for (const tool of parsed.tools) {
          if (typeof tool === 'string') configTools.push(tool);
          else if (typeof tool?.name === 'string') configTools.push(tool.name);
        }
      }
    }
  } catch {
    // Can't read config — skip manifest check
    return result;
  }

  if (configTools.length === 0) return result;

  const configToolSet = new Set(configTools.map(t => t.toLowerCase()));
  const sourceToolNames = new Set(sourceTools.map(t => t.name.toLowerCase()));

  // Find undeclared tools (in code but not config)
  for (const tool of sourceTools) {
    if (!configToolSet.has(tool.name.toLowerCase())) {
      result.undeclaredTools.push(tool.name);
    }
  }

  // Find phantom tools (in config but not code)
  for (const toolName of configTools) {
    if (!sourceToolNames.has(toolName.toLowerCase())) {
      result.phantomTools.push(toolName);
    }
  }

  // Generate findings
  for (const name of result.undeclaredTools) {
    result.findings.push({
      severity: 'high',
      type: 'undeclared-tool',
      title: `Undeclared tool: ${name}`,
      description: `Tool "${name}" exists in source code but is not declared in MCP config — may be a hidden/backdoor tool`,
      server: serverName,
      file: configPath,
    });
  }

  for (const name of result.phantomTools) {
    result.findings.push({
      severity: 'medium',
      type: 'phantom-tool',
      title: `Phantom tool: ${name}`,
      description: `Tool "${name}" is declared in MCP config but not found in source code — stale config or external dependency`,
      server: serverName,
      file: configPath,
    });
  }

  return result;
}
