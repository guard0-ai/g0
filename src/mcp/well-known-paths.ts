import * as path from 'node:path';
import * as os from 'node:os';
import * as fs from 'node:fs';
import type { MCPClient } from '../types/mcp-scan.js';

interface ClientDef {
  name: string;
  mcpKey: string;
  paths: {
    darwin?: string;
    linux?: string;
    win32?: string;
  };
}

const HOME = os.homedir();

export { ClientDef };

const WELL_KNOWN_CLIENTS: ClientDef[] = [
  {
    name: 'Claude Desktop',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, 'Library/Application Support/Claude/claude_desktop_config.json'),
      linux: path.join(HOME, '.config/claude/claude_desktop_config.json'),
      win32: path.join(HOME, 'AppData/Roaming/Claude/claude_desktop_config.json'),
    },
  },
  {
    name: 'Claude Code',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.claude/settings.json'),
      linux: path.join(HOME, '.claude/settings.json'),
      win32: path.join(HOME, '.claude/settings.json'),
    },
  },
  {
    name: 'Cursor',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.cursor/mcp.json'),
      linux: path.join(HOME, '.cursor/mcp.json'),
      win32: path.join(HOME, '.cursor/mcp.json'),
    },
  },
  {
    name: 'Windsurf',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.codeium/windsurf/mcp_config.json'),
      linux: path.join(HOME, '.codeium/windsurf/mcp_config.json'),
      win32: path.join(HOME, '.codeium/windsurf/mcp_config.json'),
    },
  },
  {
    name: 'VS Code',
    mcpKey: 'servers',
    paths: {
      darwin: path.join(HOME, 'Library/Application Support/Code/User/settings.json'),
      linux: path.join(HOME, '.config/Code/User/settings.json'),
      win32: path.join(HOME, 'AppData/Roaming/Code/User/settings.json'),
    },
  },
  {
    name: 'Zed',
    mcpKey: 'context_servers',
    paths: {
      darwin: path.join(HOME, '.config/zed/settings.json'),
      linux: path.join(HOME, '.config/zed/settings.json'),
      win32: path.join(HOME, '.config/zed/settings.json'),
    },
  },
  {
    name: 'Cline',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.cline/mcp_settings.json'),
      linux: path.join(HOME, '.cline/mcp_settings.json'),
      win32: path.join(HOME, '.cline/mcp_settings.json'),
    },
  },
  {
    name: 'Roo Code',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.roo-code/mcp_settings.json'),
      linux: path.join(HOME, '.roo-code/mcp_settings.json'),
      win32: path.join(HOME, '.roo-code/mcp_settings.json'),
    },
  },
  {
    name: 'JetBrains (Junie)',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.junie/mcp/mcp.json'),
      linux: path.join(HOME, '.junie/mcp/mcp.json'),
      win32: path.join(HOME, '.junie/mcp/mcp.json'),
    },
  },
  {
    name: 'Gemini CLI',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.gemini/settings.json'),
      linux: path.join(HOME, '.gemini/settings.json'),
      win32: path.join(HOME, '.gemini/settings.json'),
    },
  },
  {
    name: 'Amazon Q Developer',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.aws/amazonq/mcp.json'),
      linux: path.join(HOME, '.aws/amazonq/mcp.json'),
      win32: path.join(HOME, '.aws/amazonq/mcp.json'),
    },
  },
  {
    name: 'Copilot CLI',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.copilot/mcp-config.json'),
      linux: path.join(HOME, '.copilot/mcp-config.json'),
      win32: path.join(HOME, '.copilot/mcp-config.json'),
    },
  },
  {
    name: 'Kiro',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.kiro/settings/mcp.json'),
      linux: path.join(HOME, '.kiro/settings/mcp.json'),
      win32: path.join(HOME, '.kiro/settings/mcp.json'),
    },
  },
  {
    name: 'Continue',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.continue/config.json'),
      linux: path.join(HOME, '.continue/config.json'),
      win32: path.join(HOME, '.continue/config.json'),
    },
  },
  {
    name: 'Augment Code',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.augment/settings.json'),
      linux: path.join(HOME, '.augment/settings.json'),
      win32: path.join(HOME, '.augment/settings.json'),
    },
  },
  {
    name: 'Neovim (mcphub)',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.config/mcphub/servers.json'),
      linux: path.join(HOME, '.config/mcphub/servers.json'),
      win32: path.join(HOME, '.config/mcphub/servers.json'),
    },
  },
  {
    name: 'BoltAI',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, '.boltai/mcp.json'),
    },
  },
  {
    name: '5ire',
    mcpKey: 'mcpServers',
    paths: {
      darwin: path.join(HOME, 'Library/Application Support/5ire/mcp.json'),
      linux: path.join(HOME, '.config/5ire/mcp.json'),
      win32: path.join(HOME, 'AppData/Roaming/5ire/mcp.json'),
    },
  },
];

export function getAllClientDefs(): ClientDef[] {
  return WELL_KNOWN_CLIENTS;
}

export function resolveClientPaths(): MCPClient[] {
  const platform = os.platform() as 'darwin' | 'linux' | 'win32';
  const clients: MCPClient[] = [];

  for (const def of WELL_KNOWN_CLIENTS) {
    const configPath = def.paths[platform];
    if (!configPath) continue;

    if (fs.existsSync(configPath)) {
      clients.push({
        name: def.name,
        configPath,
        mcpKey: def.mcpKey,
      });
    }
  }

  return clients;
}
