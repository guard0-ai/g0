import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

export interface DetectedAgent {
  type: 'claude-code' | 'cursor' | 'mcp-server' | 'openclaw' | 'generic-agent';
  pid?: number;
  name: string;
  path?: string;
  status: 'running' | 'stopped' | 'unknown';
  metadata?: Record<string, unknown>;
}

export interface AgentWatchResult {
  agents: DetectedAgent[];
  timestamp: string;
  hostname: string;
}

/** Names we look for when detecting generic agent processes. */
const GENERIC_AGENT_NAMES = ['aider', 'continue', 'cody', 'copilot', 'langserve'];

/** Common MCP config file locations (relative to home). */
const MCP_CONFIG_PATHS = [
  '.cursor/mcp.json',
  'Library/Application Support/Claude/claude_desktop_config.json',
];

/** Paths where CLAUDE.md files might live. */
const CLAUDE_MD_SEARCH_PATHS = ['.', 'Desktop', 'Documents', 'Projects', 'repos', 'src'];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getPsOutput(): string {
  try {
    return execFileSync('ps', ['aux'], { encoding: 'utf-8', timeout: 5000 });
  } catch {
    return '';
  }
}

interface PsEntry {
  pid: number;
  command: string;
}

function parsePsOutput(raw: string): PsEntry[] {
  const lines = raw.split('\n').slice(1); // skip header
  const entries: PsEntry[] = [];
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 11) continue;
    const pid = parseInt(parts[1], 10);
    const command = parts.slice(10).join(' ');
    if (!isNaN(pid) && command) {
      entries.push({ pid, command });
    }
  }
  return entries;
}

function processMatchesName(command: string, name: string): boolean {
  const lower = command.toLowerCase();
  const base = path.basename(lower.split(/\s/)[0]);
  return base === name.toLowerCase() || base.startsWith(`${name.toLowerCase()}-`);
}

// ---------------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------------

function detectClaudeCode(ps: PsEntry[]): DetectedAgent[] {
  const agents: DetectedAgent[] = [];
  const home = os.homedir();

  // Process detection
  for (const entry of ps) {
    if (processMatchesName(entry.command, 'claude') || processMatchesName(entry.command, 'claude-code')) {
      agents.push({
        type: 'claude-code',
        pid: entry.pid,
        name: 'Claude Code',
        status: 'running',
        metadata: { detectedVia: 'process' },
      });
    }
  }

  // Directory detection
  const claudeDir = path.join(home, '.claude');
  if (fs.existsSync(claudeDir)) {
    if (agents.length === 0) {
      agents.push({
        type: 'claude-code',
        name: 'Claude Code',
        path: claudeDir,
        status: 'stopped',
        metadata: { detectedVia: 'directory' },
      });
    } else {
      agents[0].path = claudeDir;
    }
  }

  // CLAUDE.md detection
  for (const rel of CLAUDE_MD_SEARCH_PATHS) {
    const claudeMd = path.join(home, rel, 'CLAUDE.md');
    try {
      if (fs.existsSync(claudeMd)) {
        const existing = agents[0];
        if (existing) {
          existing.metadata = { ...existing.metadata, claudeMdPath: claudeMd };
        } else {
          agents.push({
            type: 'claude-code',
            name: 'Claude Code',
            path: claudeMd,
            status: 'unknown',
            metadata: { detectedVia: 'claude-md', claudeMdPath: claudeMd },
          });
        }
        break;
      }
    } catch {
      // permission errors, etc.
    }
  }

  return agents;
}

function detectCursor(ps: PsEntry[]): DetectedAgent[] {
  const agents: DetectedAgent[] = [];
  const home = os.homedir();

  for (const entry of ps) {
    if (processMatchesName(entry.command, 'Cursor') || processMatchesName(entry.command, 'cursor')) {
      agents.push({
        type: 'cursor',
        pid: entry.pid,
        name: 'Cursor',
        status: 'running',
        metadata: { detectedVia: 'process' },
      });
      break;
    }
  }

  const cursorDir = path.join(home, '.cursor');
  const cursorAppSupport = path.join(home, 'Library', 'Application Support', 'Cursor');

  const dirExists = fs.existsSync(cursorDir) || fs.existsSync(cursorAppSupport);
  if (dirExists) {
    if (agents.length === 0) {
      agents.push({
        type: 'cursor',
        name: 'Cursor',
        path: fs.existsSync(cursorDir) ? cursorDir : cursorAppSupport,
        status: 'stopped',
        metadata: { detectedVia: 'directory' },
      });
    } else {
      agents[0].path = fs.existsSync(cursorDir) ? cursorDir : cursorAppSupport;
    }
  }

  return agents;
}

function detectMcpServers(_ps: PsEntry[]): DetectedAgent[] {
  const agents: DetectedAgent[] = [];
  const home = os.homedir();

  for (const rel of MCP_CONFIG_PATHS) {
    const configPath = path.join(home, rel);
    try {
      if (!fs.existsSync(configPath)) continue;
      const raw = fs.readFileSync(configPath, 'utf-8');
      const parsed = JSON.parse(raw);

      // Both Cursor and Claude Desktop use { mcpServers: { name: { ... } } }
      const servers = parsed.mcpServers ?? parsed.servers ?? {};
      for (const [serverName, serverConfig] of Object.entries(servers)) {
        agents.push({
          type: 'mcp-server',
          name: serverName,
          path: configPath,
          status: 'unknown',
          metadata: {
            detectedVia: 'config',
            configFile: configPath,
            serverConfig,
          },
        });
      }
    } catch {
      // malformed JSON or permission error
    }
  }

  return agents;
}

function detectOpenClaw(ps: PsEntry[]): DetectedAgent[] {
  const agents: DetectedAgent[] = [];

  // Process detection — openclaw gateway or agent processes
  for (const entry of ps) {
    if (processMatchesName(entry.command, 'openclaw') ||
        processMatchesName(entry.command, 'openclaw-gateway') ||
        processMatchesName(entry.command, 'openclaw-agent') ||
        entry.command.includes('openclaw')) {
      agents.push({
        type: 'openclaw',
        pid: entry.pid,
        name: 'OpenClaw',
        status: 'running',
        metadata: { detectedVia: 'process', command: entry.command },
      });
      break;
    }
  }

  // Directory detection — common OpenClaw data paths
  const openclawPaths = [
    '/data/.openclaw',
    path.join(os.homedir(), '.openclaw'),
    path.join(os.homedir(), '.config', 'openclaw'),
  ];

  for (const oclawPath of openclawPaths) {
    try {
      if (fs.existsSync(oclawPath)) {
        if (agents.length === 0) {
          agents.push({
            type: 'openclaw',
            name: 'OpenClaw',
            path: oclawPath,
            status: 'stopped',
            metadata: { detectedVia: 'directory' },
          });
        } else {
          agents[0].path = oclawPath;
        }

        // Check for openclaw.json config
        const configPath = path.join(oclawPath, 'openclaw.json');
        if (fs.existsSync(configPath)) {
          try {
            const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
            if (agents[0]) {
              agents[0].metadata = {
                ...agents[0].metadata,
                gatewayUrl: config.gatewayUrl,
                agentCount: config.agents ? Object.keys(config.agents).length : undefined,
              };
            }
          } catch {
            // malformed config
          }
        }
        break;
      }
    } catch {
      // permission errors
    }
  }

  // Gateway port detection — check if port 18789 is listening
  if (agents.length === 0) {
    try {
      const netstat = execFileSync(
        os.platform() === 'darwin' ? 'lsof' : 'ss',
        os.platform() === 'darwin' ? ['-iTCP:18789', '-sTCP:LISTEN', '-P', '-n'] : ['-tlnp'],
        { encoding: 'utf-8', timeout: 5000 },
      );
      if (netstat.includes('18789')) {
        agents.push({
          type: 'openclaw',
          name: 'OpenClaw',
          status: 'running',
          metadata: { detectedVia: 'port', port: 18789 },
        });
      }
    } catch {
      // lsof/ss not available or no permission
    }
  }

  return agents;
}

function detectGenericAgents(ps: PsEntry[]): DetectedAgent[] {
  const agents: DetectedAgent[] = [];

  for (const name of GENERIC_AGENT_NAMES) {
    for (const entry of ps) {
      if (processMatchesName(entry.command, name)) {
        agents.push({
          type: 'generic-agent',
          pid: entry.pid,
          name,
          status: 'running',
          metadata: { detectedVia: 'process' },
        });
        break; // one per name
      }
    }
  }

  return agents;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Detect running AI agent sessions on the host.
 * Scans processes, config directories, and MCP config files.
 */
export function detectRunningAgents(): AgentWatchResult {
  const raw = getPsOutput();
  const ps = parsePsOutput(raw);

  const agents: DetectedAgent[] = [
    ...detectClaudeCode(ps),
    ...detectCursor(ps),
    ...detectOpenClaw(ps),
    ...detectMcpServers(ps),
    ...detectGenericAgents(ps),
  ];

  return {
    agents,
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
  };
}

/**
 * Format an AgentWatchResult as a human-readable summary string.
 */
export function getAgentSummary(result: AgentWatchResult): string {
  if (result.agents.length === 0) {
    return `No AI agents detected on ${result.hostname}`;
  }

  const lines: string[] = [
    `${result.agents.length} agent(s) detected on ${result.hostname}:`,
  ];

  for (const agent of result.agents) {
    const pidStr = agent.pid ? ` (PID ${agent.pid})` : '';
    const pathStr = agent.path ? ` — ${agent.path}` : '';
    lines.push(`  [${agent.status}] ${agent.name}${pidStr}${pathStr}`);
  }

  return lines.join('\n');
}

/**
 * Periodically poll for running agents and invoke the callback with results.
 * Returns a handle with a `stop()` method to cancel polling.
 */
export function watchAgents(
  intervalMs: number,
  callback: (result: AgentWatchResult) => void,
): { stop: () => void } {
  // Fire immediately, then on interval
  callback(detectRunningAgents());

  const timer = setInterval(() => {
    callback(detectRunningAgents());
  }, intervalMs);

  return {
    stop: () => clearInterval(timer),
  };
}
