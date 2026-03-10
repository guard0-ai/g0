import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as childProcess from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(() => ''),
}));

vi.mock('node:fs', async () => {
  const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
  return {
    ...actual,
    existsSync: vi.fn(() => false),
    readFileSync: vi.fn(() => ''),
  };
});

// Import after mocks are set up
const { detectRunningAgents, getAgentSummary, watchAgents } = await import(
  '../../src/daemon/agent-watchers/index.js'
);

const mockedExecFileSync = vi.mocked(childProcess.execFileSync);
const mockedExistsSync = vi.mocked(fs.existsSync);
const mockedReadFileSync = vi.mocked(fs.readFileSync);

describe('agent-watchers', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedExecFileSync.mockReturnValue('');
    mockedExistsSync.mockReturnValue(false);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns empty agents when no processes or directories found', () => {
    const result = detectRunningAgents();

    expect(result.agents).toEqual([]);
    expect(result.hostname).toBe(os.hostname());
    expect(result.timestamp).toBeTruthy();
  });

  it('detects Claude Code via ~/.claude directory', () => {
    const home = os.homedir();
    const claudeDir = path.join(home, '.claude');

    mockedExistsSync.mockImplementation((p: fs.PathLike) => {
      return String(p) === claudeDir;
    });

    const result = detectRunningAgents();

    const claude = result.agents.find((a: any) => a.type === 'claude-code');
    expect(claude).toBeDefined();
    expect(claude!.name).toBe('Claude Code');
    expect(claude!.status).toBe('stopped');
    expect(claude!.path).toBe(claudeDir);
    expect(claude!.metadata?.detectedVia).toBe('directory');
  });

  it('detects Claude Code process as running', () => {
    const psOutput = [
      'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
      'jayesh   12345  0.5  1.0 123456 78900 ?        Ssl  10:00   0:01 claude --model opus',
    ].join('\n');

    mockedExecFileSync.mockReturnValue(psOutput);

    const result = detectRunningAgents();

    const claude = result.agents.find((a: any) => a.type === 'claude-code');
    expect(claude).toBeDefined();
    expect(claude!.pid).toBe(12345);
    expect(claude!.status).toBe('running');
    expect(claude!.metadata?.detectedVia).toBe('process');
  });

  it('detects MCP servers from config file', () => {
    const home = os.homedir();
    const mcpConfig = path.join(home, '.cursor', 'mcp.json');

    mockedExistsSync.mockImplementation((p: fs.PathLike) => {
      return String(p) === mcpConfig;
    });

    mockedReadFileSync.mockImplementation((p: any) => {
      if (String(p) === mcpConfig) {
        return JSON.stringify({
          mcpServers: {
            'my-server': { command: 'node', args: ['server.js'] },
            'another-server': { command: 'python', args: ['-m', 'mcp_server'] },
          },
        });
      }
      return '';
    });

    const result = detectRunningAgents();

    const mcpAgents = result.agents.filter((a: any) => a.type === 'mcp-server');
    expect(mcpAgents).toHaveLength(2);
    expect(mcpAgents[0].name).toBe('my-server');
    expect(mcpAgents[1].name).toBe('another-server');
    expect(mcpAgents[0].path).toBe(mcpConfig);
    expect(mcpAgents[0].metadata?.detectedVia).toBe('config');
  });

  it('detects generic agent processes', () => {
    const psOutput = [
      'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
      'jayesh    5555  0.3  0.8 100000 50000 ?        Ssl  10:00   0:00 aider --model gpt-4',
      'jayesh    6666  0.1  0.4  80000 30000 ?        Ssl  10:00   0:00 copilot serve',
    ].join('\n');

    mockedExecFileSync.mockReturnValue(psOutput);

    const result = detectRunningAgents();

    const generic = result.agents.filter((a: any) => a.type === 'generic-agent');
    expect(generic).toHaveLength(2);
    expect(generic.map((a: any) => a.name)).toContain('aider');
    expect(generic.map((a: any) => a.name)).toContain('copilot');
  });

  it('formats agent summary correctly', () => {
    const result = {
      agents: [
        { type: 'claude-code' as const, pid: 123, name: 'Claude Code', status: 'running' as const, path: '/home/.claude' },
        { type: 'mcp-server' as const, name: 'my-server', status: 'unknown' as const, path: '/home/.cursor/mcp.json' },
      ],
      timestamp: '2026-03-10T00:00:00.000Z',
      hostname: 'test-host',
    };

    const summary = getAgentSummary(result);
    expect(summary).toContain('2 agent(s) detected on test-host');
    expect(summary).toContain('[running] Claude Code (PID 123)');
    expect(summary).toContain('[unknown] my-server');
  });

  it('returns "no agents" summary when empty', () => {
    const result = {
      agents: [],
      timestamp: '2026-03-10T00:00:00.000Z',
      hostname: 'test-host',
    };

    const summary = getAgentSummary(result);
    expect(summary).toBe('No AI agents detected on test-host');
  });

  it('watchAgents calls callback immediately and can be stopped', () => {
    const callback = vi.fn();

    const handle = watchAgents(100_000, callback);

    // Should have been called once immediately
    expect(callback).toHaveBeenCalledTimes(1);
    expect(callback.mock.calls[0][0]).toHaveProperty('agents');
    expect(callback.mock.calls[0][0]).toHaveProperty('hostname');

    handle.stop();

    // Ensure no further calls after stop (interval was long enough not to fire)
    expect(callback).toHaveBeenCalledTimes(1);
  });
});
