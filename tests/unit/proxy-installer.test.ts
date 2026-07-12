import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { installProxy, uninstallProxy, listInstalls } from '../../src/proxy/installer.js';
import type { MCPClient } from '../../src/types/mcp-scan.js';

let tmpDir: string;
let manifestDir: string;

const G0_BIN = 'g0-test-bin';

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-installer-'));
  manifestDir = path.join(tmpDir, '.g0-proxy-dir');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeConfig(name: string, content: unknown): string {
  const p = path.join(tmpDir, name);
  fs.writeFileSync(p, JSON.stringify(content, null, 2));
  return p;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function readConfig(p: string): any {
  return JSON.parse(fs.readFileSync(p, 'utf-8'));
}

// ─────────────────────────────────────────────────────────────────────────
// installProxy
// ─────────────────────────────────────────────────────────────────────────

describe('installProxy', () => {
  it('rewrites an npx entry to the g0 proxy -- form, preserving env', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: {
        'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'], env: { API_KEY: 'secret' } },
      },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.wrapped).toHaveLength(1);
    expect(result.errors).toEqual([]);
    expect(result.unproxyable).toEqual([]);

    const config = readConfig(configPath);
    expect(config.mcpServers['server-x']).toEqual({
      command: G0_BIN,
      args: ['proxy', '--server', 'server-x', '--', 'npx', '-y', 'server-x-pkg'],
      env: { API_KEY: 'secret' },
    });
  });

  it('wraps entries the same way across mcpServers/servers/context_servers mcpKey shapes', async () => {
    const vscodePath = writeConfig('vscode-settings.json', {
      servers: { 'my-server': { command: 'node', args: ['server.js'] } },
    });
    const zedPath = writeConfig('zed-settings.json', {
      context_servers: { 'zed-server': { command: 'python3', args: ['-m', 'server'] } },
    });
    const clientPaths: MCPClient[] = [
      { name: 'VS Code', configPath: vscodePath, mcpKey: 'servers' },
      { name: 'Zed', configPath: zedPath, mcpKey: 'context_servers' },
    ];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(result.wrapped).toHaveLength(2);

    expect(readConfig(vscodePath).servers['my-server'].command).toBe(G0_BIN);
    expect(readConfig(vscodePath).servers['my-server'].args).toEqual([
      'proxy',
      '--server',
      'my-server',
      '--',
      'node',
      'server.js',
    ]);
    expect(readConfig(zedPath).context_servers['zed-server'].command).toBe(G0_BIN);
  });

  it('is idempotent: installing twice does not double-wrap', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const first = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(first.wrapped).toHaveLength(1);

    const second = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(second.wrapped).toHaveLength(0);
    expect(second.skippedAlreadyWrapped).toEqual(['Claude Desktop:server-x']);

    // Manifest wasn't appended to a second time.
    expect(listInstalls(manifestDir)).toHaveLength(1);

    // Config still wrapped exactly once (not double-wrapped).
    const config = readConfig(configPath);
    expect(config.mcpServers['server-x'].args).toEqual([
      'proxy',
      '--server',
      'server-x',
      '--',
      'npx',
      '-y',
      'server-x-pkg',
    ]);
  });

  it('writes a .backup.<ts> file before modifying the config', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(result.backups).toHaveLength(1);
    expect(fs.existsSync(result.backups[0])).toBe(true);
    expect(path.basename(result.backups[0])).toMatch(/^claude\.json\.backup\.\d+$/);

    const backupContent = readConfig(result.backups[0]);
    expect(backupContent.mcpServers['server-x'].command).toBe('npx'); // pre-wrap snapshot
  });

  it('writes the install manifest (0600) at <dir>/installs.json, readable via listInstalls', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    const installs = listInstalls(manifestDir);
    expect(installs).toHaveLength(1);
    expect(installs[0]).toMatchObject({
      client: 'Claude Desktop',
      configPath,
      mcpKey: 'mcpServers',
      serverName: 'server-x',
      original: { command: 'npx', args: ['-y', 'server-x-pkg'] },
    });

    const manifestFile = path.join(manifestDir, 'installs.json');
    const stat = fs.statSync(manifestFile);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  it('reports a remote/url-only (non-command) entry as unproxyable and leaves it untouched', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: {
        'remote-server': { url: 'https://example.com/mcp', type: 'sse' },
      },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(result.wrapped).toEqual([]);
    expect(result.unproxyable).toEqual(['Claude Desktop:remote-server']);

    const config = readConfig(configPath);
    expect(config.mcpServers['remote-server']).toEqual({ url: 'https://example.com/mcp', type: 'sse' });
    expect(listInstalls(manifestDir)).toEqual([]);
  });

  it('--dry-run computes the result without writing the config or the manifest', async () => {
    const original = { mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } } };
    const configPath = writeConfig('claude.json', original);
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN, dryRun: true });
    expect(result.wrapped).toHaveLength(1);
    expect(result.dryRun).toBe(true);
    expect(result.backups).toEqual([]);

    expect(readConfig(configPath)).toEqual(original);
    expect(fs.existsSync(path.join(manifestDir, 'installs.json'))).toBe(false);
    expect(listInstalls(manifestDir)).toEqual([]);
  });

  it('skips a malformed (invalid JSON) config with an error in the result, not a throw', async () => {
    const configPath = path.join(tmpDir, 'broken.json');
    fs.writeFileSync(configPath, '{ this is not valid json');
    const clientPaths: MCPClient[] = [{ name: 'Broken Client', configPath, mcpKey: 'mcpServers' }];

    // Calling installProxy at all (rather than wrapping in try/catch) is the
    // assertion that it doesn't throw — an uncaught throw here fails the test.
    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.wrapped).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].client).toBe('Broken Client');
    expect(result.errors[0].message).toMatch(/invalid JSON/i);

    // Untouched — still the original broken content.
    expect(fs.readFileSync(configPath, 'utf-8')).toBe('{ this is not valid json');
  });

  it('skips gracefully when the config root or mcpKey is not an object (no throw, no error needed)', async () => {
    const configPath = writeConfig('weird.json', { mcpServers: 'not-an-object' });
    const clientPaths: MCPClient[] = [{ name: 'Weird Client', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.wrapped).toEqual([]);
  });

  it('filters by clients and servers options', async () => {
    const configA = writeConfig('a.json', {
      mcpServers: {
        'srv-1': { command: 'npx', args: ['-y', 'one'] },
        'srv-2': { command: 'npx', args: ['-y', 'two'] },
      },
    });
    const configB = writeConfig('b.json', {
      mcpServers: { 'srv-3': { command: 'npx', args: ['-y', 'three'] } },
    });
    const clientPaths: MCPClient[] = [
      { name: 'Client A', configPath: configA, mcpKey: 'mcpServers' },
      { name: 'Client B', configPath: configB, mcpKey: 'mcpServers' },
    ];

    const result = await installProxy({
      clientPaths,
      dir: manifestDir,
      g0Bin: G0_BIN,
      clients: ['Client A'],
      servers: ['srv-1'],
    });

    expect(result.wrapped).toHaveLength(1);
    expect(result.wrapped[0].serverName).toBe('srv-1');
    expect(readConfig(configA).mcpServers['srv-2'].command).toBe('npx'); // untouched (server filtered out)
    expect(readConfig(configB).mcpServers['srv-3'].command).toBe('npx'); // untouched (client filtered out)
  });
});

// ─────────────────────────────────────────────────────────────────────────
// uninstallProxy
// ─────────────────────────────────────────────────────────────────────────

describe('uninstallProxy', () => {
  it('round-trips install -> uninstall back to the original config (JSON-value-equivalent)', async () => {
    const original = {
      mcpServers: {
        'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'], env: { API_KEY: 'secret' } },
        'server-noargs': { command: 'my-binary' },
      },
    };
    const configPath = writeConfig('claude.json', original);
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(readConfig(configPath)).not.toEqual(original);

    const uninstallResult = await uninstallProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(uninstallResult.restored).toHaveLength(2);
    expect(uninstallResult.errors).toEqual([]);

    expect(readConfig(configPath)).toEqual(original);
    expect(listInstalls(manifestDir)).toEqual([]);
  });

  it('unwraps a manually-wrapped entry that was never recorded in the manifest', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: {
        'server-x': {
          command: G0_BIN,
          args: ['proxy', '--server', 'server-x', '--', 'npx', '-y', 'server-x-pkg'],
        },
      },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    // No prior installProxy call -> nothing in the manifest for this entry.
    expect(listInstalls(manifestDir)).toEqual([]);

    const result = await uninstallProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(result.restored).toHaveLength(1);
    expect(result.errors).toEqual([]);

    const config = readConfig(configPath);
    expect(config.mcpServers['server-x']).toEqual({ command: 'npx', args: ['-y', 'server-x-pkg'] });
  });

  it('is a no-op (no error) when there is nothing wrapped to restore', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await uninstallProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    expect(result.restored).toEqual([]);
    expect(result.errors).toEqual([]);
    expect(readConfig(configPath).mcpServers['server-x'].command).toBe('npx');
  });

  it('backs up the config before restoring it', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });
    const result = await uninstallProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.backups).toHaveLength(1);
    expect(fs.existsSync(result.backups[0])).toBe(true);
  });

  it('skips a malformed config with an error in the result, not a throw', async () => {
    const configPath = path.join(tmpDir, 'broken.json');
    fs.writeFileSync(configPath, 'not json at all');
    const clientPaths: MCPClient[] = [{ name: 'Broken Client', configPath, mcpKey: 'mcpServers' }];

    const result = await uninstallProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.restored).toEqual([]);
    expect(result.errors).toHaveLength(1);
  });
});
