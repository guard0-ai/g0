import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// `writeFileSync`/`renameSync` are wrapped in `vi.fn(actual.fn)` — every
// call forwards to the real implementation by default, so every other test
// in this file (which relies on real fs behavior) is unaffected. Only the
// dedicated failure-injection tests below override the implementation for
// the duration of that one test, then reset it in `afterEach`.
vi.mock('node:fs', async () => {
  const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
  return {
    ...actual,
    writeFileSync: vi.fn(actual.writeFileSync),
    renameSync: vi.fn(actual.renameSync),
  };
});

const realFs = await vi.importActual<typeof import('node:fs')>('node:fs');

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
  // Reset the mocked writeFileSync/renameSync back to real passthrough
  // behavior, regardless of what an individual test overrode them to —
  // otherwise a failure-injection test would bleed into the next one.
  vi.mocked(fs.writeFileSync).mockImplementation(realFs.writeFileSync);
  vi.mocked(fs.renameSync).mockImplementation(realFs.renameSync);
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

// ─────────────────────────────────────────────────────────────────────────
// writeConfigSafely atomicity — a write/rename failure must never leave the
// live config partially written. Regression tests for the critical
// config-corruption bug: the old `writeConfigSafely` wrote directly to the
// live config path and, when that write threw (ENOSPC, crash mid-write,
// EACCES after truncation), returned `{ok:false}` WITHOUT restoring from
// the backup it had just taken — leaving the live file truncated/invalid.
// ─────────────────────────────────────────────────────────────────────────

describe('writeConfigSafely atomicity (write/rename failure injection)', () => {
  it(
    'a write failure mid-way through the atomic write leaves the live config byte-for-byte ' +
      'unchanged and still valid JSON (fails against the old direct-write code, which left a ' +
      'truncated/invalid file behind)',
    async () => {
      const original = { mcpServers: { 'server-x': { command: 'npx', args: ['-y', 'server-x-pkg'] } } };
      const configPath = writeConfig('claude.json', original);
      const originalContent = fs.readFileSync(configPath, 'utf-8');
      const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

      // Fail whenever writeFileSync targets *this config's* live path or its
      // atomic-write temp file — covering both the old code (which wrote
      // configPath directly) and the new code (which writes a `.g0-tmp.`
      // sibling before renaming it into place). Simulate a realistic
      // interrupted write (ENOSPC mid-write) by actually writing a short,
      // truncated prefix of the intended content to whatever path was
      // targeted before throwing — exactly what a real crash mid-`write()`
      // looks like on disk.
      vi.mocked(fs.writeFileSync).mockImplementation(((p: fs.PathOrFileDescriptor, data: unknown, opts?: unknown) => {
        const isTarget = typeof p === 'string' && (p === configPath || p.startsWith(`${configPath}.g0-tmp.`));
        if (isTarget) {
          realFs.writeFileSync(p as string, String(data).slice(0, 12));
          throw new Error('ENOSPC: no space left on device, write');
        }
        return (realFs.writeFileSync as (...a: unknown[]) => void)(p, data, opts);
      }) as typeof fs.writeFileSync);

      const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

      expect(result.wrapped).toEqual([]); // the write never stuck -> not reported as wrapped
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0].message).toMatch(/backup/i);

      // The live config must be byte-for-byte unchanged and still valid
      // JSON — never truncated/partial — even though the write attempt
      // failed partway through.
      expect(fs.readFileSync(configPath, 'utf-8')).toBe(originalContent);
      expect(() => JSON.parse(fs.readFileSync(configPath, 'utf-8'))).not.toThrow();
      expect(readConfig(configPath)).toEqual(original);

      // Nothing was recorded in the manifest for a write that didn't stick.
      expect(listInstalls(manifestDir)).toEqual([]);

      // No stray `.g0-tmp.*` file left behind either.
      const leftovers = fs.readdirSync(tmpDir).filter((f) => f.includes('.g0-tmp.'));
      expect(leftovers).toEqual([]);
    },
  );

  it('a renameSync failure after the temp file is fully written also leaves the live config unchanged', async () => {
    const original = { mcpServers: { 'server-y': { command: 'npx', args: ['-y', 'server-y-pkg'] } } };
    const configPath = writeConfig('claude2.json', original);
    const originalContent = fs.readFileSync(configPath, 'utf-8');
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    vi.mocked(fs.renameSync).mockImplementation(((from: fs.PathLike, to: fs.PathLike) => {
      if (typeof from === 'string' && from.startsWith(`${configPath}.g0-tmp.`)) {
        throw new Error('EXDEV: cross-device link not permitted, rename');
      }
      return (realFs.renameSync as (...a: unknown[]) => void)(from, to);
    }) as typeof fs.renameSync);

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.wrapped).toEqual([]);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].message).toMatch(/backup/i);

    expect(fs.readFileSync(configPath, 'utf-8')).toBe(originalContent);
    expect(readConfig(configPath)).toEqual(original);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Non-string args — a config with a non-string element in a server's args
// array must not be silently mangled (neither in the rewritten config nor
// in the install manifest that uninstall relies on to restore it exactly).
// ─────────────────────────────────────────────────────────────────────────

describe('installProxy non-string args safety', () => {
  it('treats a server with a non-string arg as unproxyable instead of silently dropping the element', async () => {
    const original = { mcpServers: { 'server-x': { command: 'npx', args: ['-y', 42, 'server-x-pkg'] } } };
    const configPath = writeConfig('claude.json', original);
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.wrapped).toEqual([]);
    expect(result.unproxyable).toEqual(['Claude Desktop:server-x']);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].message).toMatch(/not a string/i);

    // Untouched — the original args (including the non-string element) are
    // exactly as they were; nothing was silently dropped from the config.
    expect(readConfig(configPath)).toEqual(original);
    expect(listInstalls(manifestDir)).toEqual([]);
  });

  it('still wraps a sibling server in the same config whose args are all strings', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: {
        'bad-server': { command: 'npx', args: ['-y', 42] },
        'good-server': { command: 'npx', args: ['-y', 'good-pkg'] },
      },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN });

    expect(result.unproxyable).toEqual(['Claude Desktop:bad-server']);
    expect(result.wrapped).toHaveLength(1);
    expect(result.wrapped[0].serverName).toBe('good-server');

    const config = readConfig(configPath);
    expect(config.mcpServers['bad-server']).toEqual({ command: 'npx', args: ['-y', 42] });
    expect(config.mcpServers['good-server'].command).toBe(G0_BIN);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Lock scope — the whole read -> wrap-decision -> write cycle for a config
// must be atomic under the lock, not just the final write, so a concurrent
// install racing on the same config can't produce a lost update.
// ─────────────────────────────────────────────────────────────────────────

describe('installProxy lock scope (read-modify-write atomicity)', () => {
  it('two concurrent installProxy calls on the same config do not lose either update', async () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: {
        'server-a': { command: 'npx', args: ['-y', 'a'] },
        'server-b': { command: 'npx', args: ['-y', 'b'] },
      },
    });
    const clientPaths: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    // Both calls target the same client config; each is scoped to wrap a
    // different server. With the lock covering only the final write (the
    // old bug), both calls can read the same pre-write snapshot before
    // either writes back, so whichever writes second clobbers the other's
    // change. With the lock covering the whole read -> write cycle, the
    // second call is forced to wait, re-read, and see the first call's
    // change before computing and writing its own.
    const [r1, r2] = await Promise.all([
      installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN, servers: ['server-a'] }),
      installProxy({ clientPaths, dir: manifestDir, g0Bin: G0_BIN, servers: ['server-b'] }),
    ]);

    expect(r1.errors).toEqual([]);
    expect(r2.errors).toEqual([]);

    const config = readConfig(configPath);
    expect(config.mcpServers['server-a'].command).toBe(G0_BIN);
    expect(config.mcpServers['server-b'].command).toBe(G0_BIN);
  });
});
