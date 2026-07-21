import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mcpAdapter } from '../../src/protect/adapters/mcp.js';
import type { ProtectContext } from '../../src/protect/types.js';

describe('mcp protect adapter', () => {
  let tmpDir: string;
  let ctx: ProtectContext;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-mcp-adapter-'));
    const configPath = path.join(tmpDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: { demo: { command: 'node', args: ['server.mjs'] } },
    }, null, 2));
    ctx = {
      clientPaths: [{ name: 'test-client', configPath, mcpKey: 'mcpServers' }],
      proxyDir: path.join(tmpDir, 'proxy-state'),
      quarantineDir: path.join(tmpDir, 'quarantine'),
      g0Bin: '/usr/local/bin/g0',
    };
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('plan() lists the wrap without touching the config', async () => {
    const before = fs.readFileSync(ctx.clientPaths![0].configPath, 'utf8');
    const plan = await mcpAdapter.plan(ctx);
    expect(plan.surface).toBe('mcp');
    expect(plan.steps.some((s) => s.id === 'wrap:test-client/demo')).toBe(true);
    expect(fs.readFileSync(ctx.clientPaths![0].configPath, 'utf8')).toBe(before);
  });

  it('apply() wraps, undo() restores byte-identically', async () => {
    const configPath = ctx.clientPaths![0].configPath;
    const before = fs.readFileSync(configPath, 'utf8');

    const applied = await mcpAdapter.apply(ctx);
    expect(applied.applied).toContain('wrap:test-client/demo');
    expect(applied.errors).toEqual([]);
    const wrapped = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(JSON.stringify(wrapped.mcpServers.demo)).toContain('proxy');

    const status = await mcpAdapter.status(ctx);
    expect(status.protected).toBe(true);

    const undone = await mcpAdapter.undo(ctx, applied.undo);
    expect(undone.errors).toEqual([]);
    // The installer's restore contract is parsed-JSON equivalence, not byte
    // equality (it reserializes configs) — mirror proxy-installer.test.ts.
    expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual(JSON.parse(before));
  });

  it('is a no-op plan on an empty estate', async () => {
    const plan = await mcpAdapter.plan({ ...ctx, clientPaths: [] });
    expect(plan.steps).toEqual([]);
  });
});
