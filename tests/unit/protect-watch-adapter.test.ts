import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { watchAdapter } from '../../src/protect/adapters/watch.js';
import type { ProtectContext } from '../../src/protect/types.js';

describe('watch protect adapter', () => {
  let tmp: string; let ctx: ProtectContext; let execCalls: Array<{ cmd: string; args: string[] }>;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-watch-adapter-'));
    execCalls = [];
    ctx = { watchUnitDir: tmp, g0Bin: '/usr/local/bin/g0', serviceExec: (cmd, args) => execCalls.push({ cmd, args }) };
  });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it.skipIf(process.platform === 'win32')('plan -> apply writes a marked unit and registers; undo removes', async () => {
    const plan = await watchAdapter.plan(ctx);
    expect(plan.steps.some((s) => s.id === 'watch:register')).toBe(true);

    const applied = await watchAdapter.apply(ctx);
    expect(applied.errors).toEqual([]);
    expect(applied.applied).toEqual(['watch:register']);
    const unitPath = applied.undo.watchUnitPath!;
    const content = fs.readFileSync(unitPath, 'utf8');
    expect(content).toContain('generated-by: g0 protect');
    expect(content).toContain('/usr/local/bin/g0');
    expect(execCalls.length).toBe(1);

    const again = await watchAdapter.apply(ctx);
    expect(again.applied).toEqual([]); // idempotent

    const undone = await watchAdapter.undo(ctx, applied.undo);
    expect(undone.restored.length).toBe(1);
    expect(fs.existsSync(unitPath)).toBe(false);
  });

  it.skipIf(process.platform === 'win32')('undo refuses a foreign unit file without force', async () => {
    const applied = await watchAdapter.apply(ctx);
    fs.writeFileSync(applied.undo.watchUnitPath!, 'someone elses unit\n');
    const refused = await watchAdapter.undo(ctx, applied.undo);
    expect(refused.restored).toEqual([]);
    expect(refused.skipped.length).toBeGreaterThan(0);
    const forced = await watchAdapter.undo(ctx, applied.undo, { force: true });
    expect(forced.restored.length).toBe(1);
  });
});
