import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { claudeAdapter } from '../../src/protect/adapters/claude.js';
import type { ProtectContext } from '../../src/protect/types.js';

describe('claude protect adapter', () => {
  let tmp: string; let settings: string; let ctx: ProtectContext;
  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-claude-adapter-'));
    settings = path.join(tmp, 'settings.json');
    fs.writeFileSync(settings, JSON.stringify({
      model: 'opus',
      hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'my-own-guard.sh' }] }] },
    }, null, 2));
    ctx = { claudeSettingsPath: settings, hookConfigDir: path.join(tmp, 'hook'), stateDir: path.join(tmp, 'protect'), hookCommand: 'g0-hook' };
  });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('plan lists both hook installs without writing', async () => {
    const before = fs.readFileSync(settings, 'utf8');
    const plan = await claudeAdapter.plan(ctx);
    expect(plan.steps.map((s) => s.id).sort()).toEqual(['hook:PostToolUse', 'hook:PreToolUse']);
    expect(fs.readFileSync(settings, 'utf8')).toBe(before);
  });

  it('apply merges (preserving user hooks), is idempotent; undo restores byte-exact', async () => {
    const before = fs.readFileSync(settings, 'utf8');
    const applied = await claudeAdapter.apply(ctx);
    expect(applied.errors).toEqual([]);
    const merged = JSON.parse(fs.readFileSync(settings, 'utf8'));
    expect(merged.model).toBe('opus');
    expect(JSON.stringify(merged.hooks.PreToolUse)).toContain('my-own-guard.sh');
    expect(JSON.stringify(merged.hooks.PreToolUse)).toContain('g0-hook pretooluse');
    expect(JSON.stringify(merged.hooks.PostToolUse)).toContain('g0-hook posttooluse');
    expect(fs.existsSync(path.join(ctx.hookConfigDir!, 'policy.yaml'))).toBe(true);

    const again = await claudeAdapter.apply(ctx);
    expect(again.applied).toEqual([]); // idempotent -> all skipped

    const status = await claudeAdapter.status(ctx);
    expect(status.protected).toBe(true);

    const undone = await claudeAdapter.undo(ctx, applied.undo);
    expect(undone.errors).toEqual([]);
    expect(fs.readFileSync(settings, 'utf8')).toBe(before);
  });

  it('undo refuses over externally-edited settings without force', async () => {
    const applied = await claudeAdapter.apply(ctx);
    fs.appendFileSync(settings, '\n');
    const refused = await claudeAdapter.undo(ctx, applied.undo);
    expect(refused.skipped.length + refused.errors.length).toBeGreaterThan(0);
    expect(refused.restored).toEqual([]);
    const forced = await claudeAdapter.undo(ctx, applied.undo, { force: true });
    expect(forced.restored.length).toBeGreaterThan(0);
  });

  it('apply with no pre-existing settings file; undo removes it again', async () => {
    const freshCtx = { ...ctx, claudeSettingsPath: path.join(tmp, 'none', 'settings.json') };
    const applied = await claudeAdapter.apply(freshCtx);
    expect(applied.errors).toEqual([]);
    expect(applied.undo.settingsBackupPath).toBeNull();
    expect(fs.existsSync(freshCtx.claudeSettingsPath!)).toBe(true);
    const undone = await claudeAdapter.undo(freshCtx, applied.undo);
    expect(undone.errors).toEqual([]);
    expect(fs.existsSync(freshCtx.claudeSettingsPath!)).toBe(false);
  });
});
