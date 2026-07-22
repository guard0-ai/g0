/**
 * The `claude` protect surface — installs g0's PreToolUse/PostToolUse hooks
 * into Claude Code's user settings so built-in tools (Bash, Write, Edit,
 * WebFetch) and MCP tools get engine enforcement the MCP proxy can't see.
 *
 * Safety grammar: byte-exact backup of settings.json before any write,
 * merge-never-clobber (every existing user hook entry is preserved), undo
 * refuses over a file edited since apply unless forced.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { protectStateDir } from '../manifest.js';
import { ensureDefaultHookPolicy } from '../hooks/policy.js';
import { hookConfigDir } from '../hooks/paths.js';
import type {
  Advisory, PlanStep, ProtectAdapter, ProtectContext,
  SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult, UndoHandle,
} from '../types.js';

const HOOK_EVENTS = ['PreToolUse', 'PostToolUse'] as const;
type HookEvent = (typeof HOOK_EVENTS)[number];

interface HookEntry { matcher?: string; hooks?: Array<{ type?: string; command?: string }>; }
type Settings = Record<string, unknown> & { hooks?: Record<string, HookEntry[]> };

function settingsPathFor(ctx: ProtectContext): string {
  return ctx.claudeSettingsPath ?? path.join(os.homedir(), '.claude', 'settings.json');
}

function hookCommandFor(ctx: ProtectContext, event: HookEvent): string {
  return `${ctx.hookCommand ?? 'g0-hook'} ${event.toLowerCase()}`;
}

function readSettings(filePath: string): Settings | null {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8')) as Settings;
  } catch {
    return null;
  }
}

function hasOurEntry(settings: Settings | null, ctx: ProtectContext, event: HookEvent): boolean {
  const entries = settings?.hooks?.[event];
  if (!Array.isArray(entries)) return false;
  const command = hookCommandFor(ctx, event);
  return entries.some((entry) => entry?.hooks?.some((h) => h?.command === command));
}

function sha256File(filePath: string): string | null {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
  } catch {
    return null;
  }
}

/** Read hook health from the last N audit records. */
function auditHealth(configDir: string): string[] {
  try {
    const lines = fs.readFileSync(path.join(configDir, 'audit.jsonl'), 'utf8').trim().split('\n').slice(-200);
    const records = lines.map((l) => { try { return JSON.parse(l) as Record<string, unknown>; } catch { return null; } }).filter(Boolean) as Record<string, unknown>[];
    if (records.length === 0) return ['no hook invocations recorded yet'];
    const errors = records.filter((r) => r.action === 'error').length;
    const durations = records.map((r) => r.durationMs).filter((d): d is number => typeof d === 'number').sort((a, b) => a - b);
    const p95 = durations.length > 0 ? durations[Math.max(0, Math.ceil(durations.length * 0.95) - 1)] : undefined;
    const last = records[records.length - 1].ts;
    return [
      `last invocation: ${String(last ?? 'unknown')}`,
      `error rate: ${errors}/${records.length} (last ${records.length} invocations)`,
      p95 !== undefined ? `decision latency p95: ${p95}ms (engine time, excl. process startup)` : 'no latency data',
    ];
  } catch {
    return ['no hook invocations recorded yet'];
  }
}

export const claudeAdapter: ProtectAdapter = {
  surface: 'claude',

  async plan(ctx: ProtectContext): Promise<SurfacePlan> {
    const settingsPath = settingsPathFor(ctx);
    const settings = readSettings(settingsPath);
    const steps: PlanStep[] = [];
    for (const event of HOOK_EVENTS) {
      if (!hasOurEntry(settings, ctx, event)) {
        steps.push({
          id: `hook:${event}`,
          description: `Install g0 ${event} hook into Claude Code (engine enforcement for built-in + MCP tools)`,
          files: [settingsPath],
        });
      }
    }
    const advisories: Advisory[] = [];
    if (!fs.existsSync(path.join(hookConfigDir(ctx.hookConfigDir), 'policy.yaml'))) {
      advisories.push({
        id: 'claude:default-policy',
        severity: 'low',
        description: 'A coach-first hook policy (mode: alert — warns, never blocks) will be created; switch to mode: enforce to block.',
      });
    }
    return { surface: 'claude', steps, advisories };
  },

  async apply(ctx: ProtectContext): Promise<SurfaceApplyResult> {
    const settingsPath = settingsPathFor(ctx);
    const applied: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];
    let settingsBackupPath: string | null = null;

    try {
      // Byte-exact pre-image (null when the file doesn't exist yet).
      if (fs.existsSync(settingsPath)) {
        const backupDir = path.join(protectStateDir(ctx.stateDir), 'backups');
        fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
        settingsBackupPath = path.join(backupDir, `${new Date().toISOString().replace(/[:.]/g, '-')}-claude-settings.json`);
        fs.copyFileSync(settingsPath, settingsBackupPath);
      }

      const settings: Settings = readSettings(settingsPath) ?? {};
      const hooks = (settings.hooks ??= {});
      for (const event of HOOK_EVENTS) {
        if (hasOurEntry(settings, ctx, event)) {
          skipped.push({ id: `hook:${event}`, reason: 'already installed' });
          continue;
        }
        const entries = (hooks[event] ??= []);
        entries.push({ matcher: '*', hooks: [{ type: 'command', command: hookCommandFor(ctx, event) }] });
        applied.push(`hook:${event}`);
      }

      if (applied.length > 0) {
        fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
        fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
      }
      ensureDefaultHookPolicy(ctx.hookConfigDir);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }

    return {
      surface: 'claude', applied, skipped, errors,
      undo: { settingsPath, settingsBackupPath, postApplySha256: sha256File(settingsPath) ?? undefined },
    };
  },

  async status(ctx: ProtectContext): Promise<SurfaceStatus> {
    const settings = readSettings(settingsPathFor(ctx));
    const installed = HOOK_EVENTS.filter((event) => hasOurEntry(settings, ctx, event));
    const isProtected = installed.length === HOOK_EVENTS.length;
    return {
      surface: 'claude',
      protected: isProtected,
      summary: isProtected
        ? 'g0 hooks active on Claude Code tool calls'
        : installed.length > 0
          ? `partially installed (${installed.join(', ')})`
          : 'not protected — g0 hooks not installed in Claude Code',
      detail: auditHealth(hookConfigDir(ctx.hookConfigDir)),
    };
  },

  async undo(ctx: ProtectContext, handle: UndoHandle, opts?: { force?: boolean }): Promise<SurfaceUndoResult> {
    const restored: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];
    const settingsPath = handle.settingsPath ?? settingsPathFor(ctx);

    try {
      if (handle.settingsBackupPath === undefined && handle.postApplySha256 === undefined) {
        skipped.push({ reason: 'no claude apply recorded in this manifest' });
        return { surface: 'claude', restored, skipped, errors };
      }

      // Refuse over drift: the file must still be exactly what apply wrote.
      const currentHash = sha256File(settingsPath);
      if (!opts?.force && handle.postApplySha256 && currentHash !== handle.postApplySha256) {
        skipped.push({
          reason: `settings.json changed since apply — re-run with --force to restore anyway (backup: ${handle.settingsBackupPath ?? 'none (file did not exist)'})`,
        });
        return { surface: 'claude', restored, skipped, errors };
      }

      if (handle.settingsBackupPath) {
        fs.copyFileSync(handle.settingsBackupPath, settingsPath);
        restored.push(`restore:${settingsPath}`);
      } else {
        // No pre-image: the file didn't exist before apply. Strip our
        // entries; if nothing else remains, remove the file entirely.
        const settings = readSettings(settingsPath);
        if (settings?.hooks) {
          for (const event of HOOK_EVENTS) {
            const entries = settings.hooks[event];
            if (!Array.isArray(entries)) continue;
            const command = hookCommandFor(ctx, event);
            settings.hooks[event] = entries.filter((entry) => !entry?.hooks?.some((h) => h?.command === command));
            if (settings.hooks[event].length === 0) delete settings.hooks[event];
          }
          if (Object.keys(settings.hooks).length === 0) delete settings.hooks;
        }
        if (settings && Object.keys(settings).length > 0) {
          fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');
        } else {
          fs.rmSync(settingsPath, { force: true });
        }
        restored.push(`remove:g0-hooks:${settingsPath}`);
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }

    return { surface: 'claude', restored, skipped, errors };
  },
};
