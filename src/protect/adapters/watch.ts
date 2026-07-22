/**
 * The `watch` protect surface — registers the g0 daemon as a per-user
 * autostart (launchd agent on macOS, systemd user unit on Linux) so
 * coverage stays continuous after the terminal closes. Windows is skipped
 * with a reason in this phase (schtasks registration deferred).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { loadDaemonConfig } from '../../daemon/config.js';
import { readPid } from '../../daemon/process.js';
import type {
  Advisory, PlanStep, ProtectAdapter, ProtectContext,
  SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult, UndoHandle,
} from '../types.js';

const UNIT_MARKER = 'generated-by: g0 protect';

function unitPathFor(ctx: ProtectContext, platform: NodeJS.Platform): { unitPath: string | null; kind: 'launchd' | 'systemd' | null } {
  const home = os.homedir();
  if (platform === 'darwin') {
    const dir = ctx.watchUnitDir ?? path.join(home, 'Library', 'LaunchAgents');
    return { unitPath: path.join(dir, 'ai.guard0.g0-watch.plist'), kind: 'launchd' };
  }
  if (platform === 'linux') {
    const dir = ctx.watchUnitDir ?? path.join(home, '.config', 'systemd', 'user');
    return { unitPath: path.join(dir, 'g0-watch.service'), kind: 'systemd' };
  }
  return { unitPath: null, kind: null };
}

function unitContent(kind: 'launchd' | 'systemd', g0Bin: string): string {
  if (kind === 'launchd') {
    return `<?xml version="1.0" encoding="UTF-8"?>
<!-- ${UNIT_MARKER} -->
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>ai.guard0.g0-watch</string>
  <key>ProgramArguments</key><array>
    <string>${g0Bin}</string><string>daemon</string><string>start</string><string>--no-banner</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
`;
  }
  return `# ${UNIT_MARKER}
[Unit]
Description=g0 resident watcher

[Service]
ExecStart=${g0Bin} daemon start --no-banner
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
`;
}

function serviceExecFor(ctx: ProtectContext): (cmd: string, args: string[]) => void {
  return ctx.serviceExec ?? ((cmd, args) => { execFile(cmd, args, () => { /* best effort */ }); });
}

export const watchAdapter: ProtectAdapter = {
  surface: 'watch',

  async plan(ctx: ProtectContext): Promise<SurfacePlan> {
    const { unitPath } = unitPathFor(ctx, process.platform);
    const steps: PlanStep[] = [];
    const advisories: Advisory[] = [];
    if (unitPath === null) {
      advisories.push({ id: 'watch:unsupported', severity: 'low', description: 'autostart registration not yet supported on this platform — run `g0 daemon start` manually' });
    } else if (!fs.existsSync(unitPath)) {
      steps.push({ id: 'watch:register', description: 'Register the g0 watcher as a per-user autostart (continuous re-checks + notifications)', files: [unitPath] });
    }
    try {
      if (!loadDaemonConfig().enforce) {
        advisories.push({ id: 'watch:observe-mode', severity: 'low', description: 'watcher will notify, not quarantine — set "enforce": true in the daemon config to auto-quarantine known-malicious findings' });
      }
    } catch { /* config unreadable — defaults apply */ }
    return { surface: 'watch', steps, advisories };
  },

  async apply(ctx: ProtectContext): Promise<SurfaceApplyResult> {
    const applied: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];
    const { unitPath, kind } = unitPathFor(ctx, process.platform);
    if (unitPath === null || kind === null) {
      skipped.push({ id: 'watch:register', reason: 'platform not supported for autostart yet' });
      return { surface: 'watch', applied, skipped, errors, undo: { watchUnitPath: null } };
    }
    try {
      if (fs.existsSync(unitPath)) {
        skipped.push({ id: 'watch:register', reason: 'already registered' });
        return { surface: 'watch', applied, skipped, errors, undo: { watchUnitPath: unitPath } };
      }
      fs.mkdirSync(path.dirname(unitPath), { recursive: true });
      fs.writeFileSync(unitPath, unitContent(kind, ctx.g0Bin ?? 'g0'), { mode: 0o644 });
      const run = serviceExecFor(ctx);
      if (kind === 'launchd') run('launchctl', ['bootstrap', `gui/${process.getuid?.() ?? 501}`, unitPath]);
      else run('systemctl', ['--user', 'enable', '--now', 'g0-watch.service']);
      applied.push('watch:register');
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
    return { surface: 'watch', applied, skipped, errors, undo: { watchUnitPath: unitPath } };
  },

  async status(ctx: ProtectContext): Promise<SurfaceStatus> {
    const { unitPath } = unitPathFor(ctx, process.platform);
    const registered = unitPath !== null && fs.existsSync(unitPath);
    let running = false;
    try {
      const pid = readPid(loadDaemonConfig().pidFile);
      running = pid !== null && pid > 0;
    } catch { /* not running */ }
    return {
      surface: 'watch',
      protected: registered && running,
      summary: registered
        ? running ? 'watcher registered and running' : 'watcher registered (daemon not currently running)'
        : 'not protected — watcher autostart not registered',
      detail: [unitPath ? `unit: ${unitPath}${registered ? '' : ' (absent)'}` : 'platform unsupported for autostart'],
    };
  },

  async undo(ctx: ProtectContext, handle: UndoHandle, opts?: { force?: boolean }): Promise<SurfaceUndoResult> {
    const restored: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];
    const unitPath = handle.watchUnitPath ?? unitPathFor(ctx, process.platform).unitPath;
    if (!unitPath || !fs.existsSync(unitPath)) {
      skipped.push({ reason: 'no watcher registration to remove' });
      return { surface: 'watch', restored, skipped, errors };
    }
    try {
      const content = fs.readFileSync(unitPath, 'utf8');
      if (!content.includes(UNIT_MARKER) && !opts?.force) {
        skipped.push({ reason: `unit file was not written by g0 protect — use --force to remove: ${unitPath}` });
        return { surface: 'watch', restored, skipped, errors };
      }
      const run = serviceExecFor(ctx);
      if (unitPath.endsWith('.plist')) run('launchctl', ['bootout', `gui/${process.getuid?.() ?? 501}`, unitPath]);
      else run('systemctl', ['--user', 'disable', '--now', 'g0-watch.service']);
      fs.rmSync(unitPath, { force: true });
      restored.push(`deregister:${unitPath}`);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
    return { surface: 'watch', restored, skipped, errors };
  },
};
