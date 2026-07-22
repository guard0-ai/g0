import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const REPO = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const G0 = path.join(REPO, 'bin', 'g0.ts');

describe('g0 hook e2e (sandboxed HOME)', () => {
  let home: string; let env: NodeJS.ProcessEnv;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-hook-home-'));
    env = { ...process.env, HOME: home, USERPROFILE: home, G0_STATE_DIR: path.join(home, '.g0'), G0_NO_CTA: '1' };
  });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  function g0(stdin: string | undefined, ...args: string[]): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      const child = spawn('npx', ['tsx', G0, ...args], { cwd: REPO, env });
      let stdout = ''; let stderr = '';
      child.stdout.on('data', (chunk) => { stdout += chunk; });
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.on('error', reject);
      child.on('close', () => resolve({ stdout, stderr }));
      if (stdin !== undefined) child.stdin.write(stdin);
      child.stdin.end(); // always: `g0 hook` reads stdin to end
    });
  }

  it('protect --apply --surfaces claude installs hooks; g0 hook denies under enforce policy; off restores', async () => {
    await g0(undefined, 'protect', '--apply', '--surfaces', 'claude', '--json');
    const settingsPath = path.join(home, '.claude', 'settings.json');
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    expect(JSON.stringify(settings.hooks.PreToolUse)).toContain('pretooluse');
    expect(JSON.stringify(settings.hooks.PostToolUse)).toContain('posttooluse');
    // coach-first default policy was created
    expect(fs.readFileSync(path.join(home, '.g0', 'hook', 'policy.yaml'), 'utf8')).toContain('mode: alert');

    fs.writeFileSync(path.join(home, '.g0', 'hook', 'policy.yaml'),
      'version: 1\nmode: enforce\nrules:\n  - id: no-rm\n    tools: ["Bash"]\n    argsRegex: "rm\\\\s+-rf"\n    action: deny\n    message: destructive\n');
    const deny = await g0(JSON.stringify({
      session_id: 'e2e', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' },
    }), 'hook', 'pretooluse');
    expect(JSON.parse(deny.stdout).hookSpecificOutput.permissionDecision).toBe('deny');

    const allow = await g0(JSON.stringify({
      session_id: 'e2e', hook_event_name: 'PreToolUse', tool_name: 'Read', tool_input: { file_path: '/tmp/x' },
    }), 'hook', 'pretooluse');
    expect(allow.stdout.trim()).toBe('');

    await g0(undefined, 'protect', 'off', '--surfaces', 'claude', '--json');
    expect(fs.existsSync(settingsPath)).toBe(false);
  }, 180_000);

  it.skipIf(!process.env.G0_DSP_E2E)('deny holds under --dangerously-skip-permissions (CI sandbox only)', () => {
    // #20946 class. Requires a real `claude` binary + API key in an ISOLATED
    // CI sandbox. Never run on a developer machine (spec §12). Skeleton:
    // install hooks into sandbox HOME, run
    //   claude -p "run rm -rf /tmp/x" --dangerously-skip-permissions
    // and assert the target survives and the audit shows the deny.
    expect.fail('implement inside the isolated CI job that sets G0_DSP_E2E');
  });
});
