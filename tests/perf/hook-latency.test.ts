import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const REPO = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const ENTRY = path.join(REPO, 'dist', 'src', 'hook-main.js');
const PAYLOAD = JSON.stringify({ session_id: 'lat', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'echo ok' } });

function p95(times: number[]): number {
  const sorted = [...times].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length * 0.95) - 1];
}

describe('hook latency budget', () => {
  // The gate's real purpose is catching import-graph bloat in the hook hot
  // path (e.g. an accidental tree-sitter import), NOT node's own cold-start —
  // which is hardware-dependent and 40–90ms slower on shared CI runners than
  // on a dev laptop. So we measure the hook's OWN overhead: hook-spawn p95
  // MINUS bare-node-spawn p95. That delta cancels runner speed and stays
  // small (~15ms local, ~40ms CI); a real regression (loading a heavy module
  // graph) would add hundreds of ms and blow the 80ms budget every time.
  // retry:2 absorbs a transient scheduling spike in either measurement.
  it('hook overhead over bare node startup p95 < 80ms', { retry: 2 }, () => {
    if (!fs.existsSync(ENTRY)) execFileSync('npx', ['tsup'], { cwd: REPO, stdio: 'ignore' });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-lat-'));
    const env = { ...process.env, G0_STATE_DIR: tmp };

    // Baseline: bare node process startup (no g0 imports, no stdin work).
    const bare: number[] = [];
    for (let i = 0; i < 12; i++) {
      const t0 = performance.now();
      execFileSync(process.execPath, ['-e', '0']);
      bare.push(performance.now() - t0);
    }

    // The real hook entry, reading a tool-call payload on stdin.
    const hook: number[] = [];
    for (let i = 0; i < 22; i++) {
      const t0 = performance.now();
      execFileSync(process.execPath, [ENTRY, 'pretooluse'], { input: PAYLOAD, env });
      hook.push(performance.now() - t0);
    }

    fs.rmSync(tmp, { recursive: true, force: true });
    const overhead = p95(hook.slice(2)) - p95(bare.slice(2));
    expect(overhead).toBeLessThan(80);
  }, 240_000);
});
