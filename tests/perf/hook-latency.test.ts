import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const REPO = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const ENTRY = path.join(REPO, 'dist', 'src', 'hook-main.js');
const PAYLOAD = JSON.stringify({ session_id: 'lat', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'echo ok' } });

function median(times: number[]): number {
  const sorted = [...times].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

describe('hook latency budget', () => {
  // This is a coarse REGRESSION tripwire for import-graph bloat in the hook
  // hot path (e.g. an accidental tree-sitter import), NOT the user-facing
  // latency budget — that's verified fast on real hardware separately.
  //
  // We measure the hook's own systematic overhead: median hook-spawn minus
  // median bare-node-spawn. Two deliberate robustness choices, because a
  // wall-clock gate on shared CI runners is inherently noisy:
  //  - MEDIAN, not p95: cancels transient GC/scheduling spikes and reflects
  //    the reproducible module-load cost, which is the real regression signal.
  //  - a generous 150ms ceiling: cold-disk module load on GH runners is
  //    ~60-90ms (vs ~15ms local), so the budget sits well clear of runner
  //    variance while a genuine regression (loading a heavy dependency graph)
  //    adds 300ms-2s and still trips it every time.
  it('hook overhead over bare node startup (median) < 150ms', () => {
    if (!fs.existsSync(ENTRY)) execFileSync('npx', ['tsup'], { cwd: REPO, stdio: 'ignore' });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-lat-'));
    const env = { ...process.env, G0_STATE_DIR: tmp };

    // Baseline: bare node process startup (no g0 imports, no stdin work).
    const bare: number[] = [];
    for (let i = 0; i < 15; i++) {
      const t0 = performance.now();
      execFileSync(process.execPath, ['-e', '0']);
      bare.push(performance.now() - t0);
    }

    // The real hook entry, reading a tool-call payload on stdin.
    const hook: number[] = [];
    for (let i = 0; i < 25; i++) {
      const t0 = performance.now();
      execFileSync(process.execPath, [ENTRY, 'pretooluse'], { input: PAYLOAD, env });
      hook.push(performance.now() - t0);
    }

    fs.rmSync(tmp, { recursive: true, force: true });
    // Drop the first 3 of each as warmups (cold module cache, JIT).
    const overhead = median(hook.slice(3)) - median(bare.slice(3));
    expect(overhead).toBeLessThan(150);
  }, 240_000);
});
