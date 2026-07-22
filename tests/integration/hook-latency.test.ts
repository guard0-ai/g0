import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

const REPO = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const ENTRY = path.join(REPO, 'dist', 'src', 'hook-main.js');
const PAYLOAD = JSON.stringify({ session_id: 'lat', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'echo ok' } });

describe('hook latency budget', () => {
  it('p95 < 100ms for the built g0-hook entry', () => {
    if (!fs.existsSync(ENTRY)) execFileSync('npx', ['tsup'], { cwd: REPO, stdio: 'ignore' });
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-lat-'));
    const env = { ...process.env, G0_STATE_DIR: tmp };
    const times: number[] = [];
    for (let i = 0; i < 22; i++) {
      const t0 = performance.now();
      execFileSync(process.execPath, [ENTRY, 'pretooluse'], { input: PAYLOAD, env });
      times.push(performance.now() - t0);
    }
    const sorted = times.slice(2).sort((a, b) => a - b); // drop 2 warmups
    const p95 = sorted[Math.floor(sorted.length * 0.95) - 1];
    fs.rmSync(tmp, { recursive: true, force: true });
    expect(p95).toBeLessThan(100);
  }, 240_000);
});
