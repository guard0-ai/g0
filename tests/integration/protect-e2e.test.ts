import { execFile } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const G0_BIN = path.join(REPO_ROOT, 'bin', 'g0.ts');

function sha256(p: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

describe('g0 protect e2e round trip (sandboxed HOME)', () => {
  let home: string;
  let configPath: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-protect-home-'));
    configPath = path.join(home, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: { demo: { command: 'node', args: ['server.mjs'] } },
    }, null, 2));
    env = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,                 // win32 parity
      G0_STATE_DIR: path.join(home, '.g0'),
      G0_NO_CTA: '1',
    };
  });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  async function g0(...args: string[]) {
    return execFileAsync('npx', ['tsx', G0_BIN, ...args], { cwd: REPO_ROOT, env });
  }

  it('plan → apply → off leaves the config equivalent to the original', async () => {
    const beforeHash = sha256(configPath);
    const beforeParsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    const plan = await g0('protect', '--json');
    const planOut = JSON.parse(plan.stdout);
    expect(planOut.mode).toBe('plan');
    const mcpPlan = planOut.plans.find((p: { surface: string }) => p.surface === 'mcp');
    expect(mcpPlan.steps.some((s: { id: string }) => s.id === 'wrap:Cursor/demo')).toBe(true);
    expect(sha256(configPath)).toBe(beforeHash); // dry-run wrote nothing

    const apply = await g0('protect', '--apply', '--json');
    const applyOut = JSON.parse(apply.stdout);
    expect(applyOut.mode).toBe('apply');
    const wrapped = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(JSON.stringify(wrapped.mcpServers.demo)).toContain('proxy');
    expect(fs.existsSync(applyOut.manifestPath)).toBe(true);

    const status = await g0('protect', 'status', '--json');
    expect(JSON.parse(status.stdout).statuses[0].protected).toBe(true);

    await g0('protect', 'off', '--json');
    // Restore contract is parsed-JSON equivalence (installer reserializes).
    expect(JSON.parse(fs.readFileSync(configPath, 'utf8'))).toEqual(beforeParsed);
  }, 120_000);
});
