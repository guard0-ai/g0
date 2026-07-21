import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { buildProtectCommand } from '../../src/cli/commands/protect.js';

describe('g0 protect command', () => {
  let tmpDir: string;
  let logs: string[];

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-protect-cmd-'));
    process.env.G0_STATE_DIR = tmpDir;
    logs = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    delete process.env.G0_STATE_DIR;
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    process.exitCode = 0;
  });

  it('default action is a dry-run that emits a plan and writes nothing', async () => {
    await buildProtectCommand().parseAsync(['node', 'g0', '--json'], { from: 'node' });
    const out = JSON.parse(logs.join('\n'));
    expect(out.mode).toBe('plan');
    expect(Array.isArray(out.plans)).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'protect', 'manifests'))).toBe(false);
  });

  it('rejects an unknown surface with exit code 1', async () => {
    await buildProtectCommand().parseAsync(['node', 'g0', '--surfaces', 'nope', '--json'], { from: 'node' });
    expect(process.exitCode).toBe(1);
  });

  it('status subcommand reports surfaces', async () => {
    await buildProtectCommand().parseAsync(['node', 'g0', 'status', '--json'], { from: 'node' });
    const out = JSON.parse(logs.join('\n'));
    expect(out.statuses[0].surface).toBe('mcp');
  });
});
