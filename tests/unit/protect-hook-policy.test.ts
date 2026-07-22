import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ensureDefaultHookPolicy, loadHookPolicy } from '../../src/protect/hooks/policy.js';

describe('default hook policy', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-hookpol-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('writes coach-first defaults once, never clobbers', () => {
    const p = ensureDefaultHookPolicy(tmp);
    expect(fs.readFileSync(p, 'utf8')).toContain('mode: alert');
    fs.writeFileSync(p, 'version: 1\nmode: enforce\n');
    ensureDefaultHookPolicy(tmp);
    expect(fs.readFileSync(p, 'utf8')).toContain('mode: enforce'); // untouched
  });

  it('loadHookPolicy parses the default to alert mode / fail-open', () => {
    ensureDefaultHookPolicy(tmp);
    const policy = loadHookPolicy(tmp);
    expect(policy.mode).toBe('alert');
    expect(policy.onError).toBe('open');
  });
});
