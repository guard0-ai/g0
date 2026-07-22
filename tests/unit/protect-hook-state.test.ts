import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadSessionState } from '../../src/protect/hooks/state.js';
import { hookStateDir } from '../../src/protect/hooks/paths.js';

describe('hook session state', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-hookstate-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('persists provenance across loads', () => {
    const opts = { configDir: path.join(tmp, 'hook'), stateDir: path.join(tmp, 'hook-state') };
    const s1 = loadSessionState('sess-1', opts);
    s1.engineState.provenance.tagResponse('vault', 'claude-code',
      [{ category: 'secret', name: 'k', severity: 'high', match: 'AKIAIOSFODNN7EXAMPLE' }]);
    s1.save();
    const s2 = loadSessionState('sess-1', opts);
    expect(s2.engineState.provenance.taintedCount).toBeGreaterThan(0);
  });

  it('fresh state on corrupt file, sanitized session ids, prunes >24h files', () => {
    const opts = { configDir: path.join(tmp, 'hook'), stateDir: path.join(tmp, 'hook-state') };
    fs.mkdirSync(opts.stateDir, { recursive: true });
    fs.writeFileSync(path.join(opts.stateDir, 'bad.json'), '{nope');
    expect(() => loadSessionState('bad', opts)).not.toThrow();

    const evil = loadSessionState('../../etc/passwd', opts);
    evil.save();
    expect(fs.readdirSync(opts.stateDir).every((n) => !n.includes('/') && !n.startsWith('..'))).toBe(true);

    const old = path.join(opts.stateDir, 'ancient.json');
    fs.writeFileSync(old, '{}');
    const past = Date.now() - 25 * 3600 * 1000;
    fs.utimesSync(old, past / 1000, past / 1000);
    loadSessionState('sess-2', opts);
    expect(fs.existsSync(old)).toBe(false);
  });

  it('hookStateDir honors G0_STATE_DIR', () => {
    process.env.G0_STATE_DIR = tmp;
    try { expect(hookStateDir()).toBe(path.join(tmp, 'hook-state')); }
    finally { delete process.env.G0_STATE_DIR; }
  });
});
