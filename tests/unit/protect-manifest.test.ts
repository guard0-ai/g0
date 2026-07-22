import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { protectStateDir, writeManifest, readLatestManifest } from '../../src/protect/manifest.js';

describe('protect manifest', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-protect-')); });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.G0_STATE_DIR;
  });

  it('honors override, then G0_STATE_DIR, then ~/.g0', () => {
    expect(protectStateDir('/x')).toBe('/x');
    process.env.G0_STATE_DIR = tmpDir;
    expect(protectStateDir()).toBe(path.join(tmpDir, 'protect'));
    delete process.env.G0_STATE_DIR;
    expect(protectStateDir()).toBe(path.join(os.homedir(), '.g0', 'protect'));
  });

  it('round-trips and returns the newest manifest', () => {
    expect(readLatestManifest(tmpDir)).toBeNull();
    writeManifest({ id: '2026-07-21T00-00-00-000Z', timestamp: '2026-07-21T00:00:00.000Z', surfaces: {} }, tmpDir);
    const p2 = writeManifest(
      { id: '2026-07-21T00-00-01-000Z', timestamp: '2026-07-21T00:00:01.000Z', surfaces: { mcp: { quarantineManifestPath: '/q/m.json' } } },
      tmpDir,
    );
    const latest = readLatestManifest(tmpDir);
    expect(latest?.path).toBe(p2);
    expect(latest?.manifest.surfaces.mcp?.quarantineManifestPath).toBe('/q/m.json');
  });
});
