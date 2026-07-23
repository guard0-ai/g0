import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';
import { buildSnapshot, defaultSnapshotPath, writeSnapshotAtomic } from '../../src/sentinel/snapshot.js';

const fakeResult = {
  score: 82,
  tools: [
    { name: 'Claude Code', installed: true, running: true, mcpServerCount: 2 },
    { name: 'Cursor', installed: true, running: false, mcpServerCount: 0 },
  ],
} as any;

describe('sentinel snapshot', () => {
  it('builds a schema-versioned snapshot with tool footprint', () => {
    const snap = buildSnapshot(fakeResult, { hostname: 'mac-1', platform: 'darwin', arch: 'arm64', sentinelVersion: '0.0.0', generatedAtMs: 1_700_000_000_000 });
    expect(snap.schemaVersion).toBe(1);
    expect(snap.host.hostname).toBe('mac-1');
    expect(snap.tools).toHaveLength(2);
    expect(snap.tools[0]).toMatchObject({ name: 'Claude Code', installed: true, mcpServerCount: 2 });
    expect(snap.endpointScore).toBe(82);
  });

  it('picks a platform-specific default path', () => {
    expect(defaultSnapshotPath('win32')).toContain('guard0');
    expect(defaultSnapshotPath('darwin')).toContain('guard0');
  });

  it('writes valid JSON atomically', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-snap-'));
    const out = path.join(dir, 'snapshot.json');
    const snap = buildSnapshot(fakeResult, { hostname: 'h', platform: 'darwin', arch: 'arm64', sentinelVersion: '0.0.0', generatedAtMs: 1 });
    writeSnapshotAtomic(out, snap);
    const parsed = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(parsed.host.hostname).toBe('h');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
