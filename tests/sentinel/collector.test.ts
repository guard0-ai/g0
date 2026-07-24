import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { postSnapshot, startCollector, snapshotFilename } from '../../src/sentinel/collector.js';
import type { MachineSnapshot } from '../../src/sentinel/snapshot.js';

const snap: MachineSnapshot = {
  schemaVersion: 2,
  generatedAtMs: 1_700_000_000_000,
  sentinelVersion: '0.0.0',
  host: { hostname: 'mac-1', platform: 'darwin', arch: 'arm64' },
  tools: [],
  exposures: [],
  piiSummary: {},
};

describe('sentinel collector', () => {
  it('builds a safe snapshot filename from host + timestamp', () => {
    const name = snapshotFilename({ ...snap, host: { ...snap.host, hostname: 'weird/host name' } });
    expect(name).toMatch(/^weird_host_name-\d+\.json$/);
  });

  describe('POST round-trip', () => {
    let dir: string;
    let server: ReturnType<typeof startCollector>;
    let port: number;
    beforeEach(async () => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-collect-'));
      server = startCollector({ dir, port: 0 });
      await new Promise<void>((r) => server.on('listening', () => r()));
      port = (server.address() as { port: number }).port;
    });
    afterEach(() => {
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it('accepts a POSTed snapshot and writes it to the collector dir', async () => {
      const ok = await postSnapshot(`http://127.0.0.1:${port}/`, snap);
      expect(ok).toBe(true);
      const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
      expect(files).toHaveLength(1);
      const written = JSON.parse(fs.readFileSync(path.join(dir, files[0]), 'utf-8'));
      expect(written.host.hostname).toBe('mac-1');
    });

    it('postSnapshot returns false (never throws) when the collector is unreachable', async () => {
      const ok = await postSnapshot('http://127.0.0.1:1/', snap);
      expect(ok).toBe(false);
    });

    it('rejects non-snapshot POSTs (no junk files written)', async () => {
      const res = await fetch(`http://127.0.0.1:${port}/`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      expect(res.status).toBe(400);
      expect(fs.readdirSync(dir).filter((f) => f.endsWith('.json'))).toHaveLength(0);
    });
  });
});
