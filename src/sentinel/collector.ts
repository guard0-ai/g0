// Sentinel snapshot transport: a resilient POST client and a thin HTTP collector
// that writes received snapshots to a directory. ManageEngine (and most MDMs)
// cannot pull a file to the console, so the sentinel POSTs its snapshot to a
// small collector the customer hosts; `g0 fleet`/the org report reads the dir.

import * as fs from 'node:fs';
import * as http from 'node:http';
import * as path from 'node:path';
import type { MachineSnapshot } from './snapshot.js';

/** Safe on-disk filename for a snapshot: sanitized hostname + timestamp. */
export function snapshotFilename(snap: MachineSnapshot): string {
  const host = (snap.host?.hostname || 'unknown').replace(/[^A-Za-z0-9._-]+/g, '_');
  const ts = snap.generatedAtMs || 0;
  return `${host}-${ts}.json`;
}

/**
 * POST a snapshot to a collector URL. Resilient by design — returns false on any
 * failure (network, non-2xx) and never throws, so a failed upload never fails the
 * scan (the snapshot is already written locally).
 */
export async function postSnapshot(url: string, snap: MachineSnapshot): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(snap),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export interface CollectorOptions {
  dir: string;
  port: number;
  host?: string;
}

/**
 * Start a thin HTTP collector. `POST /` with a JSON snapshot body writes it to
 * `dir/<host>-<ts>.json`; `GET /health` returns 200. Returns the http.Server so
 * callers can await 'listening' and close it.
 */
export function startCollector(opts: CollectorOptions): http.Server {
  fs.mkdirSync(opts.dir, { recursive: true });
  const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
      return;
    }
    if (req.method === 'POST') {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on('data', (c: Buffer) => {
        size += c.length;
        if (size > 16 * 1024 * 1024) req.destroy(); // 16MB cap
        else chunks.push(c);
      });
      req.on('end', () => {
        try {
          const snap = JSON.parse(Buffer.concat(chunks).toString('utf-8')) as MachineSnapshot;
          // Reject anything that isn't a real snapshot (stray probes, malformed
          // bodies) so the collector never writes junk like "unknown-0.json".
          if (!snap || snap.schemaVersion !== 2 || !snap.host?.hostname || !snap.generatedAtMs) {
            res.writeHead(400, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'not a valid sentinel snapshot' }));
            return;
          }
          const file = path.join(opts.dir, snapshotFilename(snap));
          const tmp = `${file}.tmp`;
          fs.writeFileSync(tmp, JSON.stringify(snap, null, 2));
          fs.renameSync(tmp, file);
          res.writeHead(201, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: true, file: path.basename(file) }));
        } catch (err) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: err instanceof Error ? err.message : String(err) }));
        }
      });
      req.on('error', () => {
        try {
          res.writeHead(400);
          res.end();
        } catch {
          /* ignore */
        }
      });
      return;
    }
    res.writeHead(405);
    res.end();
  });
  server.listen(opts.port, opts.host);
  return server;
}
