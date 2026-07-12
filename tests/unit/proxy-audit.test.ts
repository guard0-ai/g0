import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  appendAudit,
  auditLogDir,
  DEFAULT_MAX_AUDIT_LOG_BYTES,
  readAudit,
  serverLogDir,
  summarizeAudit,
} from '../../src/proxy/audit-log.js';
import type { AuditRecord } from '../../src/types/proxy.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-audit-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function record(overrides: Partial<AuditRecord> = {}): AuditRecord {
  return {
    ts: '2026-07-10T12:00:00.000Z',
    serverName: 'my-server',
    direction: 'request',
    kind: 'tools/call',
    toolName: 'read_file',
    method: 'tools/call',
    action: 'allow',
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────
// Path helpers
// ─────────────────────────────────────────────────────────────────────────

describe('auditLogDir / serverLogDir', () => {
  it('auditLogDir is <dir>/logs', () => {
    expect(auditLogDir(tmpDir)).toBe(path.join(tmpDir, 'logs'));
  });

  it('serverLogDir is <dir>/logs/<serverName> for a clean name', () => {
    expect(serverLogDir('my-server', tmpDir)).toBe(path.join(tmpDir, 'logs', 'my-server'));
  });
});

// ─────────────────────────────────────────────────────────────────────────
// appendAudit
// ─────────────────────────────────────────────────────────────────────────

describe('appendAudit', () => {
  it('writes a JSONL line to <dir>/logs/<server>/<date>.jsonl with 0600 file / 0700 dir perms', () => {
    appendAudit(record(), tmpDir);

    const serverDir = serverLogDir('my-server', tmpDir);
    const filePath = path.join(serverDir, '2026-07-10.jsonl');

    expect(fs.existsSync(filePath)).toBe(true);

    const dirStat = fs.statSync(serverDir);
    expect(dirStat.mode & 0o777).toBe(0o700);

    const fileStat = fs.statSync(filePath);
    expect(fileStat.mode & 0o777).toBe(0o600);

    const lines = fs.readFileSync(filePath, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toMatchObject({ serverName: 'my-server', toolName: 'read_file' });
  });

  it('a second append adds a second line (append, not overwrite)', () => {
    appendAudit(record({ toolName: 'first' }), tmpDir);
    appendAudit(record({ toolName: 'second' }), tmpDir);

    const filePath = path.join(serverLogDir('my-server', tmpDir), '2026-07-10.jsonl');
    const lines = fs.readFileSync(filePath, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).toolName).toBe('first');
    expect(JSON.parse(lines[1]).toolName).toBe('second');
  });

  it('derives the log filename from record.ts (deterministic for an injected ts)', () => {
    appendAudit(record({ ts: '2020-01-15T03:04:05.000Z' }), tmpDir);
    const filePath = path.join(serverLogDir('my-server', tmpDir), '2020-01-15.jsonl');
    expect(fs.existsSync(filePath)).toBe(true);
  });

  it('falls back to an "unknown" date file (never throws) when ts is missing/unparseable', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(() => appendAudit(record({ ts: 'not-a-date' }), tmpDir)).not.toThrow();
    expect(() => appendAudit(record({ ts: undefined as unknown as string }), tmpDir)).not.toThrow();

    const filePath = path.join(serverLogDir('my-server', tmpDir), 'unknown.jsonl');
    expect(fs.existsSync(filePath)).toBe(true);
    const lines = fs.readFileSync(filePath, 'utf-8').trim().split('\n');
    expect(lines).toHaveLength(2);

    errorSpy.mockRestore();
  });

  describe('server name sanitization (path traversal defense)', () => {
    it('a "../../evil" server name writes inside <dir>/logs/, never escaping it', () => {
      appendAudit(record({ serverName: '../../evil' }), tmpDir);

      const logsRoot = auditLogDir(tmpDir);
      const entries = fs.readdirSync(logsRoot);
      // Exactly one sanitized directory was created directly under logs/.
      expect(entries).toHaveLength(1);
      const createdDir = path.join(logsRoot, entries[0]);
      const resolvedCreatedDir = fs.realpathSync(createdDir);
      const resolvedLogsRoot = fs.realpathSync(logsRoot);
      expect(resolvedCreatedDir.startsWith(resolvedLogsRoot + path.sep)).toBe(true);

      // Nothing was written outside tmpDir (e.g. no "evil" dir at tmpDir's parent).
      expect(fs.existsSync(path.join(tmpDir, '..', 'evil'))).toBe(false);
    });

    it('an "a/b" server name does not create a nested "b" file under an "a" directory outside logs/', () => {
      appendAudit(record({ serverName: 'a/b' }), tmpDir);

      const logsRoot = auditLogDir(tmpDir);
      const entries = fs.readdirSync(logsRoot);
      expect(entries).toHaveLength(1);
      // The sanitized name has no path separator, so it's a single segment.
      expect(entries[0]).not.toContain(path.sep);
      expect(entries[0]).not.toContain('/');

      const createdDir = path.join(logsRoot, entries[0]);
      expect(fs.statSync(createdDir).isDirectory()).toBe(true);
    });

    it('serverLogDir itself resolves a hostile name to a path under <dir>/logs/', () => {
      const dangerous = serverLogDir('../../../etc', tmpDir);
      const resolved = path.resolve(dangerous);
      const resolvedLogsRoot = path.resolve(auditLogDir(tmpDir));
      expect(resolved.startsWith(resolvedLogsRoot + path.sep)).toBe(true);
    });
  });

  it('never throws when the target dir is unwritable (dir path points at an existing file)', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const blockerFile = path.join(tmpDir, 'blocker');
    fs.writeFileSync(blockerFile, 'not a directory');

    // Use the file as the base "dir" — mkdirSync(<file>/logs/...) must fail internally.
    expect(() => appendAudit(record(), blockerFile)).not.toThrow();
    expect(errorSpy).toHaveBeenCalled();
    // Diagnostics must go to stderr (console.error), never stdout.
    const loggedArgs = errorSpy.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(loggedArgs.toLowerCase()).toContain('audit log');

    errorSpy.mockRestore();
  });

  describe('rotation', () => {
    it('accumulates several records before rotating, then the live file resets smaller while .1 holds the rotated generation', () => {
      const filePath = path.join(serverLogDir('my-server', tmpDir), '2026-07-10.jsonl');
      const rotatedPath = `${filePath}.1`;

      // Derive one serialized record's on-disk size at runtime (robust to
      // the exact AuditRecord field list / JSON formatting) instead of a
      // hardcoded byte count. Written and removed before the real test
      // below so it doesn't count toward it.
      appendAudit(record({ toolName: 'tool-0' }), tmpDir);
      const recordBytes = fs.statSync(filePath).size;
      fs.rmSync(filePath);

      // A cap sized to fit ~4 records before being exceeded. This is well
      // above one record's size, unlike the previous 200-byte cap, which
      // was SMALLER than a single serialized record (~220B) and therefore
      // rotated on every single append -- making a "shrinks" assertion
      // trivially true regardless of whether rotation actually accumulates
      // anything first.
      const cap = recordBytes * 4 - 10;

      const sizesAfterEachAppend: number[] = [];
      for (let i = 0; i < 5; i++) {
        appendAudit(record({ toolName: `tool-${i}` }), tmpDir, cap);
        sizesAfterEachAppend.push(fs.statSync(filePath).size);
      }

      // Records 0-3 genuinely accumulate in the same live file (the file
      // grows on each of these appends)...
      expect(sizesAfterEachAppend[0]).toBe(recordBytes);
      expect(sizesAfterEachAppend[1]).toBeGreaterThan(sizesAfterEachAppend[0]);
      expect(sizesAfterEachAppend[2]).toBeGreaterThan(sizesAfterEachAppend[1]);
      expect(sizesAfterEachAppend[3]).toBeGreaterThan(sizesAfterEachAppend[2]);
      // ...until the 5th append observes the file over the cap and rotates
      // it away first, resetting the live file back down to one record.
      expect(sizesAfterEachAppend[4]).toBeLessThan(sizesAfterEachAppend[3]);
      expect(sizesAfterEachAppend[4]).toBe(recordBytes);

      expect(fs.existsSync(rotatedPath)).toBe(true);
      const rotatedSize = fs.statSync(rotatedPath).size;
      const liveSize = fs.statSync(filePath).size;

      // .1 holds the accumulated 4-record generation; the live file only
      // holds the single record written after rotation.
      expect(rotatedSize).toBeGreaterThan(recordBytes * 3);
      expect(liveSize).toBeLessThan(rotatedSize);
    });

    it('uses DEFAULT_MAX_AUDIT_LOG_BYTES (50MB) when no cap is passed', () => {
      expect(DEFAULT_MAX_AUDIT_LOG_BYTES).toBe(50 * 1024 * 1024);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────
// readAudit
// ─────────────────────────────────────────────────────────────────────────

describe('readAudit', () => {
  it('round-trips appended records', () => {
    appendAudit(record({ toolName: 'a' }), tmpDir);
    appendAudit(record({ toolName: 'b' }), tmpDir);

    const records = readAudit({ dir: tmpDir });
    expect(records).toHaveLength(2);
    expect(records.map((r) => r.toolName).sort()).toEqual(['a', 'b']);
  });

  it('skips malformed lines without throwing', () => {
    appendAudit(record({ toolName: 'good-1' }), tmpDir);

    const filePath = path.join(serverLogDir('my-server', tmpDir), '2026-07-10.jsonl');
    fs.appendFileSync(filePath, 'not valid json\n');
    fs.appendFileSync(filePath, '{"broken":\n');

    appendAudit(record({ toolName: 'good-2' }), tmpDir);

    let records: AuditRecord[] = [];
    expect(() => {
      records = readAudit({ dir: tmpDir });
    }).not.toThrow();
    expect(records.map((r) => r.toolName).sort()).toEqual(['good-1', 'good-2']);
  });

  it('filters by sinceMs relative to now', () => {
    const now = Date.now();
    appendAudit(record({ ts: new Date(now - 1000).toISOString(), toolName: 'recent' }), tmpDir);
    appendAudit(record({ ts: new Date(now - 10 * 24 * 60 * 60 * 1000).toISOString(), toolName: 'old' }), tmpDir);

    const records = readAudit({ dir: tmpDir, sinceMs: 60_000 }); // last minute only
    expect(records.map((r) => r.toolName)).toEqual(['recent']);
  });

  it('caps results at limit', () => {
    for (let i = 0; i < 5; i++) {
      appendAudit(record({ toolName: `tool-${i}` }), tmpDir);
    }
    const records = readAudit({ dir: tmpDir, limit: 2 });
    expect(records).toHaveLength(2);
  });

  it('sorts newest-first', () => {
    appendAudit(record({ ts: '2026-07-10T12:00:00.000Z', toolName: 'earliest' }), tmpDir);
    appendAudit(record({ ts: '2026-07-10T14:00:00.000Z', toolName: 'latest' }), tmpDir);
    appendAudit(record({ ts: '2026-07-10T13:00:00.000Z', toolName: 'middle' }), tmpDir);

    const records = readAudit({ dir: tmpDir });
    expect(records.map((r) => r.toolName)).toEqual(['latest', 'middle', 'earliest']);
  });

  it('returns [] when the logs dir is missing', () => {
    expect(readAudit({ dir: path.join(tmpDir, 'does', 'not', 'exist') })).toEqual([]);
  });

  it('reads only the given server when serverName is passed', () => {
    appendAudit(record({ serverName: 'server-a', toolName: 'a-tool' }), tmpDir);
    appendAudit(record({ serverName: 'server-b', toolName: 'b-tool' }), tmpDir);

    const records = readAudit({ dir: tmpDir, serverName: 'server-a' });
    expect(records).toHaveLength(1);
    expect(records[0].toolName).toBe('a-tool');
  });

  it('reads across all servers when serverName is omitted', () => {
    appendAudit(record({ serverName: 'server-a', toolName: 'a-tool' }), tmpDir);
    appendAudit(record({ serverName: 'server-b', toolName: 'b-tool' }), tmpDir);

    const records = readAudit({ dir: tmpDir });
    expect(records.map((r) => r.toolName).sort()).toEqual(['a-tool', 'b-tool']);
  });

  it('returns every record from a large (300,000-line) day file without a call-stack overflow', () => {
    // Regression test for a spread-push (`records.push(...readJsonlRecords(...))`)
    // that passed every parsed record as a separate call argument, blowing
    // V8's call-stack argument limit well under the 50MB rotation cap (a
    // ~35.7MB / 300k-line file reproduced it) and throwing `RangeError:
    // Maximum call stack size exceeded`. readAudit's outer catch swallowed
    // that and silently returned [], zeroing out `g0 endpoint status`.
    //
    // Lines are written directly (not via 200,000+ individual appendAudit
    // calls) so the test stays fast.
    const serverDir = serverLogDir('big-server', tmpDir);
    fs.mkdirSync(serverDir, { recursive: true, mode: 0o700 });
    const filePath = path.join(serverDir, '2026-07-10.jsonl');

    const COUNT = 300_000;
    const lines = new Array<string>(COUNT);
    for (let i = 0; i < COUNT; i++) {
      lines[i] = JSON.stringify(record({ serverName: 'big-server', toolName: `tool-${i}` }));
    }
    fs.writeFileSync(filePath, lines.join('\n') + '\n', { mode: 0o600 });

    let records: AuditRecord[] = [];
    expect(() => {
      records = readAudit({ dir: tmpDir, serverName: 'big-server', limit: COUNT });
    }).not.toThrow();

    expect(records).toHaveLength(COUNT);
    expect(new Set(records.map((r) => r.toolName)).size).toBe(COUNT);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// summarizeAudit
// ─────────────────────────────────────────────────────────────────────────

describe('summarizeAudit', () => {
  it('counts totalCalls/denied/alerted/redacted and breaks them down byServer', () => {
    appendAudit(
      record({ serverName: 'server-a', kind: 'tools/call', direction: 'request', action: 'allow' }),
      tmpDir,
    );
    appendAudit(
      record({ serverName: 'server-a', kind: 'tools/call', direction: 'request', action: 'deny' }),
      tmpDir,
    );
    appendAudit(
      record({ serverName: 'server-a', kind: 'response', direction: 'response', action: 'redact' }),
      tmpDir,
    );
    appendAudit(
      record({ serverName: 'server-b', kind: 'tools/call', direction: 'request', action: 'alert' }),
      tmpDir,
    );
    appendAudit(
      record({ serverName: 'server-b', kind: 'tools/call', direction: 'request', action: 'allow' }),
      tmpDir,
    );

    const summary = summarizeAudit({ dir: tmpDir });

    expect(summary.totalCalls).toBe(4); // 3 on server-a's request kind='tools/call' would be 2 + server-b 2 = 4
    expect(summary.denied).toBe(1);
    expect(summary.alerted).toBe(1);
    expect(summary.redacted).toBe(1);

    expect(summary.byServer['server-a']).toEqual({ calls: 2, denied: 1, alerted: 0, redacted: 1 });
    expect(summary.byServer['server-b']).toEqual({ calls: 2, denied: 0, alerted: 1, redacted: 0 });

    expect(summary.proxiedServers.sort()).toEqual(['server-a', 'server-b']);
  });

  it('lastEventAt is the newest ts across all records', () => {
    appendAudit(record({ ts: '2026-07-10T10:00:00.000Z' }), tmpDir);
    appendAudit(record({ ts: '2026-07-10T15:30:00.000Z' }), tmpDir);
    appendAudit(record({ ts: '2026-07-10T12:00:00.000Z' }), tmpDir);

    const summary = summarizeAudit({ dir: tmpDir });
    expect(summary.lastEventAt).toBe('2026-07-10T15:30:00.000Z');
  });

  it('windowMs reflects sinceMs (or null for all-time)', () => {
    appendAudit(record(), tmpDir);
    expect(summarizeAudit({ dir: tmpDir }).windowMs).toBeNull();
    expect(summarizeAudit({ dir: tmpDir, sinceMs: 60_000 }).windowMs).toBe(60_000);
  });

  it('returns a zeroed summary and never throws when there are no logs', () => {
    let summary;
    expect(() => {
      summary = summarizeAudit({ dir: path.join(tmpDir, 'does', 'not', 'exist') });
    }).not.toThrow();

    expect(summary).toEqual({
      windowMs: null,
      totalCalls: 0,
      denied: 0,
      alerted: 0,
      redacted: 0,
      byServer: {},
      proxiedServers: [],
    });
  });
});
