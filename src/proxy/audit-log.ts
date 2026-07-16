/**
 * Durable audit log for `g0 proxy` — a stdio man-in-the-middle for MCP
 * servers.
 *
 * Every tool call, its policy decision, and any blocked/redacted/alerted
 * event the proxy observes is appended as one JSON line (`AuditRecord`,
 * see `src/types/proxy.ts`) to a per-server, per-day file under
 * `~/.g0/proxy/logs/<serverName>/<YYYY-MM-DD>.jsonl`. `readAudit` reads
 * those back and `summarizeAudit` rolls them up into a `ProxyAuditSummary`
 * that `g0 endpoint status` and the fleet snapshot render.
 *
 * Design constraints (see task brief):
 *  - Never throw. This module runs inline in the proxy's read/write loop —
 *    a logging failure (disk full, unwritable dir, garbage on disk) must
 *    never break the proxied JSON-RPC stream. Every export wraps its body
 *    in try/catch and degrades to a safe default (no-op / empty / zeroed).
 *  - Never write to stdout — stdout is reserved for proxied traffic. The
 *    rare diagnostic goes to stderr via `console.error`.
 *  - `serverName` may come from a config the proxy wraps, so it is treated
 *    as untrusted input: it is sanitized before ever being used as a path
 *    segment, so a hostile name (e.g. `../../evil`) can't escape the logs
 *    directory via path traversal.
 *  - Every function takes an optional `dir` (default `~/.g0/proxy`) so
 *    tests can point at a tmpdir instead of the real home directory.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import type { AuditRecord, ProxyAction } from '../types/proxy.js';

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

const DEFAULT_PROXY_DIR = path.join(os.homedir(), '.g0', 'proxy');

/** Default per-day log file size cap before single-generation rotation. */
export const DEFAULT_MAX_AUDIT_LOG_BYTES = 50 * 1024 * 1024; // 50MB

const DEFAULT_READ_LIMIT = 500;

// ─────────────────────────────────────────────────────────────────────────
// Path helpers
// ─────────────────────────────────────────────────────────────────────────

/** Root of the proxy's audit log tree: `<dir>/logs`. */
export function auditLogDir(dir: string = DEFAULT_PROXY_DIR): string {
  return path.join(dir, 'logs');
}

/**
 * Sanitize an (untrusted) server name into a single, safe filesystem path
 * segment: anything that isn't `[a-zA-Z0-9_.-]` becomes `_`, and the
 * degenerate results `''`, `'.'`, `'..'` are mapped to `'_'` so the
 * sanitized name can never resolve to the logs dir itself or its parent.
 * Because the result never contains `/` (or `\`), it is always exactly one
 * path segment directly under `<dir>/logs/` — traversal is structurally
 * impossible regardless of the input.
 */
function sanitizeServerName(serverName: unknown): string {
  const raw = typeof serverName === 'string' ? serverName : String(serverName ?? '');
  const sanitized = raw.replace(/[^a-zA-Z0-9_.-]/g, '_');
  if (sanitized === '' || sanitized === '.' || sanitized === '..') return '_';
  return sanitized;
}

/** Directory for one server's logs: `<dir>/logs/<sanitizedServerName>/`. */
export function serverLogDir(serverName: string, dir: string = DEFAULT_PROXY_DIR): string {
  return path.join(auditLogDir(dir), sanitizeServerName(serverName));
}

/**
 * Derive a `YYYY-MM-DD` date string from an `AuditRecord.ts`. Falls back to
 * `'unknown'` (never throws) when `ts` is missing or unparseable, so a
 * malformed record still lands on disk somewhere rather than being dropped.
 */
function dateFromTs(ts: unknown): string {
  try {
    if (typeof ts !== 'string' || ts.length === 0) return 'unknown';
    const parsed = new Date(ts);
    if (Number.isNaN(parsed.getTime())) return 'unknown';
    return parsed.toISOString().slice(0, 10);
  } catch {
    return 'unknown';
  }
}

function logFilePath(record: AuditRecord, dir: string): string {
  const date = dateFromTs(record?.ts);
  return path.join(serverLogDir(record?.serverName, dir), `${date}.jsonl`);
}

// ─────────────────────────────────────────────────────────────────────────
// appendAudit
// ─────────────────────────────────────────────────────────────────────────

/**
 * Rotate `filePath` to `<filePath>.1` (overwriting any previous `.1`) if it
 * is at or over `maxBytes`. Single-generation rotation: this bounds disk
 * usage, it is not meant as full log retention. Best-effort — a rotation
 * failure just means the live file keeps growing, which is preferable to
 * throwing out of `appendAudit`.
 */
function rotateIfNeeded(filePath: string, maxBytes: number): void {
  let size: number;
  try {
    size = fs.statSync(filePath).size;
  } catch {
    return; // file doesn't exist yet -> nothing to rotate
  }
  if (size < maxBytes) return;

  const rotatedPath = `${filePath}.1`;
  try {
    fs.rmSync(rotatedPath, { force: true });
  } catch {
    // best effort
  }
  try {
    fs.renameSync(filePath, rotatedPath);
  } catch {
    // best effort — worst case the live file keeps growing past the cap
  }
}

/**
 * Append one `AuditRecord` as a JSON line to the appropriate per-server,
 * per-day log file, creating the directory (`0700`) and file (`0600`) as
 * needed. Rotates the day file to `.1` first if it has grown past
 * `maxBytes`. Never throws — on any failure (unwritable dir, disk full,
 * etc.) this logs a best-effort diagnostic to stderr and returns; audit
 * failures must never break the proxy stream.
 */
export function appendAudit(
  record: AuditRecord,
  dir: string = DEFAULT_PROXY_DIR,
  maxBytes: number = DEFAULT_MAX_AUDIT_LOG_BYTES,
): void {
  try {
    const filePath = logFilePath(record, dir);
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });

    rotateIfNeeded(filePath, maxBytes);

    const line = JSON.stringify(record) + '\n';
    fs.appendFileSync(filePath, line, { mode: 0o600 });
  } catch (err) {
    try {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`g0 proxy: audit log write failed (${message}); continuing without logging this event`);
    } catch {
      // even the diagnostic must never throw out of appendAudit
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────
// readAudit
// ─────────────────────────────────────────────────────────────────────────

export interface ReadAuditOptions {
  dir?: string;
  serverName?: string;
  sinceMs?: number;
  limit?: number;
}

function listServerLogDirs(dir: string): string[] {
  const root = auditLogDir(dir);
  try {
    return fs
      .readdirSync(root, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(root, entry.name));
  } catch {
    return []; // missing (or unreadable) logs dir -> no servers
  }
}

function readJsonlRecords(filePath: string): AuditRecord[] {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return [];
  }
  const records: AuditRecord[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      records.push(JSON.parse(trimmed) as AuditRecord);
    } catch {
      // skip malformed line — one bad line must not fail the whole read
    }
  }
  return records;
}

function recordTimeMs(record: AuditRecord): number {
  const t = Date.parse(record?.ts as string);
  return Number.isFinite(t) ? t : 0;
}

/**
 * Read back audit records: a single server's logs (`serverName`) or every
 * server's logs under `<dir>/logs/`, newest-first, optionally windowed by
 * `sinceMs` (records with `ts >= now - sinceMs`) and capped at `limit`
 * (default 500). Malformed lines are silently skipped. Never throws — a
 * missing logs dir yields `[]` with no diagnostic (the expected "no logs
 * yet" case); any other failure also yields `[]` but logs a best-effort
 * diagnostic to stderr, so an unexpected read failure isn't silently
 * invisible.
 */
export function readAudit(opts: ReadAuditOptions = {}): AuditRecord[] {
  try {
    const dir = opts.dir ?? DEFAULT_PROXY_DIR;
    const limit = opts.limit ?? DEFAULT_READ_LIMIT;

    const serverDirs = opts.serverName ? [serverLogDir(opts.serverName, dir)] : listServerLogDirs(dir);

    let records: AuditRecord[] = [];
    for (const serverDir of serverDirs) {
      let files: string[];
      try {
        files = fs.readdirSync(serverDir).filter((f) => f.endsWith('.jsonl'));
      } catch {
        continue; // this one server dir is missing/unreadable -> skip it
      }
      for (const file of files) {
        // Push elements individually (not via spread) — spreading a
        // multi-hundred-thousand-element array into `push(...)` passes each
        // element as a separate call argument and overflows V8's call-stack
        // argument limit on a large day file (a file well under the 50MB
        // rotation cap can already exceed it), throwing `RangeError: Maximum
        // call stack size exceeded` and — via the outer catch below —
        // silently emptying the audit.
        for (const parsedRecord of readJsonlRecords(path.join(serverDir, file))) {
          records.push(parsedRecord);
        }
      }
    }

    if (typeof opts.sinceMs === 'number' && Number.isFinite(opts.sinceMs)) {
      const cutoff = Date.now() - opts.sinceMs;
      records = records.filter((r) => recordTimeMs(r) >= cutoff);
    }

    records.sort((a, b) => recordTimeMs(b) - recordTimeMs(a));

    return records.slice(0, Math.max(0, limit));
  } catch (err) {
    try {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`g0 proxy: audit log read failed (${message}); returning no records`);
    } catch {
      // even the diagnostic must never throw out of readAudit
    }
    return [];
  }
}

// ─────────────────────────────────────────────────────────────────────────
// summarizeAudit
// ─────────────────────────────────────────────────────────────────────────

export interface ProxyAuditSummary {
  /** The `sinceMs` window this summary was computed over, or `null` for all-time. */
  windowMs: number | null;
  /** Records with kind 'tools/call' and direction 'request'. */
  totalCalls: number;
  /** Records with action 'deny'. */
  denied: number;
  /** Records with action 'alert'. */
  alerted: number;
  /** Records with action 'redact'. */
  redacted: number;
  /** Records with action 'coach' (a would-be `deny` downgraded to a loud, forwarded warning by `alert` mode). */
  coached: number;
  byServer: Record<string, { calls: number; denied: number; alerted: number; redacted: number; coached: number }>;
  /** Distinct server names seen in the window. */
  proxiedServers: string[];
  /** The most recent record's `ts`, if any. */
  lastEventAt?: string;
}

export interface SummarizeAuditOptions {
  dir?: string;
  sinceMs?: number;
}

function emptySummary(sinceMs?: number): ProxyAuditSummary {
  return {
    windowMs: sinceMs ?? null,
    totalCalls: 0,
    denied: 0,
    alerted: 0,
    redacted: 0,
    coached: 0,
    byServer: {},
    proxiedServers: [],
  };
}

function bucketFor(
  byServer: ProxyAuditSummary['byServer'],
  serverName: string,
): { calls: number; denied: number; alerted: number; redacted: number; coached: number } {
  if (!byServer[serverName]) {
    byServer[serverName] = { calls: 0, denied: 0, alerted: 0, redacted: 0, coached: 0 };
  }
  return byServer[serverName];
}

/**
 * Roll up the audit log into totals + a per-server breakdown, over all
 * history or a `sinceMs` window. This is what `g0 endpoint status` renders
 * and what the fleet snapshot includes. Never throws — any failure yields
 * a zeroed summary, same shape as the "no logs yet" case.
 */
export function summarizeAudit(opts: SummarizeAuditOptions = {}): ProxyAuditSummary {
  try {
    // No `limit` cap here — a summary must cover the whole requested window.
    const records = readAudit({ dir: opts.dir, sinceMs: opts.sinceMs, limit: Number.MAX_SAFE_INTEGER });
    const summary = emptySummary(opts.sinceMs);

    const serversSeen = new Set<string>();
    let lastEventAt: string | undefined;
    let lastEventMs = -Infinity;

    for (const record of records) {
      const serverName = typeof record?.serverName === 'string' && record.serverName ? record.serverName : 'unknown';
      serversSeen.add(serverName);
      const bucket = bucketFor(summary.byServer, serverName);

      if (record.kind === 'tools/call' && record.direction === 'request') {
        summary.totalCalls++;
        bucket.calls++;
      }

      const action: ProxyAction | undefined = record.action;
      if (action === 'deny') {
        summary.denied++;
        bucket.denied++;
      } else if (action === 'alert') {
        summary.alerted++;
        bucket.alerted++;
      } else if (action === 'redact') {
        summary.redacted++;
        bucket.redacted++;
      } else if (action === 'coach') {
        summary.coached++;
        bucket.coached++;
      }

      const ms = recordTimeMs(record);
      if (ms > lastEventMs) {
        lastEventMs = ms;
        lastEventAt = record.ts;
      }
    }

    summary.proxiedServers = Array.from(serversSeen);
    if (lastEventAt !== undefined) summary.lastEventAt = lastEventAt;

    return summary;
  } catch {
    return emptySummary(opts.sinceMs);
  }
}
