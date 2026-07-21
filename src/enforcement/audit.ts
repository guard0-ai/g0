/**
 * Shared never-throw JSONL writer — the write+rotate half of the proxy's
 * audit log, extracted so every enforcement transport (proxy audit-log
 * today, the Claude Code hook audit trail in Phase B) appends through one
 * code path. Path derivation and record typing stay with each caller.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

export const DEFAULT_MAX_JSONL_BYTES = 50 * 1024 * 1024; // 50MB

/**
 * Rotate `filePath` to `<filePath>.1` (overwriting any previous `.1`) if it
 * is at or over `maxBytes`. Single-generation rotation: this bounds disk
 * usage, it is not meant as full log retention. Best-effort — a rotation
 * failure just means the live file keeps growing, which is preferable to
 * throwing out of `appendJsonlLine`.
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
 * Append one record as a JSON line to `filePath`, creating the directory
 * (`0700`) and file (`0600`) as needed. Rotates the file to `.1` first if it
 * has grown past `maxBytes`. Never throws — on any failure (unwritable dir,
 * disk full, etc.) this logs a best-effort diagnostic to stderr and returns;
 * audit failures must never break an enforcement path.
 */
export function appendJsonlLine(
  filePath: string,
  record: unknown,
  maxBytes: number = DEFAULT_MAX_JSONL_BYTES,
): void {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });

    rotateIfNeeded(filePath, maxBytes);

    const line = JSON.stringify(record) + '\n';
    fs.appendFileSync(filePath, line, { mode: 0o600 });
  } catch (err) {
    try {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`g0: audit log write failed (${message}); continuing without logging this event`);
    } catch {
      // even the diagnostic must never throw out of appendJsonlLine
    }
  }
}
