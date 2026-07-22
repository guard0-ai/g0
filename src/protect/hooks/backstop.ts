/**
 * Execution-verification backstop (spec §6.1): after a PreToolUse deny, a
 * cheap post-hoc check that the denied write did not leave effects anyway —
 * the anthropics/claude-code#20946 failure class. DETECTION ONLY: alerts
 * loudly, never reverts. Never throws (fail-open discipline).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { appendJsonlLine } from '../../enforcement/audit.js';
import { hookStateDir } from './paths.js';

/** Only denials newer than this are checked; older entries are dropped. */
const DENIAL_WINDOW_MS = 10 * 60_000;

export interface DenialRecord {
  sessionId: string;
  toolName: string;
  targetPath?: string;
  deniedAt: number;
}

export interface BackstopAlert {
  toolName: string;
  targetPath: string;
  deniedAt: number;
  modifiedAt: number;
}

function denialsPath(stateDir?: string): string {
  return path.join(hookStateDir(stateDir), 'denials.jsonl');
}

export function recordDenial(record: DenialRecord, stateDir?: string): void {
  appendJsonlLine(denialsPath(stateDir), record, 1024 * 1024);
}

/**
 * Check recent denials with a known write target: a file mtime NEWER than
 * the denial means the denied action (or something) landed anyway. Alerted
 * entries are consumed (alert-once); stale entries are dropped; the rest
 * are kept for the next check.
 */
export function checkDenials(stateDir?: string): BackstopAlert[] {
  const filePath = denialsPath(stateDir);
  const alerts: BackstopAlert[] = [];
  const keep: DenialRecord[] = [];
  try {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    const cutoff = Date.now() - DENIAL_WINDOW_MS;
    for (const line of lines) {
      if (line.trim().length === 0) continue;
      let record: DenialRecord;
      try {
        record = JSON.parse(line) as DenialRecord;
      } catch {
        continue; // corrupt line — drop it
      }
      if (typeof record.deniedAt !== 'number' || record.deniedAt < cutoff) continue; // stale
      if (typeof record.targetPath !== 'string' || record.targetPath.length === 0) continue;
      try {
        const mtime = fs.statSync(record.targetPath).mtimeMs;
        if (mtime > record.deniedAt) {
          alerts.push({ toolName: record.toolName, targetPath: record.targetPath, deniedAt: record.deniedAt, modifiedAt: mtime });
          continue; // consumed — alert once
        }
      } catch {
        // target missing/unreadable — nothing observable happened
      }
      keep.push(record);
    }
    // Rewrite without alerted/stale entries (best effort).
    try {
      fs.writeFileSync(filePath, keep.map((r) => JSON.stringify(r) + '\n').join(''), { mode: 0o600 });
    } catch {
      // keep-file rewrite is best effort
    }
  } catch {
    // no denial log — nothing to check
  }
  return alerts;
}
