/**
 * Per-session engine state for `g0 hook`. Each hook invocation is a fresh
 * process, so provenance (what secret left which tool this session) must
 * survive on disk: `<hook-state>/<sessionId>.json`, hashes only. Every
 * operation degrades to a fresh state rather than throwing — state loss
 * weakens dataflow detection for one session; a throw would break the
 * user's Claude Code session (spec §10 fail-open).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { EngineState } from '../../enforcement/engine.js';
import { loadEdmIndexes } from '../../enforcement/edm.js';
import { SessionProvenance } from '../../enforcement/provenance.js';
import type { ProvenanceSnapshot } from '../../enforcement/provenance.js';
import { hookConfigDir, hookStateDir } from './paths.js';

const MAX_STATE_AGE_MS = 24 * 3600 * 1000;

interface StateFile {
  v: 1;
  savedAt: string;
  provenance: ProvenanceSnapshot;
}

/** Restrict a session id to filename-safe characters (no leading dots) — never path-join raw input. */
function sanitizeSessionId(sessionId: string): string {
  const safe = sessionId.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '');
  return safe.length > 0 ? safe : 'unknown';
}

function pruneStale(stateDir: string): void {
  try {
    const cutoff = Date.now() - MAX_STATE_AGE_MS;
    for (const name of fs.readdirSync(stateDir)) {
      if (!name.endsWith('.json')) continue;
      const filePath = path.join(stateDir, name);
      try {
        if (fs.statSync(filePath).mtimeMs < cutoff) fs.rmSync(filePath, { force: true });
      } catch {
        // best effort per file
      }
    }
  } catch {
    // missing/unreadable dir — nothing to prune
  }
}

export interface SessionStateHandle {
  engineState: EngineState;
  save(): void;
}

export function loadSessionState(
  sessionId: string,
  opts?: { configDir?: string; stateDir?: string },
): SessionStateHandle {
  const configDir = hookConfigDir(opts?.configDir);
  const stateDir = hookStateDir(opts?.stateDir);
  const filePath = path.join(stateDir, `${sanitizeSessionId(sessionId)}.json`);

  pruneStale(stateDir);

  let provenance = new SessionProvenance();
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as StateFile;
    if (parsed && parsed.v === 1 && parsed.provenance) {
      provenance = SessionProvenance.fromJSON(parsed.provenance);
    }
  } catch {
    // missing or corrupt state file -> fresh provenance
  }

  const engineState: EngineState = { provenance, edmIndexes: loadEdmIndexes(configDir) };

  return {
    engineState,
    save(): void {
      try {
        fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
        const record: StateFile = { v: 1, savedAt: new Date().toISOString(), provenance: engineState.provenance.toJSON() };
        fs.writeFileSync(filePath, JSON.stringify(record), { mode: 0o600 });
      } catch {
        // state loss over session breakage, always
      }
    },
  };
}
