/**
 * Filesystem locations for the Claude Code hook adapter. Same resolution
 * order as `protectStateDir` (src/protect/manifest.ts): explicit override,
 * then $G0_STATE_DIR, then ~/.g0.
 */

import * as os from 'node:os';
import * as path from 'node:path';

function stateBase(): string {
  return process.env.G0_STATE_DIR ?? path.join(os.homedir(), '.g0');
}

/** Hook config dir — policy.yaml, audit.jsonl live here. */
export function hookConfigDir(override?: string): string {
  return override ?? path.join(stateBase(), 'hook');
}

/** Per-session engine state (provenance snapshots, denial records). */
export function hookStateDir(override?: string): string {
  return override ?? path.join(stateBase(), 'hook-state');
}
