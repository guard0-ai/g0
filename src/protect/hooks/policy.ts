/**
 * Hook policy loading + the shipped coach-first default. "Coach-first" rides
 * the existing policy semantics: `mode: alert` downgrades every would-be
 * deny to a loud `coach` warning (see adjustAction in enforcement/policy.ts)
 * — alert fatigue is the documented killer of tools in this class, so
 * blocking is strictly opt-in (`mode: enforce`).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { loadPolicy } from '../../enforcement/policy.js';
import type { ProxyPolicy } from '../../enforcement/policy.js';
import { hookConfigDir } from './paths.js';

const DEFAULT_POLICY_YAML = `# g0 hook policy — coach-first by default.
# mode: alert  -> would-be denies become loud "coach" warnings, nothing blocks.
# Switch to "mode: enforce" to make deny/redact real. Docs: docs/hooks.md
version: 1
mode: alert
onError: open
response:
  redactSecrets: false
  injection: alert
`;

/** Write the default policy.yaml iff absent; returns its path. Never clobbers. */
export function ensureDefaultHookPolicy(configDir?: string): string {
  const dir = hookConfigDir(configDir);
  const filePath = path.join(dir, 'policy.yaml');
  try {
    if (!fs.existsSync(filePath)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(filePath, DEFAULT_POLICY_YAML, { mode: 0o600, flag: 'wx' });
    }
  } catch {
    // racing writer or unwritable dir — loadPolicy's own defaults cover us
  }
  return filePath;
}

export function loadHookPolicy(configDir?: string): ProxyPolicy {
  return loadPolicy({ dir: hookConfigDir(configDir) });
}
