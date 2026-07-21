/**
 * Session manifests for `g0 protect` — one JSON file per `--apply`,
 * recording each surface's undo handle so `g0 protect off` can restore the
 * most recent apply. Direct file pre-images live with the operations that
 * take them (installer backups, quarantine backups); the manifest holds the
 * references.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { McpUndoHandle, ProtectSurface } from './types.js';

export interface ProtectManifest {
  id: string;
  timestamp: string;
  surfaces: Partial<Record<ProtectSurface, McpUndoHandle>>;
}

export function protectStateDir(override?: string): string {
  if (override) return override;
  const base = process.env.G0_STATE_DIR ?? path.join(os.homedir(), '.g0');
  return path.join(base, 'protect');
}

function manifestsDir(stateDir?: string): string {
  return path.join(protectStateDir(stateDir), 'manifests');
}

export function writeManifest(manifest: ProtectManifest, stateDir?: string): string {
  const dir = manifestsDir(stateDir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const filePath = path.join(dir, `${manifest.id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  return filePath;
}

export function readLatestManifest(stateDir?: string): { path: string; manifest: ProtectManifest } | null {
  const dir = manifestsDir(stateDir);
  if (!fs.existsSync(dir)) return null;
  const names = fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort();
  if (names.length === 0) return null;
  const filePath = path.join(dir, names[names.length - 1]);
  try {
    return { path: filePath, manifest: JSON.parse(fs.readFileSync(filePath, 'utf8')) as ProtectManifest };
  } catch {
    // Corrupt manifest: refuse quietly here; the CLI surfaces recovery
    // guidance (the raw backups referenced by older manifests are plain
    // files, restorable by hand).
    return null;
  }
}
