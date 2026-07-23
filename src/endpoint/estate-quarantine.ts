/**
 * File-level quarantine for flagged-critical Claude estate components
 * (spec §8, closing B2's report-only gap): MOVE the component's path into a
 * vault under ~/.g0/quarantine/estate/<ts>/ with a manifest, restorable via
 * undo. Same safety grammar as MCP-server quarantine: hash-verified
 * restore, refuse on vault drift unless forced.
 *
 * `hook` components are never touched here — they are settings.json
 * entries, not files; editing settings belongs to the claude protect
 * surface's backup/undo path.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { ClaudeEstateComponent, ClaudeEstateResult } from './claude-estate-scanner.js';

export interface EstateQuarantinePlan { candidates: ClaudeEstateComponent[]; }

export interface EstateQuarantineEntry {
  kind: string;
  name: string;
  originalPath: string;
  storedPath: string;
  sha256: string;
}

export interface EstateQuarantineManifest {
  id: string;
  timestamp: string;
  entries: EstateQuarantineEntry[];
}

function defaultQuarantineRoot(): string {
  return path.join(os.homedir(), '.g0', 'quarantine');
}

/** Stable hash of a file or directory tree (sorted relative-path:file-hash lines). */
function hashPath(target: string): string {
  const lines: string[] = [];
  const walk = (current: string, rel: string): void => {
    const stat = fs.statSync(current);
    if (stat.isFile()) {
      lines.push(`${rel}:${crypto.createHash('sha256').update(fs.readFileSync(current)).digest('hex')}`);
    } else if (stat.isDirectory()) {
      for (const name of fs.readdirSync(current).sort()) walk(path.join(current, name), `${rel}/${name}`);
    }
  };
  walk(target, '.');
  return crypto.createHash('sha256').update(lines.join('\n')).digest('hex');
}

export function planEstateQuarantine(estate: ClaudeEstateResult): EstateQuarantinePlan {
  return {
    candidates: estate.components.filter(
      (c) => c.kind !== 'hook' && c.findings.some((f) => f.severity === 'critical'),
    ),
  };
}

export function applyEstateQuarantine(
  plan: EstateQuarantinePlan,
  opts?: { quarantineDir?: string },
): { manifestPath: string | null; applied: EstateQuarantineEntry[]; skipped: { name: string; reason: string }[] } {
  const applied: EstateQuarantineEntry[] = [];
  const skipped: { name: string; reason: string }[] = [];
  if (plan.candidates.length === 0) return { manifestPath: null, applied, skipped };

  const id = new Date().toISOString().replace(/[:.]/g, '-');
  const vault = path.join(opts?.quarantineDir ?? defaultQuarantineRoot(), 'estate', id);

  for (const [index, candidate] of plan.candidates.entries()) {
    try {
      if (candidate.kind === 'hook') {
        skipped.push({ name: candidate.name, reason: 'settings-entry — remove via protect off/manual review' });
        continue;
      }
      if (!fs.existsSync(candidate.path)) {
        skipped.push({ name: candidate.name, reason: 'path no longer exists' });
        continue;
      }
      const sha256 = hashPath(candidate.path);
      const storedPath = path.join(vault, `${index}-${path.basename(candidate.path)}`);
      fs.mkdirSync(vault, { recursive: true, mode: 0o700 });
      fs.renameSync(candidate.path, storedPath);
      applied.push({ kind: candidate.kind, name: candidate.name, originalPath: candidate.path, storedPath, sha256 });
    } catch (err) {
      skipped.push({ name: candidate.name, reason: err instanceof Error ? err.message : String(err) });
    }
  }

  if (applied.length === 0) return { manifestPath: null, applied, skipped };
  const manifest: EstateQuarantineManifest = { id, timestamp: new Date().toISOString(), entries: applied };
  const manifestPath = path.join(vault, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), { mode: 0o600 });
  return { manifestPath, applied, skipped };
}

function findLatestEstateManifest(quarantineDir?: string): string | null {
  const root = path.join(quarantineDir ?? defaultQuarantineRoot(), 'estate');
  try {
    const ids = fs.readdirSync(root).sort();
    for (let i = ids.length - 1; i >= 0; i--) {
      const candidate = path.join(root, ids[i], 'manifest.json');
      if (fs.existsSync(candidate)) return candidate;
    }
  } catch { /* no vault yet */ }
  return null;
}

export function undoEstateQuarantine(
  opts?: { manifestPath?: string; quarantineDir?: string; force?: boolean },
): { restored: string[]; skipped: { reason: string }[] } {
  const restored: string[] = [];
  const skipped: { reason: string }[] = [];
  const manifestPath = opts?.manifestPath ?? findLatestEstateManifest(opts?.quarantineDir);
  if (!manifestPath) {
    skipped.push({ reason: 'no estate quarantine manifest found' });
    return { restored, skipped };
  }
  let manifest: EstateQuarantineManifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as EstateQuarantineManifest;
  } catch {
    skipped.push({ reason: `unreadable manifest: ${manifestPath}` });
    return { restored, skipped };
  }
  for (const entry of manifest.entries) {
    try {
      if (!fs.existsSync(entry.storedPath)) {
        skipped.push({ reason: `vault copy missing: ${entry.storedPath}` });
        continue;
      }
      if (!opts?.force && hashPath(entry.storedPath) !== entry.sha256) {
        skipped.push({ reason: `vault copy changed since quarantine (${entry.name}) — use force to restore anyway` });
        continue;
      }
      if (fs.existsSync(entry.originalPath)) {
        skipped.push({ reason: `original path re-occupied: ${entry.originalPath} — remove it first` });
        continue;
      }
      fs.mkdirSync(path.dirname(entry.originalPath), { recursive: true });
      fs.renameSync(entry.storedPath, entry.originalPath);
      restored.push(entry.originalPath);
    } catch (err) {
      skipped.push({ reason: err instanceof Error ? err.message : String(err) });
    }
  }
  return { restored, skipped };
}
