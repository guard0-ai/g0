import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { resolveClientPaths } from '../mcp/well-known-paths.js';
import { checkAgainstIOCs, scanForDangerousPrereqs, type IOCDatabase, type IOCMatch } from '../intelligence/ioc-database.js';
import { extractHosts } from '../proxy/response-inspector.js';
import { withLock } from '../utils/file-lock.js';
import type { MCPClient } from '../types/mcp-scan.js';

// ─── MCP-server quarantine (E3) ─────────────────────────────────────────────
//
// SAFETY MODEL — read this before touching this file:
//
// 1. Dry-run by default. `planQuarantine()` only reads config files and never
//    writes anything. The CLI's default `g0 endpoint quarantine` invocation
//    calls only this function. Nothing else in this module writes unless
//    `applyQuarantine()` is called explicitly (CLI `--apply`).
//
// 2. Backup BEFORE write, always. `applyQuarantine()` copies the original
//    config to `<configPath>.backup.<ts>` with `fs.copyFileSync` — a raw byte
//    copy, never a JSON re-serialization — before it mutates anything on
//    disk. If the backup copy fails for any reason, the write is skipped
//    entirely for that config; a failed backup can never be followed by a
//    write.
//
// 3. Reversibility via manifest. Every successful apply is recorded in a
//    manifest file under `~/.g0/quarantine/` (configPath, backupPath,
//    mcpKey, removedServers). `undoQuarantine()` reads a manifest (the
//    latest one by default, or one given explicitly) and restores each
//    config by copying its backup back over it with `fs.copyFileSync`, then
//    verifies byte-for-byte equality between the restored file and the
//    backup. Because the backup was itself a byte-exact copy of the
//    pre-quarantine original, this restore is a byte-exact reversal — not a
//    round-trip through JSON.parse/stringify.
//
// 4. Fail-safe, never throw. A malformed config, a missing file, a
//    permission error, or a lock timeout on any single client is caught,
//    recorded in a `skipped[]` list with a human-readable reason, and never
//    aborts the rest of the run or leaves a config partially written.
//
// 5. Scope discipline. Only server entries that actually matched an IOC are
//    removed from a config's `mcpKey` map — every other entry, and every
//    other top-level key in the file, passes through untouched. A config
//    with zero matched servers is never backed up or rewritten.
//
// Locking: every read-modify-write against a config file is wrapped in
// `withLock()` (src/utils/file-lock.ts) so a concurrent writer (e.g. the
// client itself, or another g0 process) can't interleave with the backup +
// rewrite and corrupt the file.

// ─── Types ───────────────────────────────────────────────────────────────────

export interface QuarantineCandidate {
  client: string;
  configPath: string;
  mcpKey: string;
  serverName: string;
  matches: IOCMatch[];
}

export interface QuarantineSkip {
  client?: string;
  configPath?: string;
  reason: string;
}

export interface QuarantinePlan {
  candidates: QuarantineCandidate[];
  skipped: QuarantineSkip[];
}

export interface QuarantineOptions {
  /** Injectable client list — defaults to resolveClientPaths(). Primary test seam. */
  clients?: MCPClient[];
  /** Injectable IOC database — defaults to the built-in loadIOCDatabase(). */
  iocDb?: IOCDatabase;
}

export interface QuarantineManifestEntry {
  client: string;
  configPath: string;
  backupPath: string;
  mcpKey: string;
  removedServers: string[];
  /**
   * sha256 of the config bytes as written by --apply (the post-quarantine
   * state). --undo compares the config's current bytes against this: if they
   * differ, the user edited the config after apply, so undo refuses to clobber
   * those edits unless --force is given.
   */
  postApplySha256: string;
}

export interface QuarantineManifest {
  id: string;
  timestamp: string;
  entries: QuarantineManifestEntry[];
}

export interface ApplyQuarantineOptions extends QuarantineOptions {
  /** Injectable manifest directory — defaults to ~/.g0/quarantine. Test seam. */
  quarantineDir?: string;
  /** Reuse a precomputed plan instead of recomputing it. */
  plan?: QuarantinePlan;
}

export interface QuarantineApplyResult {
  manifestPath: string | null;
  manifest: QuarantineManifest | null;
  applied: QuarantineManifestEntry[];
  skipped: QuarantineSkip[];
}

export interface UndoQuarantineOptions {
  /** Explicit manifest to restore from. Defaults to the latest manifest in quarantineDir. */
  manifestPath?: string;
  /** Injectable manifest directory — defaults to ~/.g0/quarantine. Test seam. */
  quarantineDir?: string;
  /**
   * Overwrite a config even if it was modified since --apply (its bytes no
   * longer match the manifest's postApplySha256). Default false: a modified
   * config is skipped and reported rather than silently clobbered.
   */
  force?: boolean;
}

export interface QuarantineRestoreEntry {
  configPath: string;
  backupPath: string;
  verified: boolean;
}

export interface QuarantineUndoResult {
  manifestPath: string | null;
  restored: QuarantineRestoreEntry[];
  skipped: QuarantineSkip[];
}

// ─── Paths ───────────────────────────────────────────────────────────────────

export function defaultQuarantineDir(): string {
  return path.join(os.homedir(), '.g0', 'quarantine');
}

function sha256(buf: Buffer): string {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

const MANIFEST_NAME_RE = /^manifest-(\d+)\.json$/;

export function findLatestManifestPath(quarantineDir: string): string | null {
  try {
    const files = fs.readdirSync(quarantineDir).filter((f) => MANIFEST_NAME_RE.test(f));
    if (files.length === 0) return null;
    files.sort((a, b) => {
      const ta = Number(a.match(MANIFEST_NAME_RE)![1]);
      const tb = Number(b.match(MANIFEST_NAME_RE)![1]);
      return tb - ta;
    });
    return path.join(quarantineDir, files[0]);
  } catch {
    return null;
  }
}

// ─── Domain / IP extraction ─────────────────────────────────────────────────
//
// Domain extraction reuses the exported `extractHosts` from
// proxy/response-inspector.ts (URL hostnames + bare `host.tld` tokens) so the
// two stay in lockstep. IPv4 extraction is local (the IOC DB's c2Ips are
// IPv4/CIDR only — see the documented IPv6 note in the report).

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;

function extractCandidateIps(text: string): string[] {
  const ips = new Set<string>();
  let m: RegExpExecArray | null;
  IPV4_RE.lastIndex = 0;
  while ((m = IPV4_RE.exec(text)) !== null) ips.add(m[0]);
  return [...ips];
}

// ─── IOC matching for a single server entry ─────────────────────────────────

function dedupeKey(m: IOCMatch): string {
  return `${m.type}:${m.indicator}:${m.matched}`;
}

function matchServer(serverName: string, serverConfig: unknown, db?: IOCDatabase): IOCMatch[] {
  const matches: IOCMatch[] = [];
  const seen = new Set<string>();

  const push = (list: IOCMatch[]) => {
    for (const m of list) {
      const key = dedupeKey(m);
      if (!seen.has(key)) {
        seen.add(key);
        matches.push(m);
      }
    }
  };

  const cfg = serverConfig && typeof serverConfig === 'object' && !Array.isArray(serverConfig)
    ? (serverConfig as Record<string, unknown>)
    : {};

  const command = typeof cfg.command === 'string' ? cfg.command : '';
  const args = Array.isArray(cfg.args) ? cfg.args.map((a) => String(a)) : [];
  const envValues = cfg.env && typeof cfg.env === 'object' && !Array.isArray(cfg.env)
    ? Object.values(cfg.env as Record<string, unknown>).map((v) => String(v))
    : [];

  // Name → typosquat. The friendly object key is what the user typed, NOT
  // where a malicious package's identity lives — that's the package specifier
  // passed to npx/uvx/pipx/node/etc. So check the server key AND the command
  // AND every non-flag args token (a flag like "-y"/"--yes" is never a package
  // name). This is the primary supply-chain detection surface.
  push(checkAgainstIOCs(serverName, 'name', db));
  const nameCandidates = [command, ...args.filter((a) => a.length > 0 && !a.startsWith('-'))];
  for (const candidate of nameCandidates) {
    push(checkAgainstIOCs(candidate, 'name', db));
  }

  const haystack = [command, ...args, ...envValues].join(' ');

  for (const domain of extractHosts(haystack)) {
    push(checkAgainstIOCs(domain, 'domain', db));
  }
  for (const ip of extractCandidateIps(haystack)) {
    push(checkAgainstIOCs(ip, 'ip', db));
  }

  // Dangerous prerequisite / install patterns over the full stringified
  // server config (covers command/args/env plus any other fields at once).
  let stringified = '';
  try {
    stringified = JSON.stringify(serverConfig);
  } catch {
    stringified = '';
  }
  if (stringified) {
    push(scanForDangerousPrereqs(stringified, db));
  }

  return matches;
}

// ─── Plan (dry-run) ──────────────────────────────────────────────────────────

/**
 * Enumerate configured MCP servers across all resolvable clients and match
 * each against the IOC database. Read-only — never writes to disk.
 */
export function planQuarantine(options: QuarantineOptions = {}): QuarantinePlan {
  const candidates: QuarantineCandidate[] = [];
  const skipped: QuarantineSkip[] = [];

  let clients: MCPClient[];
  try {
    clients = options.clients ?? resolveClientPaths();
  } catch (err) {
    return { candidates, skipped: [{ reason: `failed to enumerate MCP clients: ${(err as Error).message}` }] };
  }

  for (const client of clients) {
    try {
      if (!fs.existsSync(client.configPath)) {
        skipped.push({ client: client.name, configPath: client.configPath, reason: 'config file not found' });
        continue;
      }

      let raw: string;
      try {
        raw = fs.readFileSync(client.configPath, 'utf-8');
      } catch (err) {
        skipped.push({ client: client.name, configPath: client.configPath, reason: `read error: ${(err as Error).message}` });
        continue;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        skipped.push({ client: client.name, configPath: client.configPath, reason: 'invalid JSON' });
        continue;
      }

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        skipped.push({ client: client.name, configPath: client.configPath, reason: 'config root is not an object' });
        continue;
      }

      const serversObj = (parsed as Record<string, unknown>)[client.mcpKey];
      if (!serversObj || typeof serversObj !== 'object' || Array.isArray(serversObj)) {
        // No servers under this client's mcpKey — nothing to quarantine, not an error.
        continue;
      }

      for (const [serverName, serverConfig] of Object.entries(serversObj as Record<string, unknown>)) {
        const matches = matchServer(serverName, serverConfig, options.iocDb);
        if (matches.length > 0) {
          candidates.push({
            client: client.name,
            configPath: client.configPath,
            mcpKey: client.mcpKey,
            serverName,
            matches,
          });
        }
      }
    } catch (err) {
      // Never let one client's failure abort the plan.
      skipped.push({ client: client.name, configPath: client.configPath, reason: `unexpected error: ${(err as Error).message}` });
    }
  }

  return { candidates, skipped };
}

// ─── Apply ───────────────────────────────────────────────────────────────────

/**
 * Back up and rewrite every config that has at least one IOC-matched server,
 * removing ONLY the matched entries. Records a manifest under
 * `quarantineDir` (default `~/.g0/quarantine/`) so `undoQuarantine()` can
 * reverse this exactly.
 */
export async function applyQuarantine(options: ApplyQuarantineOptions = {}): Promise<QuarantineApplyResult> {
  const plan = options.plan ?? planQuarantine(options);
  const skipped: QuarantineSkip[] = [...plan.skipped];
  const applied: QuarantineManifestEntry[] = [];

  if (plan.candidates.length === 0) {
    return { manifestPath: null, manifest: null, applied, skipped };
  }

  const quarantineDir = options.quarantineDir ?? defaultQuarantineDir();

  // Group candidates by configPath so a config with multiple flagged
  // servers is backed up and rewritten exactly once.
  const byConfig = new Map<string, { client: string; mcpKey: string; serverNames: Set<string> }>();
  for (const c of plan.candidates) {
    const existing = byConfig.get(c.configPath);
    if (existing) {
      existing.serverNames.add(c.serverName);
    } else {
      byConfig.set(c.configPath, { client: c.client, mcpKey: c.mcpKey, serverNames: new Set([c.serverName]) });
    }
  }

  for (const [configPath, group] of byConfig) {
    try {
      const entry = await withLock(configPath, (): QuarantineManifestEntry | null => {
        // Re-read fresh under the lock — never trust the plan's stale snapshot for the write.
        let raw: string;
        try {
          raw = fs.readFileSync(configPath, 'utf-8');
        } catch (err) {
          skipped.push({ client: group.client, configPath, reason: `read error at apply time: ${(err as Error).message}` });
          return null;
        }

        let parsed: Record<string, unknown>;
        try {
          const p = JSON.parse(raw);
          if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('config root is not an object');
          parsed = p as Record<string, unknown>;
        } catch (err) {
          skipped.push({ client: group.client, configPath, reason: `invalid JSON at apply time: ${(err as Error).message}` });
          return null;
        }

        const serversObj = parsed[group.mcpKey];
        if (!serversObj || typeof serversObj !== 'object' || Array.isArray(serversObj)) {
          skipped.push({ client: group.client, configPath, reason: `mcpKey "${group.mcpKey}" missing at apply time` });
          return null;
        }
        const servers = serversObj as Record<string, unknown>;

        const removedServers = [...group.serverNames].filter((name) =>
          Object.prototype.hasOwnProperty.call(servers, name),
        );
        if (removedServers.length === 0) {
          skipped.push({ client: group.client, configPath, reason: 'matched server(s) no longer present at apply time' });
          return null;
        }

        // Backup BEFORE any write — byte-exact copy, never a re-serialization.
        // If this fails, we must not write.
        const backupPath = `${configPath}.backup.${Date.now()}`;
        try {
          fs.copyFileSync(configPath, backupPath);
        } catch (err) {
          skipped.push({ client: group.client, configPath, reason: `backup failed, write aborted: ${(err as Error).message}` });
          return null;
        }

        for (const name of removedServers) {
          delete servers[name];
        }

        const rewritten = Buffer.from(JSON.stringify(parsed, null, 2) + '\n', 'utf-8');
        try {
          fs.writeFileSync(configPath, rewritten);
        } catch (err) {
          skipped.push({ client: group.client, configPath, reason: `write failed after backup (backup preserved at ${backupPath}): ${(err as Error).message}` });
          return null;
        }

        return {
          client: group.client,
          configPath,
          backupPath,
          mcpKey: group.mcpKey,
          removedServers,
          postApplySha256: sha256(rewritten),
        };
      });

      if (entry) applied.push(entry);
    } catch (err) {
      skipped.push({ client: group.client, configPath, reason: `lock error: ${(err as Error).message}` });
    }
  }

  if (applied.length === 0) {
    return { manifestPath: null, manifest: null, applied, skipped };
  }

  const manifest: QuarantineManifest = {
    id: `manifest-${Date.now()}`,
    timestamp: new Date().toISOString(),
    entries: applied,
  };

  let manifestPath: string | null = null;
  try {
    fs.mkdirSync(quarantineDir, { recursive: true, mode: 0o700 });
    manifestPath = path.join(quarantineDir, `${manifest.id}.json`);
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
  } catch (err) {
    // The configs are already safely backed up on disk even though the
    // manifest couldn't be persisted — surface this loudly so the operator
    // knows `--undo` won't auto-discover this run (backups still exist for
    // manual recovery via the paths in `applied[].backupPath`).
    skipped.push({
      reason: `manifest write failed — backups exist on disk but --undo cannot auto-discover them: ${(err as Error).message}`,
    });
    manifestPath = null;
  }

  return { manifestPath, manifest: manifestPath ? manifest : null, applied, skipped };
}

// ─── Undo ────────────────────────────────────────────────────────────────────

/**
 * Restore every config recorded in a quarantine manifest from its backup.
 * Defaults to the most recently written manifest in `quarantineDir`. Verifies
 * each restore is byte-for-byte identical to the backup it was restored
 * from (which was itself a byte-exact copy of the pre-quarantine original).
 *
 * Staleness guard: before overwriting a config, its current bytes are compared
 * to the manifest's `postApplySha256` (the state --apply left it in). If they
 * differ, the user changed the config after apply — undo would destroy those
 * edits, so it is skipped and reported unless `options.force` is set.
 */
export async function undoQuarantine(options: UndoQuarantineOptions = {}): Promise<QuarantineUndoResult> {
  const quarantineDir = options.quarantineDir ?? defaultQuarantineDir();
  const restored: QuarantineRestoreEntry[] = [];
  const skipped: QuarantineSkip[] = [];

  const manifestPath = options.manifestPath ?? findLatestManifestPath(quarantineDir);
  if (!manifestPath) {
    return { manifestPath: null, restored, skipped: [{ reason: 'no quarantine manifest found' }] };
  }

  let manifest: QuarantineManifest;
  try {
    const raw = fs.readFileSync(manifestPath, 'utf-8');
    manifest = JSON.parse(raw) as QuarantineManifest;
  } catch (err) {
    return { manifestPath, restored, skipped: [{ reason: `failed to read/parse manifest: ${(err as Error).message}` }] };
  }

  if (!manifest || !Array.isArray(manifest.entries)) {
    return { manifestPath, restored, skipped: [{ reason: 'manifest is malformed (missing entries[])' }] };
  }

  for (const entry of manifest.entries) {
    try {
      if (!entry.backupPath || !fs.existsSync(entry.backupPath)) {
        skipped.push({ client: entry.client, configPath: entry.configPath, reason: `backup file missing: ${entry.backupPath}` });
        continue;
      }

      const outcome = await withLock(entry.configPath, (): { restored: boolean; verified: boolean; reason?: string } => {
        // Staleness guard — refuse to clobber edits made since --apply.
        // A missing `postApplySha256` (manifest from before this field
        // existed) can't be checked, so we fall through and restore as before.
        if (!options.force && typeof entry.postApplySha256 === 'string' && entry.postApplySha256.length > 0) {
          let currentBytes: Buffer | null = null;
          try {
            currentBytes = fs.readFileSync(entry.configPath);
          } catch {
            currentBytes = null;
          }
          if (currentBytes !== null && sha256(currentBytes) !== entry.postApplySha256) {
            return {
              restored: false,
              verified: false,
              reason: 'config was modified since --apply; refusing to overwrite (re-run with --force to restore anyway)',
            };
          }
        }

        fs.copyFileSync(entry.backupPath, entry.configPath);
        try {
          const restoredBytes = fs.readFileSync(entry.configPath);
          const backupBytes = fs.readFileSync(entry.backupPath);
          return { restored: true, verified: Buffer.compare(restoredBytes, backupBytes) === 0 };
        } catch {
          return { restored: true, verified: false };
        }
      });

      if (!outcome.restored) {
        skipped.push({ client: entry.client, configPath: entry.configPath, reason: outcome.reason ?? 'skipped' });
        continue;
      }

      if (!outcome.verified) {
        skipped.push({ client: entry.client, configPath: entry.configPath, reason: 'restore verification failed — restored bytes do not match backup' });
      }

      restored.push({ configPath: entry.configPath, backupPath: entry.backupPath, verified: outcome.verified });
    } catch (err) {
      skipped.push({ client: entry.client, configPath: entry.configPath, reason: `restore failed: ${(err as Error).message}` });
    }
  }

  return { manifestPath, restored, skipped };
}

// ─── Terminal formatting ─────────────────────────────────────────────────────

function formatSkipped(skipped: QuarantineSkip[]): string[] {
  if (skipped.length === 0) return [];
  const lines = ['', `  Skipped ${skipped.length}:`];
  for (const s of skipped) {
    lines.push(`    ${s.client ?? '(unknown)'}: ${s.reason}${s.configPath ? ` (${s.configPath})` : ''}`);
  }
  return lines;
}

export function formatQuarantinePlan(plan: QuarantinePlan): string {
  const lines: string[] = [];
  lines.push('  g0 endpoint quarantine — DRY RUN (no changes written)');
  lines.push('  ' + '─'.repeat(60));

  if (plan.candidates.length === 0) {
    lines.push('  No MCP servers matched known-malicious indicators.');
  } else {
    lines.push(`  ${plan.candidates.length} server(s) would be quarantined:`);
    lines.push('');
    for (const c of plan.candidates) {
      lines.push(`  ✗ ${c.serverName}  (${c.client} — ${c.configPath})`);
      for (const m of c.matches) {
        lines.push(`      [${m.severity.toUpperCase()}] ${m.type}: ${m.description} (matched "${m.matched}")`);
      }
    }
  }

  lines.push(...formatSkipped(plan.skipped));

  lines.push('');
  lines.push(
    plan.candidates.length > 0
      ? '  Run again with --apply to back up and remove these servers.'
      : '  Nothing to do.',
  );

  return lines.join('\n');
}

export function formatQuarantineApply(result: QuarantineApplyResult): string {
  const lines: string[] = [];
  lines.push('  g0 endpoint quarantine — APPLY');
  lines.push('  ' + '─'.repeat(60));

  if (result.applied.length === 0) {
    lines.push('  No configs were modified.');
  } else {
    for (const e of result.applied) {
      lines.push(`  ✓ ${e.client} (${e.configPath})`);
      lines.push(`      Removed: ${e.removedServers.join(', ')}`);
      lines.push(`      Backup:  ${e.backupPath}`);
    }
    if (result.manifestPath) {
      lines.push('');
      lines.push(`  Manifest: ${result.manifestPath}`);
      lines.push('  Run "g0 endpoint quarantine --undo" to restore.');
    } else {
      lines.push('');
      lines.push('  WARNING: manifest could not be written — see skipped[] for details. Backups above are still valid for manual recovery.');
    }
  }

  lines.push(...formatSkipped(result.skipped));

  return lines.join('\n');
}

export function formatQuarantineUndo(result: QuarantineUndoResult): string {
  const lines: string[] = [];
  lines.push('  g0 endpoint quarantine — UNDO');
  lines.push('  ' + '─'.repeat(60));

  if (!result.manifestPath) {
    lines.push('  No manifest found — nothing to restore.');
  } else {
    lines.push(`  Manifest: ${result.manifestPath}`);
    for (const r of result.restored) {
      lines.push(
        `  ${r.verified ? '✓' : '✗'} ${r.configPath} restored from ${r.backupPath}${r.verified ? '' : ' (VERIFICATION FAILED)'}`,
      );
    }
  }

  lines.push(...formatSkipped(result.skipped));

  return lines.join('\n');
}
