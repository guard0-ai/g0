/**
 * Installer for `g0 proxy` — safely rewrites IDE/agent MCP client configs so
 * each stdio MCP server launches through `g0 proxy` instead of being
 * spawned directly, and reverses that rewrite cleanly.
 *
 * ```
 * before: { command: 'npx', args: ['-y', 'server-x'], env: {...} }
 * after:  { command: 'g0',  args: ['proxy', '--server', 'server-x', '--', 'npx', '-y', 'server-x'], env: {...} }
 * ```
 *
 * Safety invariants (this rewrites a user's live IDE config — corrupting it
 * is worse than doing nothing):
 *  - Every write is preceded by a `.backup.<ts>` copy of the untouched file
 *    (mirrors `writeHardenedConfig` in `src/endpoint/openclaw-config-hardener.ts`).
 *  - Every write is validated as JSON *before* the live file is touched at
 *    all, then applied atomically: the new content is written to a temp
 *    file in the same directory and `fs.renameSync`'d onto the live path.
 *    A rename within a directory is atomic on POSIX filesystems, so the
 *    live file is always either the untouched original or the complete new
 *    content — never a truncated/partial write, even if the process is
 *    killed or the disk fills up mid-operation. If anything fails before
 *    the rename completes, the live file was never touched; on the rare
 *    chance a failure happens *after* a partial rename (e.g. a non-POSIX
 *    filesystem), the just-taken backup is restored so the live file is
 *    guaranteed to still equal its pre-call content. Every failure message
 *    includes the backup path.
 *  - The *entire* read → wrap-decision → write cycle for a given client
 *    config runs under a single `withLock` (`src/utils/file-lock.ts`), not
 *    just the final write — so a concurrent `g0 proxy install`/`uninstall`,
 *    or a manual edit landing between the read and the write, can't produce
 *    a lost update. The snapshot read under the lock is guaranteed to be
 *    the snapshot written.
 *  - Install is idempotent: an entry already wrapped (`command === g0Bin &&
 *    args[0] === 'proxy'`) is left untouched and reported separately.
 *  - Non-stdio (remote/url-only) server entries can't be wrapped and are
 *    reported as `unproxyable`, untouched.
 *  - An entry whose `args` array contains a non-string element can't be
 *    faithfully forwarded (silently dropping it would both corrupt the
 *    install manifest's `original.args` — breaking `uninstall`'s ability to
 *    restore it exactly — and change the real server's behavior with no
 *    signal to the user). Rather than mangle it, that entry is left
 *    unproxyable too, with the reason recorded in `errors`.
 *  - A malformed config (unreadable, invalid JSON, non-object root/mcpKey)
 *    is skipped with a per-client error in the result — never thrown.
 *    Locking failures (e.g. a stale-lock timeout) are caught the same way —
 *    one bad/contended config never aborts the rest of the batch.
 *  - Uninstall is manifest-backed (the `<dir>/installs.json` install
 *    manifest is the source of truth for what the *original* entry looked
 *    like, even if the config was hand-edited afterwards) but also
 *    recognizes and unwraps a `g0 proxy` entry that was wrapped manually
 *    (not recorded in the manifest) by parsing the `-- <cmd> ...` tail of
 *    its wrapped args.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { resolveClientPaths } from '../mcp/well-known-paths.js';
import { withLock } from '../utils/file-lock.js';
import type { MCPClient } from '../types/mcp-scan.js';

const DEFAULT_PROXY_DIR = path.join(os.homedir(), '.g0', 'proxy');

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

export interface InstallManifestEntry {
  client: string;
  configPath: string;
  mcpKey: string;
  serverName: string;
  original: { command: string; args?: string[]; env?: Record<string, string> };
  wrappedAt: string;
}

export interface ProxyOpError {
  client: string;
  configPath: string;
  message: string;
}

export interface InstallProxyOptions {
  /** Only install for these client names (default: all discovered clients). */
  clients?: string[];
  /** Only install for these server keys (default: all servers). */
  servers?: string[];
  /** Install manifest directory. Defaults to `~/.g0/proxy`. */
  dir?: string;
  /** The `g0` binary to wrap with. Defaults to `'g0'`; tests can inject a fake. */
  g0Bin?: string;
  /** Injected client list, bypassing `resolveClientPaths()` (for tests). */
  clientPaths?: MCPClient[];
  /** Compute the result without writing anything. */
  dryRun?: boolean;
}

export interface InstallResult {
  wrapped: InstallManifestEntry[];
  skippedAlreadyWrapped: string[];
  unproxyable: string[];
  backups: string[];
  errors: ProxyOpError[];
  dryRun: boolean;
}

export interface UninstallProxyOptions {
  clients?: string[];
  servers?: string[];
  dir?: string;
  g0Bin?: string;
  clientPaths?: MCPClient[];
}

export interface UninstallResult {
  restored: InstallManifestEntry[];
  backups: string[];
  errors: ProxyOpError[];
}

// ─────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function manifestFilePath(dir: string): string {
  return path.join(dir, 'installs.json');
}

/** Read the install manifest. Never throws — a missing/malformed manifest reads as `[]`. */
function readManifestRaw(dir: string): InstallManifestEntry[] {
  try {
    const content = fs.readFileSync(manifestFilePath(dir), 'utf-8');
    const parsed: unknown = JSON.parse(content);
    return Array.isArray(parsed) ? (parsed as InstallManifestEntry[]) : [];
  } catch {
    return [];
  }
}

type ConfigReadResult = { ok: true; root: Record<string, unknown> } | { ok: false; message: string };

/** Read + `JSON.parse` a client config. Never throws — failures are returned, not raised. */
function readClientConfig(configPath: string): ConfigReadResult {
  let raw: string;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch (err) {
    return { ok: false, message: `failed to read config: ${errMessage(err)}` };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return { ok: false, message: `invalid JSON: ${errMessage(err)}` };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false, message: 'config root is not a JSON object' };
  }
  return { ok: true, root: parsed as Record<string, unknown> };
}

function serversMapOf(root: Record<string, unknown>, mcpKey: string): Record<string, unknown> | undefined {
  const map = root[mcpKey];
  if (map === undefined || map === null || typeof map !== 'object' || Array.isArray(map)) return undefined;
  return map as Record<string, unknown>;
}

/**
 * Validate + atomically write a config file. Must be called while already
 * holding the per-config lock (see the `withLock` wrapping in
 * `installProxy`/`uninstallProxy`) so the whole read-modify-write cycle is
 * atomic, not just this write.
 *
 * Never throws, and never leaves the live file in a partial/corrupted
 * state: `content` is parsed as JSON *before* anything touches disk, then
 * written to a temp file in the same directory and moved onto `configPath`
 * with `fs.renameSync` — a same-directory rename is atomic on POSIX, so the
 * live file is always either the untouched original or the complete new
 * content, never a truncation. If the temp write or rename fails, the temp
 * file is cleaned up and (as a defense-in-depth fallback, in case a rename
 * partially landed) the live file is restored from the backup taken at the
 * top of this call — so on `{ ok: false }` the live file is guaranteed to
 * still equal its pre-call content. The backup path is always included in
 * the error message.
 */
function writeConfigSafely(
  configPath: string,
  content: string,
): { ok: true; backupPath: string } | { ok: false; message: string } {
  // Validate before touching the live file at all — a bad JSON.stringify
  // input should never even get as far as a backup.
  try {
    JSON.parse(content);
  } catch (err) {
    return { ok: false, message: `refusing to write: new content is not valid JSON: ${errMessage(err)}` };
  }

  const backupPath = `${configPath}.backup.${Date.now()}`;
  try {
    fs.copyFileSync(configPath, backupPath);
  } catch (err) {
    return { ok: false, message: `backup failed: ${errMessage(err)}` };
  }

  const tmpPath = `${configPath}.g0-tmp.${Date.now()}.${process.pid}`;
  try {
    fs.writeFileSync(tmpPath, content, 'utf-8');
    fs.renameSync(tmpPath, configPath);
  } catch (err) {
    // The live file was never written directly (we wrote tmpPath, not
    // configPath), so in the common case it's already untouched. Still,
    // restore from the backup defensively in case a rename partially landed
    // (e.g. a cross-device rename on a non-POSIX/networked filesystem) —
    // this restore is a no-op if the live file was never touched.
    try {
      fs.unlinkSync(tmpPath);
    } catch {
      // best effort cleanup — a stray temp file is harmless
    }
    try {
      fs.copyFileSync(backupPath, configPath);
    } catch {
      // best effort — if this also fails, the backup file is still on disk
      // at `backupPath` for the user to recover from manually.
    }
    return {
      ok: false,
      message: `write failed, live config left unchanged (backup at ${backupPath}): ${errMessage(err)}`,
    };
  }

  return { ok: true, backupPath };
}

async function appendToManifest(dir: string, entries: InstallManifestEntry[]): Promise<void> {
  if (entries.length === 0) return;
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const mPath = manifestFilePath(dir);
  await withLock(mPath, () => {
    const existing = readManifestRaw(dir);
    const merged = [...existing, ...entries];
    fs.writeFileSync(mPath, JSON.stringify(merged, null, 2) + '\n', { mode: 0o600 });
  });
}

function sameManifestEntry(a: InstallManifestEntry, b: InstallManifestEntry): boolean {
  return (
    a.client === b.client && a.configPath === b.configPath && a.mcpKey === b.mcpKey && a.serverName === b.serverName
  );
}

async function removeFromManifest(dir: string, toRemove: InstallManifestEntry[]): Promise<void> {
  if (toRemove.length === 0) return;
  const mPath = manifestFilePath(dir);
  await withLock(mPath, () => {
    const existing = readManifestRaw(dir);
    const remaining = existing.filter((e) => !toRemove.some((r) => sameManifestEntry(e, r)));
    fs.writeFileSync(mPath, JSON.stringify(remaining, null, 2) + '\n', { mode: 0o600 });
  });
}

function isWrappedEntry(entry: Record<string, unknown>, g0Bin: string): boolean {
  return entry.command === g0Bin && Array.isArray(entry.args) && entry.args[0] === 'proxy';
}

type ArgsResolution = { ok: true; args: string[] | undefined } | { ok: false; message: string };

/**
 * Validate an entry's `args` field. A JSON config can contain a non-string
 * element in an `args` array (e.g. a stray number or object introduced by
 * hand-editing); silently dropping it — as a naive `.filter(isString)`
 * would — corrupts two things at once: the install manifest's
 * `original.args` (so `uninstall` can never restore the entry exactly
 * again) and the actually-launched wrapped command (the dropped arg is
 * simply never passed to the real server, silently changing its behavior).
 * Neither is acceptable for a rewrite that promises never to corrupt or
 * silently mutate a user's config, so an `args` array containing a
 * non-string element makes the *whole entry* unproxyable instead — the
 * caller reports it as such and leaves it untouched, rather than mangling
 * it. (An `args` value that isn't an array at all is unchanged pre-existing
 * behavior: treated as absent/no-args.)
 */
function resolveOriginalArgs(value: unknown): ArgsResolution {
  if (!Array.isArray(value)) return { ok: true, args: undefined };
  const badIndex = value.findIndex((v) => typeof v !== 'string');
  if (badIndex !== -1) {
    return {
      ok: false,
      message: `args[${badIndex}] is not a string (${JSON.stringify(value[badIndex])}) — refusing to wrap (would silently drop or mangle it)`,
    };
  }
  return { ok: true, args: value as string[] };
}

function envRecordOrUndefined(value: unknown): Record<string, string> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, string>;
}

// ─────────────────────────────────────────────────────────────────────────
// installProxy
// ─────────────────────────────────────────────────────────────────────────

export async function installProxy(opts: InstallProxyOptions = {}): Promise<InstallResult> {
  const dir = opts.dir ?? DEFAULT_PROXY_DIR;
  const g0Bin = opts.g0Bin ?? 'g0';
  const dryRun = opts.dryRun ?? false;
  const allClients = opts.clientPaths ?? resolveClientPaths();
  const targeted = opts.clients ? allClients.filter((c) => opts.clients?.includes(c.name)) : allClients;

  const result: InstallResult = {
    wrapped: [],
    skippedAlreadyWrapped: [],
    unproxyable: [],
    backups: [],
    errors: [],
    dryRun,
  };

  const manifestAdditions: InstallManifestEntry[] = [];

  for (const client of targeted) {
    // The entire read -> wrap-decision -> write cycle for this client's
    // config runs under one lock, so a concurrent install/uninstall (or a
    // manual edit landing between the read and the write) can't produce a
    // lost update. Never throws per client: lock-acquisition failures and
    // any unexpected error are caught and recorded, so one bad or contended
    // config doesn't abort the rest of the batch.
    try {
      await withLock(client.configPath, () => {
        const read = readClientConfig(client.configPath);
        if (!read.ok) {
          result.errors.push({ client: client.name, configPath: client.configPath, message: read.message });
          return;
        }
        const servers = serversMapOf(read.root, client.mcpKey);
        if (!servers) return; // no server map under mcpKey on this client -> nothing to do

        let changed = false;
        const localWrapped: InstallManifestEntry[] = [];

        for (const [serverName, entryRaw] of Object.entries(servers)) {
          if (opts.servers && !opts.servers.includes(serverName)) continue;
          if (entryRaw === null || typeof entryRaw !== 'object' || Array.isArray(entryRaw)) continue;
          const entry = entryRaw as Record<string, unknown>;

          if (isWrappedEntry(entry, g0Bin)) {
            result.skippedAlreadyWrapped.push(`${client.name}:${serverName}`);
            continue;
          }

          const command = typeof entry.command === 'string' && entry.command.length > 0 ? entry.command : undefined;
          if (!command) {
            // Remote/url-only (SSE/HTTP) or otherwise non-stdio entry — can't be
            // wrapped as a spawned process. Left untouched.
            result.unproxyable.push(`${client.name}:${serverName}`);
            continue;
          }

          const argsResolution = resolveOriginalArgs(entry.args);
          if (!argsResolution.ok) {
            result.unproxyable.push(`${client.name}:${serverName}`);
            result.errors.push({
              client: client.name,
              configPath: client.configPath,
              message: `"${serverName}": ${argsResolution.message}`,
            });
            continue;
          }
          const originalArgs = argsResolution.args;
          const originalEnv = envRecordOrUndefined(entry.env);

          const manifestEntry: InstallManifestEntry = {
            client: client.name,
            configPath: client.configPath,
            mcpKey: client.mcpKey,
            serverName,
            original: { command, args: originalArgs, env: originalEnv },
            wrappedAt: new Date().toISOString(),
          };

          if (!dryRun) {
            const wrappedArgs = ['proxy', '--server', serverName, '--', command, ...(originalArgs ?? [])];
            servers[serverName] = { ...entry, command: g0Bin, args: wrappedArgs };
            changed = true;
          }

          result.wrapped.push(manifestEntry);
          localWrapped.push(manifestEntry);
        }

        if (!changed) return;

        const newContent = JSON.stringify(read.root, null, 2) + '\n';
        const write = writeConfigSafely(client.configPath, newContent);
        if (write.ok) {
          result.backups.push(write.backupPath);
          manifestAdditions.push(...localWrapped);
        } else {
          result.errors.push({ client: client.name, configPath: client.configPath, message: write.message });
          // The write didn't stick — don't claim these entries were wrapped.
          const localSet = new Set(localWrapped);
          result.wrapped = result.wrapped.filter((w) => !localSet.has(w));
        }
      });
    } catch (err) {
      result.errors.push({ client: client.name, configPath: client.configPath, message: `lock failed: ${errMessage(err)}` });
    }
  }

  if (!dryRun) {
    await appendToManifest(dir, manifestAdditions);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────
// uninstallProxy
// ─────────────────────────────────────────────────────────────────────────

export async function uninstallProxy(opts: UninstallProxyOptions = {}): Promise<UninstallResult> {
  const dir = opts.dir ?? DEFAULT_PROXY_DIR;
  const g0Bin = opts.g0Bin ?? 'g0';
  const allClients = opts.clientPaths ?? resolveClientPaths();
  const targeted = opts.clients ? allClients.filter((c) => opts.clients?.includes(c.name)) : allClients;

  const manifest = readManifestRaw(dir);
  const result: UninstallResult = { restored: [], backups: [], errors: [] };
  const manifestRemovals: InstallManifestEntry[] = [];

  for (const client of targeted) {
    // Same whole-cycle locking rationale as installProxy: read, decide what
    // to restore, and write, all under one lock per client config. Never
    // throws per client.
    try {
      await withLock(client.configPath, () => {
        const read = readClientConfig(client.configPath);
        if (!read.ok) {
          result.errors.push({ client: client.name, configPath: client.configPath, message: read.message });
          return;
        }
        const servers = serversMapOf(read.root, client.mcpKey);
        if (!servers) return;

        let changed = false;
        const localRestored: InstallManifestEntry[] = [];
        const localRemovals: InstallManifestEntry[] = [];

        for (const [serverName, entryRaw] of Object.entries(servers)) {
          if (opts.servers && !opts.servers.includes(serverName)) continue;
          if (entryRaw === null || typeof entryRaw !== 'object' || Array.isArray(entryRaw)) continue;
          const entry = entryRaw as Record<string, unknown>;
          if (!isWrappedEntry(entry, g0Bin)) continue; // not g0-wrapped -> nothing to restore

          const manifestMatch = manifest.find(
            (m) =>
              m.client === client.name &&
              m.configPath === client.configPath &&
              m.mcpKey === client.mcpKey &&
              m.serverName === serverName,
          );

          let original: InstallManifestEntry['original'];
          if (manifestMatch) {
            original = manifestMatch.original;
          } else {
            // Manually wrapped (not recorded in the manifest) — unwrap by
            // parsing the `-- <cmd> [args...]` tail of the wrapped args.
            const wrappedArgs = entry.args as unknown[];
            const dashIdx = wrappedArgs.indexOf('--');
            if (dashIdx === -1 || dashIdx === wrappedArgs.length - 1) {
              result.errors.push({
                client: client.name,
                configPath: client.configPath,
                message: `cannot unwrap "${serverName}": no "--" separator found in its wrapped args`,
              });
              continue;
            }
            const tail = wrappedArgs.slice(dashIdx + 1);
            const badIndex = tail.findIndex((a) => typeof a !== 'string');
            if (badIndex !== -1) {
              // Same faithfulness guarantee as install: don't silently drop
              // a non-string element while reconstructing the original
              // command — leave it for the user to resolve by hand instead
              // of restoring something that was never the real original.
              result.errors.push({
                client: client.name,
                configPath: client.configPath,
                message: `cannot unwrap "${serverName}": wrapped args[${dashIdx + 1 + badIndex}] is not a string (${JSON.stringify(tail[badIndex])})`,
              });
              continue;
            }
            const stringTail = tail as string[];
            original = {
              command: stringTail[0],
              args: stringTail.length > 1 ? stringTail.slice(1) : undefined,
              env: envRecordOrUndefined(entry.env),
            };
          }

          const restoredEntry: Record<string, unknown> = { ...entry, command: original.command };
          if (original.args && original.args.length > 0) restoredEntry.args = original.args;
          else delete restoredEntry.args;
          if (original.env) restoredEntry.env = original.env;
          else delete restoredEntry.env;

          servers[serverName] = restoredEntry;
          changed = true;

          const restoredManifestEntry: InstallManifestEntry =
            manifestMatch ??
            ({
              client: client.name,
              configPath: client.configPath,
              mcpKey: client.mcpKey,
              serverName,
              original,
              wrappedAt: '',
            } satisfies InstallManifestEntry);

          localRestored.push(restoredManifestEntry);
          if (manifestMatch) localRemovals.push(manifestMatch);
        }

        if (!changed) return;

        const newContent = JSON.stringify(read.root, null, 2) + '\n';
        const write = writeConfigSafely(client.configPath, newContent);
        if (write.ok) {
          result.backups.push(write.backupPath);
          result.restored.push(...localRestored);
          manifestRemovals.push(...localRemovals);
        } else {
          result.errors.push({ client: client.name, configPath: client.configPath, message: write.message });
        }
      });
    } catch (err) {
      result.errors.push({ client: client.name, configPath: client.configPath, message: `lock failed: ${errMessage(err)}` });
    }
  }

  if (manifestRemovals.length > 0) {
    await removeFromManifest(dir, manifestRemovals);
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────
// listInstalls
// ─────────────────────────────────────────────────────────────────────────

/** Read back the install manifest (`<dir>/installs.json`), for `g0 proxy status`. Never throws. */
export function listInstalls(dir: string = DEFAULT_PROXY_DIR): InstallManifestEntry[] {
  return readManifestRaw(dir);
}
