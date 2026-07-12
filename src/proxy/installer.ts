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
 *  - Every write goes through `withLock` (`src/utils/file-lock.ts`) so a
 *    concurrent `g0 proxy install`/`uninstall` can't interleave writes.
 *  - After writing, the file is re-read and re-parsed as JSON; if that
 *    fails (a corrupted write), the backup is restored immediately and the
 *    operation is reported as a per-client error — the original file is
 *    never left in an unparseable state.
 *  - Install is idempotent: an entry already wrapped (`command === g0Bin &&
 *    args[0] === 'proxy'`) is left untouched and reported separately.
 *  - Non-stdio (remote/url-only) server entries can't be wrapped and are
 *    reported as `unproxyable`, untouched.
 *  - A malformed config (unreadable, invalid JSON, non-object root/mcpKey)
 *    is skipped with a per-client error in the result — never thrown.
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
 * Backup + `withLock` + write + re-parse-to-validate. Never throws: on any
 * failure the original file is restored from the just-taken backup (best
 * effort) and the failure is returned rather than thrown, so the config is
 * never left corrupted or the failure silently swallowed.
 */
async function writeConfigSafely(
  configPath: string,
  content: string,
): Promise<{ ok: true; backupPath: string } | { ok: false; message: string }> {
  const backupPath = `${configPath}.backup.${Date.now()}`;
  try {
    fs.copyFileSync(configPath, backupPath);
  } catch (err) {
    return { ok: false, message: `backup failed: ${errMessage(err)}` };
  }

  try {
    await withLock(configPath, () => {
      fs.writeFileSync(configPath, content, 'utf-8');
    });
  } catch (err) {
    return { ok: false, message: `write failed: ${errMessage(err)}` };
  }

  try {
    JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  } catch (err) {
    // The write left the config unparseable — restore immediately so the
    // user's IDE never sees a corrupted config file, even transiently.
    try {
      fs.copyFileSync(backupPath, configPath);
    } catch {
      // best effort — if this also fails, the backup file is still there
      // on disk for the user to recover from manually.
    }
    return { ok: false, message: `write produced invalid JSON, restored from backup: ${errMessage(err)}` };
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

function stringArrayOrUndefined(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return (value as unknown[]).filter((v): v is string => typeof v === 'string');
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
    const read = readClientConfig(client.configPath);
    if (!read.ok) {
      result.errors.push({ client: client.name, configPath: client.configPath, message: read.message });
      continue;
    }
    const servers = serversMapOf(read.root, client.mcpKey);
    if (!servers) continue; // no server map under mcpKey on this client -> nothing to do

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

      const originalArgs = stringArrayOrUndefined(entry.args);
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

    if (changed) {
      const newContent = JSON.stringify(read.root, null, 2) + '\n';
      const write = await writeConfigSafely(client.configPath, newContent);
      if (write.ok) {
        result.backups.push(write.backupPath);
        manifestAdditions.push(...localWrapped);
      } else {
        result.errors.push({ client: client.name, configPath: client.configPath, message: write.message });
        // The write didn't stick — don't claim these entries were wrapped.
        const localSet = new Set(localWrapped);
        result.wrapped = result.wrapped.filter((w) => !localSet.has(w));
      }
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
    const read = readClientConfig(client.configPath);
    if (!read.ok) {
      result.errors.push({ client: client.name, configPath: client.configPath, message: read.message });
      continue;
    }
    const servers = serversMapOf(read.root, client.mcpKey);
    if (!servers) continue;

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
        const tail = wrappedArgs.slice(dashIdx + 1).filter((a): a is string => typeof a === 'string');
        original = {
          command: tail[0],
          args: tail.length > 1 ? tail.slice(1) : undefined,
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

    if (changed) {
      const newContent = JSON.stringify(read.root, null, 2) + '\n';
      const write = await writeConfigSafely(client.configPath, newContent);
      if (write.ok) {
        result.backups.push(write.backupPath);
        result.restored.push(...localRestored);
        manifestRemovals.push(...localRemovals);
      } else {
        result.errors.push({ client: client.name, configPath: client.configPath, message: write.message });
      }
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
