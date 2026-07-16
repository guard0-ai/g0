/**
 * Canonical "is this filesystem path sensitive" knowledge for g0.
 *
 * Two consumers, one list — deliberately:
 *  - `./artifact-scanner.ts` (`g0 endpoint`) reads these locations AT REST,
 *    on the analyst's own machine, looking for plaintext credentials.
 *  - `../proxy/sensitive-read.ts` (`g0 proxy`, Task 8) checks whether a
 *    live MCP tool call's REQUEST args point at one of them, so the
 *    RESPONSE can be tagged sensitive-origin for `../proxy/provenance.ts`'s
 *    dataflow tracking (see that module and `../proxy/proxy-core.ts`'s
 *    response-leg wiring).
 *
 * A second, independently-maintained list of "sensitive locations" in the
 * proxy would silently drift from this one (a new credential store added to
 * `AUTH_FILE_CHECKS` here would never protect a live tool call reading it).
 * `SHELL_PROFILE_NAMES`, `ENV_FILE_LOCATIONS`, and `CREDENTIAL_STORE_LOCATIONS`
 * below are the values `artifact-scanner.ts` already scanned before this
 * module existed (see that file's `SHELL_PROFILES`/`ENV_FILE_LOCATIONS`/
 * `AUTH_FILE_CHECKS`, now derived from these exports) — unchanged, just
 * relocated to one shared source of truth. `~/.ssh`, `~/.aws`, `~/.gnupg`
 * are new additions named explicitly (`~/.ssh`) or as a natural extension
 * (`~/.aws`, `~/.gnupg` — the other classic "read me, exfiltrate me"
 * credential directories) of Task 8's brief; they are NOT scanned by
 * `artifact-scanner.ts` today (that scanner never walked directory trees
 * for key material), so adding them here does not change its output.
 */

import * as os from 'node:os';
import * as path from 'node:path';

const HOME = os.homedir();

export type SensitiveCategory =
  | 'ssh-key'
  | 'cloud-credential'
  | 'gpg-key'
  | 'env-file'
  | 'shell-profile'
  | 'credential-store';

/** One sensitive filesystem location. `exact: true` roots must match the WHOLE resolved path (a single file); otherwise `root` is a directory prefix. */
export interface SensitiveRoot {
  root: string;
  category: SensitiveCategory;
  label: string;
  exact?: boolean;
}

/** Directory roots that are sensitive by virtue of everything under them — SSH keys, cloud credentials, a GPG keyring. */
const DIRECTORY_ROOTS: SensitiveRoot[] = [
  { root: path.join(HOME, '.ssh'), category: 'ssh-key', label: 'SSH keys' },
  { root: path.join(HOME, '.aws'), category: 'cloud-credential', label: 'AWS credentials' },
  { root: path.join(HOME, '.gnupg'), category: 'gpg-key', label: 'GnuPG keyring' },
];

/** Shell profile filenames `artifact-scanner.ts`'s `scanShellProfiles` scans for embedded keys (see that file's now-derived `SHELL_PROFILES`). */
export const SHELL_PROFILE_NAMES: string[] = ['.zshrc', '.bashrc', '.bash_profile', '.profile', '.zshenv', '.zprofile'];

/** `$HOME`-relative env file locations `artifact-scanner.ts`'s `scanEnvFiles` scans (see that file's now-derived `ENV_FILE_LOCATIONS`). */
export const ENV_FILE_LOCATIONS: string[] = [path.join(HOME, '.env')];

/** Credential/auth store files `artifact-scanner.ts`'s `scanAuthFilePermissions` checks (see that file's now-derived `AUTH_FILE_CHECKS`, which adds its own `expectedPerms`). */
export const CREDENTIAL_STORE_LOCATIONS: Array<{ tool: string; path: string }> = [
  { tool: 'Cursor', path: path.join(HOME, '.cursor', 'auth.json') },
  { tool: 'Continue', path: path.join(HOME, '.continue', 'config.json') },
  { tool: 'Claude Code', path: path.join(HOME, '.claude', 'credentials.json') },
  { tool: 'Augment', path: path.join(HOME, '.augment', 'settings.json') },
  { tool: 'g0', path: path.join(HOME, '.g0', 'auth.json') },
];

function shellProfileRoots(): SensitiveRoot[] {
  return SHELL_PROFILE_NAMES.map((name) => ({
    root: path.join(HOME, name),
    category: 'shell-profile' as const,
    label: 'a shell profile',
    exact: true,
  }));
}

function envFileRoots(): SensitiveRoot[] {
  return ENV_FILE_LOCATIONS.map((p) => ({ root: p, category: 'env-file' as const, label: 'an env file', exact: true }));
}

function credentialStoreRoots(): SensitiveRoot[] {
  return CREDENTIAL_STORE_LOCATIONS.map((c) => ({
    root: c.path,
    category: 'credential-store' as const,
    label: `the ${c.tool} credential store`,
    exact: true,
  }));
}

/** The full canonical list, built once at module load. */
export const SENSITIVE_PATH_ROOTS: SensitiveRoot[] = [
  ...DIRECTORY_ROOTS,
  ...shellProfileRoots(),
  ...envFileRoots(),
  ...credentialStoreRoots(),
];

/**
 * `~`-expand a path the same way `../proxy/policy.ts`'s `expandHome` does.
 * Duplicated as a two-line helper rather than importing from `proxy/`:
 * `endpoint/` is meant to be the dependency ROOT for this domain knowledge
 * (`../proxy/sensitive-read.ts` imports FROM here) — importing `proxy/`
 * from `endpoint/` would invert that direction for the sake of one trivial
 * string helper.
 */
function expandHome(p: string): string {
  if (p === '~') return HOME;
  if (p.startsWith('~/')) return HOME + p.slice(1);
  return p;
}

/**
 * True if `p` resolves into one of the canonical sensitive locations above.
 * `p` is `~`-expanded and `path.resolve`d (collapsing `.`/`..`) before
 * matching, so a traversal like `~/.ssh/../.ssh/id_rsa` still resolves
 * under `~/.ssh` and is still caught. Calling this with an ALREADY-resolved
 * absolute path (e.g. `../proxy/policy.ts`'s `resolvePathValue` output) is
 * safe and idempotent — `path.resolve` on an absolute, normalized input is
 * a no-op.
 *
 * Also recognizes any path whose basename is `.env` or `.env.<suffix>`
 * (`.env.local`, `.env.production`, ...) regardless of directory — a
 * generalization of `ENV_FILE_LOCATIONS` (which only covers `$HOME/.env`)
 * to catch a project-local `.env` a `read_file`-style tool call might
 * target. This does not change `artifact-scanner.ts`'s own behavior:
 * `scanEnvFiles` still only ever reads `$HOME/.env` — this predicate is
 * used by the proxy, not by that scanner's file-reading loop.
 *
 * Never throws — a malformed/adversarial `p` degrades to `{ sensitive:
 * false }`.
 */
export function isSensitivePath(p: string): { sensitive: boolean; category?: SensitiveCategory } {
  try {
    if (typeof p !== 'string' || p.length === 0) return { sensitive: false };
    const resolved = path.resolve(expandHome(p));

    for (const entry of SENSITIVE_PATH_ROOTS) {
      if (entry.exact) {
        if (resolved === entry.root) return { sensitive: true, category: entry.category };
      } else if (resolved === entry.root || resolved.startsWith(entry.root + path.sep)) {
        return { sensitive: true, category: entry.category };
      }
    }

    const base = path.basename(resolved);
    if (base === '.env' || base.startsWith('.env.')) return { sensitive: true, category: 'env-file' };

    return { sensitive: false };
  } catch {
    return { sensitive: false };
  }
}
