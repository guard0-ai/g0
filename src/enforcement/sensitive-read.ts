/**
 * Bridges `../endpoint/sensitive-paths.ts`'s "is this path sensitive" domain
 * knowledge to `g0 proxy`'s tool-call REQUEST args, for Task 8's
 * sensitive-path provenance slice: "a tool call reads `~/.ssh/id_rsa` (or a
 * `.env`, or a credential store) -> tag its RESPONSE as sensitive-origin ->
 * a later outbound flow of that content is caught by
 * `./provenance.ts`'s existing `detectDataflow`."
 *
 * Deliberately narrow, and deliberately reuses two things rather than
 * reinventing them:
 *  - the sensitive-location LIST is `../endpoint/sensitive-paths.ts`'s
 *    `isSensitivePath` — see that module's docblock for why a second,
 *    divergent list here would be a bug waiting to happen.
 *  - the path-VALUE resolution (`~`-expansion, `.`/`..` collapsing) is
 *    `./policy.ts`'s `resolvePathValue` — the exact function
 *    `pathArgs`/`allowPaths` rule matching already uses (see
 *    `hasPathViolation` there).
 *
 * `proxy-core.ts`'s response leg calls `detectSensitivePathRead(info.args)`
 * — `info.args` being the REQUEST args that produced the response now being
 * inspected — and, on a match, tags the response via
 * `./provenance.ts`'s `tagSensitiveOrigin`.
 */

import { resolvePathValue } from '../proxy/policy.js';
import { isSensitivePath } from '../endpoint/sensitive-paths.js';
import type { SensitiveCategory } from '../endpoint/sensitive-paths.js';

/** Max path-like VALUES `extractPathLikeArgValues` returns from one args object — bounds the downstream resolve/`isSensitivePath` work. */
const MAX_ARG_VALUES_SCANNED = 25;

/** Max top-level arg ENTRIES `extractPathLikeArgValues` examines — bounds the per-key check work itself (the key-name/value-shape test) so an args object with thousands of non-matching keys can't run an unbounded number of checks looking for its 25th match. */
const MAX_ARG_ENTRIES_SCANNED = 200;

/**
 * Arg key names read/write-style MCP tools commonly use for a filesystem
 * path, checked case-insensitively — so `{ path: ... }`, `{ file_path: ... }`,
 * `{ filePath: ... }`, etc. are all treated as path-bearing regardless of
 * the value's own shape (e.g. a bare relative filename with no `/`).
 */
const PATH_LIKE_KEYS = new Set([
  'path',
  'filepath',
  'file_path',
  'filename',
  'file',
  'src',
  'source',
  'target',
  'dest',
  'destination',
  'cwd',
  'dir',
  'directory',
  'uri',
]);

/** Cheap shape check: does `value` itself look like a filesystem path (as opposed to needing a path-ish key name to qualify)? No I/O, no resolution — just a prefix/length check. */
function looksLikePath(value: string): boolean {
  if (value.length === 0 || value.length > 4096) return false; // never a real path anyway; bounds the cost of the checks below
  return (
    value.startsWith('~') ||
    value.startsWith('/') ||
    value.startsWith('./') ||
    value.startsWith('../') ||
    /^[A-Za-z]:[\\/]/.test(value) // Windows drive-letter path
  );
}

/**
 * Extract candidate path-like string values from a tool call's REQUEST
 * args. Top-level only — no recursion into nested objects/arrays, so a path
 * buried under e.g. `args.options.file` is deliberately NOT extracted (that
 * scope limit is disclosed in `docs/runtime-proxy.md`). Doubly bounded, so
 * a large/adversarial args object stays cheap: at most `maxValues` values
 * are returned AND at most `MAX_ARG_ENTRIES_SCANNED` top-level entries are
 * examined (whichever comes first). Work is therefore `O(min(top-level
 * keys, MAX_ARG_ENTRIES_SCANNED))`, not `O(top-level keys)`. A value
 * qualifies if its arg KEY looks like a path parameter OR the value's own
 * text looks like a path. Never throws — a non-object/circular/weird `args`
 * degrades to `[]`.
 */
export function extractPathLikeArgValues(args: unknown, maxValues: number = MAX_ARG_VALUES_SCANNED): string[] {
  try {
    if (args === null || typeof args !== 'object' || Array.isArray(args)) return [];
    const record = args as Record<string, unknown>;
    const out: string[] = [];
    let scanned = 0;
    for (const [key, value] of Object.entries(record)) {
      if (out.length >= maxValues || scanned >= MAX_ARG_ENTRIES_SCANNED) break;
      scanned++;
      if (typeof value !== 'string' || value.length === 0) continue;
      if (PATH_LIKE_KEYS.has(key.toLowerCase()) || looksLikePath(value)) out.push(value);
    }
    return out;
  } catch {
    return [];
  }
}

export interface SensitivePathMatch {
  category: SensitiveCategory;
  /** Human-readable label for diagnostics ONLY — never the matched path itself. */
  label: string;
}

const CATEGORY_LABELS: Record<SensitiveCategory, string> = {
  'ssh-key': 'SSH keys',
  'cloud-credential': 'cloud credentials',
  'gpg-key': 'a GnuPG keyring',
  'env-file': 'an env file',
  'shell-profile': 'a shell profile',
  'credential-store': 'a credential store',
};

/**
 * True if any path-like value in a tool call's `args` resolves into a
 * sensitive filesystem location (see `../endpoint/sensitive-paths.ts`).
 * Returns only a CATEGORY + a generic label — never the matched path or
 * value itself (per Task 8's brief: "the value/full path never appears in
 * the finding or audit"). Checks candidates in `Object.entries` order and
 * returns on the FIRST sensitive match (short-circuit; this is a boolean
 * "was anything sensitive touched" check, not an enumeration).
 *
 * Never throws — any internal error degrades to `undefined` ("not
 * sensitive"), matching this proxy's fail-open discipline everywhere else
 * (see `../proxy-core.ts`'s module docblock): a bug in this NEW detector
 * must never block or corrupt the response pipeline, it can only fail to
 * add a tag.
 */
export function detectSensitivePathRead(args: unknown): SensitivePathMatch | undefined {
  try {
    for (const value of extractPathLikeArgValues(args)) {
      // `resolvePathValue` (policy.ts) and `isSensitivePath` (sensitive-paths.ts)
      // both ~-expand + `path.resolve`; calling both is intentionally
      // idempotent (resolving an already-resolved absolute path is a
      // no-op) — see `resolvePathValue`'s reuse here vs. `isSensitivePath`'s
      // own self-contained expansion in its module docblock.
      const resolved = resolvePathValue(value);
      const result = isSensitivePath(resolved);
      if (result.sensitive && result.category) {
        return { category: result.category, label: CATEGORY_LABELS[result.category] };
      }
    }
    return undefined;
  } catch {
    return undefined;
  }
}
