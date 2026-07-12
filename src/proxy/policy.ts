/**
 * Policy engine for `g0 proxy` — decides allow/deny/redact/coach/alert for
 * MCP tool calls and tool responses based on a YAML policy file.
 *
 * Loads a global `~/.g0/proxy/policy.yaml` plus an optional per-server
 * override `~/.g0/proxy/policies/<serverName>.yaml`, compiles the rules
 * (tool-name globs -> anchored RegExp, `argsRegex` strings -> RegExp), and
 * exposes two pure evaluators: `evaluateCall` for requests and
 * `evaluateResponse` for responses (consuming P2's `InspectionResult`).
 *
 * Design constraints (see task brief):
 *  - Never throw. A missing policy file is silently treated as empty; a
 *    malformed one falls back to a safe `observe` (log-only) policy. A bad
 *    `argsRegex` disables just that one rule. All of this is logged to
 *    `console.error` — this process is a stdio MITM, so stdout is reserved
 *    for the proxied JSON-RPC traffic and must never carry diagnostics.
 *  - The rule author states what they WANT (`deny`/`alert`/`allow`); the
 *    effective action is adjusted by `policy.mode` (see `adjustAction`).
 *    This is what makes `observe`/`alert` safe "learning" modes that can
 *    never silently block traffic even if a rule says `deny` — in `alert`
 *    mode a would-be `deny` becomes `coach` instead: a loud, forwarded
 *    warning (never a silent downgrade, never a block).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import YAML from 'yaml';

import type { PolicyDecision, ProxyAction, ProxyDirection, ProxyMode } from '../types/proxy.js';
import type { InspectionResult, ResponseFinding } from './response-inspector.js';

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

export interface ProxyPolicy {
  version: number;
  mode: ProxyMode; // default 'observe'
  onError: 'open' | 'closed'; // default 'open'
  limits: { maxScanBytes: number }; // default 1_048_576
  rules: CompiledRule[];
  response: { redactSecrets: boolean; injection: 'alert' | 'deny' | 'off' };
}

export interface CompiledRule {
  id: string;
  direction: ProxyDirection; // default 'request'
  toolMatchers: RegExp[]; // compiled from globs; empty = matches all tools
  argsRegex?: RegExp;
  pathArgs?: string[];
  allowPaths?: string[]; // kept as globs; matched at eval time
  action: 'allow' | 'deny' | 'alert';
  message?: string;
}

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

const DEFAULT_MAX_SCAN_BYTES = 1_048_576;

const VALID_MODES: readonly ProxyMode[] = ['enforce', 'alert', 'observe'];
const VALID_ON_ERROR: readonly string[] = ['open', 'closed'];
const VALID_RULE_ACTIONS: readonly string[] = ['allow', 'deny', 'alert'];
const VALID_DIRECTIONS: readonly ProxyDirection[] = ['request', 'response'];
const VALID_INJECTION_SETTINGS: readonly string[] = ['alert', 'deny', 'off'];

const ACTION_PRECEDENCE: Record<ProxyAction, number> = { deny: 4, redact: 3, coach: 2, alert: 1, allow: 0 };

function defaultPolicy(): ProxyPolicy {
  return {
    version: 1,
    mode: 'observe',
    onError: 'open',
    limits: { maxScanBytes: DEFAULT_MAX_SCAN_BYTES },
    rules: [],
    response: { redactSecrets: false, injection: 'alert' },
  };
}

// ─────────────────────────────────────────────────────────────────────────
// Glob -> RegExp compilation
// ─────────────────────────────────────────────────────────────────────────

/** Escape a single character if it is a regex metacharacter. */
function escapeRegexChar(ch: string): string {
  return /[.+^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
}

/**
 * Compile a tool-name glob to an anchored, case-sensitive RegExp.
 * `*` -> `.*`, `?` -> `.`, everything else is escaped literally.
 */
function compileToolGlob(glob: string): RegExp {
  let out = '';
  for (const ch of glob) {
    if (ch === '*') out += '.*';
    else if (ch === '?') out += '.';
    else out += escapeRegexChar(ch);
  }
  return new RegExp(`^${out}$`);
}

/**
 * Compile a filesystem-path glob to an anchored RegExp. `**` matches across
 * path separators (`.*`), a single `*` stays within a segment (`[^/]*`),
 * `?` matches one non-separator character, everything else is escaped.
 */
function compilePathGlob(glob: string): RegExp {
  let out = '';
  let i = 0;
  while (i < glob.length) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i += 2;
      } else {
        out += '[^/]*';
        i += 1;
      }
    } else if (ch === '?') {
      out += '[^/]';
      i += 1;
    } else {
      out += escapeRegexChar(ch);
      i += 1;
    }
  }
  return new RegExp(`^${out}$`);
}

/** Expand a leading `~` (or `~/...`) to the current user's home directory. */
function expandHome(p: string): string {
  if (p === '~') return os.homedir();
  if (p.startsWith('~/')) return os.homedir() + p.slice(1);
  return p;
}

/**
 * Expand `~` and then resolve/normalize a path-arg *value* so that `.`/`..`
 * segments are collapsed before it's ever glob-matched. Without this, a
 * value like `~/projects/../../../../etc/passwd` textually starts with the
 * allowed prefix `~/projects/` and would incorrectly pass a naive glob
 * match even though it actually resolves outside the allowlist.
 *
 * `path.resolve` on an already-absolute (post `~`-expansion) input just
 * normalizes it — no `cwd` involved. A genuinely relative value (no `~`,
 * doesn't start with `/`) is resolved against `process.cwd()`, which is a
 * deliberate, documented choice: relative path args are anchored to the
 * proxy process's working directory for the purposes of this check.
 */
function resolvePathValue(value: string): string {
  return path.resolve(expandHome(value));
}

/**
 * Normalize an `allowPaths` *pattern* before compiling it to a glob:
 * expand `~`, then run `path.normalize` to collapse any literal `.`/`..`
 * segments. `path.normalize` is safe to run on a pattern that still
 * contains `*`/`**` wildcard tokens — those tokens contain no dots, so they
 * pass through unchanged; only the literal path segments are affected.
 */
function normalizePathPattern(pattern: string): string {
  return path.normalize(expandHome(pattern));
}

// ─────────────────────────────────────────────────────────────────────────
// YAML loading
// ─────────────────────────────────────────────────────────────────────────

type YamlReadResult = { status: 'missing' } | { status: 'malformed' } | { status: 'ok'; raw: unknown };

/**
 * Read and parse a YAML file. Never throws:
 *  - file doesn't exist (`ENOENT`) -> `{ status: 'missing' }`, silent.
 *  - file exists but can't be read (e.g. `EACCES`, `EISDIR`) ->
 *    `{ status: 'missing' }` too (same safe-default fallback), but this
 *    case is *not* silent — it's logged to stderr, since it usually
 *    indicates a misconfiguration the operator should know about.
 *  - file exists but fails to parse -> `{ status: 'malformed' }`, logged to
 *    stderr (the caller falls back to a safe default policy).
 */
function readYamlFile(filePath: string): YamlReadResult {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code !== 'ENOENT') {
      console.error(
        `g0 proxy: failed to read policy file "${filePath}" (${(err as Error).message}); treating as absent`,
      );
    }
    return { status: 'missing' };
  }
  try {
    const raw = YAML.parse(content);
    return { status: 'ok', raw };
  } catch (err) {
    console.error(
      `g0 proxy: failed to parse policy file "${filePath}" (${(err as Error).message}); falling back to observe mode`,
    );
    return { status: 'malformed' };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Compilation of the parsed YAML into a ProxyPolicy
// ─────────────────────────────────────────────────────────────────────────

/** Apply mode/onError/limits/response overrides from a parsed YAML object onto `policy`, in place. */
function applyScalarFields(policy: ProxyPolicy, obj: Record<string, unknown>, context: string): void {
  if (typeof obj.version === 'number') policy.version = obj.version;

  if (typeof obj.mode === 'string') {
    if (VALID_MODES.includes(obj.mode as ProxyMode)) {
      policy.mode = obj.mode as ProxyMode;
    } else {
      console.error(`g0 proxy: ${context} has invalid mode "${obj.mode}"; keeping "${policy.mode}"`);
    }
  }

  if (typeof obj.onError === 'string') {
    if (VALID_ON_ERROR.includes(obj.onError)) {
      policy.onError = obj.onError as 'open' | 'closed';
    } else {
      console.error(`g0 proxy: ${context} has invalid onError "${obj.onError}"; keeping "${policy.onError}"`);
    }
  }

  if (obj.limits && typeof obj.limits === 'object' && !Array.isArray(obj.limits)) {
    const limits = obj.limits as Record<string, unknown>;
    if (typeof limits.maxScanBytes === 'number' && limits.maxScanBytes > 0) {
      policy.limits = { ...policy.limits, maxScanBytes: limits.maxScanBytes };
    }
  }

  if (obj.response && typeof obj.response === 'object' && !Array.isArray(obj.response)) {
    const resp = obj.response as Record<string, unknown>;
    const response = { ...policy.response };
    if (typeof resp.redactSecrets === 'boolean') response.redactSecrets = resp.redactSecrets;
    if (typeof resp.injection === 'string') {
      if (VALID_INJECTION_SETTINGS.includes(resp.injection)) {
        response.injection = resp.injection as 'alert' | 'deny' | 'off';
      } else {
        console.error(
          `g0 proxy: ${context} has invalid response.injection "${resp.injection}"; keeping "${policy.response.injection}"`,
        );
      }
    }
    policy.response = response;
  }
}

/**
 * Compile one raw rule entry. Returns null (and logs) if the entry is
 * unusable. `index` is the rule's position in its source `rules` array,
 * used as a deterministic fallback id (`rule-<index>`) when the entry omits
 * `id` — this way the same malformed policy always yields the same audit
 * ids across runs, instead of a fresh random suffix each time.
 */
function compileRule(raw: unknown, index: number, context: string): CompiledRule | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    console.error(`g0 proxy: ${context} — skipping rule entry that isn't a mapping`);
    return null;
  }
  const r = raw as Record<string, unknown>;

  let id: string;
  if (typeof r.id === 'string' && r.id.length > 0) {
    id = r.id;
  } else {
    id = `rule-${index}`;
    console.error(`g0 proxy: ${context} — rule missing "id"; generated "${id}"`);
  }

  let direction: ProxyDirection = 'request';
  if (typeof r.direction === 'string') {
    if (VALID_DIRECTIONS.includes(r.direction as ProxyDirection)) {
      direction = r.direction as ProxyDirection;
    } else {
      console.error(`g0 proxy: rule "${id}" has invalid direction "${r.direction}"; defaulting to "request"`);
    }
  }

  let action: 'allow' | 'deny' | 'alert' = 'alert';
  if (typeof r.action === 'string') {
    if (VALID_RULE_ACTIONS.includes(r.action)) {
      action = r.action as 'allow' | 'deny' | 'alert';
    } else {
      console.error(`g0 proxy: rule "${id}" has invalid action "${r.action}"; defaulting to "alert"`);
    }
  } else {
    console.error(`g0 proxy: rule "${id}" missing "action"; defaulting to "alert"`);
  }

  let toolMatchers: RegExp[] = [];
  if (Array.isArray(r.tools) && r.tools.length > 0) {
    toolMatchers = r.tools
      .filter((t: unknown): t is string => typeof t === 'string' && t.length > 0)
      .map((glob) => compileToolGlob(glob));
  }

  let argsRegex: RegExp | undefined;
  if (typeof r.argsRegex === 'string') {
    try {
      argsRegex = new RegExp(r.argsRegex);
    } catch (err) {
      console.error(
        `g0 proxy: rule "${id}" has an invalid argsRegex (${(err as Error).message}); rule disabled`,
      );
      return null; // a bad regex disables just this rule, not the whole policy load
    }
  }

  let pathArgs: string[] | undefined;
  if (Array.isArray(r.pathArgs)) {
    const filtered = r.pathArgs.filter((p: unknown): p is string => typeof p === 'string' && p.length > 0);
    if (filtered.length > 0) pathArgs = filtered;
  }

  let allowPaths: string[] | undefined;
  if (Array.isArray(r.allowPaths)) {
    const filtered = r.allowPaths.filter((p: unknown): p is string => typeof p === 'string' && p.length > 0);
    if (filtered.length > 0) allowPaths = filtered;
  }

  const message = typeof r.message === 'string' ? r.message : undefined;

  return { id, direction, toolMatchers, argsRegex, pathArgs, allowPaths, action, message };
}

/** Compile a freshly-parsed global policy document from scratch. */
function compilePolicy(raw: unknown, context: string): ProxyPolicy {
  const policy = defaultPolicy();
  if (raw === null || raw === undefined) return policy; // empty file -> default

  if (typeof raw !== 'object' || Array.isArray(raw)) {
    console.error(`g0 proxy: ${context} must be a YAML mapping; using default (observe) policy`);
    return policy;
  }

  const obj = raw as Record<string, unknown>;
  applyScalarFields(policy, obj, context);

  if (Array.isArray(obj.rules)) {
    obj.rules.forEach((r, index) => {
      const compiled = compileRule(r, index, context);
      if (compiled) policy.rules.push(compiled);
    });
  }

  return policy;
}

/** Merge a per-server override document over an already-compiled base policy. */
function mergePolicy(base: ProxyPolicy, raw: unknown, context: string): ProxyPolicy {
  if (raw === null || raw === undefined) return base; // empty override file -> no-op

  if (typeof raw !== 'object' || Array.isArray(raw)) {
    console.error(`g0 proxy: ${context} must be a YAML mapping; ignoring overrides`);
    return base;
  }

  const merged: ProxyPolicy = {
    version: base.version,
    mode: base.mode,
    onError: base.onError,
    limits: { ...base.limits },
    rules: [...base.rules],
    response: { ...base.response },
  };

  const obj = raw as Record<string, unknown>;
  applyScalarFields(merged, obj, context);

  if (Array.isArray(obj.rules)) {
    obj.rules.forEach((r, index) => {
      const compiled = compileRule(r, index, context);
      if (compiled) merged.rules.push(compiled); // appended after global rules
    });
  }

  return merged;
}

// ─────────────────────────────────────────────────────────────────────────
// loadPolicy
// ─────────────────────────────────────────────────────────────────────────

export interface LoadPolicyOptions {
  serverName?: string;
  dir?: string;
}

/**
 * Load the global proxy policy, optionally merged with a per-server
 * override. Never throws:
 *  - missing files are silently treated as empty (default/no-op).
 *  - a malformed global file falls back to the safe default policy
 *    (`mode: 'observe'`, no rules) and logs the parse error to stderr.
 *  - a malformed per-server override file is skipped (its overrides are
 *    not applied); the already-loaded base policy is kept as-is. This
 *    never *upgrades* enforcement — at worst it leaves the base policy
 *    (which parsed fine) unchanged.
 */
export function loadPolicy(opts?: LoadPolicyOptions): ProxyPolicy {
  const dir = opts?.dir ?? path.join(os.homedir(), '.g0', 'proxy');
  const globalPath = path.join(dir, 'policy.yaml');

  const globalResult = readYamlFile(globalPath);
  let policy: ProxyPolicy =
    globalResult.status === 'ok' ? compilePolicy(globalResult.raw, `policy file "${globalPath}"`) : defaultPolicy();

  if (opts?.serverName) {
    const serverPath = path.join(dir, 'policies', `${opts.serverName}.yaml`);
    const serverResult = readYamlFile(serverPath);
    if (serverResult.status === 'ok') {
      policy = mergePolicy(policy, serverResult.raw, `per-server policy file "${serverPath}"`);
    }
    // 'missing' -> nothing to merge; 'malformed' -> already logged, overrides skipped.
  }

  return policy;
}

// ─────────────────────────────────────────────────────────────────────────
// Mode adjustment (the core allow/deny/alert semantic)
// ─────────────────────────────────────────────────────────────────────────

/**
 * Adjust a rule's *wanted* action by the policy's mode:
 *  - `observe` -> always `alert` (log-only "learning" mode, never blocks).
 *  - `alert`   -> `deny` is downgraded to `coach` (a loud, forwarded warning
 *                — see `ProxyAction`'s doc comment — not a silent `alert`);
 *                `alert`/`allow` unchanged.
 *  - `enforce` -> honored as-is.
 *
 * `coach` (like `alert`) never blocks and never modifies the message; it
 * only ever appears as an OUTPUT of this adjustment, never as a rule
 * author's input `action` (rule actions are `allow`/`deny`/`alert`, enforced
 * by `VALID_RULE_ACTIONS`) — so this function's return type is the full
 * `ProxyAction` even though its parameter type is narrower.
 */
function adjustAction(action: 'allow' | 'deny' | 'alert', mode: ProxyMode): ProxyAction {
  if (mode === 'observe') return 'alert';
  if (mode === 'alert') return action === 'deny' ? 'coach' : action;
  return action;
}

// ─────────────────────────────────────────────────────────────────────────
// evaluateCall
// ─────────────────────────────────────────────────────────────────────────

function toolMatches(matchers: RegExp[], toolName: unknown): boolean {
  if (matchers.length === 0) return true; // empty tools list = matches all tools
  if (typeof toolName !== 'string') return false;
  return matchers.some((re) => re.test(toolName));
}

/**
 * Best-effort `JSON.stringify` that never throws — falls back to `String()`
 * on a circular/unserializable value (or a `JSON.stringify` returning
 * `undefined`, e.g. a bare function/symbol). Exported because the proxy's
 * EDM scan of outbound `tools/call` args (`proxy-core.ts`) needs the exact
 * same "turn args into scannable text, never throw" behavior — and Task 5's
 * `edm[]` wiring will too; keeping one implementation stops the two copies
 * from drifting.
 */
export function safeStringify(value: unknown): string {
  try {
    const s = JSON.stringify(value);
    return typeof s === 'string' ? s : String(value);
  } catch {
    return String(value);
  }
}

/**
 * True if any configured `pathArgs` value falls outside every `allowPaths`
 * glob. Both sides are normalized before matching: the arg value is
 * `~`-expanded and resolved (collapsing `.`/`..`) via `resolvePathValue`,
 * and each allowlist pattern is `~`-expanded and normalized via
 * `normalizePathPattern` before being compiled to a glob. This closes a
 * `../` traversal bypass — without resolving first, a value that textually
 * starts with an allowed prefix (e.g. `~/projects/../../../../etc/passwd`)
 * would match `~/projects/**` even though it actually resolves outside it.
 */
function hasPathViolation(pathArgs: string[], allowPaths: string[], args: unknown): boolean {
  if (args === null || typeof args !== 'object' || Array.isArray(args)) return false;
  const record = args as Record<string, unknown>;
  const compiledAllow = allowPaths.map((g) => compilePathGlob(normalizePathPattern(g)));

  for (const key of pathArgs) {
    const value = record[key];
    if (typeof value !== 'string' || value.length === 0) continue;
    const resolved = resolvePathValue(value);
    const matchesAny = compiledAllow.some((re) => re.test(resolved));
    if (!matchesAny) return true; // outside every allowlisted path -> violation
  }
  return false;
}

function ruleMatchesCall(rule: CompiledRule, toolName: unknown, args: unknown): boolean {
  if (!toolMatches(rule.toolMatchers, toolName)) return false;

  if (rule.argsRegex && !rule.argsRegex.test(safeStringify(args))) return false;

  if (rule.pathArgs && rule.pathArgs.length > 0 && rule.allowPaths && rule.allowPaths.length > 0) {
    if (!hasPathViolation(rule.pathArgs, rule.allowPaths, args)) return false;
  }

  return true;
}

/**
 * Evaluate a request (typically a `tools/call`) against the policy's
 * `direction: 'request'` rules, in order — first match wins. Never throws.
 */
export function evaluateCall(
  policy: ProxyPolicy,
  _method: string,
  toolName: string,
  args: unknown,
): PolicyDecision {
  try {
    for (const rule of policy.rules) {
      if (rule.direction !== 'request') continue;
      if (!ruleMatchesCall(rule, toolName, args)) continue;
      return {
        action: adjustAction(rule.action, policy.mode),
        ruleId: rule.id,
        message: rule.message,
        direction: 'request',
      };
    }
    return { action: 'allow', direction: 'request' };
  } catch {
    return { action: 'allow', direction: 'request' };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// evaluateResponse
// ─────────────────────────────────────────────────────────────────────────

function summarizeFindings(findings: ResponseFinding[]): string | undefined {
  if (findings.length === 0) return undefined;
  const names = findings.slice(0, 5).map((f) => f.name);
  const suffix = findings.length > 5 ? ` (+${findings.length - 5} more)` : '';
  return `${findings.length} finding(s): ${names.join(', ')}${suffix}`;
}

/**
 * Best-effort textual surrogate for "the response text", built from what
 * `InspectionResult` actually carries (it does not retain the full original
 * text — only truncated per-finding snippets and an optional redacted
 * copy). Used only to test explicit `direction: 'response'` rules'
 * `argsRegex` against.
 */
function responseTextSurrogate(inspection: InspectionResult): string {
  const parts: string[] = [];
  if (typeof inspection.redactedText === 'string') parts.push(inspection.redactedText);
  for (const f of inspection.findings ?? []) {
    if (typeof f.match === 'string') parts.push(f.match);
  }
  return parts.join('\n');
}

function pickHighestPrecedence(decisions: PolicyDecision[]): PolicyDecision {
  let best = decisions[0];
  for (const d of decisions) {
    if (ACTION_PRECEDENCE[d.action] > ACTION_PRECEDENCE[best.action]) best = d;
  }
  return best;
}

/**
 * Evaluate a tool response against the policy, combining:
 *  - secret findings + `response.redactSecrets` -> `redact`
 *  - injection/ioc findings + `response.injection` (`off`/`alert`/`deny`,
 *    the latter mode-adjusted exactly like `evaluateCall`)
 *  - any explicit `direction: 'response'` rules
 * into a single decision using precedence
 * `deny > redact > coach > alert > allow`. Never throws.
 */
export function evaluateResponse(
  policy: ProxyPolicy,
  toolName: string,
  inspection: InspectionResult,
): PolicyDecision {
  try {
    const findings = Array.isArray(inspection?.findings) ? inspection.findings : [];
    const candidates: PolicyDecision[] = [];

    const secretFindings = findings.filter((f) => f.category === 'secret');
    if (secretFindings.length > 0 && policy.response.redactSecrets) {
      candidates.push({ action: 'redact', direction: 'response', message: summarizeFindings(secretFindings) });
    }

    const threatFindings = findings.filter((f) => f.category === 'injection' || f.category === 'ioc');
    if (threatFindings.length > 0 && policy.response.injection !== 'off') {
      const wanted: 'deny' | 'alert' = policy.response.injection === 'deny' ? 'deny' : 'alert';
      candidates.push({
        action: adjustAction(wanted, policy.mode),
        direction: 'response',
        message: summarizeFindings(threatFindings),
      });
    }

    for (const rule of policy.rules) {
      if (rule.direction !== 'response') continue;
      if (!toolMatches(rule.toolMatchers, toolName)) continue;
      if (rule.argsRegex && !rule.argsRegex.test(responseTextSurrogate(inspection))) continue;
      candidates.push({
        action: adjustAction(rule.action, policy.mode),
        ruleId: rule.id,
        message: rule.message,
        direction: 'response',
      });
    }

    if (candidates.length === 0) return { action: 'allow', direction: 'response' };
    return pickHighestPrecedence(candidates);
  } catch {
    return { action: 'allow', direction: 'response' };
  }
}
