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
import { z } from 'zod';

import type { PolicyDecision, ProxyAction, ProxyDirection, ProxyMode } from '../types/proxy.js';
import type { InspectionResult, ResponseFinding } from './response-inspector.js';
import type { DataflowFinding, SessionProvenance } from './provenance.js';
import type { EdmMatch } from './edm.js';
import { ALL_STRUCTURED_DETECTORS } from './detectors/structured.js';
import type { StructuredDetector } from './detectors/structured.js';
import {
  DEFAULT_THRESHOLDS,
  decide,
  fuseSignals,
  confidenceTierSlug,
  type ConfidenceThresholds,
  type ConfidenceSeverity,
  type FusionFinding,
  type ContextMultiplier,
} from './confidence.js';

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

  // ── Policy DSL v2 (Task 5) — every field below is OPTIONAL and ONLY ever
  // populated by `compilePolicyV2`/`mergePolicyV2` (gated on `version: 2`).
  // The v1 compile path (`compilePolicy`/`mergePolicy`) never sets any of
  // these, so they are always `undefined` for a v1/version-less policy —
  // this is the concrete mechanism behind "v1 never reaches the new code":
  // every new runtime code path this task adds is guarded by either
  // `policy.version === 2` or by checking one of these fields for
  // presence, both of which are provably false/undefined for v1. See
  // `docs/runtime-proxy.md` for the full v2 DSL reference. ──────────────

  /** `decide()` thresholds for the v2 confidence-fusion decision. Undefined under v1; `evaluateCall`/`evaluateResponse` fall back to `DEFAULT_THRESHOLDS` when a v2 policy omits this block entirely. */
  thresholds?: ConfidenceThresholds;
  /** Per-detector enable/disable/confidence-override config for the Task 2 structured detectors, keyed by `StructuredDetector.id` (e.g. `'credit-card'`). Undefined under v1 -> `resolveDetectors` returns `undefined` -> `response-inspector.ts` uses its full default detector list, byte-identical to today. */
  detectors?: DetectorsConfig;
  /** Compiled `edm[]` enforcement rules (fingerprint index name -> `onMatch` action). Undefined under v1 -> EDM stays detect-only, exactly as Task 3 left it. */
  edm?: CompiledEdmRule[];
  /** Compiled `dataflow[]` enforcement rules (from/to tool+server matchers -> `onMatch` action). Undefined under v1 -> dataflow keeps using Task 4's fixed-confidence `dataflowCandidate` path unchanged. */
  dataflow?: CompiledDataflowRule[];
  /** Compiled `context` block: destination trust lists (feed confidence-fusion multipliers) and a volume/velocity override. Undefined under v1 -> `velocityCandidate` uses its pre-Task-5 constants exactly. */
  context?: CompiledContextConfig;
  /** Compiled `positiveSecurity` allow-list posture. Undefined under v1 -> no allow-list is enforced, exactly as today (only explicit `rules[]` can deny). */
  positiveSecurity?: CompiledPositiveSecurity;
}

/** One structured detector's v2 `detectors:` override. Both fields optional; an absent entry for a given detector id leaves it fully at its default behavior. */
export interface DetectorConfigEntry {
  enabled?: boolean;
  /** Fixed confidence to report instead of the detector's own tiered value, `0..1`. */
  confidence?: number;
}

/** `policy.detectors` — keyed by `StructuredDetector.id` (see `./detectors/structured.ts`). Unknown keys are harmless (they simply never match a real detector id). */
export type DetectorsConfig = Record<string, DetectorConfigEntry>;

/** One compiled `edm[]` rule: which fingerprint index it governs and what to do on a match. */
export interface CompiledEdmRule {
  index: string;
  onMatch: 'allow' | 'deny' | 'alert' | 'coach';
}

/** One compiled `dataflow[]` rule: optional from/to tool+server glob matchers (compiled to RegExp; `undefined` = matches anything for that field) and what to do on a match. */
export interface CompiledDataflowRule {
  fromTool?: RegExp;
  fromServer?: RegExp;
  toTool?: RegExp;
  toServer?: RegExp;
  onMatch: 'allow' | 'deny' | 'alert' | 'coach';
}

/** Compiled `context` block: destination-trust glob lists (compiled to RegExp) plus an optional volume/velocity override. */
export interface CompiledContextConfig {
  untrustedDestinations?: RegExp[];
  trustedDestinations?: RegExp[];
  volumeWindowMs?: number;
  volumeAlertThreshold?: number;
}

/** Compiled `positiveSecurity` block: an allow-list of tool-name globs (compiled to RegExp) and the action applied to any tool call that matches none of them. */
export interface CompiledPositiveSecurity {
  allowedTools: RegExp[];
  defaultAction: 'allow' | 'deny' | 'alert' | 'coach';
}

export interface CompiledRule {
  id: string;
  direction: ProxyDirection; // default 'request'
  toolMatchers: RegExp[]; // compiled from globs; empty = matches all tools
  argsRegex?: RegExp;
  pathArgs?: string[];
  allowPaths?: string[]; // kept as globs; matched at eval time
  /**
   * `'coach'` is a v2-only rule-author action (see `VALID_RULE_ACTIONS_V2`)
   * — the v1 hand-rolled parser (`compileRule`'s DEFAULT `validActions`
   * param, `VALID_RULE_ACTIONS`) never produces it, so a v1-compiled rule's
   * `action` is always `'allow' | 'deny' | 'alert'`, unchanged from before
   * this task. The type is widened here (additively) only so v2-compiled
   * rules can share this exact same shape/evaluation path.
   */
  action: 'allow' | 'deny' | 'alert' | 'coach';
  message?: string;
}

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

const DEFAULT_MAX_SCAN_BYTES = 1_048_576;

const VALID_MODES: readonly ProxyMode[] = ['enforce', 'alert', 'observe'];
const VALID_ON_ERROR: readonly string[] = ['open', 'closed'];
/** The v1 rule-author action set — UNCHANGED by this task. `compileRule`'s default `validActions` param, so every v1 call site (which never passes that param) is byte-identical to before. */
const VALID_RULE_ACTIONS: readonly string[] = ['allow', 'deny', 'alert'];
/** The v2 rule-author action set: adds `'coach'`, the ONE new rule-level action value the v2 DSL introduces (see the task brief). Used ONLY by the v2 compile path (`compileRuleV2`), never by v1. */
const VALID_RULE_ACTIONS_V2: readonly string[] = ['allow', 'deny', 'alert', 'coach'];
const VALID_DIRECTIONS: readonly ProxyDirection[] = ['request', 'response'];
const VALID_INJECTION_SETTINGS: readonly string[] = ['alert', 'deny', 'off'];

const ACTION_PRECEDENCE: Record<ProxyAction, number> = { deny: 4, redact: 3, coach: 2, alert: 1, allow: 0 };

/** Fixed dataflow-finding confidence — mirrors Task 4's hardcoded `dataflowCandidate` value exactly, reused as the per-finding confidence fed into the v2 fusion path (`dataflowFusionCandidate`) so both paths agree on "how strong is one cross-tool taint hit" even though only one of them runs for a given policy version. */
const DATAFLOW_BASE_CONFIDENCE = 0.9;

/** Context-multiplier factors applied to a v2 fusion pass when a call's destination tool matches `context.destinations.untrusted`/`trusted` globs (see `destinationMultipliers`). Chosen conservatively: neither factor alone can single-handedly flip a `coach`-tier finding straight to `deny` (0.6 * 1.3 = 0.78, still below the default 0.85 redact bar), it only nudges the fused score. */
const UNTRUSTED_DESTINATION_FACTOR = 1.3;
const TRUSTED_DESTINATION_FACTOR = 0.7;

/**
 * Minimum "sensitive tokens tagged within the velocity window" count before
 * `velocityCandidate` (see below) contributes a decision candidate. Fairly
 * conservative: this is a heuristic volume signal (never higher than
 * `alert` — see `velocityCandidate`), not a validator-gated finding, so it
 * should only fire on a genuine burst, not routine chatter.
 */
const VELOCITY_ALERT_THRESHOLD = 5;

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
 *
 * `validActions` (default `VALID_RULE_ACTIONS`) lets the v2 compile path
 * (`compileRuleV2`) reuse this exact function with `VALID_RULE_ACTIONS_V2`
 * (which additionally allows `'coach'`) instead of duplicating all the
 * glob/argsRegex/pathArgs compilation logic. Every v1 call site
 * (`compilePolicy`/`mergePolicy`) omits this param, so it always defaults
 * to `VALID_RULE_ACTIONS` — v1 behavior (including rejecting `action:
 * coach` with the same warning as any other unrecognized action) is
 * unchanged.
 */
function compileRule(
  raw: unknown,
  index: number,
  context: string,
  validActions: readonly string[] = VALID_RULE_ACTIONS,
): CompiledRule | null {
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

  let action: 'allow' | 'deny' | 'alert' | 'coach' = 'alert';
  if (typeof r.action === 'string') {
    if (validActions.includes(r.action)) {
      action = r.action as 'allow' | 'deny' | 'alert' | 'coach';
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
// Policy DSL v2 (Task 5) — zod schema, compilation, and merge
//
// Gated ENTIRELY on the top-level `version: 2` check in `isV2Raw`, called
// from `loadPolicy` below. A v1/version-less file NEVER reaches ANY code in
// this section — it goes through `compilePolicy`/`mergePolicy` above,
// completely unchanged by this task. zod (already a dependency — see
// `../rules/yaml-schema.ts` for the existing pattern this mirrors:
// `z.object`/`z.enum`/`.optional()`/discriminated-union-style validation,
// `safeParse`) is used HERE ONLY; the v1 path keeps its hand-rolled parse
// exactly as it was, unmodified.
//
// On a v2 `safeParse` failure, `compilePolicyV2` logs the zod error to
// stderr and returns `defaultPolicy()` — the IDENTICAL safe-`observe`
// fallback `compilePolicy` already produces for a malformed v1 file (see
// `readYamlFile`'s malformed branch above). This section never throws.
// ─────────────────────────────────────────────────────────────────────────

const v2ActionSchema = z.enum(['allow', 'deny', 'alert', 'coach']);
/** EDM/dataflow `onMatch` shares the same domain as a rule's `action` — see the module docblock's "no `redact` here" rationale in `edmMatchCandidate`/`dataflowMatchCandidate` below (there is no matched-span offset to redact surgically for either signal). */
const v2OnMatchSchema = v2ActionSchema;

const v2RuleSchema = z.object({
  id: z.string().min(1).optional(),
  direction: z.enum(['request', 'response']).optional(),
  tools: z.array(z.string()).optional(),
  argsRegex: z.string().optional(),
  pathArgs: z.array(z.string()).optional(),
  allowPaths: z.array(z.string()).optional(),
  // Optional here (unlike `id`/`message`, which v1's `compileRule` ALSO
  // treats as optional) so a rule that omits `action` degrades gracefully
  // per-rule — exactly like v1 — via `compileRule`'s own default-to-`alert`
  // fallback (with a stderr warning), instead of a single missing field on
  // ONE rule invalidating the WHOLE v2 document.
  action: v2ActionSchema.optional(),
  message: z.string().optional(),
});

const v2ThresholdsSchema = z.object({
  deny: z.number().min(0).max(1).optional(),
  redact: z.number().min(0).max(1).optional(),
  coach: z.number().min(0).max(1).optional(),
});

const v2DetectorEntrySchema = z.object({
  enabled: z.boolean().optional(),
  /** Fixed confidence to report instead of the detector's own tiered value. */
  confidence: z.number().min(0).max(1).optional(),
});

/** Keyed by `StructuredDetector.id` (see `./detectors/structured.ts`) — a plain `z.record` rather than enumerating every id, so an unrecognized key is simply inert (never matches a real detector) instead of a schema error. */
const v2DetectorsSchema = z.record(z.string(), v2DetectorEntrySchema);

const v2EdmRuleSchema = z.object({
  /** Fingerprint index name — matches `EdmMatch.indexName` (see `./edm.ts`), i.e. the `name` a corpus was built with via `g0 proxy fingerprint --name`. */
  index: z.string().min(1),
  onMatch: v2OnMatchSchema.optional(),
});

const v2FlowEndpointSchema = z.object({
  tool: z.string().optional(),
  server: z.string().optional(),
});

const v2DataflowRuleSchema = z.object({
  from: v2FlowEndpointSchema.optional(),
  to: v2FlowEndpointSchema.optional(),
  onMatch: v2OnMatchSchema.optional(),
});

const v2ContextSchema = z.object({
  destinations: z
    .object({
      untrusted: z.array(z.string()).optional(),
      trusted: z.array(z.string()).optional(),
    })
    .optional(),
  volume: z
    .object({
      windowMs: z.number().positive().optional(),
      alertThreshold: z.number().positive().optional(),
    })
    .optional(),
});

const v2PositiveSecuritySchema = z.object({
  tools: z.array(z.string()).optional(),
  default: v2ActionSchema.optional(),
});

const v2ResponseSchema = z.object({
  redactSecrets: z.boolean().optional(),
  injection: z.enum(['alert', 'deny', 'off']).optional(),
});

const v2LimitsSchema = z.object({
  maxScanBytes: z.number().positive().optional(),
});

/**
 * The shape shared by a top-level v2 policy file and a per-server v2
 * override. The override schema (`v2OverrideSchema`) is the SAME shape
 * minus a required `version` — every field is independently optional, so
 * an override document only ever describes a DELTA on top of the
 * already-compiled base (`applyV2Blocks` merges rather than replaces).
 */
const v2PolicyShape = {
  mode: z.enum(['enforce', 'alert', 'observe']).optional(),
  onError: z.enum(['open', 'closed']).optional(),
  limits: v2LimitsSchema.optional(),
  response: v2ResponseSchema.optional(),
  rules: z.array(v2RuleSchema).optional(),
  thresholds: v2ThresholdsSchema.optional(),
  detectors: v2DetectorsSchema.optional(),
  edm: z.array(v2EdmRuleSchema).optional(),
  dataflow: z.array(v2DataflowRuleSchema).optional(),
  context: v2ContextSchema.optional(),
  positiveSecurity: v2PositiveSecuritySchema.optional(),
};

const v2PolicySchema = z.object({ version: z.literal(2), ...v2PolicyShape });
const v2OverrideSchema = z.object(v2PolicyShape);

type V2Policy = z.infer<typeof v2PolicySchema>;
type V2Override = z.infer<typeof v2OverrideSchema>;

/** `raw.version === 2` (strictly, a JS number) — the ONE gate that routes a parsed YAML document to the v2 compile path instead of the v1 one. Never throws. */
function isV2Raw(raw: unknown): boolean {
  return typeof raw === 'object' && raw !== null && !Array.isArray(raw) && (raw as Record<string, unknown>).version === 2;
}

/** `compileRule` reused verbatim for v2, just with the wider `VALID_RULE_ACTIONS_V2` action set (adds `'coach'`) — see `compileRule`'s doc comment. */
function compileRuleV2(raw: unknown, index: number, context: string): CompiledRule | null {
  return compileRule(raw, index, context, VALID_RULE_ACTIONS_V2);
}

function compileEdmRules(raw: NonNullable<V2Policy['edm']>): CompiledEdmRule[] {
  return raw.map((r) => ({ index: r.index, onMatch: r.onMatch ?? 'alert' }));
}

function compileDataflowRules(raw: NonNullable<V2Policy['dataflow']>): CompiledDataflowRule[] {
  return raw.map((r) => ({
    fromTool: r.from?.tool ? compileToolGlob(r.from.tool) : undefined,
    fromServer: r.from?.server ? compileToolGlob(r.from.server) : undefined,
    toTool: r.to?.tool ? compileToolGlob(r.to.tool) : undefined,
    toServer: r.to?.server ? compileToolGlob(r.to.server) : undefined,
    onMatch: r.onMatch ?? 'alert',
  }));
}

function compileContextConfig(raw: NonNullable<V2Policy['context']>): CompiledContextConfig {
  const out: CompiledContextConfig = {};
  if (raw.destinations?.untrusted && raw.destinations.untrusted.length > 0) {
    out.untrustedDestinations = raw.destinations.untrusted.map((g) => compileToolGlob(g));
  }
  if (raw.destinations?.trusted && raw.destinations.trusted.length > 0) {
    out.trustedDestinations = raw.destinations.trusted.map((g) => compileToolGlob(g));
  }
  if (typeof raw.volume?.windowMs === 'number') out.volumeWindowMs = raw.volume.windowMs;
  if (typeof raw.volume?.alertThreshold === 'number') out.volumeAlertThreshold = raw.volume.alertThreshold;
  return out;
}

function compilePositiveSecurity(raw: NonNullable<V2Policy['positiveSecurity']>): CompiledPositiveSecurity {
  return {
    allowedTools: (raw.tools ?? []).map((g) => compileToolGlob(g)),
    defaultAction: raw.default ?? 'deny',
  };
}

/**
 * Apply every v2-only block (`thresholds`/`detectors`/`edm`/`dataflow`/
 * `context`/`positiveSecurity`) from a validated v2 document onto `policy`,
 * IN PLACE, merging rather than replacing where `policy` already carries a
 * value from a prior compile step (relevant for `mergePolicyV2`, where
 * `policy` starts as a clone of the already-compiled base): thresholds
 * shallow-merge field by field, detectors shallow-merge by key, edm/
 * dataflow rule lists concatenate (override rules apply IN ADDITION to
 * base rules, first-registered-still-first since `edmMatchCandidate`/
 * `dataflowMatchCandidate` pick the highest-precedence match across the
 * WHOLE list), context shallow-merges, positiveSecurity is wholesale
 * replaced by an override (an allow-list posture doesn't have a sensible
 * partial-merge semantic). Never throws — logs and skips just the v2
 * blocks on an internal error, never the whole compile.
 */
function applyV2Blocks(policy: ProxyPolicy, obj: V2Policy | V2Override, context: string): void {
  try {
    if (obj.thresholds) {
      policy.thresholds = { ...DEFAULT_THRESHOLDS, ...policy.thresholds, ...obj.thresholds };
    }
    if (obj.detectors) {
      policy.detectors = { ...(policy.detectors ?? {}), ...obj.detectors };
    }
    if (obj.edm && obj.edm.length > 0) {
      policy.edm = [...(policy.edm ?? []), ...compileEdmRules(obj.edm)];
    }
    if (obj.dataflow && obj.dataflow.length > 0) {
      policy.dataflow = [...(policy.dataflow ?? []), ...compileDataflowRules(obj.dataflow)];
    }
    if (obj.context) {
      policy.context = { ...(policy.context ?? {}), ...compileContextConfig(obj.context) };
    }
    if (obj.positiveSecurity) {
      policy.positiveSecurity = compilePositiveSecurity(obj.positiveSecurity);
    }
  } catch (err) {
    console.error(
      `g0 proxy: ${context} — failed to compile v2 policy blocks (${(err as Error).message}); those blocks are skipped`,
    );
  }
}

/**
 * Compile a freshly-parsed v2 global policy document from scratch. Mirrors
 * `compilePolicy`'s contract exactly, just for the v2 schema: a
 * `safeParse` failure logs to stderr and returns `defaultPolicy()` — the
 * SAME safe-`observe` fallback a malformed v1 file produces. Never throws.
 */
function compilePolicyV2(raw: unknown, context: string): ProxyPolicy {
  const parsed = v2PolicySchema.safeParse(raw);
  if (!parsed.success) {
    console.error(`g0 proxy: ${context} failed v2 schema validation (${parsed.error.message}); falling back to observe mode`);
    return defaultPolicy();
  }
  const obj = parsed.data;
  const policy = defaultPolicy();
  policy.version = 2;
  applyScalarFields(policy, obj as unknown as Record<string, unknown>, context);
  applyV2Blocks(policy, obj, context);

  if (Array.isArray(obj.rules)) {
    obj.rules.forEach((r, index) => {
      const compiled = compileRuleV2(r, index, context);
      if (compiled) policy.rules.push(compiled);
    });
  }

  return policy;
}

/**
 * Merge a per-server v2 override document over an already-compiled v2 base
 * policy. Mirrors `mergePolicy`'s contract: a malformed override is logged
 * and skipped (the base, which already parsed fine, is kept as-is) — this
 * never upgrades enforcement. Never throws.
 */
function mergePolicyV2(base: ProxyPolicy, raw: unknown, context: string): ProxyPolicy {
  const parsed = v2OverrideSchema.safeParse(raw);
  if (!parsed.success) {
    console.error(
      `g0 proxy: ${context} failed v2 override schema validation (${parsed.error.message}); overrides skipped`,
    );
    return base;
  }
  const obj = parsed.data;

  const merged: ProxyPolicy = {
    version: base.version,
    mode: base.mode,
    onError: base.onError,
    limits: { ...base.limits },
    rules: [...base.rules],
    response: { ...base.response },
    thresholds: base.thresholds ? { ...base.thresholds } : undefined,
    detectors: base.detectors ? { ...base.detectors } : undefined,
    edm: base.edm ? [...base.edm] : undefined,
    dataflow: base.dataflow ? [...base.dataflow] : undefined,
    context: base.context ? { ...base.context } : undefined,
    positiveSecurity: base.positiveSecurity,
  };

  applyScalarFields(merged, obj as unknown as Record<string, unknown>, context);
  applyV2Blocks(merged, obj, context);

  if (Array.isArray(obj.rules)) {
    obj.rules.forEach((r, index) => {
      const compiled = compileRuleV2(r, index, context);
      if (compiled) merged.rules.push(compiled); // appended after base rules
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
  let policy: ProxyPolicy;
  if (globalResult.status === 'ok') {
    // `isV2Raw` is the ONE gate into the v2 compile path (Task 5, Policy
    // DSL v2, see the section above). Anything else — `version: 1`,
    // `version: 2.5`, a string `"2"`, or no `version` key at all — falls
    // through to `compilePolicy`, the EXACT same call this line made
    // before this task existed. This is the concrete mechanism that
    // guarantees a v1/version-less file is byte-identical: it never even
    // reaches the v2 branch.
    policy = isV2Raw(globalResult.raw)
      ? compilePolicyV2(globalResult.raw, `policy file "${globalPath}"`)
      : compilePolicy(globalResult.raw, `policy file "${globalPath}"`);
  } else {
    policy = defaultPolicy();
  }

  if (opts?.serverName) {
    const serverPath = path.join(dir, 'policies', `${opts.serverName}.yaml`);
    const serverResult = readYamlFile(serverPath);
    if (serverResult.status === 'ok') {
      const serverContext = `per-server policy file "${serverPath}"`;
      // Whichever compile path produced the (possibly already-merged) base
      // policy decides which merge path an override goes through — a v2
      // base always merges via the v2 override schema, a v1 base always
      // merges via today's v1 `mergePolicy`, unchanged.
      policy =
        policy.version === 2
          ? mergePolicyV2(policy, serverResult.raw, serverContext)
          : mergePolicy(policy, serverResult.raw, serverContext);
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
 * `coach` never blocks and never modifies the message. Under v1, it only
 * ever appears as an OUTPUT of this adjustment, never as a rule author's
 * input `action` (v1 rule actions are `allow`/`deny`/`alert`, enforced by
 * `VALID_RULE_ACTIONS`). The v2 DSL (Task 5) additionally allows a rule
 * author to write `action: coach` directly (`VALID_RULE_ACTIONS_V2`) — the
 * parameter type below is widened to accept that additively, and the
 * existing logic already handles it correctly with NO change: `'coach'` is
 * not `'deny'`, so in `alert` mode it passes through unchanged (line 2
 * below), and in `enforce` mode it's honored as-is (line 3) — exactly the
 * "never blocks, forwarded as a loud warning" semantic `coach` always had.
 * `observe` mode still collapses everything (including an explicit v2
 * `coach` rule) to `alert`, consistent with observe's "everything is
 * log-only" contract.
 */
function adjustAction(action: 'allow' | 'deny' | 'alert' | 'coach', mode: ProxyMode): ProxyAction {
  if (mode === 'observe') return 'alert';
  if (mode === 'alert') return action === 'deny' ? 'coach' : action;
  return action;
}

// ─────────────────────────────────────────────────────────────────────────
// EvalContext — optional provenance/dataflow context (see provenance.ts)
// ─────────────────────────────────────────────────────────────────────────

/**
 * Optional context threaded through `evaluateCall`/`evaluateResponse` so
 * they can fold `g0 proxy`'s runtime dataflow tracking (`./provenance.ts`)
 * into the same precedence-based decision as everything else. Entirely
 * optional and additive: every field is optional, and BOTH evaluators
 * reproduce today's behavior byte-for-byte when `ctx` is omitted — see each
 * function's doc comment. This is the trailing param both evaluators
 * accept; existing callers that pass no `ctx` are unaffected.
 */
export interface EvalContext {
  /** The MCP server this call/response belongs to (typically `runProxy`'s `opts.serverName`). */
  destinationServer?: string;
  /**
   * The tool this decision concerns — for `evaluateCall`, the tool being
   * CALLED (a potential dataflow *sink*: is tainted data flowing into its
   * arguments?); for `evaluateResponse`, the tool that PRODUCED the
   * response (a potential dataflow *source*, whose volume/velocity
   * counters get consulted). Same field name, direction-dependent meaning
   * — same as the `toolName` parameter both functions already take
   * positionally.
   */
  destinationTool?: string;
  /** This session's taint/dataflow tracker. Required for either evaluator to consult provenance at all — see `./provenance.ts`. */
  provenance?: SessionProvenance;
  /** Override for `SessionProvenance.getVolumeStats`'s velocity window (ms). Omitted -> the provenance instance's own configured default. */
  volumeWindow?: number;
}

function summarizeDataflow(findings: DataflowFinding[]): string | undefined {
  if (findings.length === 0) return undefined;
  const labels = findings.slice(0, 5).map((f) => `${f.originTool} -> ${f.destinationTool}`);
  const suffix = findings.length > 5 ? ` (+${findings.length - 5} more)` : '';
  return `Dataflow: response data from [${labels.join(', ')}]${suffix} must not flow into this call's arguments`;
}

/**
 * Consult `ctx.provenance` for a cross-tool dataflow violation in this
 * call's arguments, and — if found — turn it into a decision candidate the
 * SAME way a matched policy rule would: a `deny`-*wanted* action, run
 * through `adjustAction` so it obeys the same mode semantics as every other
 * decision (never a silent block outside `enforce` mode; downgraded to
 * `coach` in `alert` mode, to `alert` in `observe` mode). Returns
 * `undefined` (no candidate) when `ctx`/`ctx.provenance` is absent or no
 * dataflow is detected. Never throws.
 */
function dataflowCandidate(
  ctx: EvalContext | undefined,
  toolName: string,
  args: unknown,
  policy: ProxyPolicy,
): PolicyDecision | undefined {
  if (!ctx?.provenance) return undefined;
  try {
    const findings = ctx.provenance.detectDataflow(ctx.destinationTool ?? toolName, args, policy.limits.maxScanBytes);
    if (findings.length === 0) return undefined;
    return {
      action: adjustAction('deny', policy.mode),
      direction: 'request',
      message: summarizeDataflow(findings),
      confidence: 0.9,
      signals: findings.map((f) => `dataflow:${f.originTool}->${f.destinationTool}`),
      reason: "provenance: response data from a different tool appeared in this call's arguments",
    };
  } catch {
    return undefined;
  }
}

/**
 * Consult `ctx.provenance`'s bounded volume/velocity counters for the tool
 * that produced this response, and — if it has emitted an unusually high
 * number of sensitive tokens within the configured window — turn that into
 * an `alert` decision candidate. Deliberately never higher than `alert`
 * (via `adjustAction`, which is a no-op on an already-`alert` wanted
 * action in every mode): a heuristic volume signal alone must never block
 * or redact traffic. Returns `undefined` when `ctx`/`ctx.provenance` is
 * absent or the tool is under threshold. Never throws.
 *
 * `policy.context.volume.{windowMs,alertThreshold}` (Task 5, v2 `context`
 * block) can override the window/threshold below — `policy.context` is
 * `undefined` for every v1/version-less policy (only `compilePolicyV2`/
 * `mergePolicyV2` ever set it), so `policy.context?.X ?? <original
 * default>` is byte-identical to the pre-Task-5 behavior for v1.
 */
function velocityCandidate(ctx: EvalContext | undefined, toolName: string, policy: ProxyPolicy): PolicyDecision | undefined {
  if (!ctx?.provenance) return undefined;
  try {
    const tool = ctx.destinationTool ?? toolName;
    const threshold = policy.context?.volumeAlertThreshold ?? VELOCITY_ALERT_THRESHOLD;
    const windowOverride = ctx.volumeWindow ?? policy.context?.volumeWindowMs;
    const stats = ctx.provenance.getVolumeStats(tool, windowOverride);
    if (!stats || stats.windowCount < threshold) return undefined;
    return {
      action: adjustAction('alert', policy.mode),
      direction: 'response',
      message: `Tool "${tool}" emitted ${stats.windowCount} sensitive token(s) within ${stats.windowMs}ms`,
      confidence: 0.5,
      signals: ['provenance-velocity', `count:${stats.windowCount}`],
      reason: 'provenance: high-velocity sensitive-data emission from this tool',
    };
  } catch {
    return undefined;
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Policy DSL v2 (Task 5) — confidence-fusion candidates, positive security,
// and edm[]/dataflow[] onMatch enforcement candidates.
//
// Every function in this block is guarded so it is a no-op / returns
// `undefined` unless the CALLER already knows it's dealing with a v2
// policy (`policy.version === 2`) — most guard on that directly; the two
// exported "onMatch" candidate builders (`edmMatchCandidate`,
// `dataflowMatchCandidate`) are called from `proxy-core.ts`, where the hit
// arrays they consult (`EdmMatch[]`/`DataflowFinding[]`) are computed
// independently of `evaluateCall`/`evaluateResponse` — see that file's
// module docblock for why EDM/dataflow enforcement lives there rather than
// inside the evaluators themselves.
// ─────────────────────────────────────────────────────────────────────────

const SEVERITY_CONFIDENCE: Record<'critical' | 'high' | 'medium' | 'low', number> = {
  critical: 0.95,
  high: 0.85,
  medium: 0.6,
  low: 0.3,
};

/** Map a `ResponseFinding.severity` to a confidence for fusion purposes — injection/IOC findings (see `response-inspector.ts`) carry a severity but no numeric confidence today, unlike secret findings (Task 2). Used ONLY by the v2 fusion path; never changes `ResponseFinding` itself. */
function severityToConfidence(severity: 'critical' | 'high' | 'medium' | 'low'): number {
  return SEVERITY_CONFIDENCE[severity] ?? 0.5;
}

const SEVERITY_RANK: Record<'critical' | 'high' | 'medium' | 'low', number> = { critical: 3, high: 2, medium: 1, low: 0 };

/** The highest-ranked severity among a set of findings, defaulting to `'low'` for an empty input. Used to pick the `severity` argument `decide()` takes (see `./confidence.ts`). */
function worstSeverity(severities: Array<'critical' | 'high' | 'medium' | 'low'>): ConfidenceSeverity {
  let worst: ConfidenceSeverity = 'low';
  for (const s of severities) {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[worst]) worst = s;
  }
  return worst;
}

/**
 * Build confidence-fusion context multipliers from `policy.context.destinations`
 * (Task 5's v2 `context` block) for one destination tool name. Returns `[]`
 * whenever `policy.context` is absent (always true for v1) or `toolName`
 * isn't a string — a pure, additive, no-op default.
 */
function destinationMultipliers(policy: ProxyPolicy, toolName: string | undefined): ContextMultiplier[] {
  if (!policy.context || typeof toolName !== 'string') return [];
  const out: ContextMultiplier[] = [];
  if (policy.context.untrustedDestinations?.some((re) => re.test(toolName))) {
    out.push({ factor: UNTRUSTED_DESTINATION_FACTOR, signal: 'context:untrusted-destination' });
  }
  if (policy.context.trustedDestinations?.some((re) => re.test(toolName))) {
    out.push({ factor: TRUSTED_DESTINATION_FACTOR, signal: 'context:trusted-destination' });
  }
  return out;
}

/**
 * Turn a `decide()` output into a `PolicyDecision.action`. `'deny'` is
 * mode-adjusted via `adjustAction` (so v2's fused confidence still can
 * never silently block traffic outside `enforce` mode — the same
 * invariant every other decision in this file honors); `'redact'`/`'coach'`
 * are applied as-is (mirroring how the EXISTING `redact` secret-finding
 * candidate in `evaluateResponse` already bypasses `adjustAction` — content
 * redaction is a safe, non-blocking mutation regardless of mode, and
 * `coach` is already the maximally-safe "forward but warn loudly" outcome
 * with nothing left to downgrade); `'allow'` produces no candidate at all
 * (the caller simply doesn't push one).
 */
function fusedAction(fused: 'allow' | 'coach' | 'redact' | 'deny', policy: ProxyPolicy): ProxyAction {
  return fused === 'deny' ? adjustAction('deny', policy.mode) : fused;
}

/**
 * The v2 replacement for `dataflowCandidate`'s fixed `0.9 -> deny`
 * hardcode: the SAME `ctx.provenance.detectDataflow` call, but its
 * confidence is now run through `fuseSignals`/`decide` against
 * `policy.thresholds` (falling back to `DEFAULT_THRESHOLDS`) — so an
 * operator's `thresholds` block (and `context.destinations` multipliers)
 * genuinely change the outcome for a dataflow signal under v2, instead of
 * always wanting `deny` regardless of configuration. `evaluateCall` only
 * calls this function when `policy.version === 2`; `dataflowCandidate`
 * (unchanged) is still used for every v1/version-less policy. Never throws.
 */
function dataflowFusionCandidate(
  ctx: EvalContext | undefined,
  toolName: string,
  args: unknown,
  policy: ProxyPolicy,
): PolicyDecision | undefined {
  if (!ctx?.provenance) return undefined;
  try {
    const findings = ctx.provenance.detectDataflow(ctx.destinationTool ?? toolName, args, policy.limits.maxScanBytes);
    if (findings.length === 0) return undefined;

    const fusionFindings: FusionFinding[] = findings.map((f) => ({
      confidence: DATAFLOW_BASE_CONFIDENCE,
      signal: `dataflow:${f.originTool}->${f.destinationTool}`,
    }));
    const multipliers = destinationMultipliers(policy, ctx.destinationTool ?? toolName);
    const { score, signals } = fuseSignals(fusionFindings, multipliers);
    const thresholds = policy.thresholds ?? DEFAULT_THRESHOLDS;
    // Dataflow (tainted secret data crossing a tool boundary) is treated as
    // a 'high'-severity signal for threshold-shifting purposes — see
    // `./confidence.ts`'s `SEVERITY_THRESHOLD_SHIFT`.
    const fused = decide(score, 'high', thresholds);
    if (fused === 'allow') return undefined;

    return {
      action: fusedAction(fused, policy),
      direction: 'request',
      message: summarizeDataflow(findings),
      confidence: score,
      signals,
      reason: 'confidence fusion (Task 5): dataflow signal(s) crossed a policy threshold',
    };
  } catch {
    return undefined;
  }
}

/**
 * v2-only `positiveSecurity` allow-list posture: a tool call whose name
 * matches none of `policy.positiveSecurity.allowedTools` contributes a
 * `policy.positiveSecurity.defaultAction` candidate (mode-adjusted). A
 * matching tool contributes nothing — the allow-list only ever ADDS
 * restriction on top of whatever the rest of the policy already decided
 * (via the normal `deny > redact > coach > alert > allow` precedence in
 * `evaluateCall`), it never grants a bypass. Returns `undefined` whenever
 * `policy.version !== 2` or `policy.positiveSecurity` is absent (always
 * true for v1). Never throws.
 */
function positiveSecurityCandidate(policy: ProxyPolicy, toolName: unknown): PolicyDecision | undefined {
  if (policy.version !== 2 || !policy.positiveSecurity) return undefined;
  try {
    const ps = policy.positiveSecurity;
    if (typeof toolName === 'string' && ps.allowedTools.some((re) => re.test(toolName))) return undefined;
    return {
      action: adjustAction(ps.defaultAction, policy.mode),
      direction: 'request',
      message: `positive-security: tool "${String(toolName)}" is not on the allow-list`,
      signals: ['positive-security:not-allow-listed'],
      reason: 'positiveSecurity: default-deny posture — tool not explicitly allow-listed',
    };
  } catch {
    return undefined;
  }
}

/**
 * v2-only confidence-fusion pass over a tool response's findings
 * (secret/injection/ioc, see `response-inspector.ts`), combining ALL of
 * them via `fuseSignals`/`decide` against `policy.thresholds` (falling
 * back to `DEFAULT_THRESHOLDS`). `evaluateResponse` only calls this when
 * `policy.version === 2`; it is purely ADDITIVE to the existing secret/
 * injection/rule/velocity candidates already in `candidates` — the
 * combination across ALL of them (via `pickHighestPrecedence`) is what
 * lets a MEDIUM secret finding plus an unrelated LOW injection pattern
 * corroborate into a stronger combined decision than either alone would
 * produce under the pre-Task-5 flat rules. Never throws.
 */
function responseFusionCandidate(policy: ProxyPolicy, findings: ResponseFinding[]): PolicyDecision | undefined {
  try {
    if (!Array.isArray(findings) || findings.length === 0) return undefined;

    const fusionFindings: FusionFinding[] = findings.map((f) => {
      const confidence = typeof f.confidence === 'number' ? f.confidence : severityToConfidence(f.severity);
      return { confidence, signal: confidenceTierSlug(f.category, confidence) };
    });
    const severity = worstSeverity(findings.map((f) => f.severity));
    const { score, signals } = fuseSignals(fusionFindings);
    const thresholds = policy.thresholds ?? DEFAULT_THRESHOLDS;
    const fused = decide(score, severity, thresholds);
    if (fused === 'allow') return undefined;

    return {
      action: fusedAction(fused, policy),
      direction: 'response',
      message: `Confidence-fused decision (score=${score.toFixed(2)}, action=${fused}): ${summarizeFindings(findings)}`,
      confidence: score,
      signals,
      reason: 'confidence fusion (Task 5): combined response-finding signal score crossed a policy threshold',
    };
  } catch {
    return undefined;
  }
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
 *
 * `ctx` is optional and additive: when omitted, this function's control
 * flow and return value are byte-for-byte identical to before `ctx`
 * existed (rule matching short-circuits on the first hit and returns
 * immediately, exactly as it always has) — see
 * `tests/unit/proxy-provenance.test.ts`'s backward-compatibility
 * regression suite. When `ctx.provenance` is present, a detected
 * cross-tool dataflow violation (see `./provenance.ts`) becomes an
 * additional decision candidate, combined with the rule-based decision via
 * the same `deny > redact > coach > alert > allow` precedence
 * `evaluateResponse` uses (`pickHighestPrecedence`).
 *
 * Under a v2 policy (`policy.version === 2`, Task 5) TWO more things
 * happen, both strictly ADDITIVE and both unreachable for a v1/version-less
 * policy (`policy.version` is never `2` unless `compilePolicyV2` produced
 * it — see `loadPolicy`):
 *  - the dataflow candidate is computed via confidence FUSION
 *    (`dataflowFusionCandidate`, driven by `policy.thresholds`) instead of
 *    Task 4's fixed `0.9 -> deny` (`dataflowCandidate`) — so `thresholds`/
 *    `context` genuinely change the outcome for a dataflow signal;
 *  - `policy.positiveSecurity`'s allow-list (if configured) can contribute
 *    an additional restrictive candidate.
 * Both compose into the SAME `pickHighestPrecedence` call every other
 * candidate here already goes through.
 */
export function evaluateCall(
  policy: ProxyPolicy,
  _method: string,
  toolName: string,
  args: unknown,
  ctx?: EvalContext,
): PolicyDecision {
  try {
    let ruleDecision: PolicyDecision = { action: 'allow', direction: 'request' };
    for (const rule of policy.rules) {
      if (rule.direction !== 'request') continue;
      if (!ruleMatchesCall(rule, toolName, args)) continue;
      ruleDecision = {
        action: adjustAction(rule.action, policy.mode),
        ruleId: rule.id,
        message: rule.message,
        direction: 'request',
      };
      break; // first-match-wins among rules, exactly as before
    }

    const candidates: PolicyDecision[] = [ruleDecision];

    const dataflow =
      policy.version === 2 ? dataflowFusionCandidate(ctx, toolName, args, policy) : dataflowCandidate(ctx, toolName, args, policy);
    if (dataflow) candidates.push(dataflow);

    if (policy.version === 2) {
      const ps = positiveSecurityCandidate(policy, toolName);
      if (ps) candidates.push(ps);
    }

    // candidates.length === 1 (just ruleDecision) is EXACTLY the pre-Task-5
    // "!dataflow -> return ruleDecision" short circuit — same object,
    // same reference, no new allocation on the v1/no-ctx hot path.
    if (candidates.length === 1) return ruleDecision;
    return pickHighestPrecedence(candidates);
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
 *
 * `ctx` is optional and additive: when omitted, the `candidates` array
 * (and therefore the returned decision) is built EXACTLY as before `ctx`
 * existed — see `tests/unit/proxy-provenance.test.ts`'s
 * backward-compatibility regression suite. When `ctx.provenance` is
 * present, a high-velocity sensitive-data signal (see `./provenance.ts`'s
 * volume/velocity counters) can contribute an additional `alert` candidate.
 *
 * Under a v2 policy (`policy.version === 2`, Task 5), one more ADDITIVE
 * candidate is folded in: a confidence-FUSION pass over every finding
 * (`responseFusionCandidate`, driven by `policy.thresholds`/`decide` — see
 * `./confidence.ts`). This is unreachable for a v1/version-less policy.
 */
export function evaluateResponse(
  policy: ProxyPolicy,
  toolName: string,
  inspection: InspectionResult,
  ctx?: EvalContext,
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

    const velocity = velocityCandidate(ctx, toolName, policy);
    if (velocity) candidates.push(velocity);

    if (policy.version === 2) {
      const fused = responseFusionCandidate(policy, findings);
      if (fused) candidates.push(fused);
    }

    if (candidates.length === 0) return { action: 'allow', direction: 'response' };
    return pickHighestPrecedence(candidates);
  } catch {
    return { action: 'allow', direction: 'response' };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// Policy DSL v2 — enforcement wiring surface for proxy-core.ts
//
// `EdmMatch[]` (Task 3) and `DataflowFinding[]` (Task 4) are both computed
// in `proxy-core.ts`, OUTSIDE `evaluateCall`/`evaluateResponse` — EDM
// scanning needs the loaded `EdmIndex[]` (session-level state that isn't
// threaded into the evaluators), and the request-side `dataflowHits` used
// here is the SAME independent audit-purposes call `proxy-core.ts` already
// made before this task (see its module docblock). Rather than re-plumb
// those hit arrays into `EvalContext`, the three functions below let
// `proxy-core.ts` turn them into `PolicyDecision` candidates and fold them
// into whatever `evaluateCall`/`evaluateResponse` already decided, via the
// SAME `deny > redact > coach > alert > allow` precedence every other
// candidate in this file uses. This is where Task 3's EDM and Task 4's
// dataflow finally ENFORCE (under a v2 policy) — Task 3 explicitly scoped
// EDM as "detect, don't enforce" and named this task as the one that wires
// `edm[]`'s `onMatch`.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Combine a `base` decision (already computed by `evaluateCall`/
 * `evaluateResponse`) with zero or more additional v2-only candidates
 * (`undefined` entries — "no candidate" — are filtered out), via the same
 * `pickHighestPrecedence` every other decision in this file uses. When
 * every extra is `undefined` (e.g. no EDM/dataflow rules configured, or
 * none matched), this returns `base` UNCHANGED (same reference) — the
 * v1/no-v2-rules case is a true no-op, not just an equal-value copy.
 */
export function combineDecisions(base: PolicyDecision, extras: Array<PolicyDecision | undefined>): PolicyDecision {
  try {
    const list = Array.isArray(extras) ? extras.filter((d): d is PolicyDecision => !!d) : [];
    if (list.length === 0) return base;
    return pickHighestPrecedence([base, ...list]);
  } catch {
    return base;
  }
}

/**
 * Turn a set of `EdmMatch[]` hits into a `PolicyDecision` candidate driven
 * by `policy.edm[]`'s configured `onMatch` actions, mode-adjusted exactly
 * like a rule (`deny`/`alert`/`coach` go through `adjustAction`; `'allow'`
 * is honored as a literal, unadjusted no-op candidate). Only ever produces
 * a candidate for indexes that BOTH matched (`edmHits`) AND have an
 * explicit `edm[]` policy entry — an EDM index with no policy entry stays
 * detect-only (audited, never enforced), exactly Task 3's original
 * behavior. When multiple matched rules disagree, the HIGHEST-precedence
 * wanted action wins (mirrors how multiple matched policy rules would
 * combine via `pickHighestPrecedence` elsewhere in this file).
 *
 * There is deliberately NO `'redact'` in `onMatch`'s domain: unlike a
 * structured-detector hit (which carries an exact `start`/`end` span, see
 * `./detectors/structured.ts`), an `EdmMatch` carries no offset or value at
 * all (see `./edm.ts`'s plaintext-never-persists guarantee) — there is no
 * span to surgically redact, only "block the whole message" (`deny`) or
 * "let it through with a warning" (`alert`/`coach`) are well-defined.
 * Returns `undefined` (no candidate) whenever `policy.version !== 2`,
 * `policy.edm` is unset, or nothing matched. Never throws.
 */
export function edmMatchCandidate(policy: ProxyPolicy, edmHits: EdmMatch[], direction: ProxyDirection): PolicyDecision | undefined {
  if (policy.version !== 2 || !Array.isArray(policy.edm) || policy.edm.length === 0) return undefined;
  try {
    if (!Array.isArray(edmHits) || edmHits.length === 0) return undefined;
    const matched = policy.edm.filter((r) => edmHits.some((h) => h.indexName === r.index));
    if (matched.length === 0) return undefined;

    let wanted: 'allow' | 'deny' | 'alert' | 'coach' = 'allow';
    for (const r of matched) {
      if (ACTION_PRECEDENCE[r.onMatch] > ACTION_PRECEDENCE[wanted]) wanted = r.onMatch;
    }

    return {
      action: adjustAction(wanted, policy.mode),
      direction,
      message: `EDM exact-data-match enforced by policy: ${matched.map((r) => r.index).join(', ')}`,
      confidence: 0.99,
      signals: matched.map((r) => `edm:${r.index}`),
      reason: 'edm[] policy: an outbound/response value matched a fingerprinted index with a configured onMatch action',
    };
  } catch {
    return undefined;
  }
}

/**
 * Turn a set of `DataflowFinding[]` hits into a `PolicyDecision` candidate
 * driven by `policy.dataflow[]`'s configured from/to tool+server matchers
 * and `onMatch` action. A rule matches a finding when EVERY matcher it
 * specifies matches (an omitted `from`/`to`/`tool`/`server` matches
 * anything for that field), mirroring how an empty `tools:` list on a
 * regular rule matches every tool. This composes with (does not replace)
 * the confidence-fusion dataflow candidate `evaluateCall` already computed
 * under v2 (`dataflowFusionCandidate`) — an operator can declare a
 * SPECIFIC from/to flow that must always `deny` regardless of confidence
 * thresholds, on top of the general fused signal. Same "no `redact`" design
 * as `edmMatchCandidate` — a `DataflowFinding` carries no matched-value
 * offset either (see `./provenance.ts`'s plaintext-never-leaks guarantee).
 * Returns `undefined` whenever `policy.version !== 2`, `policy.dataflow` is
 * unset, or nothing matched. Never throws.
 */
function dataflowRuleMatchesHit(
  rule: CompiledDataflowRule,
  h: DataflowFinding,
  destinationServer: string | undefined,
): boolean {
  if (rule.fromTool && !rule.fromTool.test(h.originTool)) return false;
  if (rule.fromServer && !rule.fromServer.test(h.originServer)) return false;
  if (rule.toTool && !rule.toTool.test(h.destinationTool)) return false;
  // A `to.server` constraint that can't be VERIFIED (destinationServer
  // absent/non-string) is treated as UNMET, not as "no constraint" — an
  // unverifiable condition must never cause a rule to match more broadly
  // than intended. In production `destinationServer` is always
  // `opts.serverName` (a required string), so this only matters for direct
  // unit-level callers of this exported function.
  if (rule.toServer && (typeof destinationServer !== 'string' || !rule.toServer.test(destinationServer))) return false;
  return true;
}

export function dataflowMatchCandidate(
  policy: ProxyPolicy,
  hits: DataflowFinding[],
  destinationServer: string | undefined,
): PolicyDecision | undefined {
  if (policy.version !== 2 || !Array.isArray(policy.dataflow) || policy.dataflow.length === 0) return undefined;
  try {
    if (!Array.isArray(hits) || hits.length === 0) return undefined;

    // Walk rule x hit pairs directly (rather than filter-rules-then-map-
    // all-hits) so `matchedHits`/`signals`/`message` below reflect ONLY the
    // hits that actually satisfied some rule's constraints — an unrelated
    // dataflow hit that happens to co-occur on the same request but matches
    // no configured rule must never appear in the enforcement message, even
    // though `hits` (the full per-request finding array) contains it.
    let wanted: 'allow' | 'deny' | 'alert' | 'coach' = 'allow';
    const matchedHits: DataflowFinding[] = [];
    const seenHitKeys = new Set<string>();
    for (const rule of policy.dataflow) {
      for (const h of hits) {
        if (!dataflowRuleMatchesHit(rule, h, destinationServer)) continue;
        if (ACTION_PRECEDENCE[rule.onMatch] > ACTION_PRECEDENCE[wanted]) wanted = rule.onMatch;
        const key = `${h.originTool} ${h.destinationTool} ${h.category}`;
        if (!seenHitKeys.has(key)) {
          seenHitKeys.add(key);
          matchedHits.push(h);
        }
      }
    }
    if (matchedHits.length === 0) return undefined;

    return {
      action: adjustAction(wanted, policy.mode),
      direction: 'request',
      message: summarizeDataflow(matchedHits),
      confidence: DATAFLOW_BASE_CONFIDENCE,
      signals: matchedHits.map((h) => `dataflow:${h.originTool}->${h.destinationTool}`),
      reason: 'dataflow[] policy: a from/to flow matched a configured onMatch action',
    };
  } catch {
    return undefined;
  }
}

/**
 * Resolve the structured-detector list `response-inspector.ts` should run,
 * honoring `policy.detectors`'s enable/disable/confidence-override config
 * (Task 5's v2 `detectors` block). Returns `undefined` whenever
 * `policy.detectors` is unset (always true for v1 — `response-inspector.ts`
 * then falls back to its own `ALL_STRUCTURED_DETECTORS` default, byte-
 * identical to before this task) or on any internal error (fail OPEN to the
 * full, unmodified detector list — never silently disable detection because
 * of a bug in this function). Bounded: iterates the fixed, small
 * `ALL_STRUCTURED_DETECTORS` array (6 entries today), no per-request cost
 * tied to input size. Never throws.
 */
export function resolveDetectors(policy: ProxyPolicy): StructuredDetector[] | undefined {
  if (!policy.detectors) return undefined;
  try {
    const cfg = policy.detectors;
    const list: StructuredDetector[] = [];
    for (const d of ALL_STRUCTURED_DETECTORS) {
      const override = cfg[d.id];
      if (!override) {
        list.push(d);
        continue;
      }
      if (override.enabled === false) continue; // disabled -> omit entirely
      if (typeof override.confidence === 'number') {
        const fixedConfidence = Math.max(0, Math.min(1, override.confidence));
        list.push({
          id: d.id,
          category: d.category,
          find(text: string) {
            try {
              return d.find(text).map((hit) => ({ ...hit, confidence: fixedConfidence }));
            } catch {
              return [];
            }
          },
        });
      } else {
        list.push(d);
      }
    }
    return list;
  } catch {
    return undefined; // fail open -> caller uses the default full detector list
  }
}
