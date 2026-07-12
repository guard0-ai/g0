/**
 * Session-scoped provenance / dataflow tracking for `g0 proxy`.
 *
 * ── Why a MITM can do this and a static scanner can't ──────────────────────
 *
 * `g0 proxy` sits on BOTH legs of every MCP tool call — the request the
 * client sends and the response the server returns. A static analyzer (see
 * `../analyzers/cross-tool-correlation.ts`) can only reason about what tools
 * an agent *could* combine, from its declared capabilities; it never sees an
 * actual value move from one tool's output into another tool's input. A
 * runtime MITM does: it can tag a token the instant it appears in tool A's
 * RESPONSE, and later — in the SAME session — notice that exact token
 * reappearing in tool B's REQUEST arguments. That's the classic
 * confused-deputy / exfiltration pattern an LLM agent can be tricked into
 * (read a secret via tool A, then unwittingly forward it through tool B),
 * and it is only observable from this vantage point.
 *
 * `SessionProvenance` is this module's runtime sibling of
 * `detectDangerousToolCombinations` in `../analyzers/cross-tool-correlation.ts`:
 * where that module flags a *static* capability combination, this module
 * flags an *actual* value crossing a tool boundary, observed live.
 *
 * ── Design constraints (see task brief) ─────────────────────────────────────
 *
 *  - Never throw. Every public method is wrapped in try/catch and degrades
 *    to a safe no-op (`void` / `[]` / `undefined`) — a bug here must forward
 *    the JSON-RPC line unmodified, exactly like every other proxy layer (see
 *    `proxy-core.ts`, which is fail-open on the response leg regardless).
 *  - Bounded. The taint LRU mirrors `CorrelationMap` in `jsonrpc.ts` exactly:
 *    a `Map`, delete-then-set to refresh recency, evict-oldest-on-insert
 *    once over `DEFAULT_MAX_TAINT_ENTRIES`. The per-tool volume/velocity
 *    tracker is bounded the same way (capped distinct-tool count) plus a
 *    capped per-tool timestamp history. Hashing on the REQUEST side is
 *    gated by the same `maxScanBytes` budget the rest of the proxy respects
 *    and skips entirely once nothing has ever been tainted this session
 *    (`this.tags.size === 0`) — mirroring `EdmIndex.match`'s empty-index
 *    short circuit in `edm.ts`. There is deliberately no candidate-COUNT
 *    cap on tokenization (see `detectDataflow`'s doc comment): `edm.ts`'s
 *    own docblock explains why a count-based cap is itself an evasion
 *    vector (filler ahead of the real payload exhausts the cap first) —
 *    the byte budget is the only bound needed, and total token count is
 *    inherently `O(text.length)` regardless.
 *  - Secrets never enter memory twice, and never leave this module in
 *    plaintext. A `TaintTag` stores only a SHA-256 `valueHash` of the
 *    tainted token — never the token itself — and `DataflowFinding`s (what
 *    reaches the policy engine and the audit log) carry only tool/server
 *    names and a category, never the matched value or its hash.
 *
 * ── Tokenization ─────────────────────────────────────────────────────────
 *
 * Reuses `lineModeCandidates` from `./edm.ts` (the same delimiter-bounded
 * "run of value characters" tokenizer EDM uses for `line`-mode matching) to
 * turn a `tools/call` request's stringified `arguments` into a bounded set
 * of candidate tokens, rather than inventing a third tokenization scheme.
 * Unlike EDM, there is no persistence and no salt: these hashes never leave
 * process memory and never touch disk, so a session-local, unsalted
 * SHA-256 is sufficient — see `hashToken`.
 *
 * ── Scope: which findings get tainted ───────────────────────────────────
 *
 * Only `category: 'secret'` response findings are tagged. "Sensitive
 * token" here means a value a real detector validated (Luhn/IBAN/ABA
 * checksum, a structurally-valid vendor key, or a context/entropy-gated
 * credential) — see `./detectors/structured.ts`. `injection`/`ioc` findings
 * are pattern matches on the RESPONSE text itself (prompt-injection
 * phrasing, a known-bad domain) rather than data an agent would
 * legitimately carry forward into another tool call, so tainting them would
 * mostly produce noisy, low-signal dataflow "findings" (e.g. two unrelated
 * tool calls both echoing the literal phrase "ignore previous
 * instructions") instead of real exfiltration signal.
 */

import * as crypto from 'node:crypto';

import { lineModeCandidates } from './edm.js';
import { safeStringify } from './policy.js';
import type { ResponseFinding } from './response-inspector.js';

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

/** Mirrors `jsonrpc.ts`'s `DEFAULT_MAX_CORRELATION_ENTRIES` — same bounded-LRU discipline, applied to tainted-value hashes instead of in-flight request ids. */
export const DEFAULT_MAX_TAINT_ENTRIES = 10_000;

/** Cap on distinct tool names tracked for volume/velocity purposes — bounds memory if a session churns through many tool names. */
const DEFAULT_MAX_VOLUME_TOOLS = 1_000;

/** Default velocity window for `getVolumeStats`, when neither the caller nor `EvalContext.volumeWindow` (see `policy.ts`) overrides it. */
export const DEFAULT_VELOCITY_WINDOW_MS = 60_000;

/** Cap on recent-timestamp history kept per tool for velocity counting — bounds memory per tool regardless of call volume. */
const MAX_TIMESTAMPS_PER_TOOL = 200;

/** Mirrors `response-inspector.ts`'s `MAX_FINDINGS` (findings are already capped there) — defensive belt-and-suspenders bound on tagging work per response. */
const MAX_TAGS_PER_RESPONSE = 50;

/** Bounded output — a single request is never allowed to produce an unbounded dataflow-finding array. */
const MAX_DATAFLOW_FINDINGS = 20;

/** Below this length a candidate token is not worth hashing/tainting — mirrors `edm.ts`'s own `MIN_TOKEN_LEN` floor (filters stray short fragments, never real secrets, which are always longer). */
const MIN_TOKEN_LEN = 4;

/** Default scan budget for `detectDataflow` when the caller doesn't pass one — mirrors `response-inspector.ts` / `edm.ts`'s shared 1 MiB default. */
const DEFAULT_MAX_SCAN_BYTES = 1_048_576;

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

/**
 * One tainted value, keyed by `valueHash` in `SessionProvenance`'s bounded
 * LRU. Never carries the plaintext token — see the module docblock.
 */
export interface TaintTag {
  /** SHA-256 hex digest of the tainted token — an opaque, one-way correlation key, never the plaintext. */
  valueHash: string;
  /** The tool whose RESPONSE this value was first observed in. */
  originTool: string;
  /** The MCP server that tool belongs to. */
  originServer: string;
  /** Mirrors `ResponseFinding.category`; today only ever `'secret'` — see the module docblock's "scope" section. */
  category: ResponseFinding['category'];
}

/**
 * A detected cross-tool dataflow: a value tainted in `originTool`'s
 * response reappeared in `destinationTool`'s request arguments, in the SAME
 * session. Metadata only — never the matched value.
 */
export interface DataflowFinding {
  originTool: string;
  originServer: string;
  destinationTool: string;
  category: ResponseFinding['category'];
}

/** A tool's bounded volume/velocity state. */
interface ToolVolumeState {
  /** Total sensitive tokens tagged from this tool for the life of the session (not windowed). */
  totalTagged: number;
  /** Recent tag timestamps (epoch ms), capped at `MAX_TIMESTAMPS_PER_TOOL`. */
  timestamps: number[];
}

/** `SessionProvenance.getVolumeStats`'s return shape. */
export interface VolumeStats {
  totalTagged: number;
  /** Number of tokens tagged within the last `windowMs` milliseconds. */
  windowCount: number;
  windowMs: number;
}

export interface SessionProvenanceOptions {
  maxTaintEntries?: number;
  maxVolumeTools?: number;
  velocityWindowMs?: number;
}

// ─────────────────────────────────────────────────────────────────────────
// Hashing
// ─────────────────────────────────────────────────────────────────────────

/**
 * Session-local, unsalted SHA-256 of a token. Unlike `edm.ts`'s persisted,
 * salted hashes (which defend against cross-INDEX correlation on disk),
 * this hash never leaves process memory and is never persisted — there is
 * nothing to salt against.
 */
function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

// ─────────────────────────────────────────────────────────────────────────
// SessionProvenance
// ─────────────────────────────────────────────────────────────────────────

/**
 * One instance per `runProxy` session (see `proxy-core.ts`, created right
 * beside its `CorrelationMap`). Tracks which tools have emitted which
 * sensitive tokens (`tagResponse`) and detects a tainted token flowing into
 * a *different* tool's request arguments (`detectDataflow`), plus bounded
 * per-tool volume/velocity counters (`getVolumeStats`).
 *
 * Every public method is defensive: it never throws, and on any internal
 * error degrades to its safe empty/no-op result — this is a MITM's hot
 * path, and a bug here must never corrupt or hang the proxied stream.
 */
export class SessionProvenance {
  private readonly tags = new Map<string, TaintTag>();
  private readonly maxTaintEntries: number;

  private readonly volume = new Map<string, ToolVolumeState>();
  private readonly maxVolumeTools: number;
  private readonly velocityWindowMs: number;

  constructor(options: SessionProvenanceOptions = {}) {
    this.maxTaintEntries = options.maxTaintEntries ?? DEFAULT_MAX_TAINT_ENTRIES;
    this.maxVolumeTools = options.maxVolumeTools ?? DEFAULT_MAX_VOLUME_TOOLS;
    this.velocityWindowMs = options.velocityWindowMs ?? DEFAULT_VELOCITY_WINDOW_MS;
  }

  /** Number of distinct tainted values currently tracked. Test/observability only. */
  get taintedCount(): number {
    return this.tags.size;
  }

  /**
   * Bounded LRU insert: delete-then-set to refresh recency, evict oldest
   * (insertion order) once over `maxTaintEntries` — mirrors
   * `CorrelationMap.register` in `jsonrpc.ts` exactly.
   */
  private setTag(hash: string, tag: TaintTag): void {
    this.tags.delete(hash);
    this.tags.set(hash, tag);
    while (this.tags.size > this.maxTaintEntries) {
      const oldestKey = this.tags.keys().next().value;
      if (oldestKey === undefined) break;
      this.tags.delete(oldestKey);
    }
  }

  private recordVolume(toolName: string, count: number, now: number): void {
    let state = this.volume.get(toolName);
    if (!state) state = { totalTagged: 0, timestamps: [] };
    state.totalTagged += count;
    for (let i = 0; i < count; i++) {
      state.timestamps.push(now);
      if (state.timestamps.length > MAX_TIMESTAMPS_PER_TOOL) state.timestamps.shift();
    }
    // Refresh recency + bound the number of distinct tools tracked, same
    // delete-then-set / evict-oldest discipline as `setTag`.
    this.volume.delete(toolName);
    this.volume.set(toolName, state);
    while (this.volume.size > this.maxVolumeTools) {
      const oldestKey = this.volume.keys().next().value;
      if (oldestKey === undefined) break;
      this.volume.delete(oldestKey);
    }
  }

  /**
   * Tag every `category: 'secret'` finding from `originTool`'s response
   * into the bounded taint LRU, and bump its volume counters. Never throws
   * — a bug here must not break the response pipeline (see
   * `proxy-core.ts`'s response handler, which is unconditionally fail-open
   * regardless of this method's outcome anyway).
   */
  tagResponse(originTool: string, originServer: string, findings: ResponseFinding[]): void {
    try {
      if (!Array.isArray(findings) || findings.length === 0) return;
      const now = Date.now();
      let tagged = 0;
      for (const finding of findings) {
        if (tagged >= MAX_TAGS_PER_RESPONSE) break;
        if (!finding || finding.category !== 'secret') continue;
        if (typeof finding.match !== 'string' || finding.match.length < MIN_TOKEN_LEN) continue;
        const hash = hashToken(finding.match);
        this.setTag(hash, { valueHash: hash, originTool, originServer, category: finding.category });
        tagged++;
      }
      if (tagged > 0) this.recordVolume(originTool, tagged, now);
    } catch {
      // never throw out of the proxy's response handler
    }
  }

  /**
   * Detect tainted values from a DIFFERENT tool appearing in
   * `requestingTool`'s request arguments — the runtime dataflow /
   * exfiltration signal. The same tool re-consuming its own prior output
   * is NOT a finding (that's the normal "read then use" pattern, not a
   * cross-tool leak).
   *
   * Bounded: skips entirely if nothing has ever been tainted this session
   * (`this.tags.size === 0`, mirroring `EdmIndex.match`'s empty-index short
   * circuit), skips entirely over `maxScanBytes` rather than scanning a
   * huge payload, and caps the returned array at `MAX_DATAFLOW_FINDINGS`.
   * Pure/read-only (never mutates taint state), so it is safe to call more
   * than once for the same request (e.g. once for a decision, once for
   * audit metadata — see `proxy-core.ts`). Never throws.
   */
  detectDataflow(requestingTool: string, args: unknown, maxScanBytes: number = DEFAULT_MAX_SCAN_BYTES): DataflowFinding[] {
    try {
      if (this.tags.size === 0) return [];
      const text = safeStringify(args);
      if (typeof text !== 'string' || text.length === 0) return [];
      if (text.length > maxScanBytes) return [];

      const findings: DataflowFinding[] = [];
      const seen = new Set<string>();
      for (const candidate of lineModeCandidates(text)) {
        if (findings.length >= MAX_DATAFLOW_FINDINGS) break;
        if (candidate.length < MIN_TOKEN_LEN) continue;
        const tag = this.tags.get(hashToken(candidate));
        if (!tag) continue;
        if (tag.originTool === requestingTool) continue; // same-tool reconsumption is not a finding
        const key = `${tag.originTool} ${requestingTool} ${tag.category}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          originTool: tag.originTool,
          originServer: tag.originServer,
          destinationTool: requestingTool,
          category: tag.category,
        });
      }
      return findings;
    } catch {
      return [];
    }
  }

  /**
   * Bounded volume/velocity counters for one tool: how many sensitive
   * tokens it has emitted total this session, and how many within the last
   * `windowMs` (defaults to this instance's configured `velocityWindowMs`,
   * itself defaulting to `DEFAULT_VELOCITY_WINDOW_MS`). Returns `undefined`
   * for a tool that has never been tagged. Never throws.
   */
  getVolumeStats(toolName: string, windowMs?: number): VolumeStats | undefined {
    try {
      const state = this.volume.get(toolName);
      if (!state) return undefined;
      const window = typeof windowMs === 'number' && windowMs > 0 ? windowMs : this.velocityWindowMs;
      const cutoff = Date.now() - window;
      let windowCount = 0;
      for (const t of state.timestamps) if (t >= cutoff) windowCount++;
      return { totalTagged: state.totalTagged, windowCount, windowMs: window };
    } catch {
      return undefined;
    }
  }
}
