/**
 * Shared types for `g0 proxy` — a stdio man-in-the-middle for MCP servers.
 *
 * This module is the single source of truth for the proxy's wire and
 * policy types. Later tasks (P2-P6: transport, rule engine, audit log,
 * CLI wiring) import from here rather than redefining these shapes.
 */

/** How the proxy enforces policy decisions. */
export type ProxyMode = 'enforce' | 'alert' | 'observe';

/**
 * The action a policy rule can take against a message.
 *
 * `coach` is "warn-loud-but-forward": the CLI analog of a coaching control.
 * It NEVER blocks and NEVER modifies the message — it always forwards, just
 * like `allow`/`alert` — but it emits a prominent `stderr` warning (see
 * `proxy-core.ts`) and is audited, because it represents a would-be `deny`
 * that a less-strict mode chose not to enforce (see `adjustAction` in
 * `policy.ts`). It exists so an operator running in `alert` mode can tell
 * "this rule never fired" apart from "this rule fired and I chose to let it
 * through" at a glance, without the proxy ever silently blocking traffic.
 */
export type ProxyAction = 'allow' | 'deny' | 'redact' | 'coach' | 'alert';

/** Which leg of the conversation a message belongs to. */
export type ProxyDirection = 'request' | 'response';

/** A JSON-RPC 2.0 message, loosely typed for defensive parsing. */
export interface JsonRpcMessage {
  jsonrpc: string;
  id?: number | string;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/**
 * The classification of a single raw line from the wire.
 *
 * `other` covers valid JSON-RPC that doesn't fit any of the recognized
 * shapes (e.g. a response with neither `result` nor `error`, or a message
 * with an `id` but no `method`/`result`/`error`).
 */
export type ParsedLine =
  | { kind: 'request'; id: number | string; method: string; params?: unknown; raw: string; message: JsonRpcMessage }
  | { kind: 'response'; id: number | string; raw: string; message: JsonRpcMessage }
  | { kind: 'notification'; method: string; params?: unknown; raw: string; message: JsonRpcMessage }
  | { kind: 'non-json'; raw: string }
  | { kind: 'other'; raw: string; message: JsonRpcMessage };

/** What the correlation map stores per in-flight request. */
export interface ToolCallInfo {
  id: number | string;
  toolName: string;
  method: string;
  args: unknown;
}

/** The outcome of evaluating policy rules against a message. */
export interface PolicyDecision {
  action: ProxyAction;
  ruleId?: string;
  message?: string;
  direction: ProxyDirection;
  /**
   * How confident the (future) fusion engine is in this decision, `0..1`.
   * Optional and unused by today's rule-based `evaluateCall`/
   * `evaluateResponse` — reserved for later tasks that layer confidence
   * scoring (validators, exact-data-match, provenance) on top of this
   * decision shape.
   */
  confidence?: number;
  /** Short machine-readable labels for what contributed to `confidence` (e.g. `["exact-match", "no-provenance"]`). Reserved for later tasks. */
  signals?: string[];
  /** Human-readable explanation of why this decision was made, distinct from the rule-author-supplied `message`. Reserved for later tasks. */
  reason?: string;
}

/**
 * One entry in the proxy's audit log.
 *
 * Every field here is metadata ABOUT a decision — never the sensitive value
 * itself. `context` in particular must only ever carry small, non-sensitive
 * descriptors (e.g. a matched field name or a source label), the same way
 * `findings` carries finding *names*, never finding *matches*. This is a
 * durable, on-disk, per-server log; anything sensitive written here would
 * defeat the whole point of the redaction the proxy performs in-line.
 */
export interface AuditRecord {
  ts: string;
  serverName: string;
  direction: ProxyDirection;
  kind: string;
  id?: number | string;
  toolName?: string;
  method?: string;
  action?: ProxyAction;
  ruleId?: string;
  note?: string;
  findings?: string[];
  /** Mirrors `PolicyDecision.confidence`, `0..1`. Reserved for later tasks. */
  confidence?: number;
  /** Mirrors `PolicyDecision.signals`. Reserved for later tasks. */
  signals?: string[];
  /**
   * Small, non-sensitive contextual metadata about the decision (e.g. which
   * field matched, which validator ran) — NEVER the sensitive value itself.
   * Reserved for later tasks.
   */
  context?: Record<string, unknown>;
}
