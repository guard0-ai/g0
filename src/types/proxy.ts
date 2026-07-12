/**
 * Shared types for `g0 proxy` — a stdio man-in-the-middle for MCP servers.
 *
 * This module is the single source of truth for the proxy's wire and
 * policy types. Later tasks (P2-P6: transport, rule engine, audit log,
 * CLI wiring) import from here rather than redefining these shapes.
 */

/** How the proxy enforces policy decisions. */
export type ProxyMode = 'enforce' | 'alert' | 'observe';

/** The action a policy rule can take against a message. */
export type ProxyAction = 'allow' | 'deny' | 'redact' | 'alert';

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
}

/** One entry in the proxy's audit log. */
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
}
