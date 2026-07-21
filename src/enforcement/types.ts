/**
 * Transport-neutral types for the enforcement engine. A transport (the MCP
 * stdio proxy today, the Claude Code hook adapter in Phase B) maps its
 * native tool-call legs onto `EnforcementEvent`s, calls `decide()`, and acts
 * on the returned `EngineDecision` — the engine itself never touches a
 * stream, a process, or a hook contract.
 */

import type { AuditRecord, PolicyDecision } from '../types/proxy.js';
import type { ResponseFinding } from './response-inspector.js';

/** One tool-call leg, in transport-neutral form. */
export interface EnforcementEvent {
  transport: 'mcp-stdio' | 'claude-hook';
  direction: 'request' | 'response';
  /** Logical destination server (proxy: the wrapped MCP server's name). */
  serverName: string;
  toolName: string;
  /** Tool-call arguments. On the response leg: the ORIGINATING request's args. */
  args?: unknown;
  /** Response leg only: the extracted response text. */
  responseText?: string;
}

/** Everything a transport needs to act on + record one decision. */
export interface EngineDecision {
  decision: PolicyDecision;
  /** Merged finding labels for the audit record (undefined when none). */
  findingNames?: string[];
  /** Response leg: raw inspection findings (empty array on the request leg). */
  inspectionFindings: ResponseFinding[];
  auditExtras: Pick<AuditRecord, 'confidence' | 'signals' | 'context'>;
  /** Response leg: fully redacted text, when redaction has something to work with. */
  redactedText?: string;
  /** Diagnostic lines (no prefix) to emit, in order, BEFORE acting on the decision. */
  diagnostics: string[];
}
