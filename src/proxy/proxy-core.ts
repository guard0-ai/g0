/**
 * Proxy core for `g0 proxy` — the stdio MITM that sits between an IDE/agent
 * client and a real MCP server.
 *
 * ```
 * client (IDE)  <->  [ runProxy: this module ]  <->  spawned real MCP server
 *    stdin/stdout                                       child stdin/stdout
 * ```
 *
 * `runProxy` spawns the real server, reads the client's requests off its own
 * stdin and the server's responses off the child's stdout, and pipes each
 * line through P3's policy engine (`evaluateCall`/`evaluateResponse`) and
 * P2's response inspector, forwarding, denying, or redacting as directed.
 * Every decision is recorded via P4's `appendAudit`.
 *
 * Non-negotiable invariants (this is in the critical path of the user's
 * IDE — a bug here must never corrupt or hang the client<->server stream):
 *  - `stdout` carries ONLY forwarded JSON-RPC lines. No banner, no
 *    `console.log`, no diagnostics — those all go to stderr.
 *  - Nothing thrown here escapes the read/write loop. Per-line processing
 *    is wrapped in try/catch and fails open (`policy.onError`, default
 *    `'open'`): a request-side bug forwards the raw line unmodified (or, in
 *    `'closed'` mode, synthesizes a deny error); a response-side bug ALWAYS
 *    forwards the raw line, regardless of `onError` — dropping a response
 *    the client is blocked waiting on would hang the IDE forever, which is
 *    strictly worse than forwarding an uninspected line.
 *  - A `deny`'d request is never forwarded to the child; a synthesized
 *    JSON-RPC error (same id) goes back to the client instead.
 *  - Framing is streaming/per-line (P1's `LineSplitter`) — the whole stream
 *    is never buffered.
 *  - The child always inherits the proxy's own `cwd` (see the spawn call
 *    below for why this must not be overridden).
 */

import { spawn as nodeSpawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import * as os from 'node:os';

import { CorrelationMap, LineSplitter, extractToolCall, parseLine } from './jsonrpc.js';
import { extractResponseText, inspectResponseText } from './response-inspector.js';
import { evaluateCall, evaluateResponse, loadPolicy } from './policy.js';
import { appendAudit } from './audit-log.js';
import { loadEdmIndexes, matchEdmIndexes } from './edm.js';
import type { EdmMatch } from './edm.js';
import type { AuditRecord, JsonRpcMessage, ParsedLine } from '../types/proxy.js';

// ─────────────────────────────────────────────────────────────────────────
// Pure JSON-RPC-shape helpers (unit-testable in isolation)
// ─────────────────────────────────────────────────────────────────────────

/** JSON-RPC error code used for a g0-policy-denied tool call. */
export const DENY_ERROR_CODE = -32001;

/**
 * Build the JSON-RPC error line sent back to the client in place of a
 * `deny`'d `tools/call` request — same `id`, so the client's pending
 * request resolves (as an error) instead of hanging.
 */
export function synthesizeDenyError(id: number | string, message?: string): string {
  const payload: JsonRpcMessage = {
    jsonrpc: '2.0',
    id,
    error: {
      code: DENY_ERROR_CODE,
      message: message && message.length > 0 ? message : 'Blocked by g0 policy',
    },
  };
  return JSON.stringify(payload);
}

/**
 * Build the JSON-RPC *result* (not error) line sent back to the client in
 * place of a `deny`'d tool *response*. This is a valid `tools/call` result
 * with `isError: true` — not a JSON-RPC protocol error — so MCP clients that
 * only render tool results (rather than surfacing protocol-level errors)
 * still show the user why the call was blocked.
 */
export function buildBlockedResponse(id: number | string, summary?: string): string {
  const text = `[g0] This tool response was blocked by policy: ${
    summary && summary.length > 0 ? summary : 'policy violation'
  }`;
  const payload: JsonRpcMessage = {
    jsonrpc: '2.0',
    id,
    result: { content: [{ type: 'text', text }], isError: true },
  };
  return JSON.stringify(payload);
}

/**
 * Rebuild a `tools/call` response message with `redactedText` swapped in
 * for its text content, preserving the original `id` and any non-text
 * content items (images, resources, ...) untouched. Handles the two shapes
 * `extractResponseText` understands (`content: [{type:'text',...}]` and a
 * bare string `result`); an unrecognized `result` shape falls back to a
 * minimal, valid, redacted text result so the output is always well-formed
 * JSON-RPC.
 *
 * Multiple text blocks: the FIRST text block is replaced with the (already
 * fully redacted) text and any additional text blocks are dropped, since
 * `inspectResponseText` redacts over the *concatenation* of all text blocks
 * and there is no reliable way to re-split that back across the originals.
 */
export function buildRedactedResponse(message: JsonRpcMessage, redactedText: string): string {
  const clone: JsonRpcMessage = { ...message };
  const result = clone.result;

  if (typeof result === 'string') {
    clone.result = redactedText;
    return JSON.stringify(clone);
  }

  if (result && typeof result === 'object' && !Array.isArray(result)) {
    const resultObj: Record<string, unknown> = { ...(result as Record<string, unknown>) };
    const content = resultObj.content;

    if (Array.isArray(content)) {
      const newContent: unknown[] = [];
      let replacedFirst = false;
      for (const item of content) {
        const isTextItem =
          item !== null &&
          typeof item === 'object' &&
          (item as { type?: unknown }).type === 'text' &&
          typeof (item as { text?: unknown }).text === 'string';

        if (isTextItem) {
          if (!replacedFirst) {
            newContent.push({ ...(item as object), text: redactedText });
            replacedFirst = true;
          }
          // Drop subsequent text blocks — see doc comment above.
        } else {
          newContent.push(item); // non-text content untouched
        }
      }
      if (!replacedFirst) {
        newContent.push({ type: 'text', text: redactedText });
      }
      resultObj.content = newContent;
      clone.result = resultObj;
      return JSON.stringify(clone);
    }
  }

  // Unrecognized result shape — still produce a valid, redacted result.
  clone.result = { content: [{ type: 'text', text: redactedText }] };
  return JSON.stringify(clone);
}

/** Best-effort extraction of `.id` from a raw line, for fail-closed error synthesis. Never throws. */
function tryExtractId(raw: string): number | string | undefined {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const id = (parsed as Record<string, unknown>).id;
      if (typeof id === 'number' || typeof id === 'string') return id;
    }
  } catch {
    // not JSON — nothing to extract
  }
  return undefined;
}

/** `ParsedLine.id`, where present, regardless of which union member it is. */
function parsedId(parsed: ParsedLine): number | string | undefined {
  if (parsed.kind === 'request' || parsed.kind === 'response') return parsed.id;
  if (parsed.kind === 'other') return parsed.message.id;
  return undefined;
}

/** `ParsedLine.method`, where present, regardless of which union member it is. */
function parsedMethod(parsed: ParsedLine): string | undefined {
  if (parsed.kind === 'request' || parsed.kind === 'notification') return parsed.method;
  if (parsed.kind === 'other') return parsed.message.method;
  return undefined;
}

/**
 * Best-effort JSON text of a `tools/call` request's `args`, for EDM
 * scanning — an outbound secret is almost always a string value nested
 * inside the args object (`{"apiKey": "sk-..."}`), and `EdmIndex.match`'s
 * `line` mode tokenizer already extracts quoted values out of JSON text.
 * Mirrors `policy.ts`'s private `safeStringify`; never throws.
 */
function safeArgsText(args: unknown): string {
  try {
    const s = JSON.stringify(args);
    return typeof s === 'string' ? s : String(args);
  } catch {
    return String(args);
  }
}

/**
 * EDM findings never carry the matched value (see `edm.ts`'s module
 * docblock) — only these two small helpers turn a set of `EdmMatch`es into
 * the metadata-only shapes `AuditRecord` and its `findings` array already
 * support. `confidence`/`signals`/`context` mirror how `structured.ts`
 * hits eventually reach `ResponseFinding`, kept consistent across both the
 * request (args) and response (text) scan sites below.
 */
function edmAuditExtras(edmHits: EdmMatch[]): Pick<AuditRecord, 'confidence' | 'signals' | 'context'> {
  if (edmHits.length === 0) return {};
  return {
    confidence: 0.99,
    signals: edmHits.map((h) => `edm:${h.indexName}`),
    context: { edmIndexes: edmHits.map((h) => h.indexName) },
  };
}

/** `EdmMatch[]` -> audit-log-safe finding labels (index name only, never the matched value). */
function edmFindingNames(edmHits: EdmMatch[]): string[] {
  return edmHits.map((h) => `EDM exact-data-match: ${h.indexName}`);
}

/** Exit code for a child killed by a signal, matching shell convention (128 + signal number). */
function exitCodeForSignal(signal: NodeJS.Signals): number {
  const num = (os.constants.signals as Record<string, number>)[signal];
  return 128 + (typeof num === 'number' ? num : 0);
}

/** `stream.end()`, but never let stream teardown throw out of the pipe. */
function safeEnd(stream: NodeJS.WritableStream): void {
  try {
    stream.end();
  } catch {
    // best effort — the process is shutting down anyway
  }
}

// ─────────────────────────────────────────────────────────────────────────
// ProxyOptions / runProxy
// ─────────────────────────────────────────────────────────────────────────

export interface ProxyOptions {
  /** Logical server name, used for policy overrides, audit logs, and diagnostics. */
  serverName: string;
  /** The real MCP server's executable, e.g. `'npx'`. */
  command: string;
  /** The real MCP server's args, e.g. `['-y', 'server-postgres']`. */
  args: string[];
  /** Policy file directory. Defaults to `~/.g0/proxy` (see `loadPolicy`). */
  policyDir?: string;
  /** Audit log directory. Defaults to `~/.g0/proxy` (see `appendAudit`). */
  auditDir?: string;
  /** The client's request stream. Defaults to `process.stdin`. Injectable for tests. */
  stdin?: NodeJS.ReadableStream;
  /** The client-facing response stream. Defaults to `process.stdout`. Injectable for tests. */
  stdout?: NodeJS.WritableStream;
  /** Where g0's own diagnostics go. Defaults to `process.stderr`. Injectable for tests. */
  stderr?: NodeJS.WritableStream;
  /** Injectable for tests; defaults to the real `node:child_process` `spawn`. */
  spawnFn?: typeof import('node:child_process').spawn;
  /** Environment passed to the spawned child. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
}

/**
 * Spawn `opts.command opts.args`, wire the client's stdio to it through
 * g0's policy/inspection pipeline, and resolve once the child exits (or
 * fails to spawn) with its exit code — mirroring what a bare, unproxied
 * server would have exited with, so the caller can `process.exit(code)` and
 * the client sees a normal server death (and can restart it) rather than a
 * g0-specific failure mode.
 */
export async function runProxy(opts: ProxyOptions): Promise<number> {
  const stdin = opts.stdin ?? process.stdin;
  const stdout = opts.stdout ?? process.stdout;
  const stderr = opts.stderr ?? process.stderr;
  const spawnFn = opts.spawnFn ?? nodeSpawn;
  const policy = loadPolicy({ serverName: opts.serverName, dir: opts.policyDir });
  // Exact-Data-Match indexes (see edm.ts). Loaded ONCE per session, right
  // next to the policy — a missing/empty `fingerprints/` dir yields `[]`,
  // making every EDM scan below a no-op, byte-for-byte identical to today's
  // behavior (see `matchEdmIndexes`'s early-return on an empty array).
  const edmIndexes = loadEdmIndexes(opts.policyDir);

  const diag = (msg: string): void => {
    try {
      stderr.write(`g0 proxy: ${msg}\n`);
    } catch {
      // diagnostics must never throw out of the pipe
    }
  };

  const auditSafe = (record: Omit<AuditRecord, 'ts' | 'serverName'>): void => {
    try {
      appendAudit({ ts: new Date().toISOString(), serverName: opts.serverName, ...record }, opts.auditDir);
    } catch {
      // appendAudit already never throws; stay defensive anyway
    }
  };

  return new Promise<number>((resolve) => {
    let settled = false;
    let onSigint: ((sig: NodeJS.Signals) => void) | undefined;
    let onSigterm: ((sig: NodeJS.Signals) => void) | undefined;

    const cleanupSignalHandlers = (): void => {
      if (onSigint) process.removeListener('SIGINT', onSigint);
      if (onSigterm) process.removeListener('SIGTERM', onSigterm);
    };

    const settle = (code: number): void => {
      if (settled) return;
      settled = true;
      cleanupSignalHandlers();
      resolve(code);
    };

    // ── client-stream failure (EPIPE etc.) handling ──────────────────────
    // `stdin/child.stdout` (readable) already have `.on('error')` handlers
    // below. The WRITABLE streams the proxy writes TO — `stdout`/`stderr`,
    // i.e. process.stdout/stderr in production — did not: `.write()` can
    // fail *asynchronously* (e.g. the IDE closes the pipe mid-response ->
    // EPIPE), which Node reports as an `'error'` event on the writable, not
    // as a synchronous throw from `.write()`. An unhandled `'error'` event
    // is an uncaught exception that crashes this whole process, orphaning
    // the spawned child with no cleanup and no exit code. Guard against that
    // here: treat a write error on either stream as "the client is gone",
    // and initiate a graceful shutdown instead of crashing.
    let clientStreamGone = false;
    const handleClientStreamError = (streamName: 'stdout' | 'stderr') => (err: unknown): void => {
      if (clientStreamGone) return;
      clientStreamGone = true;
      const message = err instanceof Error ? err.message : String(err);
      // Best-effort only: `diag` itself never throws, and if BOTH streams
      // are gone this is simply a no-op.
      diag(`client ${streamName} stream error (client likely gone), shutting down: ${message}`);
      // No one left to write responses to — there is nothing more useful to
      // do than terminate the child. `child.on('close')` below still drives
      // resolution (with a signal-derived exit code), so we don't settle()
      // here directly and risk racing/duplicating that logic.
      try {
        child.kill('SIGTERM');
      } catch {
        // best effort — child may already be gone
      }
    };

    let child: ChildProcess;
    try {
      // NOTE ON cwd: intentionally NOT set here. The child inherits the
      // proxy process's own working directory. P3's policy `pathArgs` /
      // `allowPaths` relative-path resolution (`resolvePathValue`, in
      // policy.ts) resolves relative values against `process.cwd()` of THIS
      // process at evaluation time. That is only a correct allowlist check
      // if the spawned MCP server resolves its own relative file args
      // against that same directory — i.e. child cwd === proxy cwd. Do not
      // add a `cwd` override here without re-validating that assumption
      // against P3's path checks.
      child = spawnFn(opts.command, opts.args, {
        stdio: ['pipe', 'pipe', 'inherit'],
        env: opts.env ?? process.env,
      }) as ChildProcess;
    } catch (err) {
      diag(`failed to start "${opts.command}": ${err instanceof Error ? err.message : String(err)}`);
      settle(1);
      return;
    }

    // Attach only once `child` is assigned (the handler kills it).
    stdout.on('error', handleClientStreamError('stdout'));
    stderr.on('error', handleClientStreamError('stderr'));

    // `child.stdin` is a WRITABLE this proxy writes TO, same failure mode as
    // client `stdout`/`stderr` above: if the wrapped server dies (or closes
    // its stdin) while a write is in flight, Node reports that
    // ASYNCHRONOUSLY as an `'error'` event (e.g. EPIPE) — not a synchronous
    // throw from `.write()`, so `writeToChild`'s try/catch (below) and the
    // `child.stdin?.end()` try/catch in the `stdin.on('end', ...)` handler
    // (below) can never catch it. An unhandled `'error'` event is an
    // uncaught exception that crashes this whole proxy process — mid
    // in-flight request, instead of the orderly `child.on('close')` -> flush
    // -> settle-with-exit-code shutdown a dead child should drive. Attach
    // this BEFORE any write can happen (right here, immediately after
    // spawn) and swallow it: `child.on('close')`/`child.on('error')` below
    // already own resolving `runProxy`.
    child.stdin?.on('error', () => {
      // Child's stdin is gone; nothing to do here — child 'close'/'exit'
      // drives shutdown.
    });

    const correlations = new CorrelationMap();
    const requestSplitter = new LineSplitter();
    const responseSplitter = new LineSplitter();

    const writeToChild = (line: string): void => {
      try {
        child.stdin?.write(line + '\n');
      } catch {
        // child stdin gone (e.g. already exiting) — nothing more to do
      }
    };
    const writeToClient = (line: string): void => {
      try {
        stdout.write(line + '\n');
      } catch {
        // client stdout gone — nothing more to do
      }
    };

    // ── requests: client -> child ──────────────────────────────────────
    function handleRequestLine(raw: string): void {
      try {
        const parsed = parseLine(raw);

        if (parsed.kind === 'request' && parsed.method === 'tools/call') {
          const call = extractToolCall(parsed.message);
          if (!call) {
            // Malformed tools/call shape: nothing meaningful to evaluate on
            // the request side, and we forward as-is rather than guessing
            // (never drop a request). But defense-in-depth: the RESPONSE to
            // this call still needs inspecting (secret redaction / injection
            // detection) — register a placeholder correlation so
            // `handleResponseLine`'s `correlations.take(id)` doesn't treat
            // it as an untracked response and skip inspection entirely.
            correlations.register(parsed.id, {
              id: parsed.id,
              toolName: '<unknown>',
              method: parsed.method,
              args: undefined,
            });
            writeToChild(raw);
            auditSafe({
              direction: 'request',
              kind: 'tools/call',
              id: parsed.id,
              method: parsed.method,
              action: 'allow',
              note: 'malformed tools/call params; forwarded unchecked, response will still be inspected',
            });
            return;
          }

          correlations.register(parsed.id, {
            id: parsed.id,
            toolName: call.toolName,
            method: parsed.method,
            args: call.args,
          });
          const decision = evaluateCall(policy, parsed.method, call.toolName, call.args);

          // Exact-Data-Match scan of the OUTBOUND args — a fingerprinted
          // secret/PII value being sent OUT in a tool call is the exfil
          // case (see edm.ts's module docblock). `edmIndexes` is `[]`
          // whenever no corpus has been fingerprinted, so `matchEdmIndexes`
          // short-circuits to `[]` and every line below is a no-op,
          // identical to pre-EDM behavior. This never changes `decision`
          // (that mapping is Task 5's job, via policy `edm[]` rules) — it
          // only makes the match visible in the audit trail and on stderr,
          // metadata-only, never the matched value.
          // Guarded by `edmIndexes.length > 0` (rather than relying solely on
          // `matchEdmIndexes`'s own empty-array short circuit) so the common
          // case — no corpus ever fingerprinted — skips even the
          // `JSON.stringify(call.args)` cost, not just the matching itself.
          const edmHits =
            edmIndexes.length > 0
              ? matchEdmIndexes(edmIndexes, safeArgsText(call.args), { maxScanBytes: policy.limits.maxScanBytes })
              : [];
          if (edmHits.length > 0) {
            diag(
              `EDM match: outbound arg for tools/call "${call.toolName}" matched fingerprint index(es): ${edmHits
                .map((h) => h.indexName)
                .join(', ')}`,
            );
          }

          if (decision.action === 'deny') {
            correlations.take(parsed.id); // no real response is ever coming
            writeToClient(synthesizeDenyError(parsed.id, decision.message));
            auditSafe({
              direction: 'request',
              kind: 'tools/call',
              id: parsed.id,
              toolName: call.toolName,
              method: parsed.method,
              action: 'deny',
              ruleId: decision.ruleId,
              note: decision.message,
              findings: edmHits.length > 0 ? edmFindingNames(edmHits) : undefined,
              ...edmAuditExtras(edmHits),
            });
            return;
          }

          // allow / alert / coach all forward — `alert` observes but never
          // blocks, and `coach` (a would-be `deny` downgraded by `alert`
          // mode; see adjustAction in policy.ts) NEVER blocks and NEVER
          // modifies the message either. It just gets a louder stderr
          // warning below, since it represents a rule that WOULD have
          // denied this call in enforce mode.
          writeToChild(raw);
          auditSafe({
            direction: 'request',
            kind: 'tools/call',
            id: parsed.id,
            toolName: call.toolName,
            method: parsed.method,
            action: decision.action,
            ruleId: decision.ruleId,
            note: decision.action === 'alert' || decision.action === 'coach' ? decision.message : undefined,
            findings: edmHits.length > 0 ? edmFindingNames(edmHits) : undefined,
            ...edmAuditExtras(edmHits),
          });
          if (decision.action === 'alert') {
            diag(`ALERT tools/call "${call.toolName}" (rule ${decision.ruleId ?? 'n/a'}): ${decision.message ?? ''}`);
          } else if (decision.action === 'coach') {
            diag(
              `⚠ COACH tools/call "${call.toolName}" — would be DENIED in enforce mode (rule ${decision.ruleId ?? 'n/a'}): ${decision.message ?? ''}`,
            );
          }
          return;
        }

        // Everything else — non-JSON, notifications, non-tools/call
        // requests (initialize, tools/list, ...), unclassifiable "other" —
        // is never policy-evaluated and never dropped: forward verbatim.
        writeToChild(raw);
        auditSafe({
          direction: 'request',
          kind: parsed.kind,
          id: parsedId(parsed),
          method: parsedMethod(parsed),
          action: 'allow',
        });
      } catch (err) {
        handleRequestError(raw, err);
      }
    }

    function handleRequestError(raw: string, err: unknown): void {
      const message = err instanceof Error ? err.message : String(err);
      diag(`internal error processing a client request line (onError:${policy.onError}): ${message}`);
      auditSafe({
        direction: 'request',
        kind: 'error',
        action: policy.onError === 'closed' ? 'deny' : 'allow',
        note: `internal error: ${message}`,
      });

      if (policy.onError === 'closed') {
        const id = tryExtractId(raw);
        if (id !== undefined) {
          writeToClient(synthesizeDenyError(id, 'Blocked by g0 policy (internal error, fail-closed)'));
        }
        // No id to reply to (e.g. a notification) -> nothing safe to send;
        // dropping is the closed-mode contract.
        return;
      }

      // fail-open (default): never corrupt/drop the stream over our own bug.
      writeToChild(raw);
    }

    // ── responses: child -> client ─────────────────────────────────────
    function handleResponseLine(raw: string): void {
      try {
        const parsed = parseLine(raw);

        if (parsed.kind !== 'response') {
          // Non-JSON banners, server-initiated notifications, unclassifiable
          // lines: pass through untouched (e.g. a pre-handshake banner).
          writeToClient(raw);
          return;
        }

        const info = correlations.take(parsed.id);
        if (!info) {
          // A response we never tracked as a tools/call (initialize,
          // tools/list, or one we already denied) — generic passthrough.
          writeToClient(raw);
          auditSafe({ direction: 'response', kind: 'response', id: parsed.id, action: 'allow' });
          return;
        }

        const text = extractResponseText(parsed.message.result);
        const inspection = inspectResponseText(text, {
          redactSecrets: policy.response.redactSecrets,
          maxScanBytes: policy.limits.maxScanBytes,
        });
        const decision = evaluateResponse(policy, info.toolName, inspection);
        const findingNames = inspection.findings.map((f) => f.name);

        // Exact-Data-Match scan of the response text (see edm.ts's module
        // docblock). Same no-op-when-empty guarantee as the request-side
        // scan above, and same scope: this makes a match visible in the
        // audit trail / on stderr, but never changes `decision` — actual
        // EDM-driven enforcement is Task 5's `edm[]` policy rules.
        const edmHits = matchEdmIndexes(edmIndexes, text, { maxScanBytes: policy.limits.maxScanBytes });
        const allFindingNames = edmHits.length > 0 ? [...findingNames, ...edmFindingNames(edmHits)] : findingNames;
        if (edmHits.length > 0) {
          diag(
            `EDM match: response for "${info.toolName}" matched fingerprint index(es): ${edmHits
              .map((h) => h.indexName)
              .join(', ')}`,
          );
        }

        if (decision.action === 'deny') {
          writeToClient(buildBlockedResponse(parsed.id, decision.message));
          auditSafe({
            direction: 'response',
            kind: 'response',
            id: parsed.id,
            toolName: info.toolName,
            action: 'deny',
            ruleId: decision.ruleId,
            note: decision.message,
            findings: allFindingNames.length > 0 ? allFindingNames : undefined,
            ...edmAuditExtras(edmHits),
          });
          return;
        }

        if (decision.action === 'redact') {
          if (inspection.redactedText !== undefined) {
            writeToClient(buildRedactedResponse(parsed.message, inspection.redactedText));
          } else {
            // Nothing to redact with (shouldn't normally happen) — fail
            // safe by forwarding the original rather than inventing text.
            writeToClient(raw);
          }
          auditSafe({
            direction: 'response',
            kind: 'response',
            id: parsed.id,
            toolName: info.toolName,
            action: 'redact',
            ruleId: decision.ruleId,
            note: decision.message,
            findings: allFindingNames.length > 0 ? allFindingNames : undefined,
            ...edmAuditExtras(edmHits),
          });
          return;
        }

        // allow / alert / coach: forward the original line unmodified.
        // `coach` (a would-be `deny` downgraded by `alert` mode; see
        // adjustAction in policy.ts) NEVER blocks and NEVER modifies the
        // response — it just gets a louder stderr warning below.
        writeToClient(raw);
        auditSafe({
          direction: 'response',
          kind: 'response',
          id: parsed.id,
          toolName: info.toolName,
          action: decision.action,
          ruleId: decision.ruleId,
          note: decision.action === 'alert' || decision.action === 'coach' ? decision.message : undefined,
          findings: allFindingNames.length > 0 ? allFindingNames : undefined,
          ...edmAuditExtras(edmHits),
        });
        if (decision.action === 'alert' && findingNames.length > 0) {
          diag(`ALERT response for "${info.toolName}": ${findingNames.join(', ')}`);
        } else if (decision.action === 'coach') {
          const findingsSuffix = findingNames.length > 0 ? ` (${findingNames.join(', ')})` : '';
          diag(
            `⚠ COACH response for "${info.toolName}" — would be DENIED in enforce mode${findingsSuffix}: ${decision.message ?? ''}`,
          );
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        diag(`internal error processing a server response line (always fail-open): ${message}`);
        auditSafe({ direction: 'response', kind: 'error', action: 'allow', note: `internal error: ${message}` });
        // Response-direction bugs ALWAYS fail open, regardless of
        // policy.onError: dropping a response the client is blocked
        // waiting on would hang the IDE forever, which is strictly worse
        // than forwarding an uninspected/unredacted line.
        writeToClient(raw);
      }
    }

    // ── wiring ────────────────────────────────────────────────────────
    stdin.on('data', (chunk: Buffer | string) => {
      for (const line of requestSplitter.push(chunk)) handleRequestLine(line);
    });
    stdin.on('end', () => {
      for (const line of requestSplitter.flush()) handleRequestLine(line);
      try {
        child.stdin?.end();
      } catch {
        // best effort
      }
    });
    stdin.on('error', () => {
      // Nothing more to read from the client; the child's own lifecycle
      // (its eventual 'exit') is what drives resolution from here.
    });

    child.stdout?.on('data', (chunk: Buffer | string) => {
      for (const line of responseSplitter.push(chunk)) handleResponseLine(line);
    });
    child.stdout?.on('error', () => {
      // Symmetric with stdin's 'error' handler above.
    });

    let outcomeSettled = false;

    child.on('error', (err) => {
      if (outcomeSettled) return;
      outcomeSettled = true;
      diag(`failed to run "${opts.command}": ${err.message}`);
      settle(127);
    });

    // Deliberately 'close', not 'exit': 'exit' fires the instant the child
    // process terminates, which can be BEFORE we have finished draining its
    // stdout pipe (a large final response can still be in flight in the OS
    // pipe buffer). 'close' fires only once the process has exited AND its
    // stdio streams have fully ended, so every byte the child wrote is
    // guaranteed to have already reached our 'data' handler above before we
    // flush/settle here. Using 'exit' here previously truncated any
    // in-flight response over the pipe's buffer size.
    child.on('close', (code, signal) => {
      if (outcomeSettled) return;
      outcomeSettled = true;
      for (const line of responseSplitter.flush()) handleResponseLine(line);
      safeEnd(stdout);
      const exitCode = code !== null ? code : signal ? exitCodeForSignal(signal) : 1;
      settle(exitCode);
    });

    // ── signal forwarding: never leave the child orphaned ───────────────
    onSigint = (sig: NodeJS.Signals): void => {
      try {
        child.kill(sig);
      } catch {
        // best effort
      }
    };
    onSigterm = onSigint;
    process.on('SIGINT', onSigint);
    process.on('SIGTERM', onSigterm);
  });
}
