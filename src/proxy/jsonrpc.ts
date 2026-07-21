/**
 * JSON-RPC wire framing for `g0 proxy`.
 *
 * MCP over stdio is newline-delimited JSON-RPC 2.0: one JSON message per
 * line, no Content-Length headers, no embedded newlines inside a message.
 * This module reassembles complete lines from arbitrary chunk boundaries
 * (`LineSplitter`), classifies a line as a JSON-RPC request/response/
 * notification (`parseLine`), pulls the tool name out of a `tools/call`
 * request (`extractToolCall`), and correlates responses back to the
 * request that produced them (`CorrelationMap`).
 *
 * Pure, dependency-free, and defensive: nothing in here throws on
 * malformed input — unparseable or unrecognized input is classified and
 * handed back to the caller instead.
 */

import type { JsonRpcMessage, ParsedLine, ToolCallInfo } from '../types/proxy.js';

const NEWLINE = 0x0a; // '\n'
const CARRIAGE_RETURN = 0x0d; // '\r'

/** Default cap on unterminated buffered bytes before force-flushing (8 MB). */
export const DEFAULT_MAX_BUFFER_BYTES = 8 * 1024 * 1024;

/** Default cap on in-flight correlated requests before evicting the oldest. */
export const DEFAULT_MAX_CORRELATION_ENTRIES = 10_000;

export interface LineSplitterOptions {
  /**
   * If the buffered, not-yet-terminated data exceeds this many bytes, the
   * buffer is flushed as a single "line" and reset. Guards against a
   * pathological or binary stream that never emits a newline from
   * growing the buffer without bound (OOM). Defaults to 8 MB.
   */
  maxBufferBytes?: number;
}

/**
 * Stateful incremental line splitter. Feed it arbitrary `Buffer`/string
 * chunks (as they arrive off a socket/pipe) and it returns complete,
 * newline-stripped lines, buffering any trailing partial line until the
 * rest arrives in a later chunk.
 *
 * Handles `\n` and `\r\n` line endings, multiple lines per chunk, partial
 * lines split across chunk boundaries, and skips empty lines (they are
 * never emitted).
 */
export class LineSplitter {
  private buffer: Buffer = Buffer.alloc(0);
  private readonly maxBufferBytes: number;

  constructor(options: LineSplitterOptions = {}) {
    this.maxBufferBytes = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES;
  }

  /** Feed a chunk of data; returns any complete lines it produced. */
  push(chunk: Buffer | string): string[] {
    const incoming = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    this.buffer = this.buffer.length === 0 ? incoming : Buffer.concat([this.buffer, incoming]);

    const lines: string[] = [];
    let start = 0;

    while (true) {
      const idx = this.buffer.indexOf(NEWLINE, start);
      if (idx === -1) break;
      let end = idx;
      if (end > start && this.buffer[end - 1] === CARRIAGE_RETURN) end -= 1; // strip trailing \r
      const line = this.buffer.toString('utf8', start, end);
      if (line.length > 0) lines.push(line); // skip empty lines
      start = idx + 1;
    }

    this.buffer = start > 0 ? this.buffer.subarray(start) : this.buffer;

    if (this.buffer.length > this.maxBufferBytes) {
      const overflow = this.buffer.toString('utf8');
      this.buffer = Buffer.alloc(0);
      if (overflow.length > 0) lines.push(overflow);
    }

    return lines;
  }

  /** Flush any buffered partial line (e.g. on stream end). Resets state. */
  flush(): string[] {
    if (this.buffer.length === 0) return [];
    const remainder = this.buffer.toString('utf8');
    this.buffer = Buffer.alloc(0);
    return remainder.length > 0 ? [remainder] : [];
  }
}

/**
 * Classify a single raw line (already stripped of its trailing newline)
 * as a JSON-RPC request, response, notification, unclassifiable-but-valid
 * JSON ("other"), or non-JSON. Never throws.
 */
export function parseLine(raw: string): ParsedLine {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { kind: 'non-json', raw };
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { kind: 'non-json', raw };
  }

  const message = parsed as JsonRpcMessage;
  // Presence checks use !== undefined/null rather than truthiness so that
  // id:0 and id:"" are correctly treated as present ids.
  const hasId = message.id !== undefined && message.id !== null;
  const hasMethod = typeof message.method === 'string';

  if (hasMethod && hasId) {
    return {
      kind: 'request',
      id: message.id as number | string,
      method: message.method as string,
      params: message.params,
      raw,
      message,
    };
  }

  if (hasMethod && !hasId) {
    return {
      kind: 'notification',
      method: message.method as string,
      params: message.params,
      raw,
      message,
    };
  }

  if (!hasMethod && hasId && (message.result !== undefined || message.error !== undefined)) {
    return { kind: 'response', id: message.id as number | string, raw, message };
  }

  return { kind: 'other', raw, message };
}

/**
 * Extract `{ toolName, args }` from a `tools/call` request message.
 * Returns null for any other method, or if `params.name` isn't a string
 * (malformed/missing shape). Defensive: `params` may be anything.
 */
export function extractToolCall(msg: JsonRpcMessage): { toolName: string; args: unknown } | null {
  if (msg.method !== 'tools/call') return null;

  const params = msg.params;
  if (params === null || typeof params !== 'object' || Array.isArray(params)) return null;

  const name = (params as Record<string, unknown>).name;
  if (typeof name !== 'string' || name.length === 0) return null;

  return { toolName: name, args: (params as Record<string, unknown>).arguments };
}

export interface CorrelationMapOptions {
  /**
   * Maximum number of in-flight (registered but not yet taken) entries.
   * Once exceeded, the oldest registered entry is evicted. Guards against
   * a client that sends requests but never reads responses leaking
   * memory indefinitely. Defaults to 10 000.
   */
  maxEntries?: number;
}

/**
 * Tracks in-flight requests keyed by JSON-RPC id so a later response can
 * be correlated back to the tool call that produced it. Bounded: once
 * `maxEntries` is exceeded, the oldest entry is evicted (insertion order).
 */
export class CorrelationMap {
  private readonly entries = new Map<number | string, ToolCallInfo>();
  private readonly maxEntries: number;

  constructor(options: CorrelationMapOptions = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_CORRELATION_ENTRIES;
  }

  /** Record an in-flight request (call this when a `tools/call` request is sent). */
  register(id: number | string, info: ToolCallInfo): void {
    // Delete-then-set so a re-register of an existing id moves it to the
    // most-recently-inserted position for eviction purposes.
    this.entries.delete(id);
    this.entries.set(id, info);

    while (this.entries.size > this.maxEntries) {
      const oldestKey = this.entries.keys().next().value;
      if (oldestKey === undefined) break;
      this.entries.delete(oldestKey);
    }
  }

  /** Look up and remove the in-flight info for `id` (call this on a response). */
  take(id: number | string): ToolCallInfo | undefined {
    const info = this.entries.get(id);
    this.entries.delete(id);
    return info;
  }

  /** Number of currently in-flight (registered but not yet taken) entries. */
  get size(): number {
    return this.entries.size;
  }
}

/**
 * Extract the concatenated text content of an MCP `tools/call` result.
 *
 * Handles the standard shape `{ content: [{ type: 'text', text: '...' }] }`
 * (non-text content items — images, resources — are ignored) as well as a
 * bare string result. Any other/garbage shape yields `''`; this function
 * never throws.
 */
export function extractResponseText(result: unknown): string {
  try {
    if (typeof result === 'string') return result;

    if (result && typeof result === 'object' && !Array.isArray(result)) {
      const content = (result as { content?: unknown }).content;
      if (Array.isArray(content)) {
        let out = '';
        for (const item of content) {
          if (
            item &&
            typeof item === 'object' &&
            (item as { type?: unknown }).type === 'text' &&
            typeof (item as { text?: unknown }).text === 'string'
          ) {
            out += (item as { text: string }).text;
          }
        }
        return out;
      }
    }

    return '';
  } catch {
    return '';
  }
}
