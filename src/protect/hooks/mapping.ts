/**
 * Maps Claude Code hook stdin JSON onto the engine's `EnforcementEvent`.
 * Anything unmappable returns `null` and the caller allows — malformed
 * input is a fail-open case, never an error (spec §10).
 */

import { extractResponseText } from '../../proxy/jsonrpc.js';
import type { EnforcementEvent } from '../../enforcement/types.js';

/** Bound stringified tool responses fed to the engine (1 MiB). */
const MAX_RESPONSE_TEXT = 1024 * 1024;

export interface MappedHookInput {
  sessionId: string;
  hookEventName: 'PreToolUse' | 'PostToolUse';
  event: EnforcementEvent;
}

export function mapHookInput(raw: unknown): MappedHookInput | null {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;

  const hookEventName = record.hook_event_name;
  if (hookEventName !== 'PreToolUse' && hookEventName !== 'PostToolUse') return null;

  const toolName = record.tool_name;
  if (typeof toolName !== 'string' || toolName.length === 0) return null;

  const sessionId = typeof record.session_id === 'string' && record.session_id.length > 0
    ? record.session_id
    : 'unknown';

  const base = {
    transport: 'claude-hook' as const,
    serverName: 'claude-code',
    toolName,
    args: record.tool_input,
  };

  if (hookEventName === 'PreToolUse') {
    return { sessionId, hookEventName, event: { ...base, direction: 'request' } };
  }

  return {
    sessionId,
    hookEventName,
    event: { ...base, direction: 'response', responseText: responseToText(record.tool_response) },
  };
}

function responseToText(response: unknown): string {
  if (typeof response === 'string') return response.slice(0, MAX_RESPONSE_TEXT);
  // MCP-shaped `{ content: [{type:'text',...}] }` responses extract cleanly;
  // anything else is stringified so the detectors still get a look at it.
  const mcpText = extractResponseText(response);
  if (mcpText.length > 0) return mcpText.slice(0, MAX_RESPONSE_TEXT);
  try {
    return JSON.stringify(response ?? '').slice(0, MAX_RESPONSE_TEXT);
  } catch {
    return '';
  }
}
