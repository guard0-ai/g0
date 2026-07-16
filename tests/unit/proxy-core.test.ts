import { describe, expect, it } from 'vitest';

import { buildBlockedResponse, buildRedactedResponse, DENY_ERROR_CODE, synthesizeDenyError } from '../../src/proxy/proxy-core.js';
import type { JsonRpcMessage } from '../../src/types/proxy.js';

describe('synthesizeDenyError', () => {
  it('builds a JSON-RPC error with the same id and g0 error code', () => {
    const line = synthesizeDenyError(42, 'Blocked by g0 policy: destructive command');
    expect(JSON.parse(line)).toEqual({
      jsonrpc: '2.0',
      id: 42,
      error: { code: DENY_ERROR_CODE, message: 'Blocked by g0 policy: destructive command' },
    });
  });

  it('falls back to a default message when none is given', () => {
    const line = synthesizeDenyError('req-1');
    expect(JSON.parse(line)).toEqual({
      jsonrpc: '2.0',
      id: 'req-1',
      error: { code: DENY_ERROR_CODE, message: 'Blocked by g0 policy' },
    });
  });

  it('falls back to a default message for an empty-string message', () => {
    const line = synthesizeDenyError(1, '');
    expect(JSON.parse(line).error.message).toBe('Blocked by g0 policy');
  });

  it('preserves id:0 (falsy but valid)', () => {
    const line = synthesizeDenyError(0);
    expect(JSON.parse(line).id).toBe(0);
  });

  it('is valid JSON with no trailing newline embedded', () => {
    const line = synthesizeDenyError(1, 'x');
    expect(line.includes('\n')).toBe(false);
  });
});

describe('buildBlockedResponse', () => {
  it('builds a valid tools/call result (not a protocol error) with isError:true', () => {
    const line = buildBlockedResponse(7, '3 finding(s): Ignore previous instructions');
    const parsed = JSON.parse(line);
    expect(parsed).toEqual({
      jsonrpc: '2.0',
      id: 7,
      result: {
        content: [
          { type: 'text', text: '[g0] This tool response was blocked by policy: 3 finding(s): Ignore previous instructions' },
        ],
        isError: true,
      },
    });
  });

  it('falls back to a generic summary when none is given', () => {
    const line = buildBlockedResponse('id-1');
    const parsed = JSON.parse(line);
    expect(parsed.result.content[0].text).toBe('[g0] This tool response was blocked by policy: policy violation');
    expect(parsed.result.isError).toBe(true);
  });
});

describe('buildRedactedResponse', () => {
  it('replaces text in a single-text-block content result, preserving id', () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 5,
      result: { content: [{ type: 'text', text: 'my key is sk-abc123' }], isError: false },
    };
    const line = buildRedactedResponse(message, 'my key is [g0:redacted]');
    const parsed = JSON.parse(line);
    expect(parsed.id).toBe(5);
    expect(parsed.result.content).toEqual([{ type: 'text', text: 'my key is [g0:redacted]' }]);
    expect(parsed.result.isError).toBe(false);
  });

  it('keeps the first text block, drops additional text blocks, and preserves non-text items', () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      result: {
        content: [
          { type: 'text', text: 'first sk-abc123' },
          { type: 'image', data: 'base64...', mimeType: 'image/png' },
          { type: 'text', text: 'second sk-def456' },
        ],
      },
    };
    const line = buildRedactedResponse(message, '[g0:redacted-all]');
    const parsed = JSON.parse(line);
    expect(parsed.result.content).toEqual([
      { type: 'text', text: '[g0:redacted-all]' },
      { type: 'image', data: 'base64...', mimeType: 'image/png' },
    ]);
  });

  it('handles a bare string result', () => {
    const message: JsonRpcMessage = { jsonrpc: '2.0', id: 2, result: 'raw secret text' };
    const line = buildRedactedResponse(message, 'redacted text');
    expect(JSON.parse(line)).toEqual({ jsonrpc: '2.0', id: 2, result: 'redacted text' });
  });

  it('appends a text block when content has no existing text item', () => {
    const message: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 3,
      result: { content: [{ type: 'image', data: 'x', mimeType: 'image/png' }] },
    };
    const line = buildRedactedResponse(message, 'redacted');
    const parsed = JSON.parse(line);
    expect(parsed.result.content).toEqual([
      { type: 'image', data: 'x', mimeType: 'image/png' },
      { type: 'text', text: 'redacted' },
    ]);
  });

  it('falls back to a minimal valid result for an unrecognized result shape', () => {
    const message: JsonRpcMessage = { jsonrpc: '2.0', id: 4, result: 42 as unknown };
    const line = buildRedactedResponse(message, 'redacted');
    expect(JSON.parse(line)).toEqual({
      jsonrpc: '2.0',
      id: 4,
      result: { content: [{ type: 'text', text: 'redacted' }] },
    });
  });

  it('never throws, even on a garbage message', () => {
    expect(() => buildRedactedResponse({ jsonrpc: '2.0', id: 1 }, 'x')).not.toThrow();
  });
});
