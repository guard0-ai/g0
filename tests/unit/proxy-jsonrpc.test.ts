import { describe, it, expect } from 'vitest';
import { LineSplitter, parseLine, extractToolCall, CorrelationMap } from '../../src/proxy/jsonrpc.js';
import type { JsonRpcMessage, ToolCallInfo } from '../../src/types/proxy.js';

describe('LineSplitter', () => {
  it('returns a single line delivered in one chunk', () => {
    const splitter = new LineSplitter();
    const lines = splitter.push('{"a":1}\n');
    expect(lines).toEqual(['{"a":1}']);
  });

  it('buffers a partial line split across two chunks', () => {
    const splitter = new LineSplitter();
    expect(splitter.push('{"a":1')).toEqual([]);
    expect(splitter.push('}\n')).toEqual(['{"a":1}']);
  });

  it('splits multiple lines delivered in one chunk', () => {
    const splitter = new LineSplitter();
    const lines = splitter.push('{"a":1}\n{"a":2}\n{"a":3}\n');
    expect(lines).toEqual(['{"a":1}', '{"a":2}', '{"a":3}']);
  });

  it('handles a mix of complete lines plus a trailing partial in one chunk', () => {
    const splitter = new LineSplitter();
    const lines = splitter.push('{"a":1}\n{"a":2}\n{"a":3');
    expect(lines).toEqual(['{"a":1}', '{"a":2}']);
    expect(splitter.push('}\n')).toEqual(['{"a":3}']);
  });

  it('handles \\r\\n line endings', () => {
    const splitter = new LineSplitter();
    const lines = splitter.push('{"a":1}\r\n{"a":2}\r\n');
    expect(lines).toEqual(['{"a":1}', '{"a":2}']);
  });

  it('skips interleaved empty lines without emitting them', () => {
    const splitter = new LineSplitter();
    const lines = splitter.push('{"a":1}\n\n\n{"a":2}\n\r\n{"a":3}\n');
    expect(lines).toEqual(['{"a":1}', '{"a":2}', '{"a":3}']);
  });

  it('accepts Buffer chunks as well as strings', () => {
    const splitter = new LineSplitter();
    const lines = splitter.push(Buffer.from('{"a":1}\n', 'utf8'));
    expect(lines).toEqual(['{"a":1}']);
  });

  it('flush() returns a buffered partial line and then is empty', () => {
    const splitter = new LineSplitter();
    splitter.push('{"a":1');
    expect(splitter.flush()).toEqual(['{"a":1']);
    expect(splitter.flush()).toEqual([]);
  });

  it('flush() returns nothing when there is no buffered remainder', () => {
    const splitter = new LineSplitter();
    splitter.push('{"a":1}\n');
    expect(splitter.flush()).toEqual([]);
  });

  it('force-flushes and resets when the buffer exceeds a small cap with no newline', () => {
    const splitter = new LineSplitter({ maxBufferBytes: 16 });
    // 20 bytes, no newline: exceeds the 16-byte cap.
    const lines = splitter.push('x'.repeat(20));
    expect(lines).toEqual(['x'.repeat(20)]);
    // Buffer was reset, so a subsequent small push starts fresh.
    expect(splitter.push('y\n')).toEqual(['y']);
  });

  it('does not force-flush a partial line that stays under the cap across many small pushes', () => {
    const splitter = new LineSplitter({ maxBufferBytes: 1000 });
    let lines: string[] = [];
    for (let i = 0; i < 10; i++) {
      lines = lines.concat(splitter.push('x'.repeat(50)));
    }
    expect(lines).toEqual([]);
    expect(splitter.flush()).toEqual(['x'.repeat(500)]);
  });

  it('does not hang or throw on a pathological binary-ish stream fed in tiny chunks', () => {
    const splitter = new LineSplitter({ maxBufferBytes: 8 });
    let totalLines = 0;
    for (let i = 0; i < 1000; i++) {
      totalLines += splitter.push('a').length + splitter.push('b').length;
    }
    // The cap must have forced periodic emission; buffer never grows unbounded.
    expect(totalLines).toBeGreaterThan(0);
  });
});

describe('parseLine', () => {
  it('classifies a request (id + method)', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"foo"}}');
    expect(result.kind).toBe('request');
    if (result.kind === 'request') {
      expect(result.id).toBe(1);
      expect(result.method).toBe('tools/call');
      expect(result.params).toEqual({ name: 'foo' });
    }
  });

  it('classifies a notification (method, no id)', () => {
    const result = parseLine('{"jsonrpc":"2.0","method":"notifications/progress","params":{"pct":50}}');
    expect(result.kind).toBe('notification');
    if (result.kind === 'notification') {
      expect(result.method).toBe('notifications/progress');
      expect(result.params).toEqual({ pct: 50 });
    }
  });

  it('classifies a response with a result', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}');
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.id).toBe(1);
      expect(result.message.result).toEqual({ ok: true });
    }
  });

  it('classifies a response with an error', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"not found"}}');
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.id).toBe(2);
      expect(result.message.error).toEqual({ code: -32601, message: 'not found' });
    }
  });

  it('classifies non-JSON text as non-json', () => {
    const result = parseLine('server starting...');
    expect(result).toEqual({ kind: 'non-json', raw: 'server starting...' });
  });

  it('treats id:0 as a valid, present id (not falsy-absent)', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":0,"method":"ping"}');
    expect(result.kind).toBe('request');
    if (result.kind === 'request') {
      expect(result.id).toBe(0);
    }
  });

  it('treats a response with id:0 as valid', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":0,"result":{}}');
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.id).toBe(0);
    }
  });

  it('treats id:"" (empty string) as a valid, present id', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":"","method":"ping"}');
    expect(result.kind).toBe('request');
    if (result.kind === 'request') {
      expect(result.id).toBe('');
    }
  });

  it('handles string ids', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":"req-abc-123","method":"tools/call","params":{}}');
    expect(result.kind).toBe('request');
    if (result.kind === 'request') {
      expect(result.id).toBe('req-abc-123');
    }
  });

  it('classifies id-with-no-method-result-or-error as other', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":1}');
    expect(result.kind).toBe('other');
  });

  it('classifies a bare JSON array as non-json (not a JSON-RPC object)', () => {
    const result = parseLine('[1,2,3]');
    expect(result.kind).toBe('non-json');
  });

  it('classifies null id as absent (notification-shaped, not request)', () => {
    const result = parseLine('{"jsonrpc":"2.0","id":null,"method":"ping"}');
    expect(result.kind).toBe('notification');
  });

  it('never throws on malformed JSON', () => {
    expect(() => parseLine('{not json')).not.toThrow();
    expect(parseLine('{not json').kind).toBe('non-json');
  });
});

describe('extractToolCall', () => {
  it('extracts toolName and args from a valid tools/call request', () => {
    const msg: JsonRpcMessage = {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '/etc/passwd' } },
    };
    expect(extractToolCall(msg)).toEqual({ toolName: 'read_file', args: { path: '/etc/passwd' } });
  });

  it('returns null for a non-tools/call method', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} };
    expect(extractToolCall(msg)).toBeNull();
  });

  it('returns null when params.name is missing', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { arguments: {} } };
    expect(extractToolCall(msg)).toBeNull();
  });

  it('returns null when params is missing entirely', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
    expect(extractToolCall(msg)).toBeNull();
  });

  it('returns null when params is not an object', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: 'not-an-object' };
    expect(extractToolCall(msg)).toBeNull();
  });

  it('returns null when params.name is not a string', () => {
    const msg: JsonRpcMessage = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 42 } };
    expect(extractToolCall(msg)).toBeNull();
  });
});

describe('CorrelationMap', () => {
  function makeInfo(id: number | string, toolName = 'read_file'): ToolCallInfo {
    return { id, toolName, method: 'tools/call', args: {} };
  }

  it('register then take returns the info and removes it', () => {
    const map = new CorrelationMap();
    map.register(1, makeInfo(1));
    expect(map.size).toBe(1);
    expect(map.take(1)).toEqual(makeInfo(1));
    expect(map.size).toBe(0);
  });

  it('a second take for the same id returns undefined', () => {
    const map = new CorrelationMap();
    map.register(1, makeInfo(1));
    map.take(1);
    expect(map.take(1)).toBeUndefined();
  });

  it('take for an id that was never registered returns undefined', () => {
    const map = new CorrelationMap();
    expect(map.take('never-registered')).toBeUndefined();
  });

  it('size reflects the number of live entries', () => {
    const map = new CorrelationMap();
    map.register(1, makeInfo(1));
    map.register(2, makeInfo(2));
    map.register('three', makeInfo('three'));
    expect(map.size).toBe(3);
    map.take(2);
    expect(map.size).toBe(2);
  });

  it('evicts the oldest entry once over a small injected cap', () => {
    const map = new CorrelationMap({ maxEntries: 2 });
    map.register(1, makeInfo(1));
    map.register(2, makeInfo(2));
    map.register(3, makeInfo(3));
    expect(map.size).toBe(2);
    expect(map.take(1)).toBeUndefined(); // evicted (oldest)
    expect(map.take(2)).toEqual(makeInfo(2));
    expect(map.take(3)).toEqual(makeInfo(3));
  });

  it('handles id:0 correctly as a map key', () => {
    const map = new CorrelationMap();
    map.register(0, makeInfo(0));
    expect(map.size).toBe(1);
    expect(map.take(0)).toEqual(makeInfo(0));
  });
});
