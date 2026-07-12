import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runProxy } from '../../src/proxy/proxy-core.js';
import * as policyModule from '../../src/proxy/policy.js';
import { auditLogDir } from '../../src/proxy/audit-log.js';
import type { AuditRecord } from '../../src/types/proxy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_SERVER = path.join(__dirname, '..', 'fixtures', 'mcp-stdio-server', 'server.mjs');

// The real `evaluateCall`/`evaluateResponse` are wrapped in `vi.fn` so a
// single test can force one to throw (proving runProxy's fail-open path)
// while every other test transparently exercises the real implementation.
vi.mock('../../src/proxy/policy.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/proxy/policy.js')>();
  return {
    ...actual,
    evaluateCall: vi.fn(actual.evaluateCall),
    evaluateResponse: vi.fn(actual.evaluateResponse),
  };
});

let tmpDir: string;
let policyDir: string;
let auditDir: string;
let callLogFile: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-core-'));
  policyDir = path.join(tmpDir, 'policy');
  auditDir = path.join(tmpDir, 'audit');
  callLogFile = path.join(tmpDir, 'calls.jsonl');
  fs.mkdirSync(policyDir, { recursive: true });
});

afterEach(() => {
  // `mockImplementationOnce` (used by the two fail-open tests below) is
  // self-cleaning: it reverts to the real `evaluateCall`/`evaluateResponse`
  // (the mock's base implementation, set once in the `vi.mock` factory
  // above) after a single call. Only call counts need clearing between
  // tests, never the implementation itself.
  vi.mocked(policyModule.evaluateCall).mockClear();
  vi.mocked(policyModule.evaluateResponse).mockClear();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeGlobalPolicy(yamlContent: string): void {
  fs.writeFileSync(path.join(policyDir, 'policy.yaml'), yamlContent, 'utf-8');
}

interface Harness {
  clientStdin: PassThrough;
  clientStdout: PassThrough;
  clientStderr: PassThrough;
  outLines: () => unknown[];
  rawOut: () => string;
  send: (msg: Record<string, unknown>) => void;
  runPromise: Promise<number>;
}

function startProxy(env: NodeJS.ProcessEnv = {}, overrides: Partial<Parameters<typeof runProxy>[0]> = {}): Harness {
  const clientStdin = new PassThrough();
  const clientStdout = new PassThrough();
  const clientStderr = new PassThrough();

  let collected = '';
  clientStdout.on('data', (chunk: Buffer) => {
    collected += chunk.toString('utf8');
  });
  // Drain stderr so it never backpressures the child.
  clientStderr.on('data', () => {});

  const runPromise = runProxy({
    serverName: 'fixture-server',
    command: process.execPath,
    args: [FIXTURE_SERVER],
    policyDir,
    auditDir,
    stdin: clientStdin,
    stdout: clientStdout,
    stderr: clientStderr,
    spawnFn: spawn,
    env: { ...process.env, ...env, CALL_LOG_FILE: callLogFile },
    ...overrides,
  });

  return {
    clientStdin,
    clientStdout,
    clientStderr,
    outLines: () =>
      collected
        .split('\n')
        .filter((l) => l.trim().length > 0)
        .map((l) => {
          try {
            return JSON.parse(l);
          } catch {
            return l; // non-JSON banner lines
          }
        }),
    rawOut: () => collected,
    send: (msg) => clientStdin.write(JSON.stringify(msg) + '\n'),
    runPromise,
  };
}

function readCallLog(): Array<{ id: unknown; name: unknown; args: unknown }> {
  if (!fs.existsSync(callLogFile)) return [];
  return fs
    .readFileSync(callLogFile, 'utf-8')
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

function readAllAuditRecords(): AuditRecord[] {
  const root = auditLogDir(auditDir);
  if (!fs.existsSync(root)) return [];
  const records: AuditRecord[] = [];
  for (const serverDir of fs.readdirSync(root)) {
    const serverPath = path.join(root, serverDir);
    for (const file of fs.readdirSync(serverPath)) {
      if (!file.endsWith('.jsonl')) continue;
      const lines = fs.readFileSync(path.join(serverPath, file), 'utf-8').split('\n').filter(Boolean);
      for (const line of lines) records.push(JSON.parse(line));
    }
  }
  return records;
}

describe('runProxy (integration, real fixture server)', () => {
  it('passes initialize + tools/list through byte-faithfully under the default (observe) policy', async () => {
    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    h.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines();
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ jsonrpc: '2.0', id: 1, result: { serverInfo: { name: 'g0-fake-mcp-server' } } });
    expect(lines[1]).toMatchObject({ jsonrpc: '2.0', id: 2 });
    expect((lines[1] as { result: { tools: unknown[] } }).result.tools).toHaveLength(2);
  }, 15000);

  it('forwards a benign tools/call under an allow/observe policy and returns its response', async () => {
    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { hello: 'world' } } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    expect(lines[0].id).toBe(1);
    expect(lines[0].result.content[0].text).toContain('echo:{"hello":"world"}');

    const calls = readCallLog();
    expect(calls).toEqual([{ id: 1, name: 'echo', args: { hello: 'world' } }]);
  }, 15000);

  it('denies a tools/call under an enforce policy: client gets a JSON-RPC error, child never sees the call', async () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
rules:
  - id: block-danger-tool
    direction: request
    tools: ["danger_tool"]
    action: deny
    message: "danger_tool is blocked by g0 policy"
`);
    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'danger_tool', arguments: { x: 1 } } });
    // A second, allowed call proves the proxy is still alive/responsive
    // after the deny, and gives the fixture time to have (not) logged call 1.
    h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; error?: { code: number; message: string }; result?: unknown }>;
    expect(lines).toHaveLength(2);

    const denyResponse = lines.find((l) => l.id === 1)!;
    expect(denyResponse.error).toEqual({ code: -32001, message: 'danger_tool is blocked by g0 policy' });
    expect(denyResponse.result).toBeUndefined();

    const allowResponse = lines.find((l) => l.id === 2)!;
    expect(allowResponse.error).toBeUndefined();

    // The fixture only ever logs calls it actually received.
    const calls = readCallLog();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ id: 2, name: 'echo', args: {} });
  }, 15000);

  it('redacts a secret in the response when FAKE_SECRET + response.redactSecrets:true', async () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
response:
  redactSecrets: true
  injection: alert
`);
    const h = startProxy({ FAKE_SECRET: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    const text = lines[0].result.content[0].text;
    expect(text).toContain('[g0:redacted]');
    expect(text).not.toContain('sk-ABCDEF0123456789abcdef');

    const records = readAllAuditRecords();
    const redactRecord = records.find((r) => r.direction === 'response' && r.action === 'redact');
    expect(redactRecord).toBeDefined();
  }, 15000);

  it('still inspects (and redacts) the response to a malformed tools/call whose params.name is missing', async () => {
    // extractToolCall returns null for this shape (no `params.name`), so the
    // request side can't evaluate a per-tool policy — but the RESPONSE must
    // still be inspected (secret redaction / injection detection). Before
    // the fix, the malformed request's id was never registered in the
    // correlation map, so its response skipped ALL inspection.
    writeGlobalPolicy(`
version: 1
mode: enforce
response:
  redactSecrets: true
  injection: alert
`);
    const h = startProxy({ FAKE_SECRET: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { arguments: {} } }); // no `name`
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    const text = lines[0].result.content[0].text;
    expect(text).toContain('[g0:redacted]');
    expect(text).not.toContain('sk-ABCDEF0123456789abcdef');

    const records = readAllAuditRecords();
    const malformedRequestRecord = records.find(
      (r) => r.direction === 'request' && r.kind === 'tools/call' && r.id === 1,
    );
    expect(malformedRequestRecord).toMatchObject({ action: 'allow' });

    const redactRecord = records.find((r) => r.direction === 'response' && r.action === 'redact');
    expect(redactRecord).toBeDefined();
    expect(redactRecord).toMatchObject({ id: 1, toolName: '<unknown>' });
  }, 15000);

  it('blocks an injection response under enforce + response.injection:deny with a g0 blocked-notice result', async () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
response:
  redactSecrets: false
  injection: deny
`);
    const h = startProxy({ FAKE_INJECTION: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{
      id: number;
      result: { content: Array<{ text: string }>; isError: boolean };
    }>;
    expect(lines).toHaveLength(1);
    expect(lines[0].result.isError).toBe(true);
    expect(lines[0].result.content[0].text).toContain('[g0] This tool response was blocked by policy');
    expect(lines[0].result.content[0].text).not.toContain('ignore all previous instructions');

    const records = readAllAuditRecords();
    const denyRecord = records.find((r) => r.direction === 'response' && r.action === 'deny');
    expect(denyRecord).toBeDefined();
    expect(denyRecord?.findings).toContain('Ignore previous instructions');
  }, 15000);

  it('forwards (does not block) an injection response under alert mode, but still audits it', async () => {
    writeGlobalPolicy(`
version: 1
mode: alert
response:
  redactSecrets: false
  injection: deny
`);
    const h = startProxy({ FAKE_INJECTION: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    // alert mode downgrades the deny -> the original (unblocked) text passes through.
    expect(lines[0].result.content[0].text).toContain('ignore all previous instructions');

    const records = readAllAuditRecords();
    const alertRecord = records.find((r) => r.direction === 'response' && r.action === 'alert');
    expect(alertRecord).toBeDefined();
  }, 15000);

  it('skips scanning (no redaction, no findings) when the response exceeds maxScanBytes, even with a secret embedded', async () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
response:
  redactSecrets: true
  injection: alert
`);
    const h = startProxy({ FAKE_SECRET: '1', FAKE_HUGE: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    const text = lines[0].result.content[0].text;
    // Too big to scan -> forwarded as-is, secret NOT redacted (proves the skip path).
    expect(text).toContain('sk-ABCDEF0123456789abcdef');
    expect(text).not.toContain('[g0:redacted]');

    // The secret sits BEFORE the 2MB padding, so merely containing it does
    // NOT prove the whole response made it through — a bug that truncates
    // trailing bytes (e.g. reacting on child 'exit' instead of 'close' and
    // flushing before the pipe finished draining) would still pass the
    // assertions above. HUGE_END_MARKER is placed at the very END of the
    // fixture's padded text (see tests/fixtures/mcp-stdio-server/server.mjs)
    // specifically to catch that: assert the *exact* full byte-for-byte
    // response, not just a substring.
    const expectedText = `echo:${JSON.stringify({})} sk-ABCDEF0123456789abcdef${'A'.repeat(2_000_000)}<<<G0_END_MARKER>>>`;
    expect(text.endsWith('<<<G0_END_MARKER>>>')).toBe(true);
    expect(text.length).toBe(expectedText.length);
    expect(text).toBe(expectedText);
  }, 15000);

  it('forwards a non-JSON banner line untouched and the handshake still works', async () => {
    const h = startProxy({ FAKE_BANNER: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const raw = h.rawOut();
    expect(raw).toContain('fake-mcp-server: starting up (this line is not JSON)...');

    const lines = h.outLines();
    const initResponse = lines.find((l) => typeof l === 'object' && l !== null && (l as { id?: number }).id === 1);
    expect(initResponse).toMatchObject({ jsonrpc: '2.0', id: 1 });
  }, 15000);

  it('resolves with the child exit code (3) on FAKE_CRASH, without hanging', async () => {
    const h = startProxy({ FAKE_CRASH: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    // Deliberately do NOT end stdin — the crash itself must drive resolution.

    const code = await h.runPromise;
    expect(code).toBe(3);
  }, 15000);

  it('resolves with code 127 (no hang) when the command fails to spawn (ENOENT)', async () => {
    const h = startProxy({}, { command: 'g0-test-command-that-does-not-exist-xyz', args: [] });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(127);
  }, 15000);

  it('terminates the child and resolves (no hang) when the proxy process receives SIGTERM', async () => {
    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    // Deliberately do NOT end stdin — the signal itself must drive resolution.
    process.kill(process.pid, 'SIGTERM');

    const code = await h.runPromise;
    // runProxy forwards the SAME signal it received to the child
    // (`child.kill(sig)`), so the child dies from SIGTERM too — mirrored in
    // the exit code via the shell convention (128 + signal number), same as
    // the `exitCodeForSignal` helper inside proxy-core.ts.
    const sigtermNum = (os.constants.signals as Record<string, number>).SIGTERM;
    expect(code).toBe(128 + sigtermNum);
  }, 15000);

  it('terminates the child and resolves (no hang) when the proxy process receives SIGINT', async () => {
    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    // Deliberately do NOT end stdin — the signal itself must drive resolution.
    process.kill(process.pid, 'SIGINT');

    const code = await h.runPromise;
    const sigintNum = (os.constants.signals as Record<string, number>).SIGINT;
    expect(code).toBe(128 + sigintNum);
  }, 15000);

  it('does not crash and terminates the (non-orphaned) child when the client stdout stream emits an EPIPE-like write error', async () => {
    // Reproduces the reviewer's repro (`node writer.mjs | true`): the
    // IDE/client closes its end of the pipe mid-response, so the writable
    // this proxy writes to (opts.stdout) fails ASYNCHRONOUSLY — an
    // `'error'` event on the writable, not a synchronous throw from
    // `.write()`. Before the fix, this was an unhandled `'error'` event ->
    // uncaught exception -> the whole proxy process crashes, orphaning the
    // spawned child with no cleanup and no resolved exit code.
    //
    // A real Writable whose `_write` invokes its callback with an error is
    // used (NOT a PassThrough, which never errors on write()) so this
    // exercises the exact async-'error'-event path a real EPIPE takes.
    class FailingWritable extends Writable {
      override _write(_chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
        setImmediate(() => callback(Object.assign(new Error('write EPIPE'), { code: 'EPIPE' })));
      }
    }

    let capturedChild: ReturnType<typeof spawn> | undefined;
    const capturingSpawn = ((...args: Parameters<typeof spawn>) => {
      const proc = spawn(...args);
      capturedChild = proc;
      return proc;
    }) as typeof spawn;

    const failingStdout = new FailingWritable();
    const clientStderr = new PassThrough();
    clientStderr.on('data', () => {});
    const clientStdin = new PassThrough();

    const runPromise = runProxy({
      serverName: 'fixture-server',
      command: process.execPath,
      args: [FIXTURE_SERVER],
      policyDir,
      auditDir,
      stdin: clientStdin,
      stdout: failingStdout,
      stderr: clientStderr,
      spawnFn: capturingSpawn,
      env: { ...process.env, CALL_LOG_FILE: callLogFile },
    });

    // Triggers a stdout write inside runProxy (the initialize response),
    // which is what surfaces the EPIPE-like error.
    clientStdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }) + '\n');

    // Must resolve (not hang) and must NOT crash this test process/worker.
    const code = await runPromise;

    // The child was killed with SIGTERM once the client stream errored;
    // exit-code-for-signal convention (128 + signal number) proves it.
    const sigtermNum = (os.constants.signals as Record<string, number>).SIGTERM;
    expect(code).toBe(128 + sigtermNum);

    // No orphan: the spawned child process must actually be dead, not left
    // running with nobody attached to it.
    expect(capturedChild).toBeDefined();
    const pid = capturedChild!.pid;
    expect(typeof pid).toBe('number');
    expect(() => process.kill(pid as number, 0)).toThrow();
  }, 15000);

  it('fail-open: a throwing evaluateCall still forwards the original request line to the child', async () => {
    vi.mocked(policyModule.evaluateCall).mockImplementationOnce(() => {
      throw new Error('boom: evaluateCall exploded');
    });

    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { ok: true } } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    // The request still reached the child (default onError:'open') and the
    // real response came back to the client, unmodified by g0's own bug.
    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    expect(lines[0].result.content[0].text).toContain('echo:{"ok":true}');

    const calls = readCallLog();
    expect(calls).toEqual([{ id: 1, name: 'echo', args: { ok: true } }]);
  }, 15000);

  it('fail-open: a throwing evaluateResponse still forwards the original response line to the client', async () => {
    vi.mocked(policyModule.evaluateResponse).mockImplementationOnce(() => {
      throw new Error('boom: evaluateResponse exploded');
    });

    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { ok: true } } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const lines = h.outLines() as Array<{ id: number; result: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    expect(lines[0].result.content[0].text).toContain('echo:{"ok":true}');
  }, 15000);

  it('writes audit records for allow/deny/redact decisions into auditDir', async () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
rules:
  - id: block-danger-tool
    direction: request
    tools: ["danger_tool"]
    action: deny
`);
    const h = startProxy();
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: {} } });
    h.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'danger_tool', arguments: {} } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    const records = readAllAuditRecords();
    expect(records.every((r) => r.serverName === 'fixture-server')).toBe(true);

    const denyRecord = records.find((r) => r.direction === 'request' && r.action === 'deny');
    expect(denyRecord).toMatchObject({ toolName: 'danger_tool', ruleId: 'block-danger-tool', id: 3 });

    const allowCallRecord = records.find(
      (r) => r.direction === 'request' && r.kind === 'tools/call' && r.toolName === 'echo',
    );
    expect(allowCallRecord).toMatchObject({ action: 'allow', id: 2 });

    // initialize isn't a tools/call: it's still lightly audited.
    const initRecord = records.find((r) => r.method === 'initialize');
    expect(initRecord).toBeDefined();
  }, 15000);
});
