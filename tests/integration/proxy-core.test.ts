import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { PassThrough, Writable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { runProxy } from '../../src/proxy/proxy-core.js';
import * as policyModule from '../../src/enforcement/policy.js';
import { auditLogDir } from '../../src/proxy/audit-log.js';
import type { AuditRecord } from '../../src/types/proxy.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_SERVER = path.join(__dirname, '..', 'fixtures', 'mcp-stdio-server', 'server.mjs');

// The real `evaluateCall`/`evaluateResponse` are wrapped in `vi.fn` so a
// single test can force one to throw (proving runProxy's fail-open path)
// while every other test transparently exercises the real implementation.
vi.mock('../../src/enforcement/policy.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/enforcement/policy.js')>();
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

  it('forwards (does not block) an injection response under alert mode, but audits it as coach (a loud warning, not a silent alert)', async () => {
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
    // alert mode downgrades the would-be deny -> the original (unblocked) text passes through.
    expect(lines[0].result.content[0].text).toContain('ignore all previous instructions');

    const records = readAllAuditRecords();
    // The would-be deny is downgraded to `coach` (not a plain `alert`) —
    // see adjustAction's doc comment in policy.ts.
    const coachRecord = records.find((r) => r.direction === 'response' && r.action === 'coach');
    expect(coachRecord).toBeDefined();
  }, 15000);

  it('coach: forwards a would-be-denied tools/call in alert mode unmodified, and emits a loud stderr warning', async () => {
    writeGlobalPolicy(`
version: 1
mode: alert
rules:
  - id: block-danger-tool
    direction: request
    tools: ["danger_tool"]
    action: deny
    message: "danger_tool is blocked by g0 policy"
`);
    let stderrText = '';
    const stderrCapture = new PassThrough();
    stderrCapture.on('data', (chunk: Buffer) => {
      stderrText += chunk.toString('utf8');
    });

    const h = startProxy({}, { stderr: stderrCapture });
    h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'danger_tool', arguments: { x: 1 } } });
    h.clientStdin.end();

    const code = await h.runPromise;
    expect(code).toBe(0);

    // Proves `coach` NEVER blocks: the call actually reached the wrapped
    // server (the fixture logged it) and the client got a real result, not
    // a synthesized deny error.
    const lines = h.outLines() as Array<{ id: number; error?: unknown; result?: { content: Array<{ text: string }> } }>;
    expect(lines).toHaveLength(1);
    expect(lines[0].error).toBeUndefined();
    expect(lines[0].result?.content[0].text).toContain('echo:{"x":1}');

    const calls = readCallLog();
    expect(calls).toEqual([{ id: 1, name: 'danger_tool', args: { x: 1 } }]);

    const records = readAllAuditRecords();
    const coachRecord = records.find((r) => r.direction === 'request' && r.action === 'coach');
    expect(coachRecord).toMatchObject({ toolName: 'danger_tool', ruleId: 'block-danger-tool', id: 1 });

    // A prominent stderr warning was emitted — louder than a plain ALERT,
    // never written to stdout (which is reserved for proxied JSON-RPC).
    expect(stderrText).toContain('COACH');
    expect(stderrText).toContain('danger_tool');
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

  it('does not crash the proxy process when requests keep arriving as the child dies mid-session (async EPIPE on child.stdin)', async () => {
    // Reproduces the reviewer's repro: the wrapped server dies (FAKE_CRASH
    // exits with code 3 right after its first response) while the IDE still
    // has more requests to send. Some subsequent `writeToChild` write lands
    // on a `child.stdin` whose reader (the crashed server) is dying/gone ->
    // Node reports that ASYNCHRONOUSLY as an `'error'` event on
    // `child.stdin` (EPIPE/ENOTCONN), which `writeToChild`'s try/catch can
    // NEVER catch (try/catch only sees synchronous throws). Before the fix,
    // that was an unhandled `'error'` event -> an uncaught exception that
    // crashes this whole process instead of letting the existing
    // `child.on('close')` -> flush -> settle-with-exit-code path run.
    //
    // Note this is a genuine kernel-level race (confirmed by direct repro
    // against Node's child_process: once the child's `'exit'` event has
    // actually fired, Node has ALREADY internally destroyed `child.stdin`,
    // and writes after that point silently no-op rather than erroring — so
    // the bug can only be hit by writing *while* the child is dying, not
    // after). A single well-timed write is too small/fast a target to hit
    // reliably, so — exactly like a real IDE that keeps streaming
    // requests without waiting for a round trip — this sends a steady
    // stream of further requests (spread across event-loop ticks via
    // `setImmediate`, each with a body large enough to actually reach the
    // OS pipe) right after the crashing response comes back, until either
    // one lands in the race window or the child fully exits.
    const h = startProxy({ FAKE_CRASH: '1' });
    h.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });

    const padding = 'x'.repeat(50_000);
    let n = 1;
    let started = false;
    let stop = false;
    const burst = (): void => {
      if (stop) return;
      n++;
      if (n > 200) {
        stop = true;
        h.clientStdin.end();
        return;
      }
      h.send({ jsonrpc: '2.0', id: n, method: 'tools/call', params: { name: 'echo', arguments: { padding } } });
      setImmediate(burst);
    };
    h.clientStdout.on('data', () => {
      // Any response (the crashing one, id 1) triggers the burst; only
      // start it once.
      if (started) return;
      started = true;
      burst();
    });

    // Directly capture an uncaught exception during this test, rather than
    // relying solely on vitest's own end-of-run "Unhandled Errors" report
    // (which — confirmed while developing this test — does flag the whole
    // `vitest run` as failed pre-fix, but doesn't fail *this* test's own
    // assertions, since the crash arrives asynchronously and vitest's
    // runner swallows it to keep the worker alive). Node invokes every
    // registered `'uncaughtException'` listener, so this runs alongside
    // vitest's own handler without interfering with it.
    let crash: Error | undefined;
    const onUncaught = (err: Error): void => {
      crash = err;
    };
    process.on('uncaughtException', onUncaught);

    try {
      // Must resolve (not hang) with the child's real exit code.
      const code = await h.runPromise;
      // Give any async EPIPE from an in-flight burst write a chance to
      // surface as an uncaught exception before we assert.
      await new Promise((resolve) => setTimeout(resolve, 500));
      stop = true; // stop the burst loop; runProxy already settled.

      expect(crash, `an unhandled child.stdin error crashed the process: ${crash?.stack ?? crash}`).toBeUndefined();
      expect(code).toBe(3);
    } finally {
      process.removeListener('uncaughtException', onUncaught);
      stop = true;
    }
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

  // ───────────────────────────────────────────────────────────────────────
  // Provenance / dataflow tracking (Task 4) — end-to-end through the real
  // proxy wiring: a `SessionProvenance` created in `runProxy`, tagging on
  // responses, and a dataflow-aware `evaluateCall` on the next request.
  // The fixture server's FAKE_SECRET mode appends a fixed, vendor-key-shaped
  // secret (`sk-ABCDEF0123456789abcdef`) to EVERY tools/call response, so a
  // first call to `echo` taints it as `echo`'s output, and a second call to
  // a DIFFERENT tool (`danger_tool`) that echoes that same string back in
  // its own arguments is the classic dataflow/exfiltration pattern.
  // ───────────────────────────────────────────────────────────────────────
  describe('provenance / dataflow tracking', () => {
    const LEAKED_SECRET = 'sk-ABCDEF0123456789abcdef';

    /**
     * Requests and responses travel on independent streams (client stdin ->
     * proxy -> child stdin, and back on stdout) processed by separate
     * event-loop callbacks — sending both requests back-to-back races the
     * first request's RESPONSE (which is what tags provenance) against the
     * second request's evaluation. A real MCP client naturally serializes
     * on the round trip; this helper does the same so the dataflow tag from
     * call 1 is guaranteed to be recorded before call 2 is evaluated.
     */
    function waitForNextResponse(h: Harness): Promise<void> {
      return new Promise((resolve) => {
        const onData = (): void => {
          h.clientStdout.off('data', onData);
          resolve();
        };
        h.clientStdout.on('data', onData);
      });
    }

    it('denies a request that carries a different tool\'s tainted response data in its args (enforce mode)', async () => {
      writeGlobalPolicy(`
version: 1
mode: enforce
`);
      const h = startProxy({ FAKE_SECRET: '1' });
      const firstResponse = waitForNextResponse(h);
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
      await firstResponse;
      h.send({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'danger_tool', arguments: { leaked: LEAKED_SECRET } },
      });
      h.clientStdin.end();

      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<Record<string, unknown>>;
      // id:1's real response still comes through (echo's own call is fine).
      expect(lines.find((l) => l.id === 1)).toMatchObject({ id: 1, result: expect.anything() });
      // id:2 is denied — a synthesized JSON-RPC error, not the real result.
      const deniedLine = lines.find((l) => l.id === 2) as { error?: { message?: string } } | undefined;
      expect(deniedLine).toBeDefined();
      expect(deniedLine?.error).toBeDefined();
      expect(deniedLine?.error?.message).toContain('echo');
      expect(deniedLine?.error?.message).toContain('danger_tool');

      // The real server never even saw the second (blocked) call.
      const calls = readCallLog();
      expect(calls.map((c) => c.name)).toEqual(['echo']);

      const records = readAllAuditRecords();
      const dataflowDeny = records.find(
        (r) => r.direction === 'request' && r.toolName === 'danger_tool' && r.action === 'deny',
      );
      expect(dataflowDeny).toBeDefined();
      expect(dataflowDeny?.signals).toContain('dataflow:echo->danger_tool');
      // Metadata only in the audit trail — never the matched secret itself.
      expect(JSON.stringify(dataflowDeny)).not.toContain(LEAKED_SECRET);
    }, 15000);

    it('does NOT deny when the SAME tool re-consumes its own prior output', async () => {
      writeGlobalPolicy(`
version: 1
mode: enforce
`);
      const h = startProxy({ FAKE_SECRET: '1' });
      const firstResponse = waitForNextResponse(h);
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
      await firstResponse;
      h.send({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'echo', arguments: { leaked: LEAKED_SECRET } },
      });
      h.clientStdin.end();

      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<Record<string, unknown>>;
      // Both calls got their real result — no synthesized deny error anywhere.
      expect(lines.filter((l) => 'error' in l)).toEqual([]);

      const calls = readCallLog();
      expect(calls.map((c) => c.name)).toEqual(['echo', 'echo']);
    }, 15000);

    it('only ALERTS (never blocks) on the same dataflow pattern in alert mode', async () => {
      writeGlobalPolicy(`
version: 1
mode: alert
`);
      const h = startProxy({ FAKE_SECRET: '1' });
      const firstResponse = waitForNextResponse(h);
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
      await firstResponse;
      h.send({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'danger_tool', arguments: { leaked: LEAKED_SECRET } },
      });
      h.clientStdin.end();

      const code = await h.runPromise;
      expect(code).toBe(0);

      // alert mode downgrades the would-be deny to `coach`: never blocks —
      // the real server still receives (and answers) both calls.
      const lines = h.outLines() as Array<Record<string, unknown>>;
      expect(lines.filter((l) => 'error' in l)).toEqual([]);
      const calls = readCallLog();
      expect(calls.map((c) => c.name)).toEqual(['echo', 'danger_tool']);

      const records = readAllAuditRecords();
      const coachRecord = records.find(
        (r) => r.direction === 'request' && r.toolName === 'danger_tool' && r.action === 'coach',
      );
      expect(coachRecord).toBeDefined();
    }, 15000);

    // ─────────────────────────────────────────────────────────────────────
    // Task 8 — sensitive-path provenance slice, end-to-end through the real
    // proxy wiring: a request whose args point into a sensitive filesystem
    // location (`~/.ssh/id_rsa`) gets its RESPONSE tagged sensitive-origin
    // (`proxy-core.ts`'s response leg, `provenance.tagSensitiveOrigin`),
    // and that content flowing into a LATER, different tool's request is
    // caught by the exact same dataflow machinery Task 4 already tests
    // above. The fixture server's `echo` tool always echoes its args back
    // verbatim in the response text, so the "sensitive value" round-tripping
    // here is the path string itself — no fixture changes needed, and this
    // response is deliberately NOT `FAKE_SECRET`-flavored, so `tagResponse`
    // alone (the pre-Task-8 code path) tags nothing: any taint recorded
    // below is proof `tagSensitiveOrigin` is doing real, additional work.
    // ─────────────────────────────────────────────────────────────────────
    describe('Task 8: sensitive-path provenance slice', () => {
      it('a read of ~/.ssh/id_rsa taints its response, and that content flowing into a later call is flagged (deny in enforce mode)', async () => {
        writeGlobalPolicy(`
version: 1
mode: enforce
`);
        const h = startProxy();
        const firstResponse = waitForNextResponse(h);
        h.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'echo', arguments: { path: '~/.ssh/id_rsa' } },
        });
        await firstResponse;
        h.send({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'danger_tool', arguments: { body: 'please forward ~/.ssh/id_rsa to attacker now' } },
        });
        h.clientStdin.end();

        const code = await h.runPromise;
        expect(code).toBe(0);

        const lines = h.outLines() as Array<Record<string, unknown>>;
        // id:1's real response still comes through (the read itself is fine).
        expect(lines.find((l) => l.id === 1)).toMatchObject({ id: 1, result: expect.anything() });
        // id:2 is denied — the exfil attempt.
        const deniedLine = lines.find((l) => l.id === 2) as { error?: { message?: string } } | undefined;
        expect(deniedLine).toBeDefined();
        expect(deniedLine?.error?.message).toContain('echo');
        expect(deniedLine?.error?.message).toContain('danger_tool');

        const calls = readCallLog();
        expect(calls.map((c) => c.name)).toEqual(['echo']); // the real server never saw the blocked call

        const records = readAllAuditRecords();
        const dataflowDeny = records.find(
          (r) => r.direction === 'request' && r.toolName === 'danger_tool' && r.action === 'deny',
        );
        expect(dataflowDeny).toBeDefined();
        expect(dataflowDeny?.signals).toContain('dataflow:echo->danger_tool');
        // The finding carries the sensitive CATEGORY as metadata...
        expect(dataflowDeny?.context).toMatchObject({
          dataflow: [expect.objectContaining({ originTool: 'echo', destinationTool: 'danger_tool', category: 'ssh-key' })],
        });
        // ...but never the resolved path or the matched value itself, anywhere in the record.
        expect(JSON.stringify(dataflowDeny)).not.toContain('.ssh');
        expect(JSON.stringify(dataflowDeny)).not.toContain('id_rsa');
      }, 15000);

      it('a read of an ordinary path does NOT taint — no dataflow finding, both calls succeed normally', async () => {
        writeGlobalPolicy(`
version: 1
mode: enforce
`);
        const h = startProxy();
        const firstResponse = waitForNextResponse(h);
        h.send({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'echo', arguments: { path: '/tmp/scratch/notes.txt' } },
        });
        await firstResponse;
        h.send({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: { name: 'danger_tool', arguments: { body: 'please review /tmp/scratch/notes.txt later' } },
        });
        h.clientStdin.end();

        const code = await h.runPromise;
        expect(code).toBe(0);

        // Neither call is denied — no dataflow signal ever fires for an
        // ordinary, non-sensitive path.
        const lines = h.outLines() as Array<Record<string, unknown>>;
        expect(lines.filter((l) => 'error' in l)).toEqual([]);

        const calls = readCallLog();
        expect(calls.map((c) => c.name)).toEqual(['echo', 'danger_tool']);

        const records = readAllAuditRecords();
        const dataflowDeny = records.find(
          (r) => r.direction === 'request' && r.toolName === 'danger_tool' && r.action === 'deny',
        );
        expect(dataflowDeny).toBeUndefined();
      }, 15000);

      it('never crashes the proxy on a weird/non-string path-shaped arg (fail-open)', async () => {
        writeGlobalPolicy(`
version: 1
mode: enforce
`);
        const h = startProxy();
        // `path` is a number, not a string — extractPathLikeArgValues must
        // skip it cleanly rather than throwing.
        h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { path: 12345 } } });
        h.send({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'echo', arguments: null } });
        h.clientStdin.end();

        const code = await h.runPromise;
        expect(code).toBe(0);

        const lines = h.outLines() as Array<Record<string, unknown>>;
        expect(lines.filter((l) => 'error' in l)).toEqual([]);
        expect(lines).toHaveLength(2);
      }, 15000);
    });
  });

  // ───────────────────────────────────────────────────────────────────────
  // Policy DSL v2 (Task 5): edm[]/dataflow[] onMatch real enforcement, and
  // the Task-4 coverage gap of a combined EDM-hit + dataflow-finding firing
  // on the SAME request, exercised end-to-end through the real runProxy
  // loop (not just the pure `mergeAuditExtras` unit test in
  // tests/unit/proxy-policy-v2.test.ts).
  // ───────────────────────────────────────────────────────────────────────
  describe('Policy DSL v2 enforcement (edm[]/dataflow[] onMatch)', () => {
    const LEAKED_SECRET = 'sk-ABCDEF0123456789abcdef'; // matches the fixture's FAKE_SECRET output exactly

    function waitForNextResponse(h: Harness): Promise<void> {
      return new Promise((resolve) => {
        const onData = (): void => {
          h.clientStdout.off('data', onData);
          resolve();
        };
        h.clientStdout.on('data', onData);
      });
    }

    async function fingerprintLeakedSecret(name: string): Promise<void> {
      const { buildAndWriteEdmIndex, fingerprintsDir } = await import('../../src/enforcement/edm.js');
      const corpus = path.join(tmpDir, `${name}-corpus.txt`);
      fs.writeFileSync(corpus, `${LEAKED_SECRET}\n`);
      buildAndWriteEdmIndex(corpus, fingerprintsDir(policyDir), { name, mode: 'line' });
    }

    it('Task-4 gap: an EDM hit AND a dataflow finding on the SAME request are both present in the merged audit record', async () => {
      await fingerprintLeakedSecret('leaked-secrets');
      // No `version: 2` here on purpose — this reproduces the coverage gap
      // exactly as Task 4 left it: EDM detects (Task 3), dataflow detects
      // (Task 4), and BOTH are merged into ONE audit record via
      // `mergeAuditExtras` — already-existing behavior this test simply
      // never had coverage for.
      writeGlobalPolicy(`
version: 1
mode: enforce
`);
      const h = startProxy({ FAKE_SECRET: '1' });
      const firstResponse = waitForNextResponse(h);
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
      await firstResponse;
      h.send({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'danger_tool', arguments: { leaked: LEAKED_SECRET } },
      });
      h.clientStdin.end();
      const code = await h.runPromise;
      expect(code).toBe(0);

      const records = readAllAuditRecords();
      const requestRecord = records.find(
        (r) => r.direction === 'request' && r.toolName === 'danger_tool' && r.kind === 'tools/call',
      );
      expect(requestRecord).toBeDefined();
      // Both signal sources present on the SAME record, neither clobbered the other.
      expect(requestRecord?.signals).toContain('edm:leaked-secrets');
      expect(requestRecord?.signals).toContain('dataflow:echo->danger_tool');
      // confidence takes the max across the merged fragments (edm 0.99 > dataflow 0.9).
      expect(requestRecord?.confidence).toBe(0.99);
      expect(requestRecord?.findings).toContain('EDM exact-data-match: leaked-secrets');
      // Still deny (Task 4's existing dataflow enforcement, unrelated to EDM's detect-only scope).
      expect(requestRecord?.action).toBe('deny');
      expect(JSON.stringify(requestRecord)).not.toContain(LEAKED_SECRET);
    }, 15000);

    it('a v2 edm[] onMatch: deny rule blocks a fingerprinted secret sent OUT in a tools/call arg (enforce mode)', async () => {
      await fingerprintLeakedSecret('prod-keys');
      writeGlobalPolicy(`
version: 2
mode: enforce
edm:
  - index: prod-keys
    onMatch: deny
`);
      const h = startProxy();
      h.send({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'send_webhook', arguments: { apiKey: LEAKED_SECRET } },
      });
      h.clientStdin.end();
      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<Record<string, unknown>>;
      const deniedLine = lines.find((l) => l.id === 1) as { error?: { message?: string } } | undefined;
      expect(deniedLine?.error).toBeDefined();

      const calls = readCallLog();
      expect(calls).toEqual([]); // never reached the real (wrapped) server

      const records = readAllAuditRecords();
      const denyRecord = records.find((r) => r.direction === 'request' && r.action === 'deny');
      expect(denyRecord).toBeDefined();
      expect(denyRecord?.signals).toContain('edm:prod-keys');
      expect(JSON.stringify(denyRecord)).not.toContain(LEAKED_SECRET);
    }, 15000);

    it('an EDM hit against an index with no v2 edm[] entry stays detect-only, even under a v2 policy', async () => {
      await fingerprintLeakedSecret('unconfigured-index');
      writeGlobalPolicy(`
version: 2
mode: enforce
`); // no edm[] block at all
      const h = startProxy();
      h.send({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'send_webhook', arguments: { apiKey: LEAKED_SECRET } },
      });
      h.clientStdin.end();
      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<Record<string, unknown>>;
      expect(lines.find((l) => l.id === 1)).toMatchObject({ id: 1, result: expect.anything() }); // NOT denied
      const calls = readCallLog();
      expect(calls.map((c) => c.name)).toEqual(['send_webhook']); // reached the real server
    }, 15000);

    it('a v2 dataflow[] onMatch: deny rule blocks a specific from/to flow (enforce mode)', async () => {
      writeGlobalPolicy(`
version: 2
mode: enforce
dataflow:
  - from:
      tool: echo
    to:
      tool: danger_tool
    onMatch: deny
`);
      const h = startProxy({ FAKE_SECRET: '1' });
      const firstResponse = waitForNextResponse(h);
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: {} } });
      await firstResponse;
      h.send({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: { name: 'danger_tool', arguments: { leaked: LEAKED_SECRET } },
      });
      h.clientStdin.end();
      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<Record<string, unknown>>;
      const deniedLine = lines.find((l) => l.id === 2) as { error?: { message?: string } } | undefined;
      expect(deniedLine?.error).toBeDefined();
      const calls = readCallLog();
      expect(calls.map((c) => c.name)).toEqual(['echo']); // danger_tool call never reached the real server
    }, 15000);

    it('a v2 positiveSecurity allow-list denies a tool call outside the allow-list (enforce mode)', async () => {
      writeGlobalPolicy(`
version: 2
mode: enforce
positiveSecurity:
  tools: ["echo"]
  default: deny
`);
      const h = startProxy();
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'danger_tool', arguments: {} } });
      h.clientStdin.end();
      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<Record<string, unknown>>;
      const deniedLine = lines.find((l) => l.id === 1) as { error?: { message?: string } } | undefined;
      expect(deniedLine?.error).toBeDefined();
      const calls = readCallLog();
      expect(calls).toEqual([]);
    }, 15000);

    it('the SAME positiveSecurity policy still allows an allow-listed tool through', async () => {
      writeGlobalPolicy(`
version: 2
mode: enforce
positiveSecurity:
  tools: ["echo"]
  default: deny
`);
      const h = startProxy();
      h.send({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'echo', arguments: { hello: 'world' } } });
      h.clientStdin.end();
      const code = await h.runPromise;
      expect(code).toBe(0);

      const lines = h.outLines() as Array<{ id: number; result?: { content: Array<{ text: string }> } }>;
      expect(lines[0]).toMatchObject({ id: 1, result: expect.anything() });
      const calls = readCallLog();
      expect(calls.map((c) => c.name)).toEqual(['echo']);
    }, 15000);
  });
});
