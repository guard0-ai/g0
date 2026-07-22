import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { PassThrough } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { runProxy } from '../../src/proxy/proxy-core.js';

const REPO = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const FIXTURE = path.join(REPO, 'tests', 'fixtures', 'mcp-stdio-server', 'server.mjs');

interface Session {
  send(message: unknown): void;
  end(): void;
  out(): string;
  err(): string;
  runPromise: Promise<number>;
}

function session(policyDir: string, env: Record<string, string> = {}): Session {
  const clientStdin = new PassThrough();
  const clientStdout = new PassThrough();
  const clientStderr = new PassThrough();
  let out = '';
  let err = '';
  clientStdout.on('data', (chunk) => { out += chunk; });
  clientStderr.on('data', (chunk) => { err += chunk; });
  const runPromise = runProxy({
    serverName: 'pin-test',
    command: process.execPath,
    args: [FIXTURE],
    policyDir,
    auditDir: policyDir,
    stdin: clientStdin,
    stdout: clientStdout,
    stderr: clientStderr,
    env: { ...process.env, ...env },
  });
  return {
    send: (message) => clientStdin.write(JSON.stringify(message) + '\n'),
    end: () => clientStdin.end(),
    out: () => out,
    err: () => err,
    runPromise,
  };
}

async function waitFor(predicate: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error('waitFor timed out');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe('proxy TOFU tool-list pinning', () => {
  let policyDir: string;
  beforeEach(() => { policyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-pin-')); });
  afterEach(() => { fs.rmSync(policyDir, { recursive: true, force: true }); });

  async function listSession(env: Record<string, string> = {}): Promise<Session> {
    const s = session(policyDir, env);
    s.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    s.send({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
    await waitFor(() => s.out().includes('"id":2') || s.out().includes('"id": 2'));
    return s;
  }

  it('first sight records the pin silently (TOFU)', async () => {
    const s = await listSession();
    s.end();
    await s.runPromise;
    expect(fs.existsSync(path.join(policyDir, 'pins', 'pin-test.json'))).toBe(true);
    expect(fs.existsSync(path.join(policyDir, 'pins', 'pin-test.drift.json'))).toBe(false);
    expect(s.err()).not.toContain('PIN DRIFT');
  });

  it('drift under default (alert) warns, records drift, never blocks', async () => {
    const first = await listSession();
    first.end();
    await first.runPromise;

    const second = await listSession({ TOOLS_DESC_SUFFIX: ' v2' });
    await waitFor(() => second.err().includes('PIN DRIFT'));
    second.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { x: 1 } } });
    await waitFor(() => second.out().includes('"id":3') || second.out().includes('"id": 3'));
    expect(second.out()).not.toContain('review-server'); // forwarded, not denied
    second.end();
    await second.runPromise;
    expect(fs.existsSync(path.join(policyDir, 'pins', 'pin-test.drift.json'))).toBe(true);
  });

  it('drift under pinning: deny blocks subsequent tools/call', async () => {
    fs.writeFileSync(path.join(policyDir, 'policy.yaml'), 'version: 1\nmode: enforce\npinning: deny\n');
    const first = await listSession();
    first.end();
    await first.runPromise;

    const second = await listSession({ TOOLS_DESC_SUFFIX: ' v2' });
    await waitFor(() => second.err().includes('PIN DRIFT'));
    second.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { x: 1 } } });
    await waitFor(() => second.out().includes('"id":3') || second.out().includes('"id": 3'));
    expect(second.out()).toContain('review-server'); // synthesized deny error
    second.end();
    await second.runPromise;
  });
});
