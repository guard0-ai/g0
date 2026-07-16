import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';

/**
 * End-to-end tests for `g0 proxy` — driving the REAL CLI binary (via tsx) as a
 * spawned process, speaking MCP JSON-RPC over its stdio exactly as an IDE would.
 *
 * This is deliberately broader than tests/integration/proxy-core.test.ts, which
 * exercises the `runProxy` library function with injected streams. Here we prove
 * the fully assembled path: CLI arg parsing, `--` passthrough, banner
 * suppression (stdout must carry ONLY forwarded JSON-RPC), policy load from
 * `--policy-dir`, enforcement (deny/redact), the child never seeing a denied
 * call, the audit log written to disk, and a clean child exit code — all through
 * the actual `g0 proxy -- <cmd>` entry point.
 */

const REPO_ROOT = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const G0_BIN = path.join(REPO_ROOT, 'bin', 'g0.ts');
const FIXTURE = path.join(REPO_ROOT, 'tests', 'fixtures', 'mcp-stdio-server', 'server.mjs');
const RAW_SECRET = 'sk-ABCDEF0123456789abcdef';

interface JsonRpcResponse {
  jsonrpc: string;
  id?: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

interface SessionResult {
  stdout: string;
  responses: JsonRpcResponse[];
  exitCode: number | null;
}

/**
 * Spawn the real `g0 proxy --policy-dir <dir> --server <name> -- node <fixture>`,
 * write the given JSON-RPC request lines to its stdin, close stdin, and collect
 * everything the proxy forwards to stdout until the process exits.
 */
function runProxySession(opts: {
  policyDir: string;
  serverName: string;
  requests: object[];
  env?: Record<string, string>;
}): Promise<SessionResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      'npx',
      [
        'tsx',
        G0_BIN,
        'proxy',
        '--policy-dir',
        opts.policyDir,
        '--server',
        opts.serverName,
        '--',
        'node',
        FIXTURE,
      ],
      {
        cwd: REPO_ROOT,
        env: { ...process.env, ...opts.env },
        stdio: ['pipe', 'pipe', 'inherit'],
      },
    );

    let stdout = '';
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      const responses: JsonRpcResponse[] = [];
      for (const line of stdout.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          responses.push(JSON.parse(trimmed) as JsonRpcResponse);
        } catch {
          // non-JSON forwarded line (e.g. a server banner) — ignore for parsing
        }
      }
      resolve({ stdout, responses, exitCode: code });
    });

    for (const req of opts.requests) {
      child.stdin.write(JSON.stringify(req) + '\n');
    }
    child.stdin.end();
  });
}

const INITIALIZE = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} };
const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };

describe('g0 proxy — end-to-end through the real CLI', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-e2e-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writePolicy(yaml: string): void {
    fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), yaml, 'utf-8');
  }

  it('forwards initialize/tools-list and a benign tool call, then exits cleanly', async () => {
    writePolicy(`version: 1\nmode: enforce\nrules: []\n`);

    const result = await runProxySession({
      policyDir: tmpDir,
      serverName: 'benign',
      requests: [
        INITIALIZE,
        LIST,
        { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { hello: 'world' } } },
      ],
    });

    // stdout carries only JSON-RPC (banner suppressed) — every non-empty line parsed.
    const init = result.responses.find((r) => r.id === 1);
    expect((init?.result as { serverInfo?: { name?: string } })?.serverInfo?.name).toBe('g0-fake-mcp-server');

    const call = result.responses.find((r) => r.id === 3);
    const text = (call?.result as { content?: Array<{ text?: string }> })?.content?.[0]?.text ?? '';
    expect(text).toContain('echo:');
    expect(call?.error).toBeUndefined();
    expect(result.exitCode).toBe(0);
  }, 30_000);

  it('denies a policy-blocked tool call: client gets a JSON-RPC error and the server never sees the call', async () => {
    writePolicy(
      `version: 1\nmode: enforce\nrules:\n  - id: block-danger\n    direction: request\n    tools: ["danger_tool"]\n    action: deny\n    message: "Blocked by g0 policy: danger_tool"\n`,
    );
    const callLog = path.join(tmpDir, 'calls.jsonl');

    const result = await runProxySession({
      policyDir: tmpDir,
      serverName: 'enforced',
      env: { CALL_LOG_FILE: callLog },
      requests: [
        INITIALIZE,
        { jsonrpc: '2.0', id: 42, method: 'tools/call', params: { name: 'danger_tool', arguments: { rm: '-rf /' } } },
        // a benign call after the denied one must still work
        { jsonrpc: '2.0', id: 43, method: 'tools/call', params: { name: 'echo', arguments: { ok: true } } },
      ],
    });

    // Denied call → same-id JSON-RPC error back to the client.
    const denied = result.responses.find((r) => r.id === 42);
    expect(denied?.error).toBeDefined();
    expect(denied?.error?.message).toContain('danger_tool');

    // The real server never received the denied call...
    const loggedCalls = fs.existsSync(callLog)
      ? fs.readFileSync(callLog, 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as { name: string })
      : [];
    expect(loggedCalls.some((c) => c.name === 'danger_tool')).toBe(false);
    // ...but the benign echo after it did reach the server and returned.
    expect(loggedCalls.some((c) => c.name === 'echo')).toBe(true);
    const benign = result.responses.find((r) => r.id === 43);
    expect((benign?.result as { content?: Array<{ text?: string }> })?.content?.[0]?.text).toContain('echo:');
  }, 30_000);

  it('redacts a secret echoed in a tool response before it reaches the client', async () => {
    writePolicy(`version: 1\nmode: enforce\nresponse:\n  redactSecrets: true\nrules: []\n`);

    const result = await runProxySession({
      policyDir: tmpDir,
      serverName: 'redact',
      env: { FAKE_SECRET: '1' },
      requests: [
        INITIALIZE,
        { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'echo', arguments: {} } },
      ],
    });

    // The raw secret must NOT appear anywhere in what the client received.
    expect(result.stdout).not.toContain(RAW_SECRET);
    const call = result.responses.find((r) => r.id === 7);
    const text = (call?.result as { content?: Array<{ text?: string }> })?.content?.[0]?.text ?? '';
    expect(text).toContain('[g0:redacted]');
  }, 30_000);

  it('forwards a large (2MB+) final tools/call response through the real CLI without truncation', async () => {
    // Reproduces the reviewer's repro: `runAction` (src/cli/commands/proxy.ts)
    // called `process.exit(code)` immediately after `runProxy` resolved.
    // `runProxy` resolves inside `child.on('close')` right after
    // `stdout.end()`, WITHOUT waiting for that `.end()` to actually drain
    // ('finish'). When process.stdout is a pipe (every real IDE run, and
    // this spawned-CLI e2e harness), `process.exit()` does not flush
    // pending writes -> a large final response gets cut mid-stream,
    // breaking JSON-RPC framing.
    //
    // The fixture (tests/fixtures/mcp-stdio-server/server.mjs) appends a
    // unique end marker AFTER 2,000,000 bytes of padding specifically so a
    // truncation bug — which would still let plenty of leading bytes
    // through — can be caught: assert the marker (and the exact full text)
    // reached the client, not just "some" of the response.
    writePolicy(`version: 1\nmode: enforce\nrules: []\n`);

    const result = await runProxySession({
      policyDir: tmpDir,
      serverName: 'huge',
      env: { FAKE_HUGE: '1' },
      requests: [INITIALIZE, { jsonrpc: '2.0', id: 99, method: 'tools/call', params: { name: 'echo', arguments: {} } }],
    });

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('<<<G0_END_MARKER>>>');

    const call = result.responses.find((r) => r.id === 99);
    const text = (call?.result as { content?: Array<{ text?: string }> })?.content?.[0]?.text ?? '';
    const expectedText = `echo:${JSON.stringify({})}${'A'.repeat(2_000_000)}<<<G0_END_MARKER>>>`;
    expect(text.endsWith('<<<G0_END_MARKER>>>')).toBe(true);
    expect(text.length).toBe(expectedText.length);
    expect(text).toBe(expectedText);
  }, 30_000);

  it('writes an on-disk audit trail (readable back) reflecting allow + deny decisions', async () => {
    writePolicy(
      `version: 1\nmode: enforce\nrules:\n  - id: block-danger\n    direction: request\n    tools: ["danger_tool"]\n    action: deny\n`,
    );

    await runProxySession({
      policyDir: tmpDir,
      serverName: 'audited',
      requests: [
        INITIALIZE,
        { jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'echo', arguments: { a: 1 } } },
        { jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'danger_tool', arguments: {} } },
      ],
    });

    // The proxy was run with --policy-dir = tmpDir, so audit logs land under
    // tmpDir/logs (proving --policy-dir redirects the audit log, not just policy).
    const { readAudit, summarizeAudit } = await import('../../src/proxy/audit-log.js');
    const records = readAudit({ dir: tmpDir, serverName: 'audited' });
    expect(records.length).toBeGreaterThan(0);

    const summary = summarizeAudit({ dir: tmpDir });
    expect(summary.proxiedServers).toContain('audited');
    expect(summary.totalCalls).toBeGreaterThanOrEqual(2);
    expect(summary.denied).toBeGreaterThanOrEqual(1);
  }, 30_000);
});
