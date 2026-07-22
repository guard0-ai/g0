import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadPolicy } from '../../src/enforcement/policy.js';
import { createEngineState, decide } from '../../src/enforcement/engine.js';

const DENY_POLICY = `
version: 1
mode: enforce
rules:
  - id: no-shell
    tools: ["shell*"]
    action: deny
    message: shell blocked
`;

describe('enforcement engine decide()', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-engine-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  function policyFrom(yaml: string) {
    fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), yaml);
    return loadPolicy({ dir: tmpDir });
  }

  it('denies a request matching a deny rule', () => {
    const policy = policyFrom(DENY_POLICY);
    const state = createEngineState(tmpDir);
    const out = decide(
      { transport: 'mcp-stdio', direction: 'request', serverName: 's', toolName: 'shell_exec', args: { cmd: 'rm -rf /' } },
      policy, state,
    );
    expect(out.decision.action).toBe('deny');
    expect(out.decision.message).toBe('shell blocked');
    expect(out.diagnostics).toEqual([]);      // no EDM/dataflow fired
    expect(out.inspectionFindings).toEqual([]); // request leg
  });

  it('allows an unmatched request with no findings', () => {
    const policy = policyFrom(DENY_POLICY);
    const state = createEngineState(tmpDir);
    const out = decide(
      { transport: 'mcp-stdio', direction: 'request', serverName: 's', toolName: 'read_file', args: { p: 'a.txt' } },
      policy, state,
    );
    expect(out.decision.action).toBe('allow');
    expect(out.findingNames).toBeUndefined();
  });

  it('redacts a secret-bearing response in enforce mode', () => {
    const policy = policyFrom('version: 1\nmode: enforce\nresponse:\n  redactSecrets: true\n  injection: alert\n');
    const state = createEngineState(tmpDir);
    const out = decide(
      {
        transport: 'mcp-stdio', direction: 'response', serverName: 's', toolName: 'fetch',
        args: {}, responseText: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and more',
      },
      policy, state,
    );
    expect(out.inspectionFindings.length).toBeGreaterThan(0);
    expect(out.redactedText).toBeDefined();
    expect(out.redactedText).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('tags response provenance so a later cross-tool request surfaces dataflow', () => {
    const policy = policyFrom('version: 1\nmode: enforce\nresponse:\n  redactSecrets: false\n  injection: alert\n');
    const state = createEngineState(tmpDir);
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    decide(
      { transport: 'mcp-stdio', direction: 'response', serverName: 's', toolName: 'vault_read', args: {}, responseText: `AWS_ACCESS_KEY_ID=${secret}` },
      policy, state,
    );
    const out = decide(
      { transport: 'mcp-stdio', direction: 'request', serverName: 's', toolName: 'http_post', args: { body: secret } },
      policy, state,
    );
    expect(out.diagnostics.some((d) => d.startsWith('provenance: dataflow'))).toBe(true);
  });
});
