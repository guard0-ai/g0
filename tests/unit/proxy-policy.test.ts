import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { evaluateCall, evaluateResponse, loadPolicy } from '../../src/proxy/policy.js';
import type { InspectionResult } from '../../src/proxy/response-inspector.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-policy-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeGlobalPolicy(yamlContent: string): void {
  fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), yamlContent, 'utf-8');
}

function writeServerPolicy(serverName: string, yamlContent: string): void {
  const policiesDir = path.join(tmpDir, 'policies');
  fs.mkdirSync(policiesDir, { recursive: true });
  fs.writeFileSync(path.join(policiesDir, `${serverName}.yaml`), yamlContent, 'utf-8');
}

// ─────────────────────────────────────────────────────────────────────────
// loadPolicy
// ─────────────────────────────────────────────────────────────────────────

describe('loadPolicy', () => {
  it('returns a default observe policy with no rules when no files exist', () => {
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.mode).toBe('observe');
    expect(policy.onError).toBe('open');
    expect(policy.limits.maxScanBytes).toBe(1_048_576);
    expect(policy.rules).toEqual([]);
    expect(policy.response).toEqual({ redactSecrets: false, injection: 'alert' });
  });

  it('does not throw when the dir itself does not exist', () => {
    expect(() => loadPolicy({ dir: path.join(tmpDir, 'does', 'not', 'exist') })).not.toThrow();
  });

  it('parses a valid global policy file', () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
onError: closed
limits:
  maxScanBytes: 2048
rules:
  - id: block-destructive-commands
    direction: request
    tools: ["execute_command", "run_*", "*shell*", "bash"]
    argsRegex: '(rm\\s+-rf\\s+/|mkfs|dd\\s+if=)'
    action: deny
    message: "Blocked by g0 policy: destructive command"
response:
  redactSecrets: true
  injection: alert
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.mode).toBe('enforce');
    expect(policy.onError).toBe('closed');
    expect(policy.limits.maxScanBytes).toBe(2048);
    expect(policy.response).toEqual({ redactSecrets: true, injection: 'alert' });
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].id).toBe('block-destructive-commands');
    expect(policy.rules[0].action).toBe('deny');
    expect(policy.rules[0].toolMatchers).toHaveLength(4);
    expect(policy.rules[0].argsRegex).toBeInstanceOf(RegExp);
  });

  it('merges a per-server override over the global policy: mode overridden, rules appended', () => {
    writeGlobalPolicy(`
version: 1
mode: observe
rules:
  - id: global-rule
    tools: ["*"]
    action: alert
`);
    writeServerPolicy('my-server', `
mode: enforce
rules:
  - id: server-rule
    tools: ["dangerous_tool"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir, serverName: 'my-server' });
    expect(policy.mode).toBe('enforce');
    expect(policy.rules.map((r) => r.id)).toEqual(['global-rule', 'server-rule']);
  });

  it('per-server file missing is a silent no-op (base policy unaffected)', () => {
    writeGlobalPolicy(`
version: 1
mode: alert
`);
    const policy = loadPolicy({ dir: tmpDir, serverName: 'nonexistent-server' });
    expect(policy.mode).toBe('alert');
    expect(policy.rules).toEqual([]);
  });

  it('falls back to a default observe policy on malformed global YAML, without throwing', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy('mode: enforce\n  bad indent: [oops\n:::not yaml:::');

    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir });
    }).not.toThrow();

    expect(policy!.mode).toBe('observe');
    expect(policy!.rules).toEqual([]);
    expect(errorSpy).toHaveBeenCalled();
    // Diagnostics must go to stderr (console.error), never stdout.
    expect(errorSpy.mock.calls[0][0]).toContain('policy file');

    errorSpy.mockRestore();
  });

  it('malformed per-server override is skipped without throwing, base policy kept', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy('mode: enforce\n');
    writeServerPolicy('broken-server', ':::not: valid: yaml:::\n  - [');

    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir, serverName: 'broken-server' });
    }).not.toThrow();

    // The global file parsed fine and said enforce; a broken *override* file
    // must not silently change that (nor silently upgrade it) — overrides
    // from the broken file are simply not applied.
    expect(policy!.mode).toBe('enforce');
    expect(errorSpy).toHaveBeenCalled();

    errorSpy.mockRestore();
  });

  it('a bad argsRegex disables just that rule, without crashing load', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: bad-regex-rule
    tools: ["*"]
    argsRegex: '(unterminated['
    action: deny
  - id: good-rule
    tools: ["*"]
    action: alert
`);
    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir });
    }).not.toThrow();

    // The broken rule is dropped entirely; the good rule after it survives.
    expect(policy!.rules.map((r) => r.id)).toEqual(['good-rule']);
    expect(errorSpy).toHaveBeenCalled();

    errorSpy.mockRestore();
  });

  it('an unknown mode/onError/action value warns and falls back to a safe default', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy(`
mode: yolo
onError: maybe
rules:
  - id: weird-action-rule
    tools: ["*"]
    action: nuke
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.mode).toBe('observe');
    expect(policy.onError).toBe('open');
    expect(policy.rules[0].action).toBe('alert');
    expect(errorSpy).toHaveBeenCalled();

    errorSpy.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// Glob compilation (exercised through loadPolicy + evaluateCall)
// ─────────────────────────────────────────────────────────────────────────

describe('tool glob matching', () => {
  it('run_* matches run_shell but not arun', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    tools: ["run_*"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'run_shell', {}).action).toBe('deny');
    expect(evaluateCall(policy, 'tools/call', 'arun', {}).action).toBe('allow');
  });

  it('*shell* matches myshell_exec', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    tools: ["*shell*"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'myshell_exec', {}).action).toBe('deny');
  });

  it('exact "bash" matches only bash, not bashful or gitbash', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    tools: ["bash"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'bash', {}).action).toBe('deny');
    expect(evaluateCall(policy, 'tools/call', 'bashful', {}).action).toBe('allow');
    expect(evaluateCall(policy, 'tools/call', 'gitbash', {}).action).toBe('allow');
  });

  it('an empty/omitted tools list matches everything', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'literally_anything', {}).action).toBe('deny');
    expect(evaluateCall(policy, 'tools/call', 'x', {}).action).toBe('deny');
  });

  it('escapes regex metacharacters in the literal parts of a glob', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    tools: ["a.b"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'a.b', {}).action).toBe('deny');
    // If '.' weren't escaped, "aXb" would incorrectly match "a.b" as regex.
    expect(evaluateCall(policy, 'tools/call', 'aXb', {}).action).toBe('allow');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// evaluateCall
// ─────────────────────────────────────────────────────────────────────────

describe('evaluateCall', () => {
  const destructivePolicyYaml = `
mode: enforce
rules:
  - id: block-destructive-commands
    tools: ["execute_command", "run_*", "*shell*", "bash"]
    argsRegex: '(rm\\s+-rf\\s+/|mkfs|dd\\s+if=)'
    action: deny
    message: "Blocked by g0 policy: destructive command"
`;

  it('denies a destructive command in enforce mode', () => {
    writeGlobalPolicy(destructivePolicyYaml);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'execute_command', { command: 'rm -rf /' });
    expect(decision).toMatchObject({
      action: 'deny',
      ruleId: 'block-destructive-commands',
      direction: 'request',
    });
  });

  it('downgrades the same destructive-command rule to alert in alert mode', () => {
    writeGlobalPolicy(destructivePolicyYaml.replace('mode: enforce', 'mode: alert'));
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'execute_command', { command: 'rm -rf /' });
    expect(decision.action).toBe('alert');
  });

  it('downgrades the same destructive-command rule to alert in observe mode', () => {
    writeGlobalPolicy(destructivePolicyYaml.replace('mode: enforce', 'mode: observe'));
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'execute_command', { command: 'rm -rf /' });
    expect(decision.action).toBe('alert');
  });

  it('a non-matching call is allowed', () => {
    writeGlobalPolicy(destructivePolicyYaml);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'execute_command', { command: 'ls -la' });
    expect(decision).toEqual({ action: 'allow', direction: 'request' });
  });

  it('no rules at all -> allow', () => {
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'anything', { x: 1 });
    expect(decision).toEqual({ action: 'allow', direction: 'request' });
  });

  describe('path allowlist', () => {
    const pathPolicyYaml = `
mode: enforce
rules:
  - id: file-write-allowlist
    tools: ["write_file", "edit_file", "create_file"]
    pathArgs: ["path", "file_path"]
    allowPaths: ["~/projects/**", "/tmp/**"]
    action: deny
`;

    it('denies a write outside allowPaths', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const decision = evaluateCall(policy, 'tools/call', 'write_file', { path: '/etc/passwd' });
      expect(decision.action).toBe('deny');
      expect(decision.ruleId).toBe('file-write-allowlist');
    });

    it('allows a write inside allowPaths', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const decision = evaluateCall(policy, 'tools/call', 'write_file', { path: '/tmp/scratch/out.txt' });
      expect(decision).toEqual({ action: 'allow', direction: 'request' });
    });

    it('expands ~ in both the arg value and allowPaths', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const inside = evaluateCall(policy, 'tools/call', 'write_file', { path: '~/projects/foo/bar.py' });
      expect(inside).toEqual({ action: 'allow', direction: 'request' });

      const outside = evaluateCall(policy, 'tools/call', 'write_file', { path: '~/other/bar.py' });
      expect(outside.action).toBe('deny');
    });

    it('checks the second pathArgs key (file_path) too', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const decision = evaluateCall(policy, 'tools/call', 'edit_file', { file_path: '/root/secrets.txt' });
      expect(decision.action).toBe('deny');
    });

    // ───────────────────────────────────────────────────────────────────
    // `../` traversal must not bypass the allowlist (Critical fix).
    // ───────────────────────────────────────────────────────────────────

    it('denies a ~-rooted traversal that textually starts with an allowed prefix but resolves outside it', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const decision = evaluateCall(policy, 'tools/call', 'write_file', {
        path: '~/projects/../../../../etc/passwd',
      });
      expect(decision.action).toBe('deny');
      expect(decision.ruleId).toBe('file-write-allowlist');
    });

    it('denies an absolute-path traversal that textually starts with an allowed prefix but resolves outside it', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const decision = evaluateCall(policy, 'tools/call', 'write_file', {
        path: '/tmp/../etc/passwd',
      });
      expect(decision.action).toBe('deny');
      expect(decision.ruleId).toBe('file-write-allowlist');
    });

    it('still allows a legitimate in-allowlist path (traversal fix does not break normal writes)', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      const decision = evaluateCall(policy, 'tools/call', 'write_file', { path: '/tmp/scratch/out.txt' });
      expect(decision).toEqual({ action: 'allow', direction: 'request' });
    });

    it('allows a path containing .. that still resolves inside the allowlist', () => {
      writeGlobalPolicy(pathPolicyYaml);
      const policy = loadPolicy({ dir: tmpDir });
      // ~/projects/sub/../ok.txt resolves to ~/projects/ok.txt, which is
      // inside the ~/projects/** allowlist entry.
      const decision = evaluateCall(policy, 'tools/call', 'write_file', {
        path: '~/projects/sub/../ok.txt',
      });
      expect(decision).toEqual({ action: 'allow', direction: 'request' });
    });

    it('anchors allowPaths so a same-prefix sibling directory is still denied (/home/foo vs /home/foobar)', () => {
      writeGlobalPolicy(`
mode: enforce
rules:
  - id: exact-path-allowlist
    tools: ["write_file"]
    pathArgs: ["path"]
    allowPaths: ["/home/foo"]
    action: deny
`);
      const policy = loadPolicy({ dir: tmpDir });

      const denied = evaluateCall(policy, 'tools/call', 'write_file', { path: '/home/foobar' });
      expect(denied.action).toBe('deny');
      expect(denied.ruleId).toBe('exact-path-allowlist');

      const allowed = evaluateCall(policy, 'tools/call', 'write_file', { path: '/home/foo' });
      expect(allowed).toEqual({ action: 'allow', direction: 'request' });
    });
  });

  it('first-match-wins when two rules overlap', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: first-allow
    tools: ["run_*"]
    action: allow
  - id: second-deny
    tools: ["run_*"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'run_shell', {});
    expect(decision.ruleId).toBe('first-allow');
    expect(decision.action).toBe('allow');
  });

  it('never throws when args is a string, number, or null instead of an object', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: file-write-allowlist
    tools: ["write_file"]
    pathArgs: ["path"]
    allowPaths: ["/tmp/**"]
    action: deny
  - id: destructive
    tools: ["write_file"]
    argsRegex: 'rm -rf'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });

    for (const weirdArgs of ['just a string', 42, null, undefined, ['array', 'args']]) {
      expect(() => evaluateCall(policy, 'tools/call', 'write_file', weirdArgs)).not.toThrow();
    }
    // A plain string arg contains no path violation (no object to read pathArgs
    // keys from) and doesn't match the destructive regex, so it's allowed.
    expect(evaluateCall(policy, 'tools/call', 'write_file', 'hello').action).toBe('allow');
    // But argsRegex still runs against the stringified args either way.
    expect(evaluateCall(policy, 'tools/call', 'write_file', 'please rm -rf now').action).toBe('deny');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// evaluateResponse
// ─────────────────────────────────────────────────────────────────────────

describe('evaluateResponse', () => {
  const injectionFinding: InspectionResult = {
    findings: [{ category: 'injection', name: 'Role reassignment', severity: 'high', match: 'ignore previous' }],
  };
  const secretFinding: InspectionResult = {
    findings: [{ category: 'secret', name: 'Potential secret in response', severity: 'high', match: 'sk-abc123' }],
  };
  const cleanResult: InspectionResult = { findings: [] };

  function policyWith(mode: 'enforce' | 'alert' | 'observe', injection: 'alert' | 'deny' | 'off', redactSecrets = false) {
    writeGlobalPolicy(`
mode: ${mode}
response:
  redactSecrets: ${redactSecrets}
  injection: ${injection}
`);
    return loadPolicy({ dir: tmpDir });
  }

  it('injection finding + injection: deny in enforce mode -> deny', () => {
    const policy = policyWith('enforce', 'deny');
    const decision = evaluateResponse(policy, 'some_tool', injectionFinding);
    expect(decision.action).toBe('deny');
    expect(decision.direction).toBe('response');
  });

  it('injection finding + injection: deny in alert mode -> downgraded to alert', () => {
    const policy = policyWith('alert', 'deny');
    const decision = evaluateResponse(policy, 'some_tool', injectionFinding);
    expect(decision.action).toBe('alert');
  });

  it('injection finding + injection: deny in observe mode -> downgraded to alert', () => {
    const policy = policyWith('observe', 'deny');
    const decision = evaluateResponse(policy, 'some_tool', injectionFinding);
    expect(decision.action).toBe('alert');
  });

  it('injection finding + injection: alert -> alert', () => {
    const policy = policyWith('enforce', 'alert');
    const decision = evaluateResponse(policy, 'some_tool', injectionFinding);
    expect(decision.action).toBe('alert');
  });

  it('injection finding + injection: off -> allow', () => {
    const policy = policyWith('enforce', 'off');
    const decision = evaluateResponse(policy, 'some_tool', injectionFinding);
    expect(decision.action).toBe('allow');
  });

  it('secret finding + redactSecrets: true -> redact', () => {
    const policy = policyWith('enforce', 'off', true);
    const decision = evaluateResponse(policy, 'some_tool', secretFinding);
    expect(decision.action).toBe('redact');
  });

  it('secret finding + redactSecrets: false -> allow (no rule to contribute)', () => {
    const policy = policyWith('enforce', 'off', false);
    const decision = evaluateResponse(policy, 'some_tool', secretFinding);
    expect(decision.action).toBe('allow');
  });

  it('no findings -> allow', () => {
    const policy = policyWith('enforce', 'deny', true);
    const decision = evaluateResponse(policy, 'some_tool', cleanResult);
    expect(decision).toEqual({ action: 'allow', direction: 'response' });
  });

  it('precedence deny > redact > alert > allow when multiple findings fire', () => {
    const policy = policyWith('enforce', 'alert', true); // injection -> alert, secret -> redact
    const combined: InspectionResult = { findings: [...injectionFinding.findings, ...secretFinding.findings] };
    const decision = evaluateResponse(policy, 'some_tool', combined);
    // redact (2) > alert (1) here since injection is only "alert" in this policy.
    expect(decision.action).toBe('redact');

    const denyPolicy = policyWith('enforce', 'deny', true); // injection -> deny, secret -> redact
    const decision2 = evaluateResponse(denyPolicy, 'some_tool', combined);
    expect(decision2.action).toBe('deny');
  });

  it('honors an explicit direction: response rule', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: block-bad-tool-response
    direction: response
    tools: ["risky_tool"]
    action: deny
    message: "risky_tool responses are always blocked"
`);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateResponse(policy, 'risky_tool', cleanResult);
    expect(decision.action).toBe('deny');
    expect(decision.ruleId).toBe('block-bad-tool-response');

    const other = evaluateResponse(policy, 'other_tool', cleanResult);
    expect(other.action).toBe('allow');
  });

  it('never throws on a malformed InspectionResult', () => {
    const policy = policyWith('enforce', 'deny', true);
    // @ts-expect-error deliberately passing garbage to verify defensive handling
    expect(() => evaluateResponse(policy, 'tool', null)).not.toThrow();
    // @ts-expect-error deliberately passing garbage to verify defensive handling
    expect(() => evaluateResponse(policy, 'tool', {})).not.toThrow();
    // @ts-expect-error deliberately passing garbage to verify defensive handling
    expect(() => evaluateResponse(policy, 'tool', { findings: 'not-an-array' })).not.toThrow();
  });

  // ─────────────────────────────────────────────────────────────────────
  // direction: 'response' rules with argsRegex, tested against the
  // responseTextSurrogate() built from InspectionResult (redactedText +
  // finding match snippets — the surrogate is lossy since InspectionResult
  // does not retain the full original response text).
  // ─────────────────────────────────────────────────────────────────────

  it('a direction: response argsRegex rule fires against a finding match snippet', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: response-argsregex-match
    direction: response
    tools: ["risky_tool"]
    argsRegex: 'ignore previous'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [
        { category: 'injection', name: 'Role reassignment', severity: 'high', match: 'ignore previous instructions' },
      ],
    };
    const decision = evaluateResponse(policy, 'risky_tool', inspection);
    expect(decision.action).toBe('deny');
    expect(decision.ruleId).toBe('response-argsregex-match');
  });

  it('a direction: response argsRegex rule fires against inspection.redactedText', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: response-argsregex-redacted
    direction: response
    tools: ["risky_tool"]
    argsRegex: 'secret-token'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [],
      redactedText: 'here is a secret-token that leaked',
    };
    const decision = evaluateResponse(policy, 'risky_tool', inspection);
    expect(decision.action).toBe('deny');
    expect(decision.ruleId).toBe('response-argsregex-redacted');
  });

  it('a direction: response argsRegex rule does not fire when the surrogate is empty (documented limitation)', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: response-argsregex-empty
    direction: response
    tools: ["risky_tool"]
    argsRegex: '.+'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    // No redactedText and no findings at all -> responseTextSurrogate()
    // returns '', so an argsRegex requiring at least one character can
    // never match here — even if the (unavailable) full response text
    // actually contained matching content. This pins the documented
    // lossiness of the surrogate rather than silently doing nothing.
    const inspection: InspectionResult = { findings: [] };
    const decision = evaluateResponse(policy, 'risky_tool', inspection);
    expect(decision).toEqual({ action: 'allow', direction: 'response' });
  });
});
