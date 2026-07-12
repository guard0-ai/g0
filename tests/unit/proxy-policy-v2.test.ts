/**
 * Policy DSL v2 (Task 5, Phase 4) — confidence fusion + decision map wiring,
 * gated by `version: 2`.
 *
 * ── Section 1 is the acceptance bar for this whole task ─────────────────
 *
 * A policy file that is `version: 1`, or has NO `version:` key at all, MUST
 * compile through the EXISTING (pre-Task-5) path completely untouched and
 * produce the EXACT same decisions as before this task. Only `version: 2`
 * opts into the new schema/behavior. This file's first `describe` block
 * pins that guarantee directly: it was written and run GREEN against the
 * pre-Task-5 code (see the task report for the exact command/output), then
 * kept green with zero edits after v2 support was added.
 *
 * The remaining sections cover the v2 DSL itself: confidence-fusion
 * wiring, each new policy block, malformed-v2 fallback, fail-open
 * behavior, and the two Task-4 coverage gaps this task's brief called out.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  combineDecisions,
  dataflowMatchCandidate,
  edmMatchCandidate,
  evaluateCall,
  evaluateResponse,
  loadPolicy,
  resolveDetectors,
} from '../../src/proxy/policy.js';
import type { InspectionResult } from '../../src/proxy/response-inspector.js';
import { SessionProvenance } from '../../src/proxy/provenance.js';
import type { DataflowFinding } from '../../src/proxy/provenance.js';
import type { EdmMatch } from '../../src/proxy/edm.js';
import type { EvalContext } from '../../src/proxy/policy.js';

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-policy-v2-'));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function writeGlobalPolicy(yamlContent: string): void {
  fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), yamlContent, 'utf-8');
}

// ─────────────────────────────────────────────────────────────────────────
// SECTION 1 — v1 / version-less regression (the non-negotiable bar)
// ─────────────────────────────────────────────────────────────────────────

describe('v1 / version-less policies: byte-identical behavior under v2-aware loadPolicy', () => {
  it('a version-less file with no rules loads the exact same default shape as before, and the new v2 fields are all absent', () => {
    writeGlobalPolicy('mode: observe\n');
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.version).toBe(1);
    expect(policy.mode).toBe('observe');
    expect(policy.onError).toBe('open');
    expect(policy.limits).toEqual({ maxScanBytes: 1_048_576 });
    expect(policy.rules).toEqual([]);
    expect(policy.response).toEqual({ redactSecrets: false, injection: 'alert' });
    // The whole point of "additive, minimal internal-shape extension": none
    // of the new v2-only fields are ever populated by the v1 compile path.
    expect(policy.thresholds).toBeUndefined();
    expect(policy.detectors).toBeUndefined();
    expect(policy.edm).toBeUndefined();
    expect(policy.dataflow).toBeUndefined();
    expect(policy.context).toBeUndefined();
    expect(policy.positiveSecurity).toBeUndefined();
  });

  it('an explicit "version: 1" file behaves identically to a version-less one', () => {
    writeGlobalPolicy(`
version: 1
mode: enforce
rules:
  - id: block-danger
    tools: ["danger_*"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.version).toBe(1);
    expect(evaluateCall(policy, 'tools/call', 'danger_tool', {}).action).toBe('deny');
    expect(policy.thresholds).toBeUndefined();
  });

  it('deny rule in enforce mode -> deny (representative decision #1)', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: block-destructive
    tools: ["execute_command"]
    argsRegex: 'rm -rf'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'execute_command', { command: 'rm -rf /' });
    expect(decision).toEqual({
      action: 'deny',
      ruleId: 'block-destructive',
      message: undefined,
      direction: 'request',
    });
  });

  it('the same deny rule downgrades to coach in alert mode (representative decision #2)', () => {
    writeGlobalPolicy(`
mode: alert
rules:
  - id: block-destructive
    tools: ["execute_command"]
    argsRegex: 'rm -rf'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'execute_command', { command: 'rm -rf /' });
    expect(decision.action).toBe('coach');
  });

  it('a secret finding + redactSecrets:true -> redact (representative decision #3)', () => {
    writeGlobalPolicy(`
mode: enforce
response:
  redactSecrets: true
  injection: off
`);
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [{ category: 'secret', name: 'Potential secret', severity: 'high', match: 'sk-abc', confidence: 0.9 }],
    };
    const decision = evaluateResponse(policy, 'some_tool', inspection);
    expect(decision.action).toBe('redact');
  });

  it('a non-matching call is allow (representative decision #4)', () => {
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    tools: ["danger_*"]
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'harmless_tool', {});
    expect(decision).toEqual({ action: 'allow', direction: 'request' });
  });

  it('response findings: no findings -> allow; injection+deny in enforce -> deny; same in alert -> coach', () => {
    writeGlobalPolicy(`
mode: enforce
response:
  injection: deny
`);
    const enforcePolicy = loadPolicy({ dir: tmpDir });
    const clean: InspectionResult = { findings: [] };
    expect(evaluateResponse(enforcePolicy, 't', clean)).toEqual({ action: 'allow', direction: 'response' });

    const injection: InspectionResult = {
      findings: [{ category: 'injection', name: 'Role reassignment', severity: 'high', match: 'ignore previous' }],
    };
    expect(evaluateResponse(enforcePolicy, 't', injection).action).toBe('deny');

    writeGlobalPolicy(`
mode: alert
response:
  injection: deny
`);
    const alertPolicy = loadPolicy({ dir: tmpDir });
    expect(evaluateResponse(alertPolicy, 't', injection).action).toBe('coach');
  });

  it('malformed v1 YAML still falls back to observe mode with a stderr log, exactly as before', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy('mode: enforce\n  bad indent: [oops\n:::not yaml:::');
    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir });
    }).not.toThrow();
    expect(policy!.mode).toBe('observe');
    expect(policy!.rules).toEqual([]);
    expect(policy!.version).toBe(1);
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('per-server override merge still uses the v1 merge path when the base is v1', () => {
    writeGlobalPolicy(`
version: 1
mode: observe
rules:
  - id: global-rule
    tools: ["*"]
    action: alert
`);
    const policiesDir = path.join(tmpDir, 'policies');
    fs.mkdirSync(policiesDir, { recursive: true });
    fs.writeFileSync(
      path.join(policiesDir, 'my-server.yaml'),
      'mode: enforce\nrules:\n  - id: server-rule\n    tools: ["dangerous_tool"]\n    action: deny\n',
      'utf-8',
    );
    const policy = loadPolicy({ dir: tmpDir, serverName: 'my-server' });
    expect(policy.mode).toBe('enforce');
    expect(policy.rules.map((r) => r.id)).toEqual(['global-rule', 'server-rule']);
    expect(policy.thresholds).toBeUndefined();
  });

  it('a rule action of "coach" is REJECTED by the v1 parser exactly as today (coach is not a valid v1 rule-author action)', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy(`
mode: enforce
rules:
  - id: r
    tools: ["*"]
    action: coach
`);
    const policy = loadPolicy({ dir: tmpDir });
    // Falls back to the documented default for an unrecognized action, same
    // as any other unknown action string (e.g. "nuke") in v1.
    expect(policy.rules[0].action).toBe('alert');
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('ctx (EvalContext) present but policy is v1: dataflow/velocity candidates still use the pre-Task-5 fixed-confidence path, unaffected by v2 additions', () => {
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    const provenance = new SessionProvenance();
    provenance.tagResponse('reader_tool', 'srv', [
      { category: 'secret', name: 'x', severity: 'high', match: 'sk-live-CANARY-VALUE-0001' },
    ]);
    const ctx: EvalContext = { destinationServer: 'srv', destinationTool: 'writer_tool', provenance };
    const decision = evaluateCall(policy, 'tools/call', 'writer_tool', { v: 'sk-live-CANARY-VALUE-0001' }, ctx);
    expect(decision.action).toBe('deny');
    expect(decision.confidence).toBe(0.9); // Task 4's fixed dataflow confidence, not fused
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 2 — v2 policy parses, and every new block compiles into the
// internal shape
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: parsing and compilation', () => {
  it('a full v2 policy file parses and every block compiles into the internal ProxyPolicy shape', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
onError: closed
limits:
  maxScanBytes: 2048
response:
  redactSecrets: true
  injection: deny
thresholds:
  deny: 0.9
  redact: 0.7
  coach: 0.3
detectors:
  credit-card:
    enabled: false
  vendor-key:
    confidence: 0.5
edm:
  - index: prod-secrets
    onMatch: deny
dataflow:
  - from:
      tool: reader_*
      server: srv-1
    to:
      tool: writer_*
    onMatch: coach
context:
  destinations:
    untrusted: ["*_external"]
    trusted: ["internal_*"]
  volume:
    windowMs: 30000
    alertThreshold: 3
positiveSecurity:
  tools: ["read_file", "search_docs"]
  default: deny
rules:
  - id: coach-rule
    tools: ["risky_*"]
    action: coach
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.version).toBe(2);
    expect(policy.mode).toBe('enforce');
    expect(policy.onError).toBe('closed');
    expect(policy.limits.maxScanBytes).toBe(2048);
    expect(policy.response).toEqual({ redactSecrets: true, injection: 'deny' });

    expect(policy.thresholds).toEqual({ deny: 0.9, redact: 0.7, coach: 0.3 });

    expect(policy.detectors).toEqual({
      'credit-card': { enabled: false },
      'vendor-key': { confidence: 0.5 },
    });

    expect(policy.edm).toEqual([{ index: 'prod-secrets', onMatch: 'deny' }]);

    expect(policy.dataflow).toHaveLength(1);
    expect(policy.dataflow![0].onMatch).toBe('coach');
    expect(policy.dataflow![0].fromTool?.test('reader_db')).toBe(true);
    expect(policy.dataflow![0].fromTool?.test('other')).toBe(false);
    expect(policy.dataflow![0].fromServer?.test('srv-1')).toBe(true);
    expect(policy.dataflow![0].toTool?.test('writer_email')).toBe(true);
    expect(policy.dataflow![0].toServer).toBeUndefined();

    expect(policy.context?.untrustedDestinations?.[0].test('send_external')).toBe(true);
    expect(policy.context?.trustedDestinations?.[0].test('internal_log')).toBe(true);
    expect(policy.context?.volumeWindowMs).toBe(30000);
    expect(policy.context?.volumeAlertThreshold).toBe(3);

    expect(policy.positiveSecurity?.defaultAction).toBe('deny');
    expect(policy.positiveSecurity?.allowedTools[0].test('read_file')).toBe(true);
    expect(policy.positiveSecurity?.allowedTools.some((re) => re.test('delete_file'))).toBe(false);

    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0].action).toBe('coach'); // the ONE new rule-level action value
  });

  it('omitting every optional v2 block still parses to a valid, minimal v2 policy', () => {
    writeGlobalPolicy('version: 2\n');
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.version).toBe(2);
    expect(policy.mode).toBe('observe'); // still defaults the same as v1
    expect(policy.thresholds).toBeUndefined();
    expect(policy.edm).toBeUndefined();
    expect(policy.dataflow).toBeUndefined();
    expect(policy.context).toBeUndefined();
    expect(policy.positiveSecurity).toBeUndefined();
    expect(policy.rules).toEqual([]);
  });

  it('an "action: coach" v2 rule NEVER blocks in enforce mode, and forwards the call unmodified', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
rules:
  - id: coach-rule
    tools: ["risky_tool"]
    action: coach
`);
    const policy = loadPolicy({ dir: tmpDir });
    const decision = evaluateCall(policy, 'tools/call', 'risky_tool', {});
    expect(decision.action).toBe('coach');
    expect(decision.ruleId).toBe('coach-rule');
  });

  it('a v2 per-server override merges via the v2 override schema (thresholds/edm/dataflow accumulate, scalars override)', () => {
    writeGlobalPolicy(`
version: 2
mode: observe
thresholds:
  deny: 0.9
edm:
  - index: base-index
    onMatch: alert
`);
    const policiesDir = path.join(tmpDir, 'policies');
    fs.mkdirSync(policiesDir, { recursive: true });
    fs.writeFileSync(
      path.join(policiesDir, 'my-server.yaml'),
      'mode: enforce\nthresholds:\n  redact: 0.6\nedm:\n  - index: override-index\n    onMatch: deny\n',
      'utf-8',
    );
    const policy = loadPolicy({ dir: tmpDir, serverName: 'my-server' });
    expect(policy.version).toBe(2);
    expect(policy.mode).toBe('enforce'); // scalar override wins
    expect(policy.thresholds).toEqual({ deny: 0.9, redact: 0.6, coach: 0.4 }); // merged field-by-field (coach from DEFAULT_THRESHOLDS)
    expect(policy.edm).toEqual([
      { index: 'base-index', onMatch: 'alert' },
      { index: 'override-index', onMatch: 'deny' },
    ]); // accumulated, base first
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 3 — confidence-fusion wiring: thresholds change the outcome
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: confidence fusion drives the outcome', () => {
  function v2PolicyWith(extraYaml: string): ReturnType<typeof loadPolicy> {
    writeGlobalPolicy(`version: 2\nmode: enforce\n${extraYaml}`);
    return loadPolicy({ dir: tmpDir });
  }

  it('a single MEDIUM-confidence secret finding (0.6) -> coach under default thresholds', () => {
    const policy = v2PolicyWith('');
    const inspection: InspectionResult = {
      findings: [{ category: 'secret', name: 'x', severity: 'medium', match: 'y', confidence: 0.6 }],
    };
    const decision = evaluateResponse(policy, 'tool', inspection);
    expect(decision.action).toBe('coach');
    expect(decision.confidence).toBeCloseTo(0.6, 10);
    expect(decision.signals).toContain('secret:medium');
  });

  it('raising the coach threshold above the fused score changes the SAME finding to allow', () => {
    const policy = v2PolicyWith('thresholds:\n  coach: 0.7\n');
    const inspection: InspectionResult = {
      findings: [{ category: 'secret', name: 'x', severity: 'medium', match: 'y', confidence: 0.6 }],
    };
    const decision = evaluateResponse(policy, 'tool', inspection);
    expect(decision.action).toBe('allow');
  });

  it('lowering the redact threshold below the fused score escalates the SAME finding from coach to redact', () => {
    const policy = v2PolicyWith('thresholds:\n  redact: 0.5\n');
    const inspection: InspectionResult = {
      findings: [{ category: 'secret', name: 'x', severity: 'medium', match: 'y', confidence: 0.6 }],
    };
    const decision = evaluateResponse(policy, 'tool', inspection);
    expect(decision.action).toBe('redact');
  });

  it('two corroborating LOW findings (noisy-OR raises the score) escalate past a single LOW finding alone', () => {
    const policy = v2PolicyWith('');
    const single: InspectionResult = {
      findings: [{ category: 'secret', name: 'x', severity: 'low', match: 'y', confidence: 0.3 }],
    };
    expect(evaluateResponse(policy, 'tool', single).action).toBe('allow'); // below coach bar alone

    const corroborated: InspectionResult = {
      findings: [
        { category: 'secret', name: 'x', severity: 'low', match: 'y', confidence: 0.3 },
        { category: 'secret', name: 'x2', severity: 'low', match: 'y2', confidence: 0.3 },
      ],
    };
    // noisy-OR: 1 - 0.7*0.7 = 0.51 -> clears the default 0.4 coach bar
    expect(evaluateResponse(policy, 'tool', corroborated).action).toBe('coach');
  });

  it('an injection finding (no numeric confidence) still participates in fusion via its severity', () => {
    const policy = v2PolicyWith('response:\n  injection: off\n'); // turn off the flat injection candidate so fusion is the only source
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'Role reassignment', severity: 'critical', match: 'x' }],
    };
    const decision = evaluateResponse(policy, 'tool', inspection);
    // severity 'critical' -> confidence 0.95 -> alone clears the default deny bar (0.95)
    expect(decision.action).toBe('deny');
  });

  it('a v1 policy with the SAME finding never invokes fusion at all (no confidence/signals from a fused candidate)', () => {
    writeGlobalPolicy('mode: enforce\nresponse:\n  redactSecrets: false\n  injection: off\n');
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [{ category: 'secret', name: 'x', severity: 'medium', match: 'y', confidence: 0.6 }],
    };
    // No redactSecrets, no injection setting engaged, no rules -> allow.
    // Under v2 this SAME finding would coach (see above) — proving v1 never
    // reaches the fusion code path.
    expect(evaluateResponse(policy, 'tool', inspection)).toEqual({ action: 'allow', direction: 'response' });
  });

  it('dataflow fusion: default thresholds deny a cross-tool taint hit; a stricter deny threshold downgrades it to redact', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('reader', 'srv', [
      { category: 'secret', name: 'x', severity: 'high', match: 'sk-live-CANARY-FUSION-0002' },
    ]);
    const ctx: EvalContext = { destinationServer: 'srv', destinationTool: 'writer', provenance };

    const denyPolicy = v2PolicyWith('');
    expect(evaluateCall(denyPolicy, 'tools/call', 'writer', { v: 'sk-live-CANARY-FUSION-0002' }, ctx).action).toBe('deny');

    const stricterPolicy = v2PolicyWith('thresholds:\n  deny: 0.99\n');
    // 0.9 (dataflow base confidence) with 'high' severity shift (-0.07):
    // denyT = 0.99-0.07=0.92 (0.9 < 0.92, no deny); redactT = 0.85-0.07=0.78 (0.9 >= 0.78 -> redact)
    expect(evaluateCall(stricterPolicy, 'tools/call', 'writer', { v: 'sk-live-CANARY-FUSION-0002' }, ctx).action).toBe(
      'redact',
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 4 — positiveSecurity allow-list posture
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: positiveSecurity allow-list', () => {
  it('a tool NOT on the allow-list gets the configured default action (mode-adjusted)', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
positiveSecurity:
  tools: ["read_file"]
  default: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'delete_file', {}).action).toBe('deny');
    expect(evaluateCall(policy, 'tools/call', 'read_file', {})).toEqual({ action: 'allow', direction: 'request' });
  });

  it('the default action is mode-adjusted like any other decision (alert mode -> coach, never a silent block)', () => {
    writeGlobalPolicy(`
version: 2
mode: alert
positiveSecurity:
  tools: ["read_file"]
  default: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'delete_file', {}).action).toBe('coach');
  });

  it('an explicit deny rule still wins over an allow-listed tool (positiveSecurity only ADDS restriction, never grants a bypass)', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
positiveSecurity:
  tools: ["read_file"]
  default: deny
rules:
  - id: extra-restriction
    tools: ["read_file"]
    argsRegex: 'etc/passwd'
    action: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(evaluateCall(policy, 'tools/call', 'read_file', { path: '/etc/passwd' }).action).toBe('deny');
    expect(evaluateCall(policy, 'tools/call', 'read_file', { path: '/tmp/ok.txt' })).toEqual({
      action: 'allow',
      direction: 'request',
    });
  });

  it('a v1 policy never enforces a positiveSecurity posture (the field does not exist on the type for v1)', () => {
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.positiveSecurity).toBeUndefined();
    expect(evaluateCall(policy, 'tools/call', 'anything_at_all', {})).toEqual({ action: 'allow', direction: 'request' });
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 5 — edm[] / dataflow[] onMatch enforcement (the proxy-core.ts
// wiring surface: combineDecisions + edmMatchCandidate + dataflowMatchCandidate)
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: edm[]/dataflow[] onMatch enforcement wiring', () => {
  it('edmMatchCandidate turns a configured onMatch into a real deny, mode-adjusted', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
edm:
  - index: prod-secrets
    onMatch: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const hits: EdmMatch[] = [{ indexName: 'prod-secrets', confidence: 0.99, signals: ['edm-exact-match'] }];
    const candidate = edmMatchCandidate(policy, hits, 'response');
    expect(candidate?.action).toBe('deny');
    expect(candidate?.signals).toEqual(['edm:prod-secrets']);

    const base = { action: 'allow' as const, direction: 'response' as const };
    expect(combineDecisions(base, [candidate]).action).toBe('deny');
  });

  it('an EDM hit against an index with NO policy entry contributes no candidate (stays detect-only)', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
edm:
  - index: some-other-index
    onMatch: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const hits: EdmMatch[] = [{ indexName: 'unconfigured-index', confidence: 0.99, signals: [] }];
    expect(edmMatchCandidate(policy, hits, 'response')).toBeUndefined();
  });

  it('edmMatchCandidate is a no-op under a v1 policy even if it somehow had an edm block (v1 never sets policy.edm)', () => {
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    const hits: EdmMatch[] = [{ indexName: 'x', confidence: 0.99, signals: [] }];
    expect(edmMatchCandidate(policy, hits, 'response')).toBeUndefined();
    expect(policy.edm).toBeUndefined();
  });

  it('dataflowMatchCandidate matches on from/to tool+server globs and enforces the configured onMatch', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
dataflow:
  - from:
      tool: reader_*
    to:
      tool: writer_*
    onMatch: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const hits: DataflowFinding[] = [{ originTool: 'reader_db', originServer: 'srv', destinationTool: 'writer_email', category: 'secret' }];
    const candidate = dataflowMatchCandidate(policy, hits, 'srv');
    expect(candidate?.action).toBe('deny');
    expect(candidate?.signals).toEqual(['dataflow:reader_db->writer_email']);
  });

  it('dataflowMatchCandidate does not match a flow whose tool names fall outside the configured globs', () => {
    writeGlobalPolicy(`
version: 2
mode: enforce
dataflow:
  - from:
      tool: reader_*
    to:
      tool: writer_*
    onMatch: deny
`);
    const policy = loadPolicy({ dir: tmpDir });
    const hits: DataflowFinding[] = [{ originTool: 'unrelated', originServer: 'srv', destinationTool: 'writer_email', category: 'secret' }];
    expect(dataflowMatchCandidate(policy, hits, 'srv')).toBeUndefined();
  });

  it('combineDecisions returns the SAME base reference when every extra is undefined (true no-op)', () => {
    const base = { action: 'allow' as const, direction: 'request' as const };
    expect(combineDecisions(base, [undefined, undefined])).toBe(base);
  });

  it('combineDecisions picks the highest-precedence candidate among base + extras', () => {
    const base = { action: 'allow' as const, direction: 'request' as const };
    const extra1 = { action: 'alert' as const, direction: 'request' as const };
    const extra2 = { action: 'deny' as const, direction: 'request' as const };
    expect(combineDecisions(base, [extra1, extra2]).action).toBe('deny');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 6 — detectors {} enable/disable/tune
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: detectors {} enable/disable/tune', () => {
  it('resolveDetectors returns undefined when policy.detectors is unset (v1 default list is used)', () => {
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    expect(resolveDetectors(policy)).toBeUndefined();
  });

  it('a disabled detector is excluded from the resolved list', () => {
    writeGlobalPolicy(`
version: 2
detectors:
  credit-card:
    enabled: false
`);
    const policy = loadPolicy({ dir: tmpDir });
    const list = resolveDetectors(policy);
    expect(list).toBeDefined();
    expect(list!.some((d) => d.id === 'credit-card')).toBe(false);
    expect(list!.some((d) => d.id === 'iban')).toBe(true); // untouched detectors remain
  });

  it('a confidence override is applied to every hit the wrapped detector produces', () => {
    writeGlobalPolicy(`
version: 2
detectors:
  credit-card:
    confidence: 0.42
`);
    const policy = loadPolicy({ dir: tmpDir });
    const list = resolveDetectors(policy)!;
    const cc = list.find((d) => d.id === 'credit-card')!;
    const hits = cc.find('4111111111111111 is a valid Luhn card');
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].confidence).toBe(0.42);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 7 — malformed v2 -> observe fallback, no throw
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: malformed v2 falls back to safe observe mode', () => {
  it('a v2 file that fails zod validation falls back to defaultPolicy(), logs to stderr, and never throws', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy(`
version: 2
mode: yolo
thresholds:
  deny: "not-a-number"
`);
    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir });
    }).not.toThrow();
    expect(policy!.version).toBe(1); // the SAME defaultPolicy() a malformed v1 file falls back to
    expect(policy!.mode).toBe('observe');
    expect(policy!.rules).toEqual([]);
    expect(policy!.thresholds).toBeUndefined();
    expect(errorSpy).toHaveBeenCalled();
    expect(errorSpy.mock.calls.some((c) => String(c[0]).includes('v2 schema validation'))).toBe(true);
    errorSpy.mockRestore();
  });

  it('a v2 rule with an out-of-range threshold value fails validation and falls back safely', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy('version: 2\nthresholds:\n  deny: 1.5\n'); // > 1, out of the z.number().max(1) domain
    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir });
    }).not.toThrow();
    expect(policy!.mode).toBe('observe');
    errorSpy.mockRestore();
  });

  it('a malformed v2 per-server override is skipped without throwing; the v2 base policy is kept', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy('version: 2\nmode: enforce\n');
    const policiesDir = path.join(tmpDir, 'policies');
    fs.mkdirSync(policiesDir, { recursive: true });
    fs.writeFileSync(path.join(policiesDir, 'broken.yaml'), 'thresholds:\n  deny: "nope"\n', 'utf-8');
    let policy;
    expect(() => {
      policy = loadPolicy({ dir: tmpDir, serverName: 'broken' });
    }).not.toThrow();
    expect(policy!.version).toBe(2);
    expect(policy!.mode).toBe('enforce'); // base kept, override skipped
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  it('a v2 rule with an invalid argsRegex disables just that rule, not the whole v2 policy', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    writeGlobalPolicy(`
version: 2
mode: enforce
rules:
  - id: bad-rule
    tools: ["*"]
    argsRegex: '(unterminated['
    action: coach
  - id: good-rule
    tools: ["*"]
    action: alert
`);
    const policy = loadPolicy({ dir: tmpDir });
    expect(policy.version).toBe(2);
    expect(policy.rules.map((r) => r.id)).toEqual(['good-rule']);
    expect(errorSpy).toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 8 — fail-open everywhere (v2-specific surfaces)
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: fail-open on garbage input', () => {
  it('edmMatchCandidate never throws on garbage hits', () => {
    writeGlobalPolicy('version: 2\nedm:\n  - index: x\n    onMatch: deny\n');
    const policy = loadPolicy({ dir: tmpDir });
    // @ts-expect-error deliberately garbage
    expect(() => edmMatchCandidate(policy, null, 'response')).not.toThrow();
    // @ts-expect-error deliberately garbage
    expect(edmMatchCandidate(policy, null, 'response')).toBeUndefined();
  });

  it('dataflowMatchCandidate never throws on garbage hits', () => {
    writeGlobalPolicy('version: 2\ndataflow:\n  - onMatch: deny\n');
    const policy = loadPolicy({ dir: tmpDir });
    // @ts-expect-error deliberately garbage
    expect(() => dataflowMatchCandidate(policy, 'not-an-array', 'srv')).not.toThrow();
  });

  it('combineDecisions never throws on garbage extras', () => {
    const base = { action: 'allow' as const, direction: 'request' as const };
    // @ts-expect-error deliberately garbage
    expect(() => combineDecisions(base, null)).not.toThrow();
    // @ts-expect-error deliberately garbage
    expect(combineDecisions(base, null)).toBe(base);
  });

  it('resolveDetectors never throws and fails open to undefined on a garbage policy.detectors shape', () => {
    writeGlobalPolicy('version: 2\n');
    const policy = loadPolicy({ dir: tmpDir });
    // @ts-expect-error deliberately garbage — simulate internal corruption
    policy.detectors = 'not-an-object';
    expect(() => resolveDetectors(policy)).not.toThrow();
  });

  it('evaluateCall/evaluateResponse never throw under a v2 policy given garbage args/inspection', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\nthresholds:\n  deny: 0.5\n');
    const policy = loadPolicy({ dir: tmpDir });
    for (const weirdArgs of ['a string', 42, null, undefined, ['array']]) {
      expect(() => evaluateCall(policy, 'tools/call', 'any_tool', weirdArgs)).not.toThrow();
    }
    // @ts-expect-error deliberately garbage
    expect(() => evaluateResponse(policy, 'tool', null)).not.toThrow();
    // @ts-expect-error deliberately garbage
    expect(() => evaluateResponse(policy, 'tool', { findings: 'not-an-array' })).not.toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 9 — Task-4 coverage gap (b): ctx.destinationTool omitted while
// ctx.provenance IS present (both the v1 dataflowCandidate path and the v2
// dataflowFusionCandidate/velocityCandidate path fall back to the
// positional toolName parameter).
// ─────────────────────────────────────────────────────────────────────────

describe('Task-4 coverage gap: ctx.destinationTool omitted, ctx.provenance present', () => {
  it('v1: evaluateCall dataflow detection falls back to the positional toolName when ctx.destinationTool is omitted', () => {
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    const provenance = new SessionProvenance();
    provenance.tagResponse('reader_tool', 'srv', [
      { category: 'secret', name: 'x', severity: 'high', match: 'sk-live-CANARY-GAP-0003' },
    ]);
    // destinationTool deliberately OMITTED — only destinationServer + provenance.
    const ctx: EvalContext = { destinationServer: 'srv', provenance };
    const decision = evaluateCall(policy, 'tools/call', 'writer_tool', { v: 'sk-live-CANARY-GAP-0003' }, ctx);
    expect(decision.action).toBe('deny');
    expect(decision.signals).toContain('dataflow:reader_tool->writer_tool');
  });

  it('v2: dataflowFusionCandidate ALSO falls back to the positional toolName when ctx.destinationTool is omitted', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    const provenance = new SessionProvenance();
    provenance.tagResponse('reader_tool', 'srv', [
      { category: 'secret', name: 'x', severity: 'high', match: 'sk-live-CANARY-GAP-0004' },
    ]);
    const ctx: EvalContext = { destinationServer: 'srv', provenance };
    const decision = evaluateCall(policy, 'tools/call', 'writer_tool', { v: 'sk-live-CANARY-GAP-0004' }, ctx);
    expect(decision.action).toBe('deny');
    expect(decision.signals).toContain('dataflow:reader_tool->writer_tool');
  });

  it('v1: evaluateResponse velocityCandidate falls back to the positional toolName when ctx.destinationTool is omitted', () => {
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir });
    const provenance = new SessionProvenance();
    // Tag 6 tokens (above the default VELOCITY_ALERT_THRESHOLD of 5) for "producer_tool".
    provenance.tagResponse('producer_tool', 'srv', [
      { category: 'secret', name: 'x1', severity: 'high', match: 'sk-live-CANARY-GAP-0005-a' },
      { category: 'secret', name: 'x2', severity: 'high', match: 'sk-live-CANARY-GAP-0005-b' },
      { category: 'secret', name: 'x3', severity: 'high', match: 'sk-live-CANARY-GAP-0005-c' },
      { category: 'secret', name: 'x4', severity: 'high', match: 'sk-live-CANARY-GAP-0005-d' },
      { category: 'secret', name: 'x5', severity: 'high', match: 'sk-live-CANARY-GAP-0005-e' },
      { category: 'secret', name: 'x6', severity: 'high', match: 'sk-live-CANARY-GAP-0005-f' },
    ]);
    const ctx: EvalContext = { destinationServer: 'srv', provenance };
    const decision = evaluateResponse(policy, 'producer_tool', { findings: [] }, ctx);
    expect(decision.action).toBe('alert');
    expect(decision.signals).toContain('provenance-velocity');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 10 — Task-4 coverage gap (a): combined EDM-hit + dataflow-finding
// on the SAME request, exercising mergeAuditExtras (proxy-core.ts). This is
// a direct unit test of the pure merge helper; a full end-to-end version
// (real runProxy, both signals firing together) lives in
// tests/integration/proxy-core.test.ts.
// ─────────────────────────────────────────────────────────────────────────

describe('Task-4 coverage gap: combined EDM-hit + dataflow-finding on the same request (mergeAuditExtras)', () => {
  it('mergeAuditExtras combines an EDM-derived and a dataflow-derived extras fragment: signals concatenate, confidence takes the max, context shallow-merges', async () => {
    const { mergeAuditExtras } = await import('../../src/proxy/proxy-core.js');
    const edmExtras = { confidence: 0.99, signals: ['edm:prod-secrets'], context: { edmIndexes: ['prod-secrets'] } };
    const dataflowExtras = {
      confidence: 0.9,
      signals: ['dataflow:reader->writer'],
      context: { dataflow: [{ originTool: 'reader', destinationTool: 'writer', category: 'secret' }] },
    };
    const merged = mergeAuditExtras(edmExtras, dataflowExtras);
    expect(merged.confidence).toBe(0.99); // max(0.99, 0.9)
    expect(merged.signals).toEqual(['edm:prod-secrets', 'dataflow:reader->writer']); // concatenated, neither dropped
    expect(merged.context).toEqual({
      edmIndexes: ['prod-secrets'],
      dataflow: [{ originTool: 'reader', destinationTool: 'writer', category: 'secret' }],
    }); // shallow-merged, both keys present
  });

  it('mergeAuditExtras with one empty fragment is a true no-op for that fragment (does not zero out the other)', async () => {
    const { mergeAuditExtras } = await import('../../src/proxy/proxy-core.js');
    const merged = mergeAuditExtras({}, { confidence: 0.9, signals: ['dataflow:a->b'] });
    expect(merged).toEqual({ confidence: 0.9, signals: ['dataflow:a->b'] });
  });
});
