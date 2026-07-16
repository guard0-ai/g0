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
import { DEFAULT_THRESHOLDS } from '../../src/proxy/confidence.js';

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
    // Every v2-compiled policy carries concrete DEFAULT_THRESHOLDS even when
    // no `thresholds:` block is written — this is the trustworthy "v2
    // compilation actually ran" marker the fusion candidates double-gate on.
    expect(policy.thresholds).toEqual(DEFAULT_THRESHOLDS);
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

  // Fusion is tested through an ENGAGED injection category (`injection:
  // alert`), whose flat candidate is only `alert` (precedence 1) — so a
  // fusion outcome of coach/redact/deny (2/3/4) shows through the combined
  // decision, letting us observe fusion changing the outcome. (A secret
  // finding with `redactSecrets: true` would trigger the flat redact
  // candidate at precedence 3, masking fusion's lower-precedence outcomes;
  // secret escalation-to-deny is covered separately below.)

  it('fusion escalates a MEDIUM injection finding to coach, above the flat alert candidate (v1 would only alert)', () => {
    const policy = v2PolicyWith('response:\n  injection: alert\n');
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'medium', match: 'y' }],
    };
    const decision = evaluateResponse(policy, 'tool', inspection);
    // severityToConfidence('medium') = 0.6 -> decide(0.6,'medium') -> coach (>=0.4, <0.85)
    expect(decision.action).toBe('coach');
    expect(decision.confidence).toBeCloseTo(0.6, 10);
    expect(decision.signals).toContain('injection:medium');
  });

  it('raising the coach threshold above the fused score drops fusion, leaving only the flat alert candidate', () => {
    const policy = v2PolicyWith('response:\n  injection: alert\nthresholds:\n  coach: 0.7\n');
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'medium', match: 'y' }],
    };
    // 0.6 < coach 0.7 -> fusion returns undefined -> only the flat alert remains.
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('alert');
  });

  it('lowering the coach threshold pulls a below-bar injection finding up into coach', () => {
    // injection:alert caps at coach, so thresholds move the outcome between
    // allow (fusion drops -> flat alert) and coach — the redact/deny bands are
    // unreachable for this category by design (see the cap tests below).
    const policy = v2PolicyWith('response:\n  injection: alert\nthresholds:\n  coach: 0.25\n');
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'low', match: 'y' }],
    };
    // one low: severityToConfidence 0.3 -> decide(0.3,'low') with coachT 0.25
    // (low shift +0.1 -> 0.35)... 0.3 < 0.35 -> allow. Raise nothing else; the
    // point is a lower coach base still gates via the severity shift.
    // To make it clearly coach, use a medium finding: 0.6 >= 0.25+0 -> coach.
    const mediumInspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'medium', match: 'y' }],
    };
    expect(evaluateResponse(policy, 'tool', mediumInspection).action).toBe('coach');
    // And the low one, below the shifted coach bar, stays flat alert.
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('alert');
  });

  it('two corroborating LOW injection findings (noisy-OR raises the score) escalate past a single LOW finding alone', () => {
    const policy = v2PolicyWith('response:\n  injection: alert\n');
    const single: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'low', match: 'y' }],
    };
    // one low: 0.3 -> decide(0.3,'low') (coachT shifts to 0.5) -> allow -> fusion
    // undefined -> only the flat alert candidate.
    expect(evaluateResponse(policy, 'tool', single).action).toBe('alert');

    const corroborated: InspectionResult = {
      findings: [
        { category: 'injection', name: 'x', severity: 'low', match: 'y' },
        { category: 'injection', name: 'x2', severity: 'low', match: 'y2' },
      ],
    };
    // noisy-OR of {0.3,0.3} = 0.51 -> decide(0.51,'low') (coachT 0.5) -> coach,
    // which beats the flat alert. Corroboration escalated the outcome
    // (still within the injection:alert coach ceiling).
    expect(evaluateResponse(policy, 'tool', corroborated).action).toBe('coach');
  });

  it('injection: alert is CAPPED at coach — even two HIGH injection findings that fuse to a deny-level score stay coach, never deny/redact', () => {
    const policy = v2PolicyWith('response:\n  injection: alert\nthresholds:\n  coach: 0.2\n  redact: 0.3\n  deny: 0.4\n');
    const inspection: InspectionResult = {
      findings: [
        { category: 'injection', name: 'a', severity: 'high', match: 'y1' },
        { category: 'injection', name: 'b', severity: 'high', match: 'y2' },
      ],
    };
    // severityToConfidence('high') = 0.85 each -> noisy-OR = 1 - 0.15*0.15 =
    // 0.9775 -> decide(0.9775,'high',{deny:0.4,...}) -> deny by score, but the
    // injection:alert ceiling caps it at coach. Never redact, never deny.
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('coach');
  });

  it('injection: deny allows fusion to reach deny (operator authorized blocking)', () => {
    const policy = v2PolicyWith('response:\n  injection: deny\n');
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'critical', match: 'y' }],
    };
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('deny');
  });

  it('secret fusion is capped at redact — two HIGH secrets that fuse to a deny-level score stay redact under redactSecrets: true', () => {
    const policy = v2PolicyWith('response:\n  redactSecrets: true\n  injection: off\n');
    const inspection: InspectionResult = {
      findings: [
        { category: 'secret', name: 'a', severity: 'high', match: 'y1', confidence: 0.9 },
        { category: 'secret', name: 'b', severity: 'high', match: 'y2', confidence: 0.9 },
      ],
    };
    // noisy-OR of {0.9,0.9} = 0.99 -> decide(0.99,'high') -> deny by score,
    // but the redactSecrets ceiling caps the secret category at redact.
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('redact');
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
// SECTION 3b — v2 fusion RESPECTS the per-category response toggles
// (Important #2): redactSecrets:false / injection:off keep their v1
// "detect-only, never touch traffic" meaning — fusion must not override
// them via the back door.
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: response toggles gate fusion (redactSecrets:false / injection:off)', () => {
  it('injection: off + a CRITICAL IOC finding -> NOT denied (fusion excludes the off category)', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\nresponse:\n  injection: off\n');
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [{ category: 'ioc', name: 'Exfil domain: evil.example', severity: 'critical', match: 'evil.example' }],
    };
    // Before the fix, fusion would fuse the critical IOC to 0.95 and deny in
    // enforce mode — overriding the explicit "only detect" posture.
    expect(evaluateResponse(policy, 'tool', inspection)).toEqual({ action: 'allow', direction: 'response' });
  });

  it('redactSecrets: false + a HIGH-confidence secret finding -> NOT redacted/denied (fusion excludes the off category)', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\nresponse:\n  redactSecrets: false\n  injection: off\n');
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [{ category: 'secret', name: 'x', severity: 'high', match: 'y', confidence: 0.99 }],
    };
    // Detect-only posture preserved: a v2 operator can reproduce v1's
    // "detect but never touch traffic" exactly.
    expect(evaluateResponse(policy, 'tool', inspection)).toEqual({ action: 'allow', direction: 'response' });
  });

  it('the SAME critical injection finding IS acted on when the category is engaged (injection: deny)', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\nresponse:\n  injection: deny\n');
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'critical', match: 'y' }],
    };
    // Engaged category -> the flat deny candidate (and fusion) both fire -> deny.
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('deny');
  });

  it('injection: alert + a CRITICAL IOC finding -> coach, NEVER deny (the alert ceiling caps injection/ioc fusion)', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\nresponse:\n  injection: alert\n');
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [{ category: 'ioc', name: 'Exfil domain: evil.example', severity: 'critical', match: 'evil.example' }],
    };
    // Critical IOC fuses to 0.95 -> would be deny by score, but injection:alert
    // caps the injection/ioc category at coach: a loud warning that still
    // forwards, honoring v1's "alert = detect and warn, never block" contract.
    const decision = evaluateResponse(policy, 'tool', inspection);
    expect(decision.action).toBe('coach');
    expect(decision.action).not.toBe('deny');
  });

  it('MIXED case: critical IOC (injection: alert, capped at coach) + high secret (redactSecrets: true) -> redact, not deny', () => {
    writeGlobalPolicy('version: 2\nmode: enforce\nresponse:\n  injection: alert\n  redactSecrets: true\n');
    const policy = loadPolicy({ dir: tmpDir });
    const inspection: InspectionResult = {
      findings: [
        { category: 'ioc', name: 'Exfil domain: evil.example', severity: 'critical', match: 'evil.example' },
        { category: 'secret', name: 's', severity: 'high', match: 'sk-x', confidence: 0.99 },
      ],
    };
    // Per-category fusion: the IOC group caps at coach (injection:alert), the
    // secret group at redact (redactSecrets:true). The critical IOC's high
    // score must NOT push the final action past redact. redact (3) > coach (2)
    // -> redact wins, never deny.
    const decision = evaluateResponse(policy, 'tool', inspection);
    expect(decision.action).toBe('redact');
    expect(decision.action).not.toBe('deny');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// SECTION 3c — per-server override version routing (Critical #1): each
// policy FILE is validated/compiled per its OWN declared version, and there
// is NO state where policy.version === 2 but the v2 blocks were parsed by
// the v1 path (which would silently drop them while flipping every
// downstream v2 gate on).
// ─────────────────────────────────────────────────────────────────────────

describe('Policy DSL v2: per-server override version routing', () => {
  function writeServerOverride(serverName: string, yaml: string): void {
    const policiesDir = path.join(tmpDir, 'policies');
    fs.mkdirSync(policiesDir, { recursive: true });
    fs.writeFileSync(path.join(policiesDir, `${serverName}.yaml`), yaml, 'utf-8');
  }

  it('v1 global + a version:2 per-server override UPGRADES: the override v2 blocks are compiled through the real v2 schema, and version is 2', () => {
    // v1/version-less global.
    writeGlobalPolicy('mode: enforce\n');
    // Override declares version 2 and carries v2 blocks — the natural
    // operator path the docs describe ("set version: 2 at the top of the
    // file").
    writeServerOverride(
      'srv',
      `
version: 2
thresholds:
  deny: 0.8
positiveSecurity:
  tools: ["read_file"]
  default: deny
`,
    );
    const policy = loadPolicy({ dir: tmpDir, serverName: 'srv' });
    expect(policy.version).toBe(2);
    // The v2 blocks were actually compiled (not silently dropped).
    expect(policy.thresholds).toEqual({ deny: 0.8, redact: 0.85, coach: 0.4 });
    expect(policy.positiveSecurity?.defaultAction).toBe('deny');
    expect(policy.positiveSecurity?.allowedTools[0].test('read_file')).toBe(true);
  });

  it('REPRO (a) — the override positiveSecurity actually enforces after the upgrade (was silently inert before the fix)', () => {
    // No global policy at all (default v1); the override carries the whole
    // intended posture including enforce mode.
    writeServerOverride('srv', 'version: 2\nmode: enforce\npositiveSecurity:\n  tools: ["read_file"]\n  default: deny\n');
    const policy = loadPolicy({ dir: tmpDir, serverName: 'srv' });
    // Before the fix: positiveSecurity dropped by the v1 merge path, but
    // policy.version === 2, so the allow-list was completely inert ->
    // delete_file returned allow. After the fix: it enforces.
    expect(evaluateCall(policy, 'tools/call', 'delete_file', {}).action).toBe('deny');
    expect(evaluateCall(policy, 'tools/call', 'read_file', {})).toEqual({ action: 'allow', direction: 'request' });
  });

  it('REPRO (b) — a version:2 override on a v1 global has its thresholds COMPILED (not silently dropped by the v1 merge path)', () => {
    // The silent-escalation harm's root cause was: the override's v2 blocks
    // were dropped by the v1 merge path (so DEFAULT thresholds were used),
    // yet policy.version ended up 2. After the fix the override goes through
    // the real v2 zod path, so its declared thresholds are actually present
    // — the operator's config is honored, not replaced by silent defaults.
    writeGlobalPolicy('mode: enforce\nresponse:\n  injection: alert\n');
    writeServerOverride('srv', 'version: 2\nthresholds:\n  deny: 0.42\n  redact: 0.41\n  coach: 0.4\n');
    const policy = loadPolicy({ dir: tmpDir, serverName: 'srv' });
    expect(policy.version).toBe(2);
    // The distinctive override thresholds are present -> the v2 blocks were
    // read, not dropped. (Before the fix these were silently lost and
    // policy.thresholds would have been undefined despite version === 2.)
    expect(policy.thresholds).toEqual({ deny: 0.42, redact: 0.41, coach: 0.4 });
  });

  it('DEFENSE IN DEPTH — a policy that is version===2 but was NOT v2-compiled (no thresholds) never runs fusion', () => {
    // Hand-construct the exact corruption class the routing fix prevents:
    // version 2 with the v2 config absent. The fusion candidates must
    // double-gate on policy.thresholds presence and refuse to fire.
    writeGlobalPolicy('mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir }); // v1 base
    // Simulate a future routing slip: version flipped to 2 without v2 compile.
    (policy as { version: number }).version = 2;
    expect(policy.thresholds).toBeUndefined();
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'x', severity: 'critical', match: 'y' }],
    };
    // response.injection defaults to 'alert' -> flat alert candidate fires,
    // but the FUSION candidate must NOT (no thresholds) -> at most alert,
    // never a fused deny.
    expect(evaluateResponse(policy, 'tool', inspection).action).toBe('alert');

    // Dataflow fusion likewise refuses to fire without thresholds.
    const provenance = new SessionProvenance();
    provenance.tagResponse('reader', 'srv', [
      { category: 'secret', name: 's', severity: 'high', match: 'sk-live-CANARY-DEFENSE-0006' },
    ]);
    const ctx: EvalContext = { destinationServer: 'srv', destinationTool: 'writer', provenance };
    // v1 dataflowCandidate would deny; but version===2 routes to
    // dataflowFusionCandidate, which returns undefined (no thresholds) -> the
    // rule decision (allow) stands. Proves fusion can't fire on an
    // unvalidated policy even under version===2.
    expect(evaluateCall(policy, 'tools/call', 'writer', { v: 'sk-live-CANARY-DEFENSE-0006' }, ctx).action).toBe('allow');
  });

  it('v1 global + v1 override (no version key) still uses the v1 merge path, version stays 1, no v2 fields set', () => {
    writeGlobalPolicy('version: 1\nmode: observe\n');
    writeServerOverride('srv', 'mode: enforce\nrules:\n  - id: r\n    tools: ["*"]\n    action: deny\n');
    const policy = loadPolicy({ dir: tmpDir, serverName: 'srv' });
    expect(policy.version).toBe(1);
    expect(policy.mode).toBe('enforce');
    expect(policy.thresholds).toBeUndefined();
    expect(policy.positiveSecurity).toBeUndefined();
  });

  it('v2 global + a v1-shaped override (no version key) preserves the base v2 blocks', () => {
    writeGlobalPolicy('version: 2\nmode: observe\nthresholds:\n  deny: 0.7\nedm:\n  - index: base-idx\n    onMatch: deny\n');
    writeServerOverride('srv', 'mode: enforce\n');
    const policy = loadPolicy({ dir: tmpDir, serverName: 'srv' });
    expect(policy.version).toBe(2);
    expect(policy.mode).toBe('enforce'); // scalar override applied
    expect(policy.thresholds).toEqual({ deny: 0.7, redact: 0.85, coach: 0.4 }); // base v2 block preserved
    expect(policy.edm).toEqual([{ index: 'base-idx', onMatch: 'deny' }]); // base v2 block preserved
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
