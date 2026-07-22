import { describe, expect, it } from 'vitest';

import {
  confidenceTierSlug,
  DEFAULT_THRESHOLDS,
  decide,
  fuseSignals,
  type ConfidenceThresholds,
  type ContextMultiplier,
  type FusionFinding,
} from '../../src/enforcement/confidence.js';

// ─────────────────────────────────────────────────────────────────────────
// fuseSignals
// ─────────────────────────────────────────────────────────────────────────

describe('fuseSignals', () => {
  it('empty findings -> score 0, no signals', () => {
    expect(fuseSignals([])).toEqual({ score: 0, signals: [] });
  });

  it('a single finding -> its own confidence, unchanged', () => {
    const result = fuseSignals([{ confidence: 0.9, signal: 'secret:high' }]);
    expect(result.score).toBeCloseTo(0.9, 10);
    expect(result.signals).toEqual(['secret:high']);
  });

  it('noisy-OR of {0.9, 0.6} = 1 - (0.1 * 0.4) = 0.96', () => {
    const result = fuseSignals([
      { confidence: 0.9, signal: 'a' },
      { confidence: 0.6, signal: 'b' },
    ]);
    expect(result.score).toBeCloseTo(0.96, 10);
    expect(result.signals).toEqual(['a', 'b']);
  });

  it('noisy-OR of two 0.6 findings = 1 - 0.4*0.4 = 0.84 (corroboration raises the score above either alone)', () => {
    const result = fuseSignals([
      { confidence: 0.6, signal: 'a' },
      { confidence: 0.6, signal: 'b' },
    ]);
    expect(result.score).toBeCloseTo(0.84, 10);
  });

  it('stays in [0,1] even with many high-confidence findings', () => {
    const findings: FusionFinding[] = Array.from({ length: 20 }, (_, i) => ({ confidence: 0.9, signal: `f${i}` }));
    const result = fuseSignals(findings);
    expect(result.score).toBeLessThanOrEqual(1);
    expect(result.score).toBeGreaterThan(0.999999);
  });

  it('a multiplier with factor 1 is a no-op: score and signals unchanged, its own signal omitted', () => {
    const withoutMultiplier = fuseSignals([{ confidence: 0.5, signal: 'a' }]);
    const withNoopMultiplier = fuseSignals([{ confidence: 0.5, signal: 'a' }], [{ factor: 1, signal: 'context:x' }]);
    expect(withNoopMultiplier.score).toBeCloseTo(withoutMultiplier.score, 10);
    expect(withNoopMultiplier.signals).toEqual(['a']); // multiplier signal NOT included
  });

  it('a multiplier > 1 escalates confidence, clamped to 1, and its signal is included', () => {
    const result = fuseSignals([{ confidence: 0.6, signal: 'a' }], [{ factor: 2, signal: 'context:untrusted' }]);
    // 0.6 * 2 = 1.2, clamped to 1.0
    expect(result.score).toBeCloseTo(1, 10);
    expect(result.signals).toEqual(['a', 'context:untrusted']);
  });

  it('a multiplier < 1 dampens confidence and its signal is included', () => {
    const result = fuseSignals([{ confidence: 0.8, signal: 'a' }], [{ factor: 0.5, signal: 'context:trusted' }]);
    expect(result.score).toBeCloseTo(0.4, 10);
    expect(result.signals).toEqual(['a', 'context:trusted']);
  });

  it('multiple multipliers compose multiplicatively', () => {
    const result = fuseSignals(
      [{ confidence: 0.5, signal: 'a' }],
      [
        { factor: 2, signal: 'context:x' },
        { factor: 0.5, signal: 'context:y' },
      ],
    );
    // 0.5 * 2 * 0.5 = 0.5 -> unchanged net effect, but both signals recorded
    expect(result.score).toBeCloseTo(0.5, 10);
    expect(result.signals).toEqual(['a', 'context:x', 'context:y']);
  });

  it('a multiplier factor is clamped to [0,3] before composing (defends against a misconfigured multiplier)', () => {
    const result = fuseSignals([{ confidence: 0.5, signal: 'a' }], [{ factor: 1000, signal: 'huge' }]);
    // factor clamps to 3 -> 0.5*3 = 1.5 -> clamped to 1
    expect(result.score).toBeCloseTo(1, 10);
  });

  it('a finding whose confidence becomes <= 0 after multiplier contributes nothing and is omitted from signals', () => {
    const result = fuseSignals([{ confidence: 0.5, signal: 'a' }], [{ factor: 0, signal: 'zeroed' }]);
    expect(result.score).toBe(0);
    expect(result.signals).toEqual([]);
  });

  it('deduplicates identical signal slugs across findings/multipliers', () => {
    const result = fuseSignals(
      [
        { confidence: 0.5, signal: 'dup' },
        { confidence: 0.5, signal: 'dup' },
      ],
      [{ factor: 1.5, signal: 'dup' }],
    );
    expect(result.signals).toEqual(['dup']);
  });

  it('never throws on garbage input: non-array findings, NaN confidence, non-string signal, null elements', () => {
    // @ts-expect-error deliberately garbage
    expect(() => fuseSignals(null)).not.toThrow();
    // @ts-expect-error deliberately garbage
    expect(fuseSignals('not-an-array')).toEqual({ score: 0, signals: [] });
    expect(
      fuseSignals([
        // @ts-expect-error deliberately garbage
        { confidence: NaN, signal: 'x' },
        null as unknown as FusionFinding,
        // @ts-expect-error deliberately garbage
        { confidence: 'oops', signal: 'y' },
        { confidence: 0.7, signal: 123 as unknown as string },
      ]).score,
    ).toBeCloseTo(0.7, 10);
    // @ts-expect-error deliberately garbage
    expect(() => fuseSignals([{ confidence: 0.5, signal: 'a' }], 'not-an-array')).not.toThrow();
  });

  it('is bounded: a very large findings array does not throw or hang', () => {
    const huge: FusionFinding[] = Array.from({ length: 5000 }, (_, i) => ({ confidence: 0.1, signal: `f${i}` }));
    expect(() => fuseSignals(huge)).not.toThrow();
    const result = fuseSignals(huge);
    expect(result.score).toBeGreaterThan(0);
    expect(result.score).toBeLessThanOrEqual(1);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// decide
// ─────────────────────────────────────────────────────────────────────────

describe('decide', () => {
  it('empty/zero score -> allow', () => {
    expect(decide(0)).toBe('allow');
  });

  it('a score exactly at the coach threshold -> coach (inclusive boundary)', () => {
    expect(decide(DEFAULT_THRESHOLDS.coach)).toBe('coach');
  });

  it('just below the coach threshold -> allow', () => {
    expect(decide(DEFAULT_THRESHOLDS.coach - 0.0001)).toBe('allow');
  });

  it('a score exactly at the redact threshold -> redact (inclusive boundary)', () => {
    expect(decide(DEFAULT_THRESHOLDS.redact)).toBe('redact');
  });

  it('just below the redact threshold -> coach', () => {
    expect(decide(DEFAULT_THRESHOLDS.redact - 0.0001)).toBe('coach');
  });

  it('a score exactly at the deny threshold -> deny (inclusive boundary)', () => {
    expect(decide(DEFAULT_THRESHOLDS.deny)).toBe('deny');
  });

  it('just below the deny threshold -> redact', () => {
    expect(decide(DEFAULT_THRESHOLDS.deny - 0.0001)).toBe('redact');
  });

  it('score of 1.0 -> deny', () => {
    expect(decide(1)).toBe('deny');
  });

  it('worked example: one HIGH structured finding (0.9) alone -> redact, not deny', () => {
    expect(decide(0.9)).toBe('redact');
  });

  it('worked example: one EDM exact match (0.99) alone -> deny', () => {
    expect(decide(0.99)).toBe('deny');
  });

  it('worked example: one MEDIUM finding (0.6) alone -> coach', () => {
    expect(decide(0.6)).toBe('coach');
  });

  it('worked example: one LOW finding (0.3) alone -> allow (below the coach bar)', () => {
    expect(decide(0.3)).toBe('allow');
  });

  it('severity "critical" shifts thresholds down, so a lower score reaches deny', () => {
    // 0.85 is below the default deny threshold (0.95) but critical severity
    // shifts denyT to 0.95 - 0.15 = 0.8, so 0.85 clears it.
    expect(decide(0.85, 'critical')).toBe('deny');
    expect(decide(0.85, 'medium')).toBe('redact');
    expect(decide(0.85)).toBe('redact'); // undefined severity == medium (neutral)
  });

  it('severity "low" shifts thresholds up, so a score that would deny at medium severity does not', () => {
    expect(decide(0.95, 'low')).not.toBe('deny'); // denyT = 0.95 + 0.1 = 1.0 (clamped), 0.95 < 1.0
    expect(decide(1, 'low')).toBe('deny');
  });

  it('custom thresholds override the defaults', () => {
    const thresholds: ConfidenceThresholds = { deny: 0.5, redact: 0.3, coach: 0.1 };
    expect(decide(0.5, undefined, thresholds)).toBe('deny');
    expect(decide(0.3, undefined, thresholds)).toBe('redact');
    expect(decide(0.1, undefined, thresholds)).toBe('coach');
    expect(decide(0.05, undefined, thresholds)).toBe('allow');
  });

  it('a partial/malformed thresholds object falls back to DEFAULT_THRESHOLDS field-by-field', () => {
    // deny:0.5 is honored (score 0.5 >= denyT 0.5, inclusive boundary); redact/coach fall back to defaults (0.85/0.4).
    // @ts-expect-error deliberately partial
    expect(decide(0.5, undefined, { deny: 0.5 })).toBe('deny');
    // A score below the custom deny but that would clear the fallback redact/coach still uses the defaults for those.
    // @ts-expect-error deliberately partial
    expect(decide(0.45, undefined, { deny: 0.5 })).toBe('coach'); // < redact default 0.85, >= coach default 0.4
  });

  it('never throws on garbage input: NaN/Infinity/-Infinity/non-number score, garbage thresholds', () => {
    // Non-finite scores are treated as invalid input, not clamped -> safe 'allow' default.
    expect(decide(NaN)).toBe('allow');
    expect(decide(Infinity)).toBe('allow');
    expect(decide(-Infinity)).toBe('allow');
    // @ts-expect-error deliberately garbage
    expect(() => decide('oops')).not.toThrow();
    // @ts-expect-error deliberately garbage
    expect(decide(0.5, undefined, null)).toBe('coach'); // falls back to defaults entirely
    // @ts-expect-error deliberately garbage
    expect(() => decide(0.5, 'not-a-real-severity')).not.toThrow();
  });

  it('score outside [0,1] is clamped before comparison', () => {
    expect(decide(1.5)).toBe('deny');
    expect(decide(-0.5)).toBe('allow');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// confidenceTierSlug
// ─────────────────────────────────────────────────────────────────────────

describe('confidenceTierSlug', () => {
  it('buckets into exact/high/medium/low', () => {
    expect(confidenceTierSlug('edm', 0.99)).toBe('edm:exact');
    expect(confidenceTierSlug('secret', 0.9)).toBe('secret:high');
    expect(confidenceTierSlug('secret', 0.6)).toBe('secret:medium');
    expect(confidenceTierSlug('secret', 0.3)).toBe('secret:low');
  });

  it('never throws on a bad category/confidence', () => {
    // @ts-expect-error deliberately garbage
    expect(() => confidenceTierSlug(null, NaN)).not.toThrow();
    // @ts-expect-error deliberately garbage
    expect(confidenceTierSlug(null, 0.9)).toBe('signal:high');
  });
});

// ContextMultiplier type-only smoke check (compile-time), keeps the import used.
const _typeCheck: ContextMultiplier = { factor: 1, signal: 'x' };
void _typeCheck;
