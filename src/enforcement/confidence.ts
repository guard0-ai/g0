/**
 * Confidence fusion + decision mapping — Task 5 (Phase 4) of the runtime
 * MCP proxy.
 *
 * Tasks 1-4 each produce their OWN confidence signal on their OWN scale:
 *  - structured detectors (./detectors/structured.ts): HIGH 0.9 / MEDIUM 0.6
 *    / LOW 0.3, gated by real validators (Luhn/IBAN/ABA/vendor-key/JWT) or
 *    entropy+context heuristics.
 *  - EDM (./edm.ts): a fixed 0.99 — an exact hash match is the strongest
 *    possible evidence.
 *  - provenance/dataflow (./provenance.ts, via `dataflowCandidate` in
 *    ./policy.ts): 0.9 for a cross-tool taint hit.
 *  - injection/IOC (./response-inspector.ts): pattern matches with a
 *    `severity`, no numeric confidence — `./policy.ts` maps severity to a
 *    confidence before fusing it, see `severityToConfidence` there.
 *
 * None of these signals is trustworthy alone at "block traffic" strength —
 * that's WHY each one is emitted at a modest per-signal confidence rather
 * than a blanket 1.0. This module is where they get COMBINED into a single
 * score (`fuseSignals`) and where that score becomes an actual, bounded
 * `allow | coach | redact | deny` outcome (`decide`).
 *
 * ── The fusion model: noisy-OR ──────────────────────────────────────────
 *
 * Findings are treated as INDEPENDENT pieces of evidence for a single
 * underlying event ("this traffic is bad"). Noisy-OR is the standard way to
 * combine independent evidence like this: if finding i, on its own, would
 * correctly explain the event with probability c_i, then the probability
 * that AT LEAST ONE finding correctly flags the event is
 * `1 - Π(1 - c_i)`. This has exactly the properties this domain needs:
 *   - one HIGH-confidence finding (0.9) alone already yields a high score
 *     (0.9) — a single strong signal is not diluted by fusion.
 *   - two MEDIUM findings (0.6, 0.6) compound to 0.84 — corroborating weak
 *     signals raise confidence, without simply averaging (0.6, which would
 *     UNDER-weight corroboration) or summing past 1.0 (which would be an
 *     invalid probability).
 *   - it is monotonic and bounded to [0,1] by construction: a product of
 *     terms in [0,1] is itself in [0,1], so `1 - product` is too. No
 *     clamping is needed for the base case — clamping is only needed AFTER
 *     a context multiplier is applied (see below), since a multiplier can
 *     push an adjusted per-finding confidence outside [0,1].
 *
 * ── Context multipliers ─────────────────────────────────────────────────
 *
 * A `ContextMultiplier` scales EVERY finding's confidence before fusion —
 * e.g. "this destination tool is on an untrusted list" might carry
 * `factor: 1.2` (escalate), while "this destination tool is on a trusted
 * list" might carry `factor: 0.7` (dampen). Multipliers compose
 * multiplicatively (their factors are simply multiplied together into one
 * combined factor) and that combined factor is applied to each finding's
 * confidence, then the result is clamped back to [0,1] — this is what keeps
 * the noisy-OR math well-defined even when a multiplier alone would push a
 * value out of range. A multiplier whose factor is exactly `1` is a no-op:
 * it changes nothing and its signal is not added to the output (only
 * multipliers that actually moved the score are worth explaining in the
 * audit trail). A caller that never passes multipliers (every v1 code path)
 * is completely unaffected — `combinedFactor` defaults to `1`.
 *
 * ── Signal slugs ─────────────────────────────────────────────────────────
 *
 * Every `FusionFinding`/`ContextMultiplier` the caller passes in already
 * carries its own short, audit-safe signal slug (e.g. `secret:high`,
 * `edm:exact`, `dataflow:cross-tool`, `ioc:critical` — see call sites in
 * `./policy.ts`). `fuseSignals` does not invent slugs from nothing; it
 * collects the slugs of everything that actually contributed to the score
 * (a finding whose adjusted confidence is `<= 0`, or a multiplier whose
 * factor is `1`, contributes nothing and its slug is omitted) into one
 * order-preserving, deduplicated list — so the audit log can show exactly
 * what combined to produce the score, never the underlying sensitive value.
 * `confidenceTierSlug` is a small helper for callers that want a slug
 * bucketed by confidence tier (mirrors `./detectors/structured.ts`'s
 * HIGH/MEDIUM/LOW cutoffs, plus an `exact` tier for EDM-strength evidence)
 * instead of inventing their own bucketing.
 *
 * ── decide(): "coach on uncertainty" ────────────────────────────────────
 *
 * `decide` maps a fused score (plus an optional coarse `severity`) to one
 * of `allow | coach | redact | deny` via three thresholds (`coach`,
 * `redact`, `deny`). The core design rule is **"coach on uncertainty": a
 * score that clears the `coach` bar but not the `redact` bar produces a
 * loud, forwarded warning instead of either quietly doing nothing OR
 * silently blocking/mutating traffic on shaky evidence.** This is what lets
 * the proxy usefully surface LOW/MEDIUM-confidence findings to the
 * operator/agent without tanking precision the way blocking on them would
 * (see `DEFAULT_THRESHOLDS`'s doc comment for the concrete worked
 * examples).
 *
 * `severity` (when provided) nudges the effective thresholds: a `critical`
 * finding (e.g. a live exfil IOC, or tainted data crossing a tool boundary)
 * needs LESS corroborating confidence to reach `deny`/`redact` than a
 * `low`-severity one needs to reach the same bar — reflecting that the COST
 * of a false negative differs by what is at stake, not just how sure the
 * detector is. See `SEVERITY_THRESHOLD_SHIFT`. The adjusted thresholds are
 * clamped to [0,1] before comparison. `decide` never throws, and a garbage
 * `score` (NaN, non-number, out of [0,1] before clamping) degrades to
 * `'allow'` — the safe default for a PURE decision function: this module
 * never fails closed on its own; the caller's own fail-open contract lives
 * one level up, in `./policy.ts` / `./proxy-core.ts`.
 *
 * ── Never throw / bounded ───────────────────────────────────────────────
 *
 * Both functions are pure and wrapped in try/catch; a bad element (NaN
 * confidence, a non-string signal, a garbage thresholds object) is skipped
 * or defaulted rather than corrupting the whole computation. `fuseSignals`
 * is `O(findings.length + multipliers.length)` with no unbounded work —
 * every real caller's arrays are themselves already bounded (structured-
 * detector/EDM/dataflow finding arrays all cap their own size; see each
 * module's docblock), and this module additionally caps how many elements
 * it will iterate (`MAX_FUSION_ITEMS`) as a defensive backstop, not a
 * functional requirement.
 */

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

export interface FusionFinding {
  /** `0..1` confidence this ONE finding contributes. Values outside [0,1] are clamped; non-numbers are skipped. */
  confidence: number;
  /** Short, audit-safe signal slug describing this finding, e.g. `secret:high`, `edm:exact`. Never the matched value. */
  signal: string;
}

export interface ContextMultiplier {
  /** Multiplies every finding's confidence before fusion. `1` = no-op. Clamped to `[0, 3]` so a misconfigured multiplier can't zero out or unboundedly blow up the math. */
  factor: number;
  /** Short, audit-safe signal slug describing WHY this multiplier applies, e.g. `context:untrusted-destination`. Only included in the output when `factor !== 1`. */
  signal: string;
}

export interface FusionResult {
  /** Combined noisy-OR score, always in `[0,1]`. */
  score: number;
  /** Deduplicated, order-preserving signal slugs from every finding/multiplier that actually contributed. */
  signals: string[];
}

export type ConfidenceSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ConfidenceThresholds {
  deny: number;
  redact: number;
  coach: number;
}

export type ConfidenceAction = 'allow' | 'coach' | 'redact' | 'deny';

// ─────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────

/**
 * Default thresholds, chosen so the worked examples below hold with NO
 * severity adjustment (`severity` undefined / `'medium'`):
 *
 *  - ONE HIGH-confidence structured-detector finding alone (0.9, see
 *    `./detectors/structured.ts`) lands in `redact` (0.9 >= 0.85 redact,
 *    < 0.95 deny) — strong enough evidence to act on without any
 *    corroboration, but below the bar reserved for near-certain /
 *    multiply-corroborated evidence.
 *  - ONE EDM exact match (0.99, see `./edm.ts`) alone clears `deny`
 *    (0.99 >= 0.95) — an exact hash match against operator-fingerprinted
 *    data is treated as definitive on its own.
 *  - ONE MEDIUM finding (0.6, context-corroborated entropy) lands in
 *    `coach` (0.6 >= 0.4, < 0.85) — enough to warn loudly, not enough to
 *    touch the traffic.
 *  - ONE LOW finding (0.3, bare entropy — today's dominant false-positive
 *    class) lands in `allow` (0.3 < 0.4) — below even `coach`'s bar, so a
 *    single noisy low-confidence hit doesn't spam the operator; it only
 *    escalates when CORROBORATED by another signal (noisy-OR raises the
 *    fused score, e.g. two LOW findings fuse to 0.51, clearing `coach`).
 */
export const DEFAULT_THRESHOLDS: ConfidenceThresholds = {
  deny: 0.95,
  redact: 0.85,
  coach: 0.4,
};

/**
 * How much `decide` shifts the effective thresholds for a given severity,
 * SUBTRACTED from each threshold (so `critical` needs LESS fused score to
 * reach the same action; `low` needs MORE). `medium` (and `undefined`) is
 * the neutral baseline — a caller that never passes `severity` sees the raw
 * `thresholds` unchanged.
 */
const SEVERITY_THRESHOLD_SHIFT: Record<ConfidenceSeverity, number> = {
  critical: 0.15,
  high: 0.07,
  medium: 0,
  low: -0.1,
};

/** Confidence-tier cutoffs for `confidenceTierSlug`. `EXACT` mirrors EDM's fixed 0.99; `HIGH`/`MEDIUM` mirror `./detectors/structured.ts`'s `CONFIDENCE.HIGH`/`MEDIUM`. */
const TIER_EXACT = 0.95;
const TIER_HIGH = 0.9;
const TIER_MEDIUM = 0.6;

/** Defensive backstop only (see module docblock) — real callers' arrays are already bounded far below this. */
const MAX_FUSION_ITEMS = 1000;

const MULTIPLIER_MIN = 0;
const MULTIPLIER_MAX = 3;

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

function clamp01(v: number): number {
  if (typeof v !== 'number' || !Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(1, v));
}

/** Bucket a raw confidence into a short slug prefixed by `category`, e.g. `confidenceTierSlug('secret', 0.9) === 'secret:high'`. Mirrors the EXACT/HIGH/MEDIUM/LOW cutoffs documented above. Never throws. */
export function confidenceTierSlug(category: string, confidence: number): string {
  const c = clamp01(confidence);
  const tier = c >= TIER_EXACT ? 'exact' : c >= TIER_HIGH ? 'high' : c >= TIER_MEDIUM ? 'medium' : 'low';
  const cat = typeof category === 'string' && category.length > 0 ? category : 'signal';
  return `${cat}:${tier}`;
}

// ─────────────────────────────────────────────────────────────────────────
// fuseSignals
// ─────────────────────────────────────────────────────────────────────────

/**
 * Combine independent per-finding confidences into one score via noisy-OR
 * (`1 - Π(1 - c_i)`), after applying the combined product of any context
 * multipliers to each finding's confidence. See the module docblock for the
 * full rationale. Never throws: a non-array/empty/garbage `findings` input
 * degrades to `{ score: 0, signals: [] }` — empty evidence has no basis to
 * act on, which is the safe default. Bounded: `O(findings.length +
 * multipliers.length)`, both defensively capped at `MAX_FUSION_ITEMS`.
 */
export function fuseSignals(findings: FusionFinding[], multipliers: ContextMultiplier[] = []): FusionResult {
  try {
    if (!Array.isArray(findings) || findings.length === 0) return { score: 0, signals: [] };

    const safeMultipliers = Array.isArray(multipliers) ? multipliers.slice(0, MAX_FUSION_ITEMS) : [];
    let combinedFactor = 1;
    const multiplierSignals: string[] = [];
    for (const m of safeMultipliers) {
      if (!m || typeof m.factor !== 'number' || !Number.isFinite(m.factor)) continue;
      const factor = Math.max(MULTIPLIER_MIN, Math.min(MULTIPLIER_MAX, m.factor));
      combinedFactor *= factor;
      if (factor !== 1 && typeof m.signal === 'string' && m.signal.length > 0) multiplierSignals.push(m.signal);
    }

    let productOfComplements = 1;
    const findingSignals: string[] = [];
    let contributed = 0;
    for (const f of findings.slice(0, MAX_FUSION_ITEMS)) {
      if (!f || typeof f.confidence !== 'number' || !Number.isFinite(f.confidence)) continue;
      const adjusted = clamp01(f.confidence * combinedFactor);
      if (adjusted <= 0) continue;
      productOfComplements *= 1 - adjusted;
      contributed++;
      if (typeof f.signal === 'string' && f.signal.length > 0) findingSignals.push(f.signal);
    }

    if (contributed === 0) return { score: 0, signals: [] };

    const score = clamp01(1 - productOfComplements);
    const signals = [...new Set([...findingSignals, ...multiplierSignals])];
    return { score, signals };
  } catch {
    return { score: 0, signals: [] };
  }
}

// ─────────────────────────────────────────────────────────────────────────
// decide
// ─────────────────────────────────────────────────────────────────────────

/**
 * Map a fused confidence `score` (plus an optional coarse `severity`) to
 * one of `allow | coach | redact | deny` via three ascending thresholds.
 * See the module docblock for the full "coach on uncertainty" rationale and
 * the severity-shift design. Never throws: a non-finite/out-of-domain
 * `score` degrades to `'allow'`; a malformed `thresholds` object falls back
 * to `DEFAULT_THRESHOLDS` field-by-field.
 */
export function decide(
  score: number,
  severity?: ConfidenceSeverity,
  thresholds: ConfidenceThresholds = DEFAULT_THRESHOLDS,
): ConfidenceAction {
  try {
    if (typeof score !== 'number' || !Number.isFinite(score)) return 'allow';
    const s = clamp01(score);

    const shift =
      severity !== undefined && Object.prototype.hasOwnProperty.call(SEVERITY_THRESHOLD_SHIFT, severity)
        ? SEVERITY_THRESHOLD_SHIFT[severity]
        : 0;

    const t = thresholds && typeof thresholds === 'object' ? thresholds : DEFAULT_THRESHOLDS;
    const denyT = clamp01((typeof t.deny === 'number' ? t.deny : DEFAULT_THRESHOLDS.deny) - shift);
    const redactT = clamp01((typeof t.redact === 'number' ? t.redact : DEFAULT_THRESHOLDS.redact) - shift);
    const coachT = clamp01((typeof t.coach === 'number' ? t.coach : DEFAULT_THRESHOLDS.coach) - shift);

    if (s >= denyT) return 'deny';
    if (s >= redactT) return 'redact';
    if (s >= coachT) return 'coach';
    return 'allow';
  } catch {
    return 'allow';
  }
}
