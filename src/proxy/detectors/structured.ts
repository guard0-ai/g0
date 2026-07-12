/**
 * Validator-gated structured secret/PII detectors for MCP tool-call
 * response text.
 *
 * This module replaces the old "does it merely look random?" secret check
 * (`looksLikeSecret` in `src/mcp/config-scanner.ts`, still used by that
 * file's *other* callers and intentionally left untouched) with detectors
 * that only ever report a hit once a candidate has passed a real
 * checksum/format validator from `./validators.ts`. A 16-digit number that
 * fails the Luhn check, or an IBAN-shaped string with a bad check digit,
 * produces **no finding at all** — not a low-confidence one, none.
 *
 * ── Confidence scale (consumed by Task 5's fusion math) ────────────────
 *
 *   HIGH   (0.9) — the candidate passed a real checksum OR an exact,
 *                  structurally-validated vendor format: a Luhn-valid card
 *                  number, a mod-97-valid IBAN, an ABA-checksum-valid
 *                  routing number, a real-shaped vendor key (`AKIA...`,
 *                  `ghp_...`, `sk-...`, `xox[baprs]-...`), or a JWT whose
 *                  header segment actually base64url-decodes to
 *                  `{"alg":...}`/`{"typ":...}`-shaped JSON. False-positive
 *                  rate here is very low — these are real, specific
 *                  structural facts about the candidate, not vibes.
 *
 *   MEDIUM (0.6) — a high-entropy value with NO recognized format, but
 *                  found immediately after a credential-shaped keyword
 *                  (`key=`, `token:`, `secret=`, `Authorization: Bearer `,
 *                  ...). The context corroborates the entropy signal, but
 *                  there's no independent structural/checksum proof, so
 *                  this sits below the HIGH tier.
 *
 *   LOW    (0.3) — a bare high-entropy blob: no recognized vendor format,
 *                  no adjacent credential keyword, just "this looks
 *                  random." This is exactly the class of thing that
 *                  generated today's false positives (hashes, UUIDs,
 *                  build IDs, base64-encoded non-secret payloads all
 *                  measure as "high entropy"). It is reported, but at the
 *                  bottom of the scale, so a fusion/confidence-weighted
 *                  consumer can discount it appropriately.
 *
 * Entropy thresholds (bits/char, Shannon) were picked empirically against
 * common false-positive sources rather than guessed: plain English prose
 * and camelCase identifiers land ~3.4-4.0 bits/char (a 46-char camelCase
 * variable name measured ~4.08 in testing — see the "must contain both a
 * letter and a digit" gate below, which is what actually excludes it, not
 * the threshold alone), hex hashes/UUIDs land ~3.4-3.6 (their 16-symbol
 * alphabet caps out at 4.0 and rarely gets close with realistic samples),
 * while genuinely random base64/mixed-charset secrets land ~4.7-5.5+. The
 * LOW tier's bar (4.0) sits above the prose/hash/UUID band; the MEDIUM
 * tier's bar (3.5) is lower because the adjacent keyword is doing
 * corroborating work the entropy number alone doesn't have to.
 *
 * Every detector's `find()` is pure, never throws (caught defensively at
 * the top level too, in `runStructuredDetectors`), and only matches over
 * length-bounded regex quantifiers — no nested/ambiguous quantifiers
 * anywhere, so there's no catastrophic-backtracking surface even on
 * adversarial multi-hundred-KB input.
 */

import { luhn, iban, abaRouting, hasHighEntropy, keyFormat } from './validators.js';

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────

export interface StructuredHit {
  /** `0..1`, see the confidence-scale docblock above. */
  confidence: number;
  /** Short machine-readable labels for what contributed to this hit (e.g. `["luhn-valid", "len:16"]`). */
  signals: string[];
  /** The matched candidate text, already truncated to a log-safe length — never the full original payload. */
  matchTruncated: string;
}

export interface StructuredDetector {
  /** Stable machine-readable id, e.g. `'credit-card'`. */
  id: string;
  /** Human-readable label used to build the finding's display name. */
  category: string;
  /** Scan `text` and return only hits that already passed this detector's validator. Must never throw. */
  find(text: string): StructuredHit[];
}

export interface AggregatedHit extends StructuredHit {
  detectorId: string;
  category: string;
}

// ─────────────────────────────────────────────────────────────────────────
// Shared constants
// ─────────────────────────────────────────────────────────────────────────

export const CONFIDENCE = {
  HIGH: 0.9,
  MEDIUM: 0.6,
  LOW: 0.3,
} as const;

/** Per-detector cap on reported hits — independent of `response-inspector.ts`'s overall `MAX_FINDINGS`, this just bounds a single detector's own work/output on a pathological input. */
const MAX_HITS_PER_DETECTOR = 20;

/** Per-detector cap on how many raw regex matches are even considered, so a huge run of non-qualifying candidates can't turn into unbounded work. */
const MAX_CANDIDATES_SCANNED = 5000;

/** Matches `response-inspector.ts`'s `MAX_SNIPPET_LEN` — detectors truncate their own output defensively rather than trusting a downstream caller to. */
const MAX_MATCH_LEN = 120;

function truncate(s: string): string {
  return s.length > MAX_MATCH_LEN ? s.slice(0, MAX_MATCH_LEN) : s;
}

// ─────────────────────────────────────────────────────────────────────────
// Credit card numbers (Luhn)
// ─────────────────────────────────────────────────────────────────────────

// Bounded: a leading/trailing digit with 12-18 middle repetitions each
// allowing at most one separator — no nested quantifiers, so the worst case
// per starting position is a fixed ~19-iteration scan, not exponential.
const CARD_CANDIDATE = /\b\d(?:[ -]?\d){12,18}\b/g;

export const creditCardDetector: StructuredDetector = {
  id: 'credit-card',
  category: 'Financial: credit card number (Luhn-valid)',
  find(text) {
    const hits: StructuredHit[] = [];
    if (typeof text !== 'string') return hits;
    CARD_CANDIDATE.lastIndex = 0;
    let m: RegExpExecArray | null;
    let scanned = 0;
    while ((m = CARD_CANDIDATE.exec(text)) !== null) {
      if (++scanned > MAX_CANDIDATES_SCANNED || hits.length >= MAX_HITS_PER_DETECTOR) break;
      const digits = m[0].replace(/[ -]/g, '');
      if (!luhn(digits)) continue; // validator gate — no finding on failure
      hits.push({
        confidence: CONFIDENCE.HIGH,
        signals: ['luhn-valid', `len:${digits.length}`],
        matchTruncated: truncate(m[0]),
      });
    }
    return hits;
  },
};

// ─────────────────────────────────────────────────────────────────────────
// IBAN (mod-97)
// ─────────────────────────────────────────────────────────────────────────

// Bounded: compact form, or grouped in fixed 4-char blocks (2-7 of them)
// plus an optional short trailing partial block — every repeat count is a
// literal bound, no nesting.
const IBAN_CANDIDATE = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g;

export const ibanDetector: StructuredDetector = {
  id: 'iban',
  category: 'Financial: IBAN (mod-97 checksum valid)',
  find(text) {
    const hits: StructuredHit[] = [];
    if (typeof text !== 'string') return hits;
    IBAN_CANDIDATE.lastIndex = 0;
    let m: RegExpExecArray | null;
    let scanned = 0;
    while ((m = IBAN_CANDIDATE.exec(text)) !== null) {
      if (++scanned > MAX_CANDIDATES_SCANNED || hits.length >= MAX_HITS_PER_DETECTOR) break;
      if (!iban(m[0])) continue; // validator gate — no finding on failure
      hits.push({
        confidence: CONFIDENCE.HIGH,
        signals: ['iban-mod97-valid'],
        matchTruncated: truncate(m[0]),
      });
    }
    return hits;
  },
};

// ─────────────────────────────────────────────────────────────────────────
// ABA routing numbers
// ─────────────────────────────────────────────────────────────────────────

const ABA_CANDIDATE = /\b\d{9}\b/g;

export const abaRoutingDetector: StructuredDetector = {
  id: 'aba-routing',
  category: 'Financial: US bank routing number (ABA checksum valid)',
  find(text) {
    const hits: StructuredHit[] = [];
    if (typeof text !== 'string') return hits;
    ABA_CANDIDATE.lastIndex = 0;
    let m: RegExpExecArray | null;
    let scanned = 0;
    while ((m = ABA_CANDIDATE.exec(text)) !== null) {
      if (++scanned > MAX_CANDIDATES_SCANNED || hits.length >= MAX_HITS_PER_DETECTOR) break;
      if (!abaRouting(m[0])) continue; // validator gate — no finding on failure
      hits.push({
        confidence: CONFIDENCE.HIGH,
        signals: ['aba-checksum-valid'],
        matchTruncated: truncate(m[0]),
      });
    }
    return hits;
  },
};

// ─────────────────────────────────────────────────────────────────────────
// Vendor API keys / JWTs
// ─────────────────────────────────────────────────────────────────────────

// Bounded run of key-shaped characters, including '.' so a JWT's three
// dot-separated segments stay intact as a single candidate.
const KEY_CANDIDATE = /[A-Za-z0-9._-]{8,600}/g;

/**
 * A candidate immediately followed by end-of-sentence punctuation (e.g. a
 * JWT quoted in prose: "...the token is eyJ....sig.") can pick up a
 * trailing '.' that isn't part of the key. Trim a few trailing dots and
 * retry rather than missing the match entirely — bounded to a handful of
 * attempts, never a loop over untrusted-length input.
 */
function keyFormatWithTrim(candidate: string): { vendor: string; value: string } | null {
  let value = candidate;
  for (let i = 0; i < 3; i++) {
    const match = keyFormat(value);
    if (match) return { vendor: match.vendor, value };
    if (!value.endsWith('.')) return null;
    value = value.slice(0, -1);
  }
  return null;
}

export const vendorKeyDetector: StructuredDetector = {
  id: 'vendor-key',
  category: 'Vendor API key / JWT (structurally valid)',
  find(text) {
    const hits: StructuredHit[] = [];
    if (typeof text !== 'string') return hits;
    KEY_CANDIDATE.lastIndex = 0;
    let m: RegExpExecArray | null;
    let scanned = 0;
    while ((m = KEY_CANDIDATE.exec(text)) !== null) {
      if (++scanned > MAX_CANDIDATES_SCANNED || hits.length >= MAX_HITS_PER_DETECTOR) break;
      const matched = keyFormatWithTrim(m[0]);
      if (!matched) continue; // validator gate — no finding on failure
      hits.push({
        confidence: CONFIDENCE.HIGH,
        signals: [`vendor:${matched.vendor}`, 'structurally-valid'],
        matchTruncated: truncate(matched.value),
      });
    }
    return hits;
  },
};

// ─────────────────────────────────────────────────────────────────────────
// High-entropy fallback (context-corroborated, and bare)
// ─────────────────────────────────────────────────────────────────────────

const CONTEXT_MIN_LEN = 16;
const CONTEXT_THRESHOLD = 3.5;
const BARE_MIN_LEN = 20;
const BARE_THRESHOLD = 4.0;

const CONTEXT_CANDIDATE = /[A-Za-z0-9+/_-]{16,256}/g;
const BARE_CANDIDATE = /[A-Za-z0-9+/_-]{20,256}/g;

/** Credential-shaped keywords whose immediate presence corroborates a high-entropy value. Bounded alternation, anchored to end-of-window. */
const CONTEXT_KEYWORD_RE =
  /(?:api[-_]?key|access[-_]?key|secret|password|passwd|credential|authorization|bearer|token|key)\s*[:=]\s*$/i;
const CONTEXT_WINDOW = 40;

function hasPrecedingKeyword(text: string, index: number): boolean {
  const start = Math.max(0, index - CONTEXT_WINDOW);
  return CONTEXT_KEYWORD_RE.test(text.slice(start, index));
}

/** True if `value` has at least one letter and one digit — filters out plain-prose/identifier false positives that pure entropy alone doesn't (see the module docblock's camelCase example). */
function isMixedAlnum(value: string): boolean {
  return /[0-9]/.test(value) && /[A-Za-z]/.test(value);
}

export const contextEntropyDetector: StructuredDetector = {
  id: 'context-entropy',
  category: 'High-entropy value adjacent to a credential keyword',
  find(text) {
    const hits: StructuredHit[] = [];
    if (typeof text !== 'string') return hits;
    CONTEXT_CANDIDATE.lastIndex = 0;
    let m: RegExpExecArray | null;
    let scanned = 0;
    while ((m = CONTEXT_CANDIDATE.exec(text)) !== null) {
      if (++scanned > MAX_CANDIDATES_SCANNED || hits.length >= MAX_HITS_PER_DETECTOR) break;
      const value = m[0];
      if (value.length < CONTEXT_MIN_LEN) continue;
      if (!isMixedAlnum(value)) continue;
      if (keyFormat(value)) continue; // already owned by vendorKeyDetector at HIGH confidence
      if (!hasPrecedingKeyword(text, m.index)) continue; // validator gate part 1
      if (!hasHighEntropy(value, CONTEXT_THRESHOLD)) continue; // validator gate part 2
      hits.push({
        confidence: CONFIDENCE.MEDIUM,
        signals: ['high-entropy', 'adjacent-credential-keyword', `len:${value.length}`],
        matchTruncated: truncate(value),
      });
    }
    return hits;
  },
};

export const bareEntropyDetector: StructuredDetector = {
  id: 'bare-entropy',
  category: 'Bare high-entropy value, no recognized format',
  find(text) {
    const hits: StructuredHit[] = [];
    if (typeof text !== 'string') return hits;
    BARE_CANDIDATE.lastIndex = 0;
    let m: RegExpExecArray | null;
    let scanned = 0;
    while ((m = BARE_CANDIDATE.exec(text)) !== null) {
      if (++scanned > MAX_CANDIDATES_SCANNED || hits.length >= MAX_HITS_PER_DETECTOR) break;
      const value = m[0];
      if (value.length < BARE_MIN_LEN) continue;
      if (!isMixedAlnum(value)) continue;
      if (keyFormat(value)) continue; // already owned by vendorKeyDetector at HIGH confidence
      if (hasPrecedingKeyword(text, m.index)) continue; // owned by contextEntropyDetector instead
      if (!hasHighEntropy(value, BARE_THRESHOLD)) continue; // validator gate
      hits.push({
        confidence: CONFIDENCE.LOW,
        signals: ['high-entropy', 'no-recognized-format', `len:${value.length}`],
        matchTruncated: truncate(value),
      });
    }
    return hits;
  },
};

// ─────────────────────────────────────────────────────────────────────────
// Aggregation
// ─────────────────────────────────────────────────────────────────────────

export const ALL_STRUCTURED_DETECTORS: StructuredDetector[] = [
  creditCardDetector,
  ibanDetector,
  abaRoutingDetector,
  vendorKeyDetector,
  contextEntropyDetector,
  bareEntropyDetector,
];

/**
 * Run every detector over `text`, tagging each hit with its detector's
 * `id`/`category`. A single misbehaving detector — one that throws, or
 * returns something that isn't an array — is skipped and never prevents
 * the remaining detectors from reporting; this is what lets
 * `response-inspector.ts` promise "a throwing detector must not break
 * `inspectResponseText`."
 */
export function runStructuredDetectors(detectors: StructuredDetector[], text: string): AggregatedHit[] {
  const out: AggregatedHit[] = [];
  if (!Array.isArray(detectors) || typeof text !== 'string') return out;

  for (const detector of detectors) {
    try {
      const hits = detector.find(text);
      if (!Array.isArray(hits)) continue;
      for (const hit of hits) {
        if (!hit || typeof hit.matchTruncated !== 'string') continue;
        out.push({ ...hit, detectorId: detector.id, category: detector.category });
      }
    } catch {
      // One detector's failure must never break the others or the caller.
      continue;
    }
  }
  return out;
}
