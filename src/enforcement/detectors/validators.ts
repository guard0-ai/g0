/**
 * Pure, never-throwing checksum/format validators used to *gate* the
 * structured secret detectors in `./structured.ts`.
 *
 * These are the accuracy backbone of Task 2's false-positive cut: instead
 * of flagging anything that merely "looks random" (the old
 * `looksLikeSecret` heuristic in `src/mcp/config-scanner.ts`), a candidate
 * is only ever reported once it passes a *real* validator here — Luhn for
 * card numbers, IBAN mod-97, the US ABA routing checksum, or a recognized
 * vendor key shape (with a structural check where one exists, e.g. a
 * decodable JWT header). A 16-digit number that fails Luhn is invisible to
 * this module; it never even reaches the detector layer.
 *
 * Every export here is a pure function over its input string: no I/O, no
 * shared mutable state, and no throwing — malformed/adversarial input
 * (wrong type, huge length, non-numeric characters where digits are
 * expected) always degrades to a safe negative (`false`/`null`/`0`) rather
 * than an exception. Detectors run over untrusted, potentially huge,
 * potentially adversarial MCP response text, so every function here also
 * bounds its own work (explicit length caps) independent of whatever
 * upstream `maxScanBytes` budget the caller enforces.
 */

// ─────────────────────────────────────────────────────────────────────────
// Luhn (credit/debit card numbers)
// ─────────────────────────────────────────────────────────────────────────

/** Defensive upper bound on input length for the checksum validators below — well beyond any real PAN/IBAN/routing number, just enough to keep a pathological input O(1)-ish. */
const MAX_VALIDATOR_INPUT_LEN = 64;

/**
 * Luhn checksum (mod-10, ISO/IEC 7812-1) used by credit/debit card PANs.
 * `digits` must already be normalized to digits-only by the caller (the
 * card detector strips spaces/dashes before calling this).
 */
export function luhn(digits: string): boolean {
  if (typeof digits !== 'string') return false;
  if (digits.length === 0 || digits.length > MAX_VALIDATOR_INPUT_LEN) return false;
  if (!/^\d+$/.test(digits)) return false;

  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48; // '0'
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

// ─────────────────────────────────────────────────────────────────────────
// IBAN (mod-97, ISO 7064)
// ─────────────────────────────────────────────────────────────────────────

/**
 * IBAN check-digit validation (ISO 7064 MOD97-10). Accepts the compact form
 * or the human-readable 4-char-grouped form (spaces are stripped first).
 * Structure: 2 letters (country) + 2 digits (check) + 11-30 alphanumeric
 * (BBAN), total length 15-34 — this module doesn't enforce per-country
 * exact lengths, only the general ISO 13616 envelope, before running the
 * checksum.
 */
export function iban(candidate: string): boolean {
  if (typeof candidate !== 'string') return false;
  if (candidate.length === 0 || candidate.length > MAX_VALIDATOR_INPUT_LEN) return false;

  const cleaned = candidate.replace(/\s+/g, '').toUpperCase();
  if (cleaned.length < 15 || cleaned.length > 34) return false;
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(cleaned)) return false;

  // Move the country code + check digits to the end, then convert letters
  // to numbers (A=10 .. Z=35) per ISO 7064, and reduce mod 97 digit-by-digit
  // to avoid ever forming a number too large for JS's safe integer range.
  const rearranged = cleaned.slice(4) + cleaned.slice(0, 4);
  let numeric = '';
  for (let i = 0; i < rearranged.length; i++) {
    const ch = rearranged[i];
    if (ch >= '0' && ch <= '9') {
      numeric += ch;
    } else if (ch >= 'A' && ch <= 'Z') {
      numeric += (ch.charCodeAt(0) - 55).toString(); // 'A' -> 10 ... 'Z' -> 35
    } else {
      return false; // shouldn't happen given the regex above, but never throw
    }
  }

  let mod = 0;
  for (let i = 0; i < numeric.length; i++) {
    mod = (mod * 10 + (numeric.charCodeAt(i) - 48)) % 97;
  }
  return mod === 1;
}

// ─────────────────────────────────────────────────────────────────────────
// ABA routing number (US bank routing transit number checksum)
// ─────────────────────────────────────────────────────────────────────────

/**
 * US ABA routing transit number checksum:
 * `3*(d1+d4+d7) + 7*(d2+d5+d8) + 1*(d3+d6+d9) ≡ 0 (mod 10)`.
 * Accepts digits with optional spaces/dashes; requires exactly 9 digits.
 */
export function abaRouting(candidate: string): boolean {
  if (typeof candidate !== 'string') return false;
  if (candidate.length === 0 || candidate.length > MAX_VALIDATOR_INPUT_LEN) return false;

  const cleaned = candidate.replace(/[\s-]/g, '');
  if (!/^\d{9}$/.test(cleaned)) return false;

  const d = cleaned.split('').map((c) => c.charCodeAt(0) - 48);
  const sum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + 1 * (d[2] + d[5] + d[8]);
  return sum % 10 === 0;
}

// ─────────────────────────────────────────────────────────────────────────
// Shannon entropy (for the low-confidence "bare high-entropy blob" tier)
// ─────────────────────────────────────────────────────────────────────────

/** Bound how much of a candidate string entropy is computed over — a defensive cap independent of the caller's own token-length limits. */
const MAX_ENTROPY_INPUT_LEN = 4096;

/** Shannon entropy in bits/char over `s`. Never throws; empty/invalid input yields `0`. */
export function shannonEntropy(s: string): number {
  if (typeof s !== 'string' || s.length === 0) return 0;
  const bounded = s.length > MAX_ENTROPY_INPUT_LEN ? s.slice(0, MAX_ENTROPY_INPUT_LEN) : s;

  const freq = new Map<string, number>();
  for (let i = 0; i < bounded.length; i++) {
    const ch = bounded[i];
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = bounded.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** True iff `shannonEntropy(s) >= threshold`. Never throws. */
export function hasHighEntropy(s: string, threshold: number): boolean {
  if (typeof s !== 'string' || s.length === 0) return false;
  if (typeof threshold !== 'number' || Number.isNaN(threshold)) return false;
  return shannonEntropy(s) >= threshold;
}

// ─────────────────────────────────────────────────────────────────────────
// Vendor key shape recognition (+ JWT structural check)
// ─────────────────────────────────────────────────────────────────────────

export interface KeyFormatMatch {
  /** Short vendor/format label, e.g. `'openai' | 'github' | 'aws' | 'slack' | 'jwt'`. */
  vendor: string;
  /**
   * True when the match went beyond a bare prefix — an exact fixed-shape
   * vendor format (prefix + exact length/charset, e.g. `AKIA` + 16 upper
   * alphanumerics) or a JWT whose header segment actually base64url-decodes
   * to a JSON object with `alg`/`typ`. All of `keyFormat`'s current matches
   * satisfy this, but the field is kept explicit so a future looser/prefix
   * -only match (if one is ever added) can be told apart from a fully
   * validated one.
   */
  structurallyValid: boolean;
}

/** Defensive upper bound on how long a single candidate token can be before we bother format-checking it. */
const MAX_KEY_CANDIDATE_LEN = 4096;

interface VendorShape {
  vendor: string;
  pattern: RegExp;
}

// Exact, fixed-shape vendor key formats. Every pattern is anchored
// (`^...$`) against a single already-tokenized candidate (never run against
// a whole blob of text), so there is no risk of runaway backtracking
// regardless of input size.
const VENDOR_SHAPES: VendorShape[] = [
  { vendor: 'aws', pattern: /^AKIA[0-9A-Z]{16}$/ },
  { vendor: 'github', pattern: /^gh[ps]_[A-Za-z0-9]{36,255}$/ },
  { vendor: 'openai', pattern: /^sk-[A-Za-z0-9_-]{20,300}$/ },
  { vendor: 'slack', pattern: /^xox[baprs]-[A-Za-z0-9-]{10,200}$/ },
  { vendor: 'gitlab', pattern: /^glpat-[A-Za-z0-9_-]{20,100}$/ },
];

/** Decode a base64url segment to a UTF-8 string, or `null` on any failure. Never throws. */
function base64UrlDecode(segment: string): string | null {
  if (typeof segment !== 'string' || segment.length === 0 || segment.length > MAX_KEY_CANDIDATE_LEN) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  try {
    let s = segment.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4 !== 0) s += '=';
    return Buffer.from(s, 'base64').toString('utf-8');
  } catch {
    return null;
  }
}

/**
 * True iff `token` is a `header.payload.signature` triple whose header
 * segment base64url-decodes to a JSON object carrying a JWT-shaped field
 * (`alg` or `typ`). This is the "structural check" the brief asks for —
 * three dot-separated segments alone is too weak a signal (lots of
 * non-secret text is dot-separated), but a header that actually decodes to
 * `{"alg":"HS256","typ":"JWT"}`-shaped JSON is a strong, specific signal.
 */
function isStructurallyValidJwt(token: string): boolean {
  if (typeof token !== 'string' || token.length === 0 || token.length > MAX_KEY_CANDIDATE_LEN) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [header, payload, signature] = parts;
  if (header.length === 0 || payload.length === 0 || signature.length === 0) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(payload) || !/^[A-Za-z0-9_-]+$/.test(signature)) return false;

  const decodedHeader = base64UrlDecode(header);
  if (!decodedHeader) return false;

  try {
    const obj: unknown = JSON.parse(decodedHeader);
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return false;
    const rec = obj as Record<string, unknown>;
    return typeof rec.alg === 'string' || typeof rec.typ === 'string';
  } catch {
    return false;
  }
}

/**
 * Recognize a single candidate token as a vendor API key / token shape, or
 * a structurally-valid JWT. Returns `null` (no finding) unless the token
 * matches one of the known exact shapes or decodes as a real JWT header —
 * this is the validator gate for the vendor-key detector in
 * `./structured.ts`.
 */
export function keyFormat(token: string): KeyFormatMatch | null {
  if (typeof token !== 'string') return null;
  if (token.length < 8 || token.length > MAX_KEY_CANDIDATE_LEN) return null;

  for (const shape of VENDOR_SHAPES) {
    if (shape.pattern.test(token)) {
      return { vendor: shape.vendor, structurallyValid: true };
    }
  }

  if (isStructurallyValidJwt(token)) {
    return { vendor: 'jwt', structurallyValid: true };
  }

  return null;
}
