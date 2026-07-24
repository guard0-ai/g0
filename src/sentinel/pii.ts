// Local-artifact PII classifier for the sentinel exposure engine.
//
// Contract: given text, return a map of PII CLASS -> COUNT of DISTINCT matches.
// It NEVER returns the raw matched values — only classes and counts — because
// the output travels into snapshots and reports that must carry no raw PII.
// Structured classes use regex + checksum validation (Luhn for cards, octet
// range for IPv4) so counts are trustworthy rather than pattern-noise.

export const PII_CLASSES = [
  'email',
  'credit_card',
  'us_ssn',
  'ipv4',
  'phone',
  'aws_access_key',
  'api_token',
  'jwt',
  'private_key',
] as const;

export type PiiClass = (typeof PII_CLASSES)[number];
export type PiiCounts = Partial<Record<PiiClass, number>>;

const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const IPV4 = /\b(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\b/g;
const SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const AWS_KEY = /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b/g;
const API_TOKEN = /\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20})\b/g;
const JWT = /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{2,}\b/g;
const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g;
// Card candidates: 13–19 digit runs allowing space/dash separators.
const CARD_CANDIDATE = /\b(?:\d[ -]?){13,19}\b/g;
// Conservative phone: E.164 or NANP-style with separators; validated by digit count.
const PHONE_CANDIDATE = /(?:\+?\d[\d\s().-]{7,}\d)/g;

/** Luhn checksum — true if the digit string is a valid Luhn (card) number. */
function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function validIpv4(s: string): boolean {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

/** Count DISTINCT regex matches, optionally filtered by a validator. */
function countDistinct(text: string, re: RegExp, valid?: (m: string) => boolean): number {
  const seen = new Set<string>();
  for (const m of text.matchAll(re)) {
    const v = m[0];
    if (valid && !valid(v)) continue;
    seen.add(v);
  }
  return seen.size;
}

/**
 * Classify text into distinct-count per PII class. Returns only classes that
 * matched (>0). Never includes raw values.
 */
export function classifyText(text: string): PiiCounts {
  const out: PiiCounts = {};
  const put = (k: PiiClass, n: number) => {
    if (n > 0) out[k] = n;
  };

  put('email', countDistinct(text, EMAIL));
  put('ipv4', countDistinct(text, IPV4, validIpv4));
  put('us_ssn', countDistinct(text, SSN));
  put('aws_access_key', countDistinct(text, AWS_KEY));
  put('api_token', countDistinct(text, API_TOKEN));
  put('jwt', countDistinct(text, JWT));
  put('private_key', countDistinct(text, PRIVATE_KEY));

  put(
    'credit_card',
    countDistinct(text, CARD_CANDIDATE, (m) => {
      const digits = m.replace(/[ -]/g, '');
      return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
    }),
  );

  // Phones are noisy; require exactly 10–15 digits and avoid collision with
  // things already counted as cards/SSNs by rejecting >15 digits.
  put(
    'phone',
    countDistinct(text, PHONE_CANDIDATE, (m) => {
      const digits = m.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 15 && !luhnValid(digits.slice(0, 16));
    }),
  );

  return out;
}

/** Sum per-class counts across multiple artifact results. */
export function mergeCounts(list: PiiCounts[]): PiiCounts {
  const out: PiiCounts = {};
  for (const c of list) {
    for (const [k, v] of Object.entries(c) as [PiiClass, number][]) {
      out[k] = (out[k] ?? 0) + v;
    }
  }
  return out;
}
