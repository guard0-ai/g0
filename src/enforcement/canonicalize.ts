/**
 * Detection-side text canonicalization (spec §6.1 hardening): NFKC
 * normalization plus stripping of zero-width / bidi-control characters that
 * attackers lard into payloads to break naive pattern matching.
 *
 * NEVER applied to forwarded traffic — only to the copies detectors scan.
 * Injection/unicode-trick patterns deliberately keep scanning the RAW text
 * (canonicalizing first would erase exactly what UNICODE_TRICKS detects).
 */

// ZWSP..RLM, bidi embeds/overrides, word-joiner + invisible operators,
// bidi isolates, ALM, BOM/ZWNBSP.
const STRIP =
  /[؜​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

export function canonicalize(text: string): string {
  return text.normalize('NFKC').replace(STRIP, '');
}
