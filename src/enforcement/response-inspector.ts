/**
 * Security analysis for MCP `tools/call` *responses*.
 *
 * A malicious or compromised MCP server can return text engineered to
 * hijack the calling LLM once the client renders the tool result back into
 * context — prompt injection, chat-template smuggling, secrets echoed back
 * from the server, or known-bad exfil domains. `g0 proxy` sits between the
 * MCP server and the client, so this layer is genuinely enforceable: it
 * inspects response text before the LLM ever sees it.
 *
 * Design constraints (see task brief):
 *  - Never throw. Any unexpected shape/error degrades to "no findings"
 *    rather than crashing the proxy's message loop.
 *  - Respect a `maxScanBytes` budget — huge payloads (base64 images, giant
 *    file dumps) are skipped rather than regex-scanned, to bound latency.
 *  - Matched snippets are truncated to ~120 chars — findings never carry
 *    the whole payload (which could itself leak secrets into logs/UI).
 *  - Total findings are capped so a pathological input can't produce an
 *    unbounded array.
 */

import {
  RESPONSE_INJECTION_PATTERNS,
  UNICODE_TRICKS,
} from './injection-patterns.js';
import { checkAgainstIOCs } from '../intelligence/ioc-database.js';
import { canonicalize } from './canonicalize.js';
import { ALL_STRUCTURED_DETECTORS, runStructuredDetectors, CONFIDENCE } from './detectors/structured.js';
import type { StructuredDetector } from './detectors/structured.js';

export interface ResponseFinding {
  category: 'injection' | 'secret' | 'ioc';
  name: string; // human label, e.g. "Role reassignment", "Exfil domain: webhook.site"
  severity: 'critical' | 'high' | 'medium' | 'low';
  match?: string; // the offending snippet (TRUNCATED to ~120 chars, never the whole payload)
  /**
   * How confident the detector is in this finding, `0..1`. Only populated
   * for `category: 'secret'` findings today — see the confidence-scale
   * docblock in `./detectors/structured.ts`. Absent from injection/IOC
   * findings, which are pattern matches rather than validator-gated.
   */
  confidence?: number;
  /** Short machine-readable labels for what contributed to `confidence` (e.g. `["luhn-valid", "len:16"]`). Mirrors `PolicyDecision.signals`. */
  signals?: string[];
}

export interface InspectionResult {
  findings: ResponseFinding[];
  redactedText?: string; // present only if redaction changed the text
}

const DEFAULT_MAX_SCAN_BYTES = 1_000_000;
const MAX_FINDINGS = 50;
const MAX_SNIPPET_LEN = 120;
const REDACTED_PLACEHOLDER = '[g0:redacted]';

function truncateSnippet(s: string): string {
  return s.length > MAX_SNIPPET_LEN ? s.slice(0, MAX_SNIPPET_LEN) : s;
}

/**
 * Replace every `[start, end)` range in `text` with `REDACTED_PLACEHOLDER`,
 * in a SINGLE pass: sort ranges, merge overlaps/adjacencies, then rebuild the
 * string once. O(n log n) total.
 *
 * This replaces an earlier `for (secret of detected) text.split(secret).join(
 * placeholder)` loop, which was O(distinct_secrets × text_length). Once the
 * per-detector hit cap was removed, `detected` could grow one entry per
 * distinct high-entropy token, so a malicious server could flood a ~1MB
 * response with distinct tokens and force a multi-second synchronous stall on
 * the proxy's response hot path (measured ~7s at 1MB). Redacting by
 * precomputed offsets is both fast and correct for duplicate tokens (each
 * occurrence is its own range) — an `indexOf`-based reconstruction would be
 * neither. Never throws; ranges are clamped and defensively validated.
 */
function redactRanges(text: string, ranges: Array<[number, number]>): string {
  const clean: Array<[number, number]> = [];
  for (const [s, e] of ranges) {
    if (!Number.isFinite(s) || !Number.isFinite(e)) continue;
    const start = Math.max(0, Math.min(s, text.length));
    const end = Math.max(0, Math.min(e, text.length));
    if (end > start) clean.push([start, end]);
  }
  if (clean.length === 0) return text;

  clean.sort((a, b) => a[0] - b[0]);

  let out = '';
  let cursor = 0;
  // Track the running merged range so overlapping/adjacent ranges collapse
  // into a single placeholder instead of emitting several in a row.
  let mergeStart = clean[0][0];
  let mergeEnd = clean[0][1];
  for (let i = 1; i < clean.length; i++) {
    const [s, e] = clean[i];
    if (s <= mergeEnd) {
      if (e > mergeEnd) mergeEnd = e; // extend the current merged range
    } else {
      out += text.slice(cursor, mergeStart) + REDACTED_PLACEHOLDER;
      cursor = mergeEnd;
      mergeStart = s;
      mergeEnd = e;
    }
  }
  out += text.slice(cursor, mergeStart) + REDACTED_PLACEHOLDER;
  cursor = mergeEnd;
  out += text.slice(cursor);
  return out;
}

/** Extract candidate hostnames from `https?://host` URLs and bare `host.tld` tokens. */
export function extractHosts(text: string): string[] {
  const hosts = new Set<string>();

  // Bounded: host label is [^\s/?#:]{1,253}, no nested quantifiers.
  const urlPattern = /https?:\/\/([^\s/?#:]{1,253})(?::\d{1,5})?(?:[/?#]|\s|$)/gi;
  let m: RegExpExecArray | null;
  while ((m = urlPattern.exec(text)) !== null) {
    hosts.add(m[1].toLowerCase());
  }

  // Bare "word.tld" tokens — DNS-label-shaped, bounded repeat counts.
  const barePattern = /\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.){1,8}[a-zA-Z]{2,24})\b/g;
  while ((m = barePattern.exec(text)) !== null) {
    hosts.add(m[1].toLowerCase());
  }

  return [...hosts];
}

/**
 * Run injection, IOC-domain, and secret analysis over a chunk of response
 * text. Never throws; respects `opts.maxScanBytes`.
 *
 * ── Ordering is a security property, not cosmetic ───────────────────────
 *
 * The security-critical, deny-driving categories (injection and IOC/exfil
 * domains — see `evaluateResponse` in `policy.ts`, whose `threatFindings`
 * includes both) run FIRST and are NOT gated by the secret-findings cap.
 * Only the *secret* findings array is capped (`MAX_SECRET_FINDINGS`), because
 * only it can grow unbounded with input — an injection is bounded by the
 * fixed pattern count, IOC by distinct matched hosts.
 *
 * If the cap gated injection/IOC (as an earlier version did — those ran
 * AFTER secret detection behind a shared `atCap()`), a malicious server could
 * pad a response with ~50 decoy high-entropy blobs to saturate the cap and
 * suppress a `webhook.site` exfil URL entirely — a deny bypass in enforce
 * mode. A reporting/size cap must never decide whether a security category
 * runs.
 */
const MAX_SECRET_FINDINGS = MAX_FINDINGS;
const MAX_IOC_FINDINGS = MAX_FINDINGS;

export function inspectResponseText(
  text: string,
  opts?: {
    redactSecrets?: boolean;
    maxScanBytes?: number;
    /**
     * Structured-detector list to run instead of `ALL_STRUCTURED_DETECTORS`
     * (Task 5's v2 `detectors:` policy block, via `resolveDetectors` in
     * `./policy.ts`). Omitted -> `ALL_STRUCTURED_DETECTORS`, byte-identical
     * to this function's behavior before this option existed — every v1
     * caller (and any v2 caller with no `detectors:` block configured)
     * never passes this, so nothing changes for them.
     */
    detectors?: StructuredDetector[];
    /**
     * Re-run the structured detectors on `canonicalize(text)` (NFKC +
     * zero-width strip) and report NEW hits as detection-only findings
     * tagged `'canonicalized'`. Canonical offsets don't map back into the
     * raw text, so these hits never contribute redaction ranges. Default
     * false -> byte-identical to pre-option behavior.
     */
    canonicalPass?: boolean;
  },
): InspectionResult {
  try {
    if (typeof text !== 'string' || text.length === 0) {
      return { findings: [] };
    }

    const maxScanBytes = opts?.maxScanBytes ?? DEFAULT_MAX_SCAN_BYTES;
    if (text.length > maxScanBytes) {
      return { findings: [] };
    }

    const findings: ResponseFinding[] = [];

    // ── Injection patterns (response-specific) ──────────────────────────
    // Bounded by the fixed pattern-array length; always runs, never capped.
    for (const { pattern, name } of RESPONSE_INJECTION_PATTERNS) {
      const match = text.match(pattern);
      if (match) {
        const severity = /ansi escape/i.test(name) ? 'medium' : 'high';
        findings.push({
          category: 'injection',
          name,
          severity,
          match: truncateSnippet(match[0]),
        });
      }
    }

    // ── Unicode obfuscation tricks ───────────────────────────────────────
    for (const { pattern, name } of UNICODE_TRICKS) {
      const match = text.match(pattern);
      if (match && match.length > 0) {
        findings.push({
          category: 'injection',
          name,
          severity: 'medium',
          match: truncateSnippet(match[0]),
        });
      }
    }

    // ── IOC domain matching ──────────────────────────────────────────────
    // Runs BEFORE secret detection and independent of the secret cap, so a
    // flood of decoy secrets can never suppress a critical exfil-domain
    // finding (which is exactly what drives `deny`). Capped by its own budget
    // purely to bound the array on pathological input.
    try {
      let iocCount = 0;
      for (const host of extractHosts(text)) {
        if (iocCount >= MAX_IOC_FINDINGS) break;
        const matches = checkAgainstIOCs(host, 'domain');
        for (const ioc of matches) {
          if (iocCount >= MAX_IOC_FINDINGS) break;
          findings.push({
            category: 'ioc',
            name: `Exfil domain: ${ioc.indicator}`,
            severity: 'critical',
            match: truncateSnippet(host),
          });
          iocCount++;
        }
      }
    } catch {
      // IOC DB load/lookup is best-effort — never let it break the response.
    }

    // ── Secret detection ─────────────────────────────────────────────────
    //
    // Validator-gated structured detectors (see ./detectors/structured.ts):
    // a candidate is only ever reported once it passes a real checksum or
    // format validator (Luhn, IBAN mod-97, ABA routing checksum, a
    // real-shaped vendor key, or a context/format-gated high-entropy check).
    // `runStructuredDetectors` never throws even if an individual detector
    // does, so a bug in one detector can't take out the findings above or the
    // response itself.
    let redactedText: string | undefined;
    try {
      const detectors = Array.isArray(opts?.detectors) ? opts.detectors : ALL_STRUCTURED_DETECTORS;
      const structuredHits = runStructuredDetectors(detectors, text);

      // Redaction is driven by per-hit OFFSET ranges (see `redactRanges`), not
      // by matching secret *strings* against the text — that keeps it single
      // pass and correct for duplicate tokens. Ranges are collected for EVERY
      // hit regardless of the reporting cap: bounding what we *report* is a UI
      // concern, but a secret past the cap must still be scrubbed, or the cap
      // itself becomes a leak.
      const ranges: Array<[number, number]> = [];
      const reported = new Set<string>(); // dedupe the reported findings by full value
      let secretCount = 0;
      for (const hit of structuredHits) {
        if (opts?.redactSecrets && Number.isFinite(hit.start) && Number.isFinite(hit.end) && hit.end > hit.start) {
          ranges.push([hit.start, hit.end]);
        }
        if (reported.has(hit.value)) continue;
        reported.add(hit.value);
        if (secretCount >= MAX_SECRET_FINDINGS) continue; // cap the reported array only
        secretCount++;
        findings.push({
          category: 'secret',
          name: `Potential secret in response (${hit.category})`,
          severity: hit.confidence >= CONFIDENCE.HIGH ? 'high' : hit.confidence >= CONFIDENCE.MEDIUM ? 'medium' : 'low',
          match: truncateSnippet(hit.matchTruncated),
          confidence: hit.confidence,
          signals: hit.signals,
        });
      }

      // Canonicalization pass (spec §6.1 hardening): re-run the detectors on
      // the NFKC/zero-width-stripped text to catch encoding-larded secrets.
      // Detection-only — canonical offsets don't map back into the raw text,
      // so these hits never contribute redaction ranges.
      if (opts?.canonicalPass) {
        const canon = canonicalize(text);
        if (canon !== text) {
          for (const hit of runStructuredDetectors(detectors, canon)) {
            if (reported.has(hit.value)) continue;
            reported.add(hit.value);
            if (secretCount >= MAX_SECRET_FINDINGS) continue;
            secretCount++;
            findings.push({
              category: 'secret',
              name: `Potential secret in response (${hit.category})`,
              severity: hit.confidence >= CONFIDENCE.HIGH ? 'high' : hit.confidence >= CONFIDENCE.MEDIUM ? 'medium' : 'low',
              match: truncateSnippet(hit.matchTruncated),
              confidence: hit.confidence,
              signals: [...hit.signals, 'canonicalized'],
            });
          }
        }
      }

      if (opts?.redactSecrets && ranges.length > 0) {
        const redacted = redactRanges(text, ranges);
        if (redacted !== text) redactedText = redacted;
      }
    } catch {
      // Secret detection is best-effort — never let it break the response.
    }

    return redactedText !== undefined ? { findings, redactedText } : { findings };
  } catch {
    return { findings: [] };
  }
}
