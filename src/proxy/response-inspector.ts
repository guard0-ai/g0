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
import { looksLikeSecret } from '../mcp/config-scanner.js';
import { checkAgainstIOCs } from '../intelligence/ioc-database.js';

export interface ResponseFinding {
  category: 'injection' | 'secret' | 'ioc';
  name: string; // human label, e.g. "Role reassignment", "Exfil domain: webhook.site"
  severity: 'critical' | 'high' | 'medium' | 'low';
  match?: string; // the offending snippet (TRUNCATED to ~120 chars, never the whole payload)
}

export interface InspectionResult {
  findings: ResponseFinding[];
  redactedText?: string; // present only if redaction changed the text
}

const DEFAULT_MAX_SCAN_BYTES = 1_000_000;
// Bounds only the *reported* secret findings (see the secret-detection
// block below). Injection and IOC findings are naturally bounded — by the
// fixed RESPONSE_INJECTION_PATTERNS/UNICODE_TRICKS array lengths and by the
// number of distinct hosts in the text, respectively — so they are never
// gated by this cap. A response can't smuggle in decoy secrets to crowd out
// (and thereby suppress) a deny-driving injection/IOC finding.
const MAX_SECRET_FINDINGS = 50;
const MAX_SNIPPET_LEN = 120;
const REDACTED_PLACEHOLDER = '[g0:redacted]';

function truncateSnippet(s: string): string {
  return s.length > MAX_SNIPPET_LEN ? s.slice(0, MAX_SNIPPET_LEN) : s;
}

/**
 * Extract the concatenated text content of an MCP `tools/call` result.
 *
 * Handles the standard shape `{ content: [{ type: 'text', text: '...' }] }`
 * (non-text content items — images, resources — are ignored) as well as a
 * bare string result. Any other/garbage shape yields `''`; this function
 * never throws.
 */
export function extractResponseText(result: unknown): string {
  try {
    if (typeof result === 'string') return result;

    if (result && typeof result === 'object' && !Array.isArray(result)) {
      const content = (result as { content?: unknown }).content;
      if (Array.isArray(content)) {
        let out = '';
        for (const item of content) {
          if (
            item &&
            typeof item === 'object' &&
            (item as { type?: unknown }).type === 'text' &&
            typeof (item as { text?: unknown }).text === 'string'
          ) {
            out += (item as { text: string }).text;
          }
        }
        return out;
      }
    }

    return '';
  } catch {
    return '';
  }
}

/** Extract candidate hostnames from `https?://host` URLs and bare `host.tld` tokens. */
function extractHosts(text: string): string[] {
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
 * Run injection, secret, and IOC-domain analysis over a chunk of response
 * text. Never throws; respects `opts.maxScanBytes` and caps total findings.
 */
export function inspectResponseText(
  text: string,
  opts?: { redactSecrets?: boolean; maxScanBytes?: number },
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
    // Bounded by RESPONSE_INJECTION_PATTERNS.length (fixed, small) — at
    // most one finding per pattern — so this never needs a findings-array
    // cap and must never be skipped because unrelated secret findings
    // filled up the array.
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
    // Same reasoning: bounded by UNICODE_TRICKS.length.
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
    // Runs BEFORE secret detection, and is bounded only by the number of
    // distinct hosts in the text (small in practice) — never by the secret
    // findings cap below. IOC findings are `severity: 'critical'` and are
    // what `evaluateResponse` keys a `deny` decision on: a response padded
    // with decoy secret-shaped tokens must never be able to suppress a
    // real exfil-domain finding.
    try {
      for (const host of extractHosts(text)) {
        const matches = checkAgainstIOCs(host, 'domain');
        for (const ioc of matches) {
          findings.push({
            category: 'ioc',
            name: `Exfil domain: ${ioc.indicator}`,
            severity: 'critical',
            match: truncateSnippet(host),
          });
        }
      }
    } catch {
      // IOC DB load/lookup is best-effort — never let it break the response.
    }

    // ── Secret detection ─────────────────────────────────────────────────
    // `MAX_SECRET_FINDINGS` bounds only the *reported* secret findings
    // array, so a pathological response can't grow it unboundedly. It must
    // NOT gate population of `detected` (the redaction key-set): every
    // secret-shaped token has to be added to `detected`, or a real secret
    // that happens to appear after 50 decoys would be forwarded to the
    // client verbatim even with `redactSecrets: true`.
    let redactedText: string | undefined;
    try {
      const tokens = text.split(/[\s'"`]+/).filter(Boolean);
      const detected = new Set<string>();
      let secretFindingsCount = 0;
      for (const token of tokens) {
        if (detected.has(token)) continue;
        if (looksLikeSecret(token)) {
          detected.add(token);
          if (secretFindingsCount < MAX_SECRET_FINDINGS) {
            findings.push({
              category: 'secret',
              name: 'Potential secret in response',
              severity: 'high',
              match: truncateSnippet(token),
            });
            secretFindingsCount++;
          }
        }
      }

      if (opts?.redactSecrets && detected.size > 0) {
        // Single O(n) pass: replace any whole token that matches a detected
        // secret. `detected.has()` is O(1), so total cost is linear in text
        // length regardless of how many distinct secrets were found — no
        // per-secret full-text scan, no O(n²) blowup on an adversarial
        // response padded with tens of thousands of distinct secret-shaped
        // tokens. The regex matches only non-delimiter runs (the same
        // tokenization detection used above), so all whitespace/quote
        // delimiters are preserved exactly. Whole-token equality is also
        // more precise than the previous substring split/join, which could
        // over-redact a secret that appeared inside an unrelated token.
        const redacted = text.replace(/[^\s'"`]+/g, (tok) =>
          detected.has(tok) ? REDACTED_PLACEHOLDER : tok,
        );
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
