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
import { ALL_STRUCTURED_DETECTORS, runStructuredDetectors, CONFIDENCE } from './detectors/structured.js';

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
    const atCap = () => findings.length >= MAX_FINDINGS;

    // ── Injection patterns (response-specific) ──────────────────────────
    for (const { pattern, name } of RESPONSE_INJECTION_PATTERNS) {
      if (atCap()) break;
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
      if (atCap()) break;
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

    // ── Secret detection ─────────────────────────────────────────────────
    //
    // Validator-gated structured detectors (see ./detectors/structured.ts)
    // replace the old raw "does this token merely look random?" heuristic:
    // a candidate is only ever reported once it passes a real checksum or
    // format validator (Luhn, IBAN mod-97, ABA routing checksum, a
    // real-shaped vendor key, or a high-entropy check gated by context/
    // recognizability). `runStructuredDetectors` never throws even if an
    // individual detector does, so a bug in one detector can't take out the
    // other findings below or the response itself.
    let redactedText: string | undefined;
    try {
      const structuredHits = runStructuredDetectors(ALL_STRUCTURED_DETECTORS, text);
      const detected = new Set<string>();
      for (const hit of structuredHits) {
        if (atCap()) break;
        if (detected.has(hit.matchTruncated)) continue;
        detected.add(hit.matchTruncated);
        findings.push({
          category: 'secret',
          name: `Potential secret in response (${hit.category})`,
          severity: hit.confidence >= CONFIDENCE.HIGH ? 'high' : hit.confidence >= CONFIDENCE.MEDIUM ? 'medium' : 'low',
          match: truncateSnippet(hit.matchTruncated),
          confidence: hit.confidence,
          signals: hit.signals,
        });
      }

      if (opts?.redactSecrets && detected.size > 0) {
        let redacted = text;
        for (const secret of detected) {
          redacted = redacted.split(secret).join(REDACTED_PLACEHOLDER);
        }
        if (redacted !== text) redactedText = redacted;
      }
    } catch {
      // Secret detection is best-effort — never let it break the response.
    }

    // ── IOC domain matching ──────────────────────────────────────────────
    try {
      if (!atCap()) {
        for (const host of extractHosts(text)) {
          if (atCap()) break;
          const matches = checkAgainstIOCs(host, 'domain');
          for (const ioc of matches) {
            if (atCap()) break;
            findings.push({
              category: 'ioc',
              name: `Exfil domain: ${ioc.indicator}`,
              severity: 'critical',
              match: truncateSnippet(host),
            });
          }
        }
      }
    } catch {
      // IOC DB load/lookup is best-effort — never let it break the response.
    }

    return redactedText !== undefined ? { findings, redactedText } : { findings };
  } catch {
    return { findings: [] };
  }
}
