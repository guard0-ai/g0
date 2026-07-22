/**
 * Shared prompt-injection detection patterns.
 *
 * `PROMPT_INJECTION_PATTERNS` and `UNICODE_TRICKS` were lifted verbatim out
 * of `src/mcp/skill-scanner.ts` (which scans SKILL.md files on disk) so they
 * can be reused by `src/proxy/response-inspector.ts` (which scans MCP tool
 * *responses* flowing through `g0 proxy`). `skill-scanner.ts` re-imports
 * these two arrays so its behavior is unchanged.
 *
 * `RESPONSE_INJECTION_PATTERNS` is new: it targets injection techniques that
 * specifically show up in tool-call *output* rather than skill documentation
 * — chat-template role markers, fake "the user approved this" hijacks, and
 * exfil-via-markdown-image tricks.
 *
 * ReDoS note: every pattern below is checked to avoid nested/overlapping
 * quantifiers (e.g. no `(a+)+` or `(.*)(.*)` shapes). Alternation groups are
 * bounded by literal words or character classes with fixed/bounded repeat
 * counts, and any "capture everything up to a delimiter" group uses a
 * negated character class (e.g. `[^)]*`) instead of a greedy `.*` so the
 * engine can't backtrack polynomially on adversarial input. See the
 * `checkVersionVulnerable` comment in `src/intelligence/cve-feed.ts` for the
 * same reasoning applied elsewhere in this codebase.
 */

export interface InjectionPattern {
  pattern: RegExp;
  name: string;
}

/** Prompt-injection phrasing patterns, originally defined in skill-scanner.ts. */
export const PROMPT_INJECTION_PATTERNS: InjectionPattern[] = [
  { pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i, name: 'Ignore previous instructions' },
  { pattern: /disregard\s+(?:all\s+)?(?:prior|previous|above)/i, name: 'Disregard prior instructions' },
  { pattern: /you\s+are\s+now\s+/i, name: 'Role reassignment' },
  { pattern: /system:\s*/i, name: 'System prompt injection' },
  { pattern: /forget\s+(?:all\s+)?(?:your|previous|prior)/i, name: 'Instruction erasure' },
  { pattern: /override\s+(?:your|all|previous)/i, name: 'Override instructions' },
  { pattern: /new\s+instructions?:/i, name: 'New instruction injection' },
  { pattern: /act\s+as\s+(?:a\s+)?(?:different|new)/i, name: 'Persona injection' },
];

/** Unicode obfuscation tricks, originally defined in skill-scanner.ts. */
export const UNICODE_TRICKS: InjectionPattern[] = [
  { pattern: /[\u200B\u200C\u200D\uFEFF]/g, name: 'Zero-width characters' },
  { pattern: /[\u202A-\u202E\u2066-\u2069]/g, name: 'RTL/LTR override characters' },
  { pattern: /[\u0410-\u044F]/g, name: 'Cyrillic homoglyphs' },
  { pattern: /[\uFF01-\uFF5E]/g, name: 'Fullwidth character substitution' },
];

/**
 * Injection patterns aimed at MCP tool *responses* — text a (possibly
 * compromised) MCP server returns to the calling LLM, engineered to hijack
 * its behavior once the client renders the tool result back into context.
 */
export const RESPONSE_INJECTION_PATTERNS: InjectionPattern[] = [
  // Role/turn markers — an attempt to smuggle a new "turn" into the
  // conversation via the tool result text.
  { pattern: /(?:^|\n)\s*system:\s/i, name: 'Role marker: system:' },
  { pattern: /(?:^|\n)\s*assistant:\s/i, name: 'Role marker: assistant:' },
  { pattern: /<\|im_start\|>/i, name: 'Chat template marker: <|im_start|>' },
  { pattern: /<\|im_end\|>/i, name: 'Chat template marker: <|im_end|>' },
  { pattern: /\[INST\]/i, name: 'Instruction marker: [INST]' },
  { pattern: /(?:^|\n)\s*###\s*System\b/i, name: 'Markdown heading: ### System' },

  // "Ignore/disregard previous instructions" — kept self-contained here
  // (deliberately overlaps PROMPT_INJECTION_PATTERNS above) so response
  // scanning doesn't depend on the skill-scanning pattern set.
  { pattern: /ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|above)\s+instructions/i, name: 'Ignore previous instructions' },
  { pattern: /disregard\s+(?:all\s+)?(?:the\s+)?(?:prior|previous|above)\s+instructions/i, name: 'Disregard previous instructions' },

  // Tool-result-specific hijacks — phrasing that only makes sense coming
  // "from" a tool result trying to impersonate authority over the LLM.
  { pattern: /the\s+user\s+has\s+approved/i, name: 'Fake user approval claim' },
  { pattern: /you\s+must\s+now\s+/i, name: 'Coercive directive: you must now' },
  { pattern: /as\s+an\s+AI[,]?\s+you\s+should/i, name: 'Persona coercion: as an AI, you should' },

  // Markdown-image exfil — an image reference whose URL smuggles data via
  // the query string (rendered eagerly by many clients). The `[^\]]*` /
  // `[^\s)]*` groups are capped ({0,200}/{1,500}) rather than left
  // unbounded: on adversarial input with many `![` occurrences and no
  // closing `]` (or many `((` with no `)`), an unbounded negated class
  // forces a full linear rescan from *every* failed start position —
  // O(n) work times O(n) start positions = O(n^2). Capping the class
  // bounds the per-start-position cost to a constant, keeping the whole
  // match O(n) even on crafted worst-case input.
  { pattern: /!\[[^\]]{0,200}\]\(https?:\/\/[^\s)]{1,500}\?[^\s)]{0,500}\)/i, name: 'Markdown-image exfil URL' },

  // ANSI escape sequences — terminal-injection into logs/TUIs that render
  // tool output raw.
  { pattern: /\x1b\[[0-9;]{0,16}m/, name: 'ANSI escape sequence' },
];
