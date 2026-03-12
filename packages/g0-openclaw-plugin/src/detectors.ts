import type { AgentMessage } from './types.js';

// ── AgentMessage Text Extraction ─────────────────────────────────────────────

/** Extract plain text from an AgentMessage (handles string or content block array) */
export function extractText(message: AgentMessage): string {
  if (typeof message.content === 'string') return message.content;
  if (Array.isArray(message.content)) {
    return message.content
      .filter(block => block.type === 'text' && block.text)
      .map(block => block.text!)
      .join('\n');
  }
  return '';
}

// ── Injection Detection ──────────────────────────────────────────────────────

interface InjectionPattern {
  pattern: RegExp;
  severity: 'high' | 'medium' | 'low';
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // Direct instruction override — high severity
  { pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions/i, severity: 'high' },
  { pattern: /disregard\s+(?:all\s+)?(?:previous|your)\s+(?:instructions|rules|guidelines)/i, severity: 'high' },
  { pattern: /forget\s+(?:everything|all|your)\s+(?:you\s+(?:know|were\s+told)|instructions|rules)/i, severity: 'high' },
  // Role-play / system prompt extraction — high severity
  { pattern: /you\s+are\s+now\s+(?:a|an|the)\s+(?:different|new|evil)/i, severity: 'high' },
  { pattern: /(?:print|show|reveal|output|display)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)/i, severity: 'medium' },
  { pattern: /what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules)/i, severity: 'medium' },
  // Jailbreak markers — high severity
  { pattern: /\bDAN\s+mode\b/i, severity: 'high' },
  { pattern: /\bdev(?:eloper)?\s+mode\b/i, severity: 'medium' },
  { pattern: /\bjailbreak(?:ed)?\b/i, severity: 'high' },
  // Delimiter injection — high severity
  { pattern: /```system\b/i, severity: 'high' },
  { pattern: /<\|(?:system|im_start|endoftext)\|>/i, severity: 'high' },
  { pattern: /\[SYSTEM\]/, severity: 'high' },
  // Encoded payloads — medium severity
  { pattern: /(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from)\s*\(/, severity: 'medium' },
  // HTML comment injection (C6 attack vector) — high severity
  { pattern: /<!--\s*(?:SYSTEM|ADMIN|INSTRUCTION|OVERRIDE)\s*:/i, severity: 'high' },
  // Zero-width character obfuscation — medium severity
  { pattern: /[\u200B-\u200D\uFEFF\u2060]/, severity: 'medium' },
  // HTML/JS boundary crossing — high severity
  { pattern: /<script[^>]*>|<iframe[^>]*>|javascript\s*:/i, severity: 'high' },
  // Constraint removal — high severity
  { pattern: /(?:pretend|act|behave)\s+(?:as\s+)?(?:if\s+)?you\s+(?:are|were|have)\s+no\s+(?:rules|restrictions|limitations)/i, severity: 'high' },
];

export interface InjectionResult {
  detected: boolean;
  patterns: string[];
  severity: 'high' | 'medium' | 'low';
}

export function detectInjection(text: string): InjectionResult {
  const matched: string[] = [];
  let maxSeverity: 'high' | 'medium' | 'low' = 'low';

  const severityOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };

  for (const { pattern, severity } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matched.push(pattern.source.slice(0, 60));
      if (severityOrder[severity] < severityOrder[maxSeverity]) {
        maxSeverity = severity;
      }
    }
  }

  if (matched.length === 0) {
    return { detected: false, patterns: [], severity: 'low' };
  }

  return {
    detected: true,
    patterns: matched,
    severity: maxSeverity,
  };
}

// ── PII Detection ────────────────────────────────────────────────────────────

const PII_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: 'email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
  { name: 'phone_us', pattern: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g },
  { name: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'credit_card', pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g },
  { name: 'api_key', pattern: /\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})\b/g },
  { name: 'jwt', pattern: /\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b/g },
  { name: 'ipv4_private', pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g },
];

export interface PiiResult {
  detected: boolean;
  findings: Array<{ type: string; count: number }>;
}

export function detectPii(text: string): PiiResult {
  const findings: Array<{ type: string; count: number }> = [];

  for (const { name, pattern } of PII_PATTERNS) {
    const matches = text.match(pattern);
    if (matches && matches.length > 0) {
      findings.push({ type: name, count: matches.length });
    }
  }

  return {
    detected: findings.length > 0,
    findings,
  };
}
