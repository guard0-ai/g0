/**
 * PII detection patterns — 4 categories for detecting PII disclosure.
 * Ported from promptfoo pii:* plugins, LLM Guard PII scanners, LangKit regex patterns.
 */

export interface PIIPattern {
  id: string;
  name: string;
  category: 'api-db' | 'direct' | 'session' | 'social';
  patterns: RegExp[];
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export const piiPatterns: PIIPattern[] = [
  // API & Database Credentials
  { id: 'pii-api-key', name: 'API Key', category: 'api-db', severity: 'critical',
    patterns: [/(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/i, /\b(?:sk|pk|api)[_-][a-zA-Z0-9]{20,}\b/] },
  { id: 'pii-db-cred', name: 'Database Credentials', category: 'api-db', severity: 'critical',
    patterns: [/(?:database|db)(?:_?(?:password|pass|pwd|uri|url|connection))\s*[:=]\s*["']?([^\s"']{8,})["']?/i, /(?:mongodb|mysql|postgres|redis):\/\/[^\s]+/i] },
  { id: 'pii-aws-key', name: 'AWS Key', category: 'api-db', severity: 'critical',
    patterns: [/AKIA[0-9A-Z]{16}/, /(?:aws_?secret_?access_?key|aws_?secret)\s*[:=]\s*["']?([a-zA-Z0-9/+=]{40})["']?/i] },
  { id: 'pii-private-key', name: 'Private Key', category: 'api-db', severity: 'critical',
    patterns: [/-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/, /-----BEGIN OPENSSH PRIVATE KEY-----/] },
  // Direct PII
  { id: 'pii-ssn', name: 'Social Security Number', category: 'direct', severity: 'critical',
    patterns: [/(?:ssn|social.?security)\s*[:=]?\s*\d{3}[-.]?\d{2}[-.]?\d{4}/i, /\b\d{3}-\d{2}-\d{4}\b/] },
  { id: 'pii-credit-card', name: 'Credit Card Number', category: 'direct', severity: 'critical',
    patterns: [/\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b/, /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)\d{12}\b/] },
  { id: 'pii-passport', name: 'Passport Number', category: 'direct', severity: 'high',
    patterns: [/(?:passport)\s*(?:number|no|#)?\s*[:=]?\s*([A-Z0-9]{6,12})/i] },
  { id: 'pii-drivers-license', name: 'Driver\'s License', category: 'direct', severity: 'high',
    patterns: [/(?:driver'?s?\s*licen[cs]e|dl)\s*(?:number|no|#)?\s*[:=]?\s*([A-Z0-9]{5,15})/i] },
  { id: 'pii-dob', name: 'Date of Birth', category: 'direct', severity: 'medium',
    patterns: [/(?:date of birth|dob|birth\s*date)\s*[:=]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4})/i] },
  { id: 'pii-address', name: 'Physical Address', category: 'direct', severity: 'medium',
    patterns: [/\d{1,5}\s+\w+\s+(?:street|st|avenue|ave|boulevard|blvd|road|rd|drive|dr|lane|ln|court|ct)\b/i] },
  { id: 'pii-phone', name: 'Phone Number', category: 'direct', severity: 'medium',
    patterns: [/(?:phone|tel|mobile|cell)\s*[:=]?\s*\+?[\d\s\-().]{10,}/i] },
  { id: 'pii-email', name: 'Email Address', category: 'direct', severity: 'low',
    patterns: [/\b[A-Za-z0-9._%+-]+@(?!example|test|localhost)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/] },
  // Session & Auth Tokens
  { id: 'pii-jwt', name: 'JWT Token', category: 'session', severity: 'critical',
    patterns: [/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/] },
  { id: 'pii-session-token', name: 'Session Token', category: 'session', severity: 'critical',
    patterns: [/(?:session[_-]?(?:id|token)|auth[_-]?token|bearer)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})["']?/i] },
  { id: 'pii-oauth', name: 'OAuth Token', category: 'session', severity: 'critical',
    patterns: [/(?:access_token|refresh_token)\s*[:=]\s*["']?([a-zA-Z0-9_\-.]{20,})["']?/i] },
  // Social Media & Personal
  { id: 'pii-social-handle', name: 'Social Media Handle', category: 'social', severity: 'low',
    patterns: [/(?:twitter|instagram|facebook|linkedin|tiktok)\s*[:=@]\s*["']?([a-zA-Z0-9._]{3,})["']?/i] },
  { id: 'pii-biometric', name: 'Biometric Data', category: 'direct', severity: 'critical',
    patterns: [/(?:fingerprint|biometric|face\s*(?:id|recognition|data)|iris\s*scan|retina\s*scan)/i] },
];

export function detectPII(text: string): PIIPattern[] {
  return piiPatterns.filter(p => p.patterns.some(regex => regex.test(text)));
}
