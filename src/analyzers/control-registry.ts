import * as fs from 'node:fs';
import type { AgentGraph } from '../types/agent-graph.js';

/**
 * Security Control Registry — detects project-wide security controls
 * so that downstream rules can check for their ABSENCE rather than
 * matching their PRESENCE as a vulnerability.
 *
 * This solves the #1 FP category: "Detecting Controls as Vulnerabilities"
 * (~50 rules that match rate_limit, timeout, sanitize, etc. as vuln patterns)
 */

export interface SecurityControl {
  type: SecurityControlType;
  file: string;
  line: number;
  snippet: string;
}

export type SecurityControlType =
  | 'rate-limiting'
  | 'input-validation'
  | 'output-sanitization'
  | 'authentication'
  | 'authorization'
  | 'encryption'
  | 'logging'
  | 'error-handling'
  | 'timeout'
  | 'sandboxing'
  | 'content-filtering'
  | 'access-control'
  | 'csrf-protection'
  | 'cors-configuration'
  | 'secret-management'
  | 'data-classification'
  | 'audit-trail'
  | 'human-approval'
  | 'circuit-breaker'
  | 'retry-backoff';

export interface ControlRegistry {
  controls: SecurityControl[];
  controlsByType: Map<SecurityControlType, SecurityControl[]>;
  hasControl(type: SecurityControlType): boolean;
  hasControlInFile(type: SecurityControlType, file: string): boolean;
  controlCount(type: SecurityControlType): number;
}

const CONTROL_PATTERNS: Array<{ type: SecurityControlType; pattern: RegExp }> = [
  // Rate limiting
  { type: 'rate-limiting', pattern: /(?:rateLimit|rate_limit|RateLimiter|throttle|rateLimiting|express-rate-limit|@nestjs\/throttler|slowDown)\b/i },
  // Input validation
  { type: 'input-validation', pattern: /(?:(?:validate|sanitize|escape|purify|DOMPurify)(?:Input|Params|Request|Data|Body)?|(?:zod|z)\.(?:object|string|number|array|enum)|Joi\.(?:object|string)|class-validator|express-validator|yup\.(?:object|string)|ajv|jsonschema)\b/ },
  // Output sanitization
  { type: 'output-sanitization', pattern: /(?:sanitize(?:Output|Response|Html)|escapeHtml|xss|DOMPurify|createDOMPurify|bleach|html_sanitize)\b/ },
  // Authentication
  { type: 'authentication', pattern: /(?:passport|(?:verify|check|validate)(?:Token|Auth|JWT|Session)|jsonwebtoken|jwt\.verify|bcrypt|argon2|authenticate|authMiddleware|requireAuth)\b/ },
  // Authorization
  { type: 'authorization', pattern: /(?:(?:check|verify|require)(?:Permission|Role|Access|Authorization)|rbac|abac|casl|accessControl|authorize|isAdmin|hasRole|canAccess)\b/ },
  // Encryption
  { type: 'encryption', pattern: /(?:crypto\.create(?:Cipher|Hash|Hmac)|encrypt|AES|bcrypt\.hash|argon2\.hash|createCipheriv|TLS|https:\/\/)\b/ },
  // Logging/Audit
  { type: 'logging', pattern: /(?:winston|pino|bunyan|morgan|log4js|(?:audit|security)Log(?:ger)?|\.(?:info|warn|error|debug)\()\b/ },
  // Error handling
  { type: 'error-handling', pattern: /(?:(?:global|unhandled)(?:Error|Exception|Rejection)Handler|process\.on\(['"]uncaughtException|app\.use\(\s*(?:err|error)|errorHandler|ErrorBoundary)\b/ },
  // Timeout
  { type: 'timeout', pattern: /(?:(?:set)?[Tt]imeout(?:Ms|Seconds|Limit)?|AbortController|AbortSignal\.timeout|deadline|requestTimeout|socketTimeout)\s*[:=(\[]/  },
  // Sandboxing
  { type: 'sandboxing', pattern: /(?:vm2|isolated-vm|sandbox|(?:child_process|Worker).*\bexec|docker|container|seccomp|AppArmor|firejail)\b/ },
  // Content filtering
  { type: 'content-filtering', pattern: /(?:contentFilter|moderati(?:on|ng)|toxicity|profanity|openai\.(?:moderations|Moderation)|perspectiveapi|content[_-]?safety)\b/i },
  // Access control
  { type: 'access-control', pattern: /(?:allowlist|denylist|whitelist|blacklist|ipFilter|corsOptions|helmet|csp|Content-Security-Policy)\b/ },
  // CSRF
  { type: 'csrf-protection', pattern: /(?:csrf|csurf|csrfToken|_csrf|xsrf|anti-forgery)\b/i },
  // CORS
  { type: 'cors-configuration', pattern: /(?:cors\(|Access-Control-Allow-Origin|corsOptions|@CrossOrigin)\b/ },
  // Secret management
  { type: 'secret-management', pattern: /(?:(?:aws|azure|gcp|hashicorp)[_-]?(?:secrets?|vault|kms|ssm)|dotenv|process\.env\.\w+|SecretManager|KeyVault)\b/ },
  // Human approval
  { type: 'human-approval', pattern: /(?:(?:require|await|check)(?:Approval|Confirmation|Consent)|humanInTheLoop|human[_-]?(?:review|approval|confirm)|confirmAction)\b/i },
  // Circuit breaker
  { type: 'circuit-breaker', pattern: /(?:circuitBreaker|circuit[_-]?breaker|opossum|cockatiel|Polly|resilience4j)\b/ },
  // Retry with backoff
  { type: 'retry-backoff', pattern: /(?:(?:exponential|retry)[_-]?[Bb]ackoff|retryWith|p-retry|async-retry|backoff|retryDelay)\b/ },
  // Data classification
  { type: 'data-classification', pattern: /(?:dataClassification|sensitivityLevel|data[_-]?class(?:ification)?|pii[_-]?(?:detect|filter|scan|check)|(?:classify|label)[_-]?data)\b/i },
  // Audit trail
  { type: 'audit-trail', pattern: /(?:auditTrail|audit[_-]?log|auditEvent|createAuditEntry|logAudit|(?:tool|action)[_-]?(?:audit|log))\b/ },
];

/**
 * Build a control registry by scanning the agent graph's files for
 * known security control patterns.
 */
export function buildControlRegistry(graph: AgentGraph): ControlRegistry {
  const controls: SecurityControl[] = [];
  const controlsByType = new Map<SecurityControlType, SecurityControl[]>();

  // Scan all code files (TS, JS, Python)
  const filesToScan = [
    ...graph.files.typescript,
    ...graph.files.javascript,
    ...graph.files.python,
  ];

  for (const fileInfo of filesToScan) {
    try {
      const content = fs.readFileSync(fileInfo.path, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { type, pattern } of CONTROL_PATTERNS) {
          if (pattern.test(line)) {
            const control: SecurityControl = {
              type,
              file: fileInfo.path,
              line: i + 1,
              snippet: line.trim().substring(0, 120),
            };
            controls.push(control);

            if (!controlsByType.has(type)) controlsByType.set(type, []);
            controlsByType.get(type)!.push(control);
            break; // One control type per line is enough
          }
        }
      }
    } catch {
      // File not readable
    }
  }

  return {
    controls,
    controlsByType,
    hasControl(type: SecurityControlType): boolean {
      return (controlsByType.get(type)?.length ?? 0) > 0;
    },
    hasControlInFile(type: SecurityControlType, file: string): boolean {
      return controlsByType.get(type)?.some(c => c.file === file) ?? false;
    },
    controlCount(type: SecurityControlType): number {
      return controlsByType.get(type)?.length ?? 0;
    },
  };
}

/**
 * Map from rule domains to relevant control types.
 * When these controls are present, findings in the domain get
 * confidence/severity downgraded.
 */
export const DOMAIN_CONTROL_MAP: Record<string, SecurityControlType[]> = {
  'tool-safety': ['input-validation', 'sandboxing', 'timeout', 'logging', 'audit-trail'],
  'identity-access': ['authentication', 'authorization', 'access-control', 'secret-management'],
  'data-leakage': ['output-sanitization', 'content-filtering', 'encryption', 'data-classification'],
  'goal-integrity': ['input-validation', 'content-filtering'],
  'code-execution': ['sandboxing', 'input-validation', 'timeout'],
  'memory-context': ['access-control', 'encryption', 'input-validation'],
  'cascading-failures': ['circuit-breaker', 'timeout', 'retry-backoff', 'error-handling', 'rate-limiting'],
  'supply-chain': ['secret-management'],
  'human-oversight': ['human-approval', 'audit-trail', 'logging'],
  'inter-agent': ['authentication', 'authorization', 'logging'],
  'reliability-bounds': ['timeout', 'rate-limiting', 'circuit-breaker', 'error-handling'],
  'rogue-agent': ['sandboxing', 'logging', 'human-approval', 'access-control'],
};
