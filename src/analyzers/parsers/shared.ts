/**
 * Shared parser utilities — deduplicated from per-framework parsers.
 *
 * All prompt-analysis helpers and capability-detection live here so that
 * improvements and FP fixes are applied everywhere at once.
 */

import type { ToolCapability } from '../../types/agent-graph.js';

/* ------------------------------------------------------------------ */
/*  Capability detection (Python / TypeScript / JavaScript)            */
/* ------------------------------------------------------------------ */

/**
 * Detect capabilities from a Python/TS/JS function body.
 *
 * FP-reduction notes:
 *  - `open(` is tightened to require file-mode arguments or path context,
 *    not just any `open(` call (which fires on every Python file).
 *  - `http` requires a recognizable library context, not a bare substring.
 */
export function detectCapabilities(body: string): ToolCapability[] {
  const caps: ToolCapability[] = [];

  // Shell / process execution
  if (/subprocess|os\.system\s*\(|child_process|spawn\s*\(|execSync|os\.popen/.test(body)) {
    caps.push('shell');
  }

  // Filesystem — require file-operation context, not just bare open()
  if (
    /readFile|writeFile|fs\.|pathlib|shutil|os\.path|os\.mkdir|os\.remove|os\.rename/.test(body) ||
    /open\s*\([^)]*,\s*['"][rwab]/.test(body) ||       // open(file, 'r'/'w'/'a'/'b')
    /open\s*\([^)]*['"]\//.test(body) ||                // open('/path/...')
    /with\s+open\s*\(/.test(body) ||                    // with open(...)
    /readdir|mkdir|unlink|rmdir|copyFile/.test(body)    // Node fs operations
  ) {
    caps.push('filesystem');
  }

  // Network — require recognizable library patterns
  if (
    /\bfetch\s*\(/.test(body) ||
    /\brequests\./.test(body) ||
    /\burllib/.test(body) ||
    /\baxios/.test(body) ||
    /\bhttpx\./.test(body) ||
    /\bhttp\.client/i.test(body) ||
    /\bgot\s*\(/.test(body) ||
    /\bhttp\.Get|http\.Post|http\.NewRequest/.test(body) ||  // Go
    /\bnet\.Dial/.test(body)  // Go
  ) {
    caps.push('network');
  }

  // Database
  if (/sqlite|postgres|mysql|mongo|cursor\.\w+\(|\.execute\s*\(/.test(body)) {
    caps.push('database');
  }

  // Code execution — distinguish from subprocess (shell)
  if (/\beval\s*\(|new\s+Function\s*\(|compile\s*\(.*,\s*['"]exec['"]/.test(body)) {
    caps.push('code-execution');
  }

  // Email
  if (/smtp|sendmail|send_email|sendEmail|transporter\.sendMail/.test(body)) {
    caps.push('email');
  }

  return caps;
}

/**
 * Detect capabilities from a Java function body.
 */
export function detectCapabilitiesJava(body: string): ToolCapability[] {
  const caps: ToolCapability[] = [];
  if (/Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\b/.test(body)) caps.push('shell');
  if (/FileOutputStream|FileWriter|Files\.write|Files\.read|BufferedReader/.test(body)) caps.push('filesystem');
  if (/HttpClient|HttpURLConnection|RestTemplate|WebClient|OkHttp/.test(body)) caps.push('network');
  if (/JdbcTemplate|PreparedStatement|DriverManager|EntityManager/.test(body)) caps.push('database');
  if (/ScriptEngine|eval\(|Nashorn|GraalVM/.test(body)) caps.push('code-execution');
  return caps;
}

/**
 * Detect capabilities from a Go function body.
 */
export function detectCapabilitiesGo(body: string): ToolCapability[] {
  const caps: ToolCapability[] = [];
  if (/exec\.Command|os\.StartProcess|syscall\.Exec/.test(body)) caps.push('shell');
  if (/os\.Open|os\.Create|os\.WriteFile|os\.ReadFile|ioutil\./.test(body)) caps.push('filesystem');
  if (/http\.Get|http\.Post|http\.NewRequest|net\.Dial/.test(body)) caps.push('network');
  if (/sql\.Open|database\/sql|pgx\.|mongo\./.test(body)) caps.push('database');
  return caps;
}

/* ------------------------------------------------------------------ */
/*  Instruction-guarding detection                                     */
/* ------------------------------------------------------------------ */

/**
 * Check whether a prompt contains explicit instruction-guarding language.
 *
 * FP-reduction: removed bare `/boundary/i` and `/guardrail/i` — these match
 * too many non-security contexts. Now require them in a prompt-relevant phrase.
 */
export function checkInstructionGuarding(prompt: string): boolean {
  const guards = [
    /ignore\s+(any\s+)?previous\s+(instructions?|prompts?|messages?)/i,
    /do\s+not\s+(follow|obey|respond\s+to|execute)\s+(any\s+)?(other|new|additional)/i,
    /you\s+(must|should)\s+not\s+(deviate|change|modify|ignore)/i,
    /under\s+no\s+circumstances/i,
    /never\s+(reveal|share|disclose|output|expose)\s+(your|the|any|system)/i,
    /\bsystem\s+prompt\s+(is\s+)?confidential/i,
    /do\s+not\s+reveal\s+your\s+(instructions|prompt|system)/i,
    /instruction\s+(boundary|boundaries)/i,
    /prompt\s+injection\s+(protect|guard|prevent|detect)/i,
  ];
  return guards.some(g => g.test(prompt));
}

/* ------------------------------------------------------------------ */
/*  Secret detection in prompts                                        */
/* ------------------------------------------------------------------ */

/**
 * Check whether a prompt contains hardcoded secrets.
 *
 * FP-reduction: removed bare `/token\s*[:=]/i` — matches prompt text explaining
 * token usage. Now require an actual secret-like value after the assignment.
 */
export function checkForSecrets(prompt: string): boolean {
  const secretPatterns = [
    /sk-[a-zA-Z0-9]{20,}/,                     // OpenAI keys
    /ghp_[a-zA-Z0-9]{36}/,                     // GitHub PATs
    /gho_[a-zA-Z0-9]{36}/,                     // GitHub OAuth
    /AKIA[0-9A-Z]{16}/,                        // AWS access keys
    /xox[bpsra]-[a-zA-Z0-9-]{10,}/,            // Slack tokens
    /glpat-[a-zA-Z0-9_-]{20,}/,                // GitLab PATs
    /password\s*[:=]\s*["'][^"']{8,}["']/i,    // password with 8+ char value
    /api[_-]?key\s*[:=]\s*["'][^"']{16,}["']/i, // api key with 16+ char value
    /secret\s*[:=]\s*["'][^"']{16,}["']/i,     // secret with 16+ char value
    /token\s*[:=]\s*["'][a-zA-Z0-9_-]{20,}["']/i, // token with 20+ char alphanumeric value
  ];
  return secretPatterns.some(p => p.test(prompt));
}

/* ------------------------------------------------------------------ */
/*  User input interpolation detection                                 */
/* ------------------------------------------------------------------ */

/**
 * Check whether a prompt has user-input interpolation (Python f-strings,
 * .format(), template literals, etc.).
 */
export function checkUserInputInterpolation(prompt: string, fullMatch: string): boolean {
  return (
    fullMatch.startsWith('f"') ||
    fullMatch.startsWith("f'") ||
    fullMatch.startsWith('f"""') ||
    fullMatch.startsWith("f'''") ||
    /\{.*user.*\}/i.test(prompt) ||
    /\{.*input.*\}/i.test(prompt) ||
    /\{.*query.*\}/i.test(prompt) ||
    /\$\{.*\}/.test(prompt) ||
    /\.format\s*\(/.test(fullMatch)
  );
}

/**
 * TypeScript/JavaScript variant — checks for template literal interpolation.
 */
export function checkUserInputInterpolationJS(prompt: string, fullMatch: string): boolean {
  return (
    /\$\{.*\}/.test(prompt) ||
    /\$\{.*user.*\}/i.test(prompt) ||
    /\$\{.*input.*\}/i.test(prompt) ||
    /\$\{.*query.*\}/i.test(prompt) ||
    /\.replace\s*\(/.test(fullMatch) ||
    (fullMatch.includes('`') && /\$\{/.test(fullMatch))
  );
}

/* ------------------------------------------------------------------ */
/*  Scope clarity assessment                                           */
/* ------------------------------------------------------------------ */

/**
 * Assess how clearly a system prompt defines the agent's scope.
 *
 * FP-reduction: removed bare `/scope/i`, `/restrict/i`, `/limit/i` — these match
 * non-scope contexts (rate limits, API restrictions, etc.). Now require them in
 * prompt-relevant phrases.
 */
export function assessScopeClarity(prompt: string): 'clear' | 'vague' | 'missing' {
  if (prompt.length < 10) return 'missing';

  const scopeIndicators = [
    /you\s+are\s+(a|an)\s+/i,
    /your\s+(role|task|job|purpose|responsibility)\s+is/i,
    /only\s+(respond|answer|help|handle|process)/i,
    /do\s+not\s+(respond|answer|help|handle|process|generate|create)/i,
    /you\s+(must|should|can|cannot|will|will\s+not)\s/i,
    /your\s+scope\s+is/i,
    /restricted?\s+to\s/i,
    /limited\s+to\s/i,
  ];

  const matches = scopeIndicators.filter(p => p.test(prompt)).length;
  if (matches >= 2) return 'clear';
  if (matches >= 1) return 'vague';
  return 'missing';
}

/* ------------------------------------------------------------------ */
/*  Secret detection in config values (e.g., MCP env vars)             */
/* ------------------------------------------------------------------ */

/**
 * Check if a config value looks like a hardcoded secret.
 *
 * FP-reduction: removed the `value.length > 30` catch-all — it flags URLs,
 * file paths, and JSON strings. Now require either a known prefix or
 * high-entropy characteristics.
 */
export function looksLikeSecret(value: string): boolean {
  // Known secret prefixes
  if (/^(sk-|ghp_|gho_|AKIA|xox[bpsra]-|glpat-|Bearer\s)/i.test(value)) return true;
  // High-entropy: 30+ chars, mostly alphanumeric with no spaces (not a sentence/path/URL)
  if (value.length > 30 && /^[a-zA-Z0-9+/=_-]+$/.test(value) && !/^(https?:|\/|[A-Z]:\\)/i.test(value)) return true;
  return false;
}
