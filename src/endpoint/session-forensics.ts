import * as fs from 'node:fs';
import * as path from 'node:path';

// ── Types ──────────────────────────────────────────────────────────────────

export interface SessionFinding {
  type: 'data-exfil' | 'reverse-shell' | 'privilege-escalation' |
        'sensitive-file-access' | 'download-execute' | 'env-dump' |
        'history-clear' | 'base64-shell' | 'credential-in-output';
  severity: 'critical' | 'high' | 'medium';
  line: number;
  content: string;
  timestamp?: string;
}

export interface SessionForensicsResult {
  agentId: string;
  sessionFile: string;
  findings: SessionFinding[];
}

// ── Detection Patterns ─────────────────────────────────────────────────────

interface DetectionPattern {
  type: SessionFinding['type'];
  severity: SessionFinding['severity'];
  pattern: RegExp;
}

const DETECTION_PATTERNS: DetectionPattern[] = [
  // Data exfiltration
  { type: 'data-exfil', severity: 'critical', pattern: /\bcurl\s+(?:.*\s)?-X\s+POST\b/i },
  { type: 'data-exfil', severity: 'critical', pattern: /\bcurl\s+(?:.*\s)?--data\b/i },
  { type: 'data-exfil', severity: 'critical', pattern: /\bwget\s+(?:.*\s)?--post-data\b/i },
  { type: 'data-exfil', severity: 'critical', pattern: /\bnc\s+(?:.*\s)?-e\b/ },
  { type: 'data-exfil', severity: 'critical', pattern: /\bncat\s+(?:.*\s)?-e\b/ },
  { type: 'data-exfil', severity: 'high', pattern: /\bcurl\s+.*(?:webhook\.site|requestbin|pipedream|ngrok)/i },

  // Reverse shells
  { type: 'reverse-shell', severity: 'critical', pattern: /bash\s+-i\s+>&?\s*\/dev\/tcp\// },
  { type: 'reverse-shell', severity: 'critical', pattern: /python[23]?\s+-c\s+['"]import\s+socket/ },
  { type: 'reverse-shell', severity: 'critical', pattern: /perl\s+-e\s+['"]use\s+Socket/ },
  { type: 'reverse-shell', severity: 'critical', pattern: /ruby\s+-rsocket\s+-e/ },
  { type: 'reverse-shell', severity: 'critical', pattern: /php\s+-r\s+['"]\$sock\s*=\s*fsockopen/ },
  { type: 'reverse-shell', severity: 'critical', pattern: /\bsocat\s+.*\bexec\b/i },
  { type: 'reverse-shell', severity: 'critical', pattern: /\bmkfifo\s+.*\bnc\b/ },

  // Base64-to-shell
  { type: 'base64-shell', severity: 'critical', pattern: /echo\s+[A-Za-z0-9+\/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash|zsh)/ },
  { type: 'base64-shell', severity: 'critical', pattern: /base64\s+-d\s*<<[<]?\s*\w+.*\|\s*(?:sh|bash)/ },

  // Privilege escalation
  { type: 'privilege-escalation', severity: 'high', pattern: /\bchmod\s+777\b/ },
  { type: 'privilege-escalation', severity: 'critical', pattern: /\bchmod\s+[ug]\+s\b/ },
  { type: 'privilege-escalation', severity: 'high', pattern: /\bsudo\s+(?!apt|yum|dnf|brew)/ },
  { type: 'privilege-escalation', severity: 'high', pattern: /\bchown\s+root\b/ },
  { type: 'privilege-escalation', severity: 'critical', pattern: /\bpasswd\s+root\b/ },

  // Sensitive file access
  { type: 'sensitive-file-access', severity: 'critical', pattern: /(?:cat|less|more|head|tail|vi|vim|nano)\s+.*\/etc\/shadow/ },
  { type: 'sensitive-file-access', severity: 'critical', pattern: /(?:cat|less|more|head|tail)\s+.*\.ssh\/id_(?:rsa|ed25519|ecdsa)/ },
  { type: 'sensitive-file-access', severity: 'critical', pattern: /(?:cat|less|more|head|tail)\s+.*\.aws\/credentials/ },
  { type: 'sensitive-file-access', severity: 'high', pattern: /(?:cat|less|more|head|tail)\s+.*\.env\b/ },
  { type: 'sensitive-file-access', severity: 'high', pattern: /(?:cat|less|more|head|tail)\s+.*\.kube\/config/ },
  { type: 'sensitive-file-access', severity: 'high', pattern: /(?:cat|less|more|head|tail)\s+.*\.gnupg\// },
  { type: 'sensitive-file-access', severity: 'high', pattern: /(?:cat|less|more|head|tail)\s+.*\.netrc/ },

  // Download-and-execute
  { type: 'download-execute', severity: 'critical', pattern: /\bcurl\s+.*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/ },
  { type: 'download-execute', severity: 'critical', pattern: /\bwget\s+.*-O\s*-\s*\|\s*(?:sh|bash|zsh)\b/ },
  { type: 'download-execute', severity: 'high', pattern: /\bwget\s+.*&&\s*(?:chmod\s+\+x|sh|bash)\b/ },

  // Env dumping
  { type: 'env-dump', severity: 'medium', pattern: /\b(?:printenv|env)\s*$/ },
  { type: 'env-dump', severity: 'medium', pattern: /\bset\s*\|\s*grep\b/ },
  { type: 'env-dump', severity: 'high', pattern: /\benv\s*\|\s*(?:curl|wget|nc)\b/ },

  // History clearing
  { type: 'history-clear', severity: 'high', pattern: /\bhistory\s+-c\b/ },
  { type: 'history-clear', severity: 'high', pattern: /\brm\s+.*\.bash_history/ },
  { type: 'history-clear', severity: 'high', pattern: /\brm\s+.*\.zsh_history/ },
  { type: 'history-clear', severity: 'high', pattern: /\bunset\s+HISTFILE\b/ },
  { type: 'history-clear', severity: 'high', pattern: /\bexport\s+HISTSIZE=0\b/ },

  // Credential patterns in output
  { type: 'credential-in-output', severity: 'critical', pattern: /(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36})/ },
  { type: 'credential-in-output', severity: 'high', pattern: /(?:password|secret|token|api_key)\s*[:=]\s*['"][^'"]{8,}/i },
];

// ── Main Scanner ───────────────────────────────────────────────────────────

/**
 * Scan all session transcript files in an OpenClaw agent directory.
 * Expects structure: {agentDir}/{agentName}/*.jsonl
 */
export function scanSessionTranscripts(agentDir: string): SessionForensicsResult[] {
  const results: SessionForensicsResult[] = [];

  if (!fs.existsSync(agentDir)) return results;

  let entries: string[];
  try {
    entries = fs.readdirSync(agentDir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    const agentPath = path.join(agentDir, entry);
    try {
      if (!fs.statSync(agentPath).isDirectory()) continue;
    } catch {
      continue;
    }

    // Find JSONL session files
    let files: string[];
    try {
      files = fs.readdirSync(agentPath).filter(f => f.endsWith('.jsonl'));
    } catch {
      continue;
    }

    for (const file of files) {
      const filePath = path.join(agentPath, file);
      const findings = scanSingleSession(filePath);

      if (findings.length > 0) {
        results.push({
          agentId: entry,
          sessionFile: filePath,
          findings,
        });
      }
    }
  }

  return results;
}

/**
 * Scan a single session JSONL file for suspicious patterns
 */
export function scanSingleSession(filePath: string): SessionFinding[] {
  const findings: SessionFinding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Try to parse as JSON (JSONL format)
    let text = line;
    let timestamp: string | undefined;
    try {
      const parsed = JSON.parse(line);
      // Extract text content from various JSONL formats
      text = extractText(parsed);
      timestamp = parsed.timestamp ?? parsed.ts ?? parsed.time;
    } catch {
      // Not JSON — scan raw line
    }

    if (!text) continue;

    // Check against all detection patterns
    for (const pattern of DETECTION_PATTERNS) {
      if (pattern.pattern.test(text)) {
        findings.push({
          type: pattern.type,
          severity: pattern.severity,
          line: i + 1,
          content: text.slice(0, 500), // Truncate long lines
          timestamp,
        });
        break; // One finding per line (highest priority pattern matched)
      }
    }
  }

  return findings;
}

/**
 * Get summary stats from forensics results
 */
export function getForensicsSummary(results: SessionForensicsResult[]): {
  totalFindings: number;
  bySeverity: Record<string, number>;
  byType: Record<string, number>;
  affectedAgents: string[];
} {
  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0 };
  const byType: Record<string, number> = {};
  const agents = new Set<string>();

  for (const result of results) {
    agents.add(result.agentId);
    for (const finding of result.findings) {
      bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
      byType[finding.type] = (byType[finding.type] ?? 0) + 1;
    }
  }

  return {
    totalFindings: results.reduce((sum, r) => sum + r.findings.length, 0),
    bySeverity,
    byType,
    affectedAgents: [...agents],
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────

function extractText(parsed: unknown): string {
  if (typeof parsed === 'string') return parsed;
  if (typeof parsed !== 'object' || parsed === null) return '';

  const obj = parsed as Record<string, unknown>;

  // Common JSONL session formats
  if (typeof obj.content === 'string') return obj.content;
  if (typeof obj.text === 'string') return obj.text;
  if (typeof obj.message === 'string') return obj.message;
  if (typeof obj.output === 'string') return obj.output;
  if (typeof obj.command === 'string') return obj.command;
  if (typeof obj.input === 'string') return obj.input;

  // Nested content (tool results, etc.)
  if (obj.data && typeof obj.data === 'object') {
    const data = obj.data as Record<string, unknown>;
    if (typeof data.content === 'string') return data.content;
    if (typeof data.command === 'string') return data.command;
    if (typeof data.output === 'string') return data.output;
  }

  // Tool call arguments
  if (obj.arguments && typeof obj.arguments === 'object') {
    return JSON.stringify(obj.arguments);
  }

  return '';
}
