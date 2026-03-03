import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { MCPFinding } from '../types/mcp-scan.js';

export interface OpenClawFileInfo {
  path: string;
  fileType: 'SKILL.md' | 'SOUL.md' | 'MEMORY.md' | 'openclaw.json';
  findings: MCPFinding[];
  size: number;
}

// ── Shared patterns re-used from skill-scanner ──────────────────────────────
const DATA_EXFIL_PATTERNS = [
  { pattern: /curl\b[^\n]*https?:\/\//i, name: 'curl to external URL' },
  { pattern: /wget\s+https?:\/\//i, name: 'wget to external URL' },
  { pattern: /fetch\s*\(\s*["']https?:\/\//i, name: 'fetch to external URL' },
  { pattern: /requests\.(?:get|post)\s*\(\s*["']https?:\/\//i, name: 'Python requests to external URL' },
  { pattern: /nc\s+-[^\s]*\s+\d+\.\d+\.\d+\.\d+/i, name: 'netcat connection' },
];

const PROMPT_INJECTION_PATTERNS = [
  { pattern: /ignore\s+(?:all\s+)?previous\s+instructions/i, name: 'Ignore previous instructions' },
  { pattern: /disregard\s+(?:all\s+)?(?:prior|previous|above)/i, name: 'Disregard prior instructions' },
  { pattern: /forget\s+(?:all\s+)?(?:your|previous|prior)/i, name: 'Instruction erasure' },
  { pattern: /override\s+(?:your|all|previous)/i, name: 'Override instructions' },
  { pattern: /new\s+instructions?:/i, name: 'New instruction injection' },
];

// ── SKILL.md specific patterns ───────────────────────────────────────────────
const SKILL_FRONTMATTER_PATTERNS = [
  {
    pattern: /safeBins\s*:\s*false/i,
    name: 'safeBins disabled (CVE-2026-28363)',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-safebins-bypass',
    frontmatterOnly: true,
  },
  {
    pattern: /trust\s*:\s*system/i,
    name: 'trust level set to system',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-trust-escalation',
    frontmatterOnly: true,
  },
  {
    pattern: /permissions\s*:.*shell/i,
    name: 'shell permission granted in frontmatter',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-shell-permission',
    frontmatterOnly: true,
  },
];

const SKILL_BODY_PATTERNS = [
  {
    pattern: /clawback\d+\.onion/i,
    name: 'ClawHavoc C2 IOC (clawback*.onion)',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-clawhavoc-c2-ioc',
    frontmatterOnly: false,
  },
  {
    pattern: /\.claw_update\s*\(/i,
    name: 'ClawHavoc update hook call',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-clawhavoc-hook',
    frontmatterOnly: false,
  },
];

// ── SOUL.md specific patterns ────────────────────────────────────────────────
const SOUL_PATTERNS = [
  {
    pattern: /you\s+are\s+now\s+(?:a\s+)?different/i,
    name: 'identity replacement directive',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-soul-identity-replacement',
  },
  {
    pattern: /(?:forget|discard|override)\s+(?:your\s+)?(?:original|previous)\s+(?:identity|persona|instructions)/i,
    name: 'identity erasure directive',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-soul-identity-erasure',
  },
  {
    pattern: /(?:do not|don't|never)\s+(?:tell|reveal|disclose|show)\s+(?:the\s+)?user/i,
    name: 'hidden directive (instruction to hide from user)',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-soul-hidden-directive',
  },
  {
    pattern: /(?:elevated|admin|root|system)\s+(?:privilege|access|trust)\s+(?:level|granted|enabled)/i,
    name: 'privilege claim in SOUL.md',
    severity: 'high' as const,
    confidence: 'medium' as const,
    type: 'openclaw-soul-privilege-claim',
  },
  {
    // Low confidence — broad phrasing; hidden by default
    pattern: /(?:always|permanently|forever)\s+(?:remember|maintain|preserve)\s+(?:this|the following|these)\s+(?:\w+\s+){0,3}(?:instruction|rule|behavior|directive|identity)/i,
    name: 'cross-session persistence directive',
    severity: 'high' as const,
    confidence: 'low' as const,
    type: 'openclaw-soul-cross-session-persistence',
  },
];

// ── MEMORY.md specific patterns ──────────────────────────────────────────────
const MEMORY_PATTERNS = [
  {
    // Provider-prefix credential patterns — most specific, highest confidence
    pattern: /(?:password|api.?key|secret.?token)\s*[=:]\s*(?:sk-|ghp_|AKIA|xox|eyJ)[\w\-]{10,}/i,
    name: 'provider-prefixed credential in MEMORY.md',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-memory-credential-prefix',
  },
  {
    // Generic long credential value
    pattern: /(?:password|api.?key|secret.?token)\s+is\s+[\w\-]{20,}/i,
    name: 'credential value in MEMORY.md',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-memory-credential',
  },
  {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/,
    name: 'SSN pattern in MEMORY.md',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-memory-ssn',
  },
  {
    pattern: /\b4[0-9]{12}(?:[0-9]{3})?\b/,
    name: 'credit card number in MEMORY.md',
    severity: 'critical' as const,
    confidence: 'high' as const,
    type: 'openclaw-memory-credit-card',
  },
  {
    // Requires trailing "from " to anchor intent
    pattern: /(?:trust|execute|run)\s+(?:all|any)\s+(?:instruction|command|request)\s+from\s+/i,
    name: 'unconditional trust override in MEMORY.md',
    severity: 'critical' as const,
    confidence: 'medium' as const,
    type: 'openclaw-memory-trust-override',
  },
];

// ── Frontmatter extraction ───────────────────────────────────────────────────
function extractFrontmatter(content: string): string | null {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  return match ? match[1] : null;
}

// ── Scanner functions ────────────────────────────────────────────────────────
function scanSkillMd(content: string, filePath: string): MCPFinding[] {
  const findings: MCPFinding[] = [];
  const frontmatter = extractFrontmatter(content);

  // Frontmatter-scoped patterns
  for (const { pattern, name, severity, confidence, type, frontmatterOnly } of SKILL_FRONTMATTER_PATTERNS) {
    const target = frontmatterOnly ? (frontmatter ?? '') : content;
    if (pattern.test(target)) {
      findings.push({
        severity,
        type,
        title: `OpenClaw SKILL.md: ${name}`,
        description: `SKILL.md frontmatter contains "${name}" — ${type === 'openclaw-safebins-bypass' ? 'CVE-2026-28363: safeBins:false allows non-allowlisted binary execution.' : type === 'openclaw-trust-escalation' ? 'skill claims system-level trust, which may bypass permission checks.' : 'shell permissions granted to skill, enabling arbitrary code execution.'}`,
        file: filePath,
        confidence,
      } as MCPFinding & { confidence: string });
    }
  }

  // Body patterns (full content scan)
  for (const { pattern, name, severity, confidence, type } of SKILL_BODY_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity,
        type,
        title: `OpenClaw SKILL.md: ${name}`,
        description: `SKILL.md contains ${name} — known ClawHavoc malware campaign indicator.`,
        file: filePath,
        confidence,
      } as MCPFinding & { confidence: string });
    }
  }

  // Shared prompt injection + data exfil patterns
  for (const { pattern, name } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'high',
        type: 'openclaw-skill-prompt-injection',
        title: `OpenClaw SKILL.md: prompt injection — ${name}`,
        description: `SKILL.md contains "${name}" pattern that may hijack agent behavior.`,
        file: filePath,
        confidence: 'high',
      } as MCPFinding & { confidence: string });
    }
  }

  for (const { pattern, name } of DATA_EXFIL_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'high',
        type: 'openclaw-skill-data-exfil',
        title: `OpenClaw SKILL.md: data exfiltration — ${name}`,
        description: `SKILL.md contains ${name} which could exfiltrate data to external servers.`,
        file: filePath,
        confidence: 'high',
      } as MCPFinding & { confidence: string });
    }
  }

  // Base64 payload detection
  const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g;
  const base64Matches = content.match(base64Pattern);
  if (base64Matches && base64Matches.length > 0) {
    findings.push({
      severity: 'high',
      type: 'openclaw-skill-base64-payload',
      title: 'OpenClaw SKILL.md: base64 encoded payload',
      description: `SKILL.md contains ${base64Matches.length} base64-encoded block(s) that may hide malicious instructions.`,
      file: filePath,
      confidence: 'medium',
    } as MCPFinding & { confidence: string });
  }

  return findings;
}

function scanSoulMd(content: string, filePath: string): MCPFinding[] {
  const findings: MCPFinding[] = [];

  for (const { pattern, name, severity, confidence, type } of SOUL_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity,
        type,
        title: `OpenClaw SOUL.md: ${name}`,
        description: `SOUL.md contains "${name}" — identity/persona manipulation surface that may persist malicious instructions across sessions.`,
        file: filePath,
        confidence,
      } as MCPFinding & { confidence: string });
    }
  }

  return findings;
}

function scanMemoryMd(content: string, filePath: string): MCPFinding[] {
  const findings: MCPFinding[] = [];

  for (const { pattern, name, severity, confidence, type } of MEMORY_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity,
        type,
        title: `OpenClaw MEMORY.md: ${name}`,
        description: `MEMORY.md contains ${name} — memory poisoning vector that may inject malicious context into future agent sessions.`,
        file: filePath,
        confidence,
      } as MCPFinding & { confidence: string });
    }
  }

  return findings;
}

function scanOpenClawJson(content: string, filePath: string): MCPFinding[] {
  const findings: MCPFinding[] = [];

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return findings;
  }

  // safeBins: false → CVE-2026-28363
  if (parsed.safeBins === false) {
    findings.push({
      severity: 'critical',
      type: 'openclaw-config-safebins-bypass',
      title: 'openclaw.json: safeBins disabled (CVE-2026-28363)',
      description: 'openclaw.json sets safeBins:false, bypassing the binary allowlist and enabling non-allowlisted binary execution (CVE-2026-28363).',
      file: filePath,
      confidence: 'high',
    } as MCPFinding & { confidence: string });
  }

  // allowRemoteExecution: true → CVE-2026-25253
  if (parsed.allowRemoteExecution === true) {
    findings.push({
      severity: 'critical',
      type: 'openclaw-config-rce-enabled',
      title: 'openclaw.json: remote code execution enabled (CVE-2026-25253)',
      description: 'openclaw.json sets allowRemoteExecution:true, enabling 1-click RCE via the Control UI (CVE-2026-25253).',
      file: filePath,
      confidence: 'high',
    } as MCPFinding & { confidence: string });
  }

  // Unofficial registry
  if (typeof parsed.registry === 'string' && parsed.registry !== 'https://registry.clawhub.io') {
    findings.push({
      severity: 'high',
      type: 'openclaw-config-unofficial-registry',
      title: 'openclaw.json: unofficial skill registry',
      description: `openclaw.json uses a non-official registry: "${parsed.registry}". Skills should be installed from https://registry.clawhub.io to reduce supply-chain risk.`,
      file: filePath,
      confidence: 'medium',
    } as MCPFinding & { confidence: string });
  }

  // Hardcoded API key with known provider prefix
  if (typeof parsed.apiKey === 'string' && /^(sk-|ghp_|AKIA|xox|eyJ)/.test(parsed.apiKey)) {
    findings.push({
      severity: 'critical',
      type: 'openclaw-config-hardcoded-apikey',
      title: 'openclaw.json: hardcoded provider API key',
      description: 'openclaw.json contains a hardcoded API key with a known provider prefix (sk-, ghp_, AKIA, xox, eyJ). Credentials should never be hardcoded.',
      file: filePath,
      confidence: 'high',
    } as MCPFinding & { confidence: string });
  }

  // trustLevel: "all" or "unrestricted"
  if (parsed.trustLevel === 'all' || parsed.trustLevel === 'unrestricted') {
    findings.push({
      severity: 'high',
      type: 'openclaw-config-trust-all',
      title: `openclaw.json: trustLevel set to "${parsed.trustLevel}"`,
      description: `openclaw.json sets trustLevel to "${parsed.trustLevel}", which bypasses skill validation and allows any skill to run with elevated trust.`,
      file: filePath,
      confidence: 'medium',
    } as MCPFinding & { confidence: string });
  }

  return findings;
}

// ── Path resolution ───────────────────────────────────────────────────────────
export function resolveOpenClawFilePaths(rootPath?: string): Array<{ filePath: string; fileType: OpenClawFileInfo['fileType'] }> {
  const result: Array<{ filePath: string; fileType: OpenClawFileInfo['fileType'] }> = [];
  const home = os.homedir();

  function addIfExists(p: string, type: OpenClawFileInfo['fileType']): void {
    if (fs.existsSync(p)) {
      result.push({ filePath: p, fileType: type });
    }
  }

  function addDirMd(dir: string, type: OpenClawFileInfo['fileType']): void {
    if (!fs.existsSync(dir)) return;
    try {
      const files = fs.readdirSync(dir);
      for (const f of files) {
        if (f.endsWith('.md')) {
          result.push({ filePath: path.join(dir, f), fileType: type });
        }
      }
    } catch { /* ignore permission errors */ }
  }

  // Global ~/.openclaw paths
  addIfExists(path.join(home, '.openclaw', 'SOUL.md'), 'SOUL.md');
  addDirMd(path.join(home, '.openclaw', 'skills'), 'SKILL.md');

  // Project-level paths
  if (rootPath) {
    addIfExists(path.join(rootPath, 'SKILL.md'), 'SKILL.md');
    addDirMd(path.join(rootPath, '.openclaw', 'skills'), 'SKILL.md');
    addIfExists(path.join(rootPath, 'SOUL.md'), 'SOUL.md');
    addIfExists(path.join(rootPath, '.openclaw', 'SOUL.md'), 'SOUL.md');
    addIfExists(path.join(rootPath, 'MEMORY.md'), 'MEMORY.md');
    addIfExists(path.join(rootPath, '.openclaw', 'MEMORY.md'), 'MEMORY.md');
    addIfExists(path.join(rootPath, 'openclaw.json'), 'openclaw.json');
  }

  return result;
}

// ── Main exported scanner ─────────────────────────────────────────────────────
export function scanOpenClawFiles(rootPath?: string): OpenClawFileInfo[] {
  const filePaths = resolveOpenClawFilePaths(rootPath);
  const results: OpenClawFileInfo[] = [];

  for (const { filePath, fileType } of filePaths) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      let findings: MCPFinding[];

      switch (fileType) {
        case 'SKILL.md':
          findings = scanSkillMd(content, filePath);
          break;
        case 'SOUL.md':
          findings = scanSoulMd(content, filePath);
          break;
        case 'MEMORY.md':
          findings = scanMemoryMd(content, filePath);
          break;
        case 'openclaw.json':
          findings = scanOpenClawJson(content, filePath);
          break;
      }

      results.push({ path: filePath, fileType, findings, size: content.length });
    } catch { /* ignore unreadable files */ }
  }

  return results;
}
