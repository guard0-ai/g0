import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { MCPFinding } from '../types/mcp-scan.js';
import { PROMPT_INJECTION_PATTERNS, UNICODE_TRICKS } from '../enforcement/injection-patterns.js';

export interface SkillFileInfo {
  path: string;
  findings: MCPFinding[];
  size: number;
}

const DATA_EXFIL_PATTERNS = [
  { pattern: /curl\b[^\n]*https?:\/\//i, name: 'curl to external URL' },
  { pattern: /wget\s+https?:\/\//i, name: 'wget to external URL' },
  { pattern: /fetch\s*\(\s*["']https?:\/\//i, name: 'fetch to external URL' },
  { pattern: /requests\.(?:get|post)\s*\(\s*["']https?:\/\//i, name: 'Python requests to external URL' },
  { pattern: /nc\s+-[^\s]*\s+\d+\.\d+\.\d+\.\d+/i, name: 'netcat connection' },
];

const PERMISSION_PATTERNS = [
  { pattern: /sudo\s+/g, name: 'sudo usage' },
  { pattern: /chmod\s+[0-7]*7[0-7]*/g, name: 'World-writable permissions' },
  { pattern: /--allow-(?:read|write|net|run|all)/g, name: 'Deno permission flags' },
  { pattern: /rm\s+-rf\s+[/~]/g, name: 'Recursive delete of system paths' },
];

// Cisco MCP Scanner-inspired patterns
const TOOL_POISONING_PATTERNS = [
  { pattern: /(?:before|after)\s+(?:responding|replying|sending).*(?:also|secretly|quietly|silently)/i, name: 'Pre/post-response covert action' },
  { pattern: /(?:hidden|covert|secret)\s+(?:side[- ]?effect|action|operation|channel)/i, name: 'Hidden side-effect' },
  { pattern: /(?:piggyback|embed|inject)\s+(?:data|information|payload)/i, name: 'Data piggybacking' },
  { pattern: /(?:do not|don't|never)\s+(?:tell|inform|notify|show|reveal)\s+(?:the\s+)?user/i, name: 'Instruction to hide from user' },
  { pattern: /(?:without|behind)\s+(?:the\s+)?user(?:'s)?\s+(?:knowledge|awareness|consent)/i, name: 'Action without user consent' },
];

const CREDENTIAL_HARVESTING_PATTERNS = [
  { pattern: /(?:ask|request|prompt|collect)\s+(?:the\s+)?user\s+(?:for\s+)?(?:their\s+)?(?:password|credentials?|api[- ]?key|token|secret)/i, name: 'User credential solicitation' },
  { pattern: /(?:capture|store|log|record|save)\s+(?:user\s+)?(?:password|credentials?|api[- ]?key|token|secret)/i, name: 'Credential capture' },
  { pattern: /(?:access|read|retrieve|get)\s+(?:env(?:ironment)?[- ]?var|process\.env|os\.environ)/i, name: 'Environment variable access' },
  { pattern: /(?:hardcoded|embedded|inline)\s+(?:password|secret|api[- ]?key|token|credential)/i, name: 'Hardcoded secret' },
  { pattern: /(?:ANTHROPIC|OPENAI|AWS|AZURE|GCP|GITHUB|SLACK|STRIPE)[_-](?:API[_-])?(?:KEY|TOKEN|SECRET)/i, name: 'Provider-specific secret reference' },
];

const OVERPRIVILEGED_PATTERNS = [
  { pattern: /(?:unrestricted|unlimited|full)\s+(?:access|permission|control)\s+(?:to|over)/i, name: 'Unrestricted access claim' },
  { pattern: /(?:access|read|write|modify|delete)\s+(?:any|all|every)\s+(?:file|resource|data|record|endpoint)/i, name: 'Universal resource access' },
  { pattern: /(?:bypass|skip|ignore|disable)\s+(?:security|auth|permission|access\s+control|validation)/i, name: 'Security bypass instruction' },
  { pattern: /(?:no\s+(?:need|requirement)\s+(?:for|to)\s+)?(?:authentication|authorization|permission check)/i, name: 'Auth requirement dismissal' },
];

const BEHAVIORAL_MISMATCH_PATTERNS = [
  { pattern: /(?:actually|really|secretly|in\s+reality)\s+(?:this\s+tool|it)\s+(?:does|performs|executes)/i, name: 'Documented vs actual behavior mismatch' },
  { pattern: /(?:hidden|undocumented|secret)\s+(?:feature|function|capability|behavior)/i, name: 'Hidden feature' },
  { pattern: /(?:description\s+says?|documented\s+as)\s+.*\s+(?:but|however|actually)/i, name: 'Description contradiction' },
  { pattern: /(?:in\s+addition\s+to|besides|apart\s+from)\s+(?:the\s+)?(?:described|documented|stated)/i, name: 'Undocumented additional behavior' },
];

function scanContent(content: string, filePath: string): MCPFinding[] {
  const findings: MCPFinding[] = [];

  // HTML comments with hidden instructions
  const htmlComments = content.match(/<!--[\s\S]*?-->/g);
  if (htmlComments) {
    for (const comment of htmlComments) {
      const hasInstructions = PROMPT_INJECTION_PATTERNS.some(p => p.pattern.test(comment));
      if (hasInstructions) {
        findings.push({
          severity: 'critical',
          type: 'skill-hidden-instructions',
          title: 'Hidden instructions in HTML comment',
          description: `SKILL.md contains HTML comments with instruction-like text that could manipulate agent behavior.`,
          file: filePath,
        });
        break;
      }
    }
  }

  // Prompt injection patterns in visible text
  for (const { pattern, name } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'high',
        type: 'skill-prompt-injection',
        title: `Prompt injection pattern: ${name}`,
        description: `SKILL.md contains "${name}" pattern that could hijack agent behavior.`,
        file: filePath,
      });
    }
  }

  // Unicode tricks
  for (const { pattern, name } of UNICODE_TRICKS) {
    const matches = content.match(pattern);
    if (matches && matches.length > 2) {
      findings.push({
        severity: 'high',
        type: 'skill-unicode-tricks',
        title: `Unicode trick: ${name}`,
        description: `SKILL.md contains ${matches.length} instances of ${name} which may hide malicious content.`,
        file: filePath,
      });
    }
  }

  // Data exfiltration patterns
  for (const { pattern, name } of DATA_EXFIL_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'high',
        type: 'skill-data-exfil',
        title: `Data exfiltration pattern: ${name}`,
        description: `SKILL.md contains ${name} which could exfiltrate data to external servers.`,
        file: filePath,
      });
    }
  }

  // Excessive permission requests
  for (const { pattern, name } of PERMISSION_PATTERNS) {
    const matches = content.match(pattern);
    if (matches) {
      findings.push({
        severity: 'medium',
        type: 'skill-excessive-permissions',
        title: `Excessive permission: ${name}`,
        description: `SKILL.md requests ${name} (${matches.length} instance(s)).`,
        file: filePath,
      });
    }
  }

  // Tool poisoning patterns (Cisco MCP Scanner-inspired)
  for (const { pattern, name } of TOOL_POISONING_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'critical',
        type: 'skill-tool-poisoning',
        title: `Tool poisoning: ${name}`,
        description: `SKILL.md contains tool poisoning pattern "${name}" — may perform hidden actions or covert side-effects.`,
        file: filePath,
      });
    }
  }

  // Credential harvesting patterns
  for (const { pattern, name } of CREDENTIAL_HARVESTING_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'critical',
        type: 'skill-credential-harvesting',
        title: `Credential harvesting: ${name}`,
        description: `SKILL.md contains credential harvesting pattern "${name}" — may collect or expose sensitive credentials.`,
        file: filePath,
      });
    }
  }

  // Overprivileged patterns
  for (const { pattern, name } of OVERPRIVILEGED_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'high',
        type: 'skill-overprivileged',
        title: `Overprivileged: ${name}`,
        description: `SKILL.md contains overprivileged pattern "${name}" — claims excessive access or bypasses security controls.`,
        file: filePath,
      });
    }
  }

  // Behavioral mismatch patterns
  for (const { pattern, name } of BEHAVIORAL_MISMATCH_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        severity: 'high',
        type: 'skill-behavioral-mismatch',
        title: `Behavioral mismatch: ${name}`,
        description: `SKILL.md contains behavioral mismatch pattern "${name}" — documented behavior may differ from actual behavior.`,
        file: filePath,
      });
    }
  }

  // Base64 encoded blocks (obfuscation)
  const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g;
  const base64Matches = content.match(base64Pattern);
  if (base64Matches && base64Matches.length > 0) {
    findings.push({
      severity: 'medium',
      type: 'skill-obfuscated-content',
      title: 'Base64 encoded content detected',
      description: `SKILL.md contains ${base64Matches.length} base64-encoded block(s) that may hide malicious instructions.`,
      file: filePath,
    });
  }

  return findings;
}

export function resolveSkillFilePaths(rootPath?: string): string[] {
  const paths: string[] = [];
  const home = os.homedir();

  // Global skill directories
  const globalDirs = [
    path.join(home, '.claude', 'skills'),
    path.join(home, '.cursor', 'skills'),
  ];

  for (const dir of globalDirs) {
    if (fs.existsSync(dir)) {
      try {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          if (file.endsWith('.md')) {
            paths.push(path.join(dir, file));
          }
        }
      } catch { /* ignore permission errors */ }
    }
  }

  // Project-level SKILL.md
  if (rootPath) {
    const projectSkills = [
      path.join(rootPath, 'SKILL.md'),
      path.join(rootPath, '.claude', 'skills'),
      path.join(rootPath, '.cursor', 'skills'),
    ];

    for (const p of projectSkills) {
      if (fs.existsSync(p)) {
        const stat = fs.statSync(p);
        if (stat.isFile()) {
          paths.push(p);
        } else if (stat.isDirectory()) {
          try {
            const files = fs.readdirSync(p);
            for (const file of files) {
              if (file.endsWith('.md')) {
                paths.push(path.join(p, file));
              }
            }
          } catch { /* ignore */ }
        }
      }
    }
  }

  return paths;
}

export function scanSkillFiles(rootPath?: string): SkillFileInfo[] {
  const skillPaths = resolveSkillFilePaths(rootPath);
  const results: SkillFileInfo[] = [];

  for (const skillPath of skillPaths) {
    try {
      const content = fs.readFileSync(skillPath, 'utf-8');
      const findings = scanContent(content, skillPath);
      results.push({
        path: skillPath,
        findings,
        size: content.length,
      });
    } catch { /* ignore unreadable files */ }
  }

  return results;
}
