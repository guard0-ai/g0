import * as fs from 'node:fs';
import * as path from 'node:path';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  findNodes,
} from '../ast/index.js';
import { findRouteHandlers } from '../ast/typescript.js';

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const SECRET_PATTERNS = [
  { regex: /(?:^|["'\s=])sk-[a-zA-Z0-9_-]{20,}/g, name: 'OpenAI API key' },
  { regex: /(?:^|["'\s=])ghp_[a-zA-Z0-9]{36}/g, name: 'GitHub personal access token' },
  { regex: /(?:^|["'\s=])gho_[a-zA-Z0-9]{36}/g, name: 'GitHub OAuth token' },
  { regex: /(?:^|["'\s=])AKIA[0-9A-Z]{16}/g, name: 'AWS access key' },
  { regex: /(?:^|["'\s=])xox[bpsra]-[a-zA-Z0-9-]{10,}/g, name: 'Slack token' },
  { regex: /(?:^|["'\s=])glpat-[a-zA-Z0-9_-]{20,}/g, name: 'GitLab personal access token' },
  { regex: /(?:^|["'\s=])sk_live_[a-zA-Z0-9]{20,}/g, name: 'Stripe live key' },
  { regex: /(?:^|["'\s=])rk_live_[a-zA-Z0-9]{20,}/g, name: 'Stripe restricted key' },
  { regex: /(?:^|["'\s=])sq0atp-[a-zA-Z0-9_-]{22,}/g, name: 'Square access token' },
  { regex: /(?:^|["'\s=])SG\.[a-zA-Z0-9_-]{22,}/g, name: 'SendGrid API key' },
];

const HARDCODED_SECRET_PATTERNS = [
  { regex: /(?:api[_-]?key|apikey|secret|token|password|passwd|credential)\s*[:=]\s*["']([^"'\s]{8,})["']/gi, name: 'hardcoded credential' },
];

export const identityAccessRules: Rule[] = [
  {
    id: 'AA-IA-001',
    name: 'Hardcoded API key detected',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'API key or secret token is hardcoded in source code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.all) {
        if (file.language === 'other') continue;
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        for (const { regex, name } of SECRET_PATTERNS) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const lineNum = content.substring(0, match.index).split('\n').length;
            const lineText = lines[lineNum - 1] ?? '';
            // Skip import/require lines (FP reduction)
            if (/^\s*(import\s|from\s|const\s+\w+\s*=\s*require)/.test(lineText)) continue;
            const snippet = match[0].trim().substring(0, 20) + '...';
            findings.push({
              id: `AA-IA-001-${findings.length}`,
              ruleId: 'AA-IA-001',
              title: `${name} detected in source code`,
              description: `${name} found hardcoded in ${file.relativePath}.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: file.relativePath, line: lineNum, snippet },
              remediation: 'Move secrets to environment variables or a secret manager. Never commit secrets to source code.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-002',
    name: 'Hardcoded credential in config',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'medium',
    description: 'Credential appears hardcoded in a configuration file.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.yaml, ...graph.files.json, ...graph.files.configs]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        for (const { regex, name } of HARDCODED_SECRET_PATTERNS) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const value = match[1];
            if (/^(your[_-]|<|TODO|REPLACE|xxx|placeholder)/i.test(value)) continue;
            if (/^\$\{?[A-Z_]+\}?$/.test(value) || /^process\.env/.test(value)) continue;
            if (/^(my[_-]|sample|dummy|fake|test[_-]?|changeme|insert|put[_-]|example)/i.test(value)) continue;
            if (/^os\.(?:environ|getenv)/.test(value)) continue;
            if (/^(.)\1{7,}$/.test(value)) continue;
            if (/^(none|null|undefined|empty|n\/a|tbd|fixme|hack)$/i.test(value)) continue;
            if (value.length >= 8 && shannonEntropy(value) < 2.5) continue;

            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-002-${findings.length}`,
              ruleId: 'AA-IA-002',
              title: 'Hardcoded credential in config',
              description: `Possible ${name} found in ${file.relativePath}.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'identity-access',
              location: { file: file.relativePath, line },
              remediation: 'Use environment variables or a secret manager instead of hardcoding credentials.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-003',
    name: 'API key in prompt content',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'API key or secret found in prompt content, risking exposure to the LLM.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.hasSecrets) {
          findings.push({
            id: `AA-IA-003-${findings.length}`,
            ruleId: 'AA-IA-003',
            title: 'Secret detected in prompt content',
            description: `Prompt in ${prompt.file} contains what appears to be an API key or secret.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: prompt.file, line: prompt.line },
            remediation: 'Never include API keys in prompts. Use server-side configuration instead.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-004',
    name: '.env file committed',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: '.env file found in project, which may be committed to source control.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.all) {
        const basename = path.basename(file.path);
        if (basename === '.env' || basename === '.env.local' || basename === '.env.production') {
          const gitignorePath = path.join(graph.rootPath, '.gitignore');
          let isIgnored = false;
          try {
            const gitignore = fs.readFileSync(gitignorePath, 'utf-8');
            isIgnored = gitignore.includes('.env');
          } catch {
            // No .gitignore found
          }

          if (!isIgnored) {
            findings.push({
              id: `AA-IA-004-${findings.length}`,
              ruleId: 'AA-IA-004',
              title: '.env file may be committed',
              description: `${basename} found and .gitignore does not exclude .env files.`,
              severity: 'high',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: file.relativePath, line: 1 },
              remediation: 'Add .env to .gitignore and use .env.example for templates.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-005',
    name: 'Secrets in MCP config',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Hardcoded secrets found in MCP configuration.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03', 'ASI04'], aiuc1: ['B002'], iso42001: ['A.6.3', 'A.7.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const config of graph.configs) {
        for (const secret of config.secrets) {
          if (secret.isHardcoded) {
            findings.push({
              id: `AA-IA-005-${findings.length}`,
              ruleId: 'AA-IA-005',
              title: 'Hardcoded secret in MCP config',
              description: `Secret "${secret.key}" is hardcoded in ${config.file}.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: config.file, line: secret.line },
              remediation: 'Use environment variable references instead of hardcoded secrets in MCP config.',
              standards: { owaspAgentic: ['ASI03', 'ASI04'], aiuc1: ['B002'], iso42001: ['A.6.3', 'A.7.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-006',
    name: 'No authentication on agent endpoint',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent endpoint has no authentication middleware.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const astLang = file.language === 'python' ? 'python' as const
          : file.language === 'typescript' ? 'typescript' as const
          : file.language === 'javascript' ? 'javascript' as const : null;
        const tree = astLang && isTreeSitterAvailable() ? getFileTreeForLang(file.path, content, astLang) : null;

        if (tree) {
          const handlers = findRouteHandlers(tree);
          for (const { node, path: routePath } of handlers) {
            if (!/agent|chat|completion|invoke/i.test(routePath)) continue;

            const startLine = Math.max(0, node.startPosition.row - 10);
            const endLine = node.endPosition.row + 10;
            const lines = content.split('\n');
            const region = lines.slice(startLine, endLine).join('\n');
            const hasAuth = /auth|jwt|bearer|api[_-]?key|verify|session|middleware/i.test(region);

            if (node.type === 'decorator' && node.parent?.type === 'decorated_definition') {
              const siblings = node.parent.children.filter((c) => c.type === 'decorator');
              const hasAuthDecorator = siblings.some((d) =>
                /auth|login_required|require|protect|verify/i.test(d.text),
              );
              if (hasAuthDecorator) continue;
            }

            if (!hasAuth) {
              const line = node.startPosition.row + 1;
              findings.push({
                id: `AA-IA-006-${findings.length}`,
                ruleId: 'AA-IA-006',
                title: 'Agent endpoint without authentication',
                description: `Agent endpoint in ${file.relativePath} has no apparent authentication.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'identity-access',
                location: { file: file.relativePath, line, snippet: node.text.substring(0, 60) },
                remediation: 'Add authentication middleware (JWT, API key, OAuth) to agent endpoints.',
                standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
              });
            }
          }
        } else {
          const endpointPatterns = [
            /app\.(post|get|put)\s*\(\s*["'].*(?:agent|chat|completion|invoke)/gi,
            /@app\.(?:post|get|route)\s*\(\s*["'].*(?:agent|chat|completion|invoke)/gi,
          ];

          for (const pattern of endpointPatterns) {
            pattern.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = pattern.exec(content)) !== null) {
              const region = content.substring(Math.max(0, match.index - 500), match.index + 500);
              const hasAuth = /auth|jwt|bearer|api[_-]?key|verify|session|middleware/i.test(region);

              if (!hasAuth) {
                const line = content.substring(0, match.index).split('\n').length;
                findings.push({
                  id: `AA-IA-006-${findings.length}`,
                  ruleId: 'AA-IA-006',
                  title: 'Agent endpoint without authentication',
                  description: `Agent endpoint in ${file.relativePath} has no apparent authentication.`,
                  severity: 'high',
                  confidence: 'medium',
                  domain: 'identity-access',
                  location: { file: file.relativePath, line, snippet: match[0] },
                  remediation: 'Add authentication middleware (JWT, API key, OAuth) to agent endpoints.',
                  standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
                });
              }
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-007',
    name: 'Overly permissive CORS',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'high',
    description: 'CORS is configured to allow all origins.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const corsPatterns = [
          /cors\s*\(\s*\*\s*\)/gi,
          /allow_origins\s*=\s*\[\s*["']\*["']\s*\]/gi,
          /origin\s*:\s*["']\*["']/gi,
          /Access-Control-Allow-Origin.*\*/gi,
        ];

        for (const pattern of corsPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-007-${findings.length}`,
              ruleId: 'AA-IA-007',
              title: 'CORS allows all origins',
              description: `CORS configured with wildcard origin in ${file.relativePath}.`,
              severity: 'medium',
              confidence: 'high',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Restrict CORS to specific trusted origins.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-008',
    name: 'Secrets in environment variables without validation',
    domain: 'identity-access',
    severity: 'low',
    confidence: 'medium',
    description: 'Environment variables for secrets are used without validating they exist.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const unsafeEnvPattern = /os\.environ\s*\[\s*["']([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z_]*)["']\s*\]/g;
        let match: RegExpExecArray | null;
        while ((match = unsafeEnvPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-008-${findings.length}`,
            ruleId: 'AA-IA-008',
            title: 'Environment secret accessed without fallback',
            description: `${match[1]} accessed via os.environ[] in ${file.relativePath} (will crash if missing).`,
            severity: 'low',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Use os.getenv() with a default or validate env vars at startup.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-009',
    name: 'Private key file in repo',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Private key file found in the repository, which may be committed to source control.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const privateKeyNames = ['id_rsa', 'id_ed25519'];
      const privateKeyExtensions = ['.pem', '.key'];
      for (const file of graph.files.all) {
        const basename = path.basename(file.path);
        const ext = path.extname(file.path);
        if (privateKeyNames.includes(basename) || privateKeyExtensions.includes(ext)) {
          findings.push({
            id: `AA-IA-009-${findings.length}`,
            ruleId: 'AA-IA-009',
            title: 'Private key file in repository',
            description: `Private key file "${basename}" found in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Remove private key files from the repository and add them to .gitignore. Use a secret manager for key storage.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-010',
    name: 'JWT secret hardcoded',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'JWT signing or verification uses a hardcoded string literal as the secret.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001', 'B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const jwtPattern = /jwt\.(sign|verify|encode|decode)\s*\([^)]*["'][^"']{8,}["']/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        jwtPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = jwtPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-010-${findings.length}`,
            ruleId: 'AA-IA-010',
            title: 'JWT secret hardcoded',
            description: `JWT ${match[1]} uses a hardcoded secret in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use environment variables or a secret manager for JWT secrets. Never hardcode signing keys.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001', 'B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-011',
    name: 'API key in URL/query string',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'API key or token passed in URL query string, which may be logged or cached.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const urlKeyPattern = /[?&](key|token|api_key|apikey)\s*=/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        urlKeyPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = urlKeyPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-011-${findings.length}`,
            ruleId: 'AA-IA-011',
            title: 'API key in URL query string',
            description: `API key/token passed in URL query parameter "${match[1]}" in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Pass API keys in request headers (e.g., Authorization header) instead of URL query parameters.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-012',
    name: 'Default/example credentials',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Default or example credentials detected in source code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const defaultCredPattern = /password\s*[:=]\s*["'](admin|password|test|123456|default|changeme|secret)["']/gi;
      for (const file of graph.files.all) {
        if (file.language === 'other') continue;
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        defaultCredPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = defaultCredPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-012-${findings.length}`,
            ruleId: 'AA-IA-012',
            title: 'Default/example credentials detected',
            description: `Default credential value "${match[1]}" found in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Replace default credentials with strong, unique values. Use a secret manager for credential storage.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-013',
    name: 'Secrets in Docker/container config',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Secrets are hardcoded in Docker or container configuration files.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const dockerEnvPattern = /ENV\s+\w*(SECRET|KEY|TOKEN|PASSWORD)\w*\s*=\s*\S+/gi;
      for (const file of graph.files.all) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        dockerEnvPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = dockerEnvPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-013-${findings.length}`,
            ruleId: 'AA-IA-013',
            title: 'Secret in Docker/container config',
            description: `Hardcoded secret in ENV directive found in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use Docker secrets, build args, or runtime environment variables instead of hardcoding secrets in Dockerfiles.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-014',
    name: 'Shared secrets across environments',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'The same hardcoded secret value appears in multiple configuration files.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const secretValuePattern = /(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*["']([^"'\s]{8,})["']/gi;
      const valueToFiles: Map<string, { file: string; line: number }[]> = new Map();

      for (const file of [...graph.files.configs, ...graph.files.yaml, ...graph.files.json]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        secretValuePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = secretValuePattern.exec(content)) !== null) {
          const value = match[1];
          if (/^(your[_-]|<|TODO|REPLACE|xxx|placeholder|\$\{)/i.test(value)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          if (!valueToFiles.has(value)) {
            valueToFiles.set(value, []);
          }
          valueToFiles.get(value)!.push({ file: file.relativePath, line });
        }
      }

      for (const [_value, locations] of valueToFiles) {
        if (locations.length > 1) {
          const fileList = locations.map((l) => l.file).join(', ');
          findings.push({
            id: `AA-IA-014-${findings.length}`,
            ruleId: 'AA-IA-014',
            title: 'Shared secret across config files',
            description: `The same secret value appears in multiple files: ${fileList}.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: locations[0].file, line: locations[0].line },
            remediation: 'Use unique secrets per environment. Reference a centralized secret manager instead of duplicating values.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-015',
    name: 'Missing rate limiting on auth endpoints',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Authentication endpoints lack rate limiting, enabling brute-force attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const authEndpointPattern = /(?:login|signin|sign_in|authenticate|auth)\s*[("'\/]/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        authEndpointPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = authEndpointPattern.exec(content)) !== null) {
          const start = Math.max(0, match.index - 500);
          const end = Math.min(content.length, match.index + 500);
          const region = content.substring(start, end);
          const hasRateLimit = /rate_limit|ratelimit|throttle|limiter/i.test(region);

          if (!hasRateLimit) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-015-${findings.length}`,
              ruleId: 'AA-IA-015',
              title: 'Auth endpoint without rate limiting',
              description: `Authentication endpoint in ${file.relativePath} has no apparent rate limiting.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add rate limiting middleware to authentication endpoints to prevent brute-force attacks.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-016',
    name: 'OAuth without PKCE',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'OAuth authorization code flow is used without PKCE (Proof Key for Code Exchange).',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const oauthPattern = /authorize.*response_type\s*=\s*code/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        oauthPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = oauthPattern.exec(content)) !== null) {
          const regionEnd = Math.min(content.length, match.index + match[0].length + 500);
          const region = content.substring(match.index, regionEnd);
          const hasPkce = /code_challenge|code_verifier/i.test(region);

          if (!hasPkce) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-016-${findings.length}`,
              ruleId: 'AA-IA-016',
              title: 'OAuth without PKCE',
              description: `OAuth authorization code flow in ${file.relativePath} does not use PKCE.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Implement PKCE (code_challenge and code_verifier) in OAuth authorization code flows.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-017',
    name: 'Bearer token logged',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Bearer token or authorization header is being logged, risking credential exposure.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E003'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const tokenLogPattern = /(?:print|console\.log|logging\.\w+|logger\.\w+)\s*\(.*(?:authorization|bearer|auth.*header)/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        tokenLogPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = tokenLogPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-017-${findings.length}`,
            ruleId: 'AA-IA-017',
            title: 'Bearer token logged',
            description: `Authorization header or bearer token is being logged in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Never log authorization headers or bearer tokens. Redact sensitive values before logging.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'E003'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-018',
    name: 'Credential in CLI argument',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'high',
    description: 'Credentials are passed as CLI arguments, which may appear in process listings and shell history.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const cliCredPattern = /--(?:api[_-]?key|password|secret|token)\s*[=\s]\s*[^\s"'$\\]+/gi;
      for (const file of graph.files.all) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        cliCredPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = cliCredPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-018-${findings.length}`,
            ruleId: 'AA-IA-018',
            title: 'Credential in CLI argument',
            description: `Credential passed as CLI argument in ${file.relativePath}.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use environment variables or config files instead of passing credentials as CLI arguments.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-019',
    name: 'Insecure token storage (localStorage)',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Sensitive tokens are stored in localStorage, which is vulnerable to XSS attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const localStoragePattern = /localStorage\.setItem\s*\(\s*["'][^"']*(?:token|key|secret|auth|session|jwt)[^"']*["']/gi;
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        localStoragePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = localStoragePattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-019-${findings.length}`,
            ruleId: 'AA-IA-019',
            title: 'Token stored in localStorage',
            description: `Sensitive token stored in localStorage in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use httpOnly cookies or secure session storage instead of localStorage for sensitive tokens.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-020',
    name: 'Missing API key scope restriction',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'low',
    description: 'OpenAI or Anthropic API key is used without organization or project scope restriction.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const unscopedKeyPattern = /(?:openai|anthropic).*api[_-]?key(?!.*(?:org|project|scope))/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        unscopedKeyPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = unscopedKeyPattern.exec(content)) !== null) {
          // Skip if the key is loaded from environment variable (proper pattern)
          const lineStart = content.lastIndexOf('\n', match.index) + 1;
          const lineEnd = content.indexOf('\n', match.index);
          const matchLine = content.substring(lineStart, lineEnd !== -1 ? lineEnd : undefined);
          if (/os\.getenv|os\.environ|process\.env|getenv|environ\.get/.test(matchLine)) continue;

          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-020-${findings.length}`,
            ruleId: 'AA-IA-020',
            title: 'API key without scope restriction',
            description: `API key usage in ${file.relativePath} lacks organization or project scoping.`,
            severity: 'medium',
            confidence: 'low',
            domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use organization-scoped or project-scoped API keys to limit access. Configure org/project IDs alongside API keys.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B002', 'B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-021',
    name: 'Permission checks in prompt only (not code)',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'medium',
    description: 'Authorization or permission keywords appear in prompts but no corresponding enforcement exists in code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const authKeywords = /\b(check permissions?|verify access|authorize|role[_-]?based|admin only|require auth)\b/i;
      const codeAuthPatterns = /\b(isAuthorized|checkPermission|hasRole|requireAuth|canAccess|isAdmin|authorize|@requires_auth|@login_required)\b/i;
      const promptFiles = new Set(graph.prompts.map((p) => p.file));
      const promptsWithAuth = graph.prompts.filter((p) => authKeywords.test(p.content));
      if (promptsWithAuth.length === 0) return findings;
      let codeHasAuth = false;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        if (promptFiles.has(file.relativePath)) continue;
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (codeAuthPatterns.test(content)) { codeHasAuth = true; break; }
        } catch { continue; }
      }
      if (!codeHasAuth) {
        for (const prompt of promptsWithAuth) {
          findings.push({
            id: `AA-IA-021-${findings.length}`, ruleId: 'AA-IA-021',
            title: 'Permission checks in prompt only',
            description: `Prompt in ${prompt.file} references authorization but no code-level enforcement found.`,
            severity: 'critical', confidence: 'medium', domain: 'identity-access',
            location: { file: prompt.file, line: prompt.line },
            remediation: 'Implement authorization checks in code, not just in prompt instructions. LLMs cannot enforce access control.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-030',
    name: 'No RBAC enforcement',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Codebase lacks role-based access control patterns for agent or user actions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const rbacPatterns = /\b(hasRole|checkRole|role_required|roles_allowed|RBAC|RoleGuard|@roles|user\.role|currentUser\.role|req\.user\.role)\b/i;
      const codeFiles = [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
      if (codeFiles.length === 0) return findings;
      let hasRbac = false;
      for (const file of codeFiles) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (rbacPatterns.test(content)) { hasRbac = true; break; }
        } catch { continue; }
      }
      if (!hasRbac && graph.agents.length > 0) {
        findings.push({
          id: 'AA-IA-030-0', ruleId: 'AA-IA-030',
          title: 'No RBAC enforcement detected',
          description: 'No role-based access control patterns found in the codebase. Agent actions may lack authorization checks.',
          severity: 'high', confidence: 'medium', domain: 'identity-access',
          location: { file: graph.files.all[0]?.relativePath ?? 'project', line: 1 },
          remediation: 'Implement role-based access control to restrict agent and user actions based on assigned roles.',
          standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-031',
    name: 'JWT without audience restriction',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'JWT verify or decode calls lack an audience parameter, allowing token misuse across services.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const jwtVerifyPattern = /jwt\.(verify|decode)\s*\([^)]{5,}\)/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        jwtVerifyPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = jwtVerifyPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 300));
          if (!/audience|aud/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-031-${findings.length}`, ruleId: 'AA-IA-031',
              title: 'JWT without audience restriction',
              description: `JWT ${match[1]} in ${file.relativePath} does not specify an audience claim.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Always verify the "aud" (audience) claim when validating JWTs to prevent token misuse across services.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-032',
    name: 'No token revocation mechanism',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'JWT or token usage lacks a revocation or blacklist mechanism.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const jwtUsagePattern = /jwt\.(sign|verify|encode|decode)\b/gi;
      const revocationPatterns = /\b(revoke|blacklist|blocklist|token_blacklist|revoked_tokens|invalidate_token|denylist)\b/i;
      const codeFiles = [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
      let usesJwt = false;
      let hasRevocation = false;
      for (const file of codeFiles) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (jwtUsagePattern.test(content)) usesJwt = true;
          jwtUsagePattern.lastIndex = 0;
          if (revocationPatterns.test(content)) hasRevocation = true;
        } catch { continue; }
      }
      if (usesJwt && !hasRevocation) {
        findings.push({
          id: 'AA-IA-032-0', ruleId: 'AA-IA-032',
          title: 'No token revocation mechanism',
          description: 'JWT tokens are used but no revocation or blacklist mechanism was detected.',
          severity: 'high', confidence: 'medium', domain: 'identity-access',
          location: { file: codeFiles[0]?.relativePath ?? 'project', line: 1 },
          remediation: 'Implement a token revocation mechanism (blacklist, blocklist, or short-lived tokens with refresh) to invalidate compromised tokens.',
          standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-033',
    name: 'Session not invalidated on perm change',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Permission or role updates do not invalidate existing sessions, allowing stale privileges.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const permChangePattern = /\b(update_role|set_permissions?|change_role|assign_role|remove_role|grant_permission|revoke_permission)\b/gi;
      const sessionInvalidatePattern = /\b(session\.destroy|session\.invalidate|req\.logout|session_store\.delete|clear_session|invalidate_sessions?)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        permChangePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = permChangePattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!sessionInvalidatePattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-033-${findings.length}`, ruleId: 'AA-IA-033',
              title: 'Session not invalidated on permission change',
              description: `Permission change "${match[0]}" in ${file.relativePath} does not invalidate existing sessions.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Invalidate all active sessions when user permissions or roles are changed to prevent privilege persistence.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-034',
    name: 'Agent can modify own permissions',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent has access to tools or functions that can modify its own permission configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const selfModifyPatterns = /\b(self\.permissions|self\.allowed_tools|agent\.permissions|update_own_role|modify_permissions|set_own_access|self\.role\s*=)\b/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        selfModifyPatterns.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = selfModifyPatterns.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-034-${findings.length}`, ruleId: 'AA-IA-034',
            title: 'Agent can modify own permissions',
            description: `Agent self-modification pattern "${match[0]}" found in ${file.relativePath}.`,
            severity: 'high', confidence: 'medium', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Agents should never be able to modify their own permissions. Use an external authorization service with immutable role assignments.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-035',
    name: 'No audit logging for privileged actions',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Privileged operations lack audit logging, making it hard to detect unauthorized access.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const privilegedPattern = /\b(delete_user|grant_admin|sudo|escalate|create_admin|drop_table|rm\s+-rf|destroy_all|purge)\b/gi;
      const auditPattern = /\b(audit_log|audit\.log|logger\.audit|log_action|create_audit_entry|AuditLog)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        privilegedPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = privilegedPattern.exec(content)) !== null) {
          const start = Math.max(0, match.index - 300);
          const end = Math.min(content.length, match.index + 300);
          const region = content.substring(start, end);
          if (!auditPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-035-${findings.length}`, ruleId: 'AA-IA-035',
              title: 'No audit logging for privileged action',
              description: `Privileged operation "${match[0]}" in ${file.relativePath} lacks audit logging.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add audit logging for all privileged operations to maintain an accountability trail.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-036',
    name: 'Credential caching without TTL',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Credentials are cached in memory or storage without an expiration or TTL.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const credCachePattern = /\b(cache\.(set|put|store)|redis\.set|memcache\.set)\s*\([^)]*(?:token|credential|secret|password|api_key)/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        credCachePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = credCachePattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 200));
          if (!/ttl|expire|expir|max_age|timeout/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-036-${findings.length}`, ruleId: 'AA-IA-036',
              title: 'Credential cached without TTL',
              description: `Credential cached without expiration in ${file.relativePath}.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Always set a TTL (time-to-live) when caching credentials. Cached credentials should expire within minutes.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-037',
    name: 'Same credentials across environments',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Environment files share the same credential values across different environments.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const envFiles = graph.files.all.filter((f) => /\.env(\.\w+)?$/.test(path.basename(f.path)));
      if (envFiles.length < 2) return findings;
      const credPattern = /^(\w*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*)\s*=\s*(.{8,})$/gim;
      const fileCredMap: Map<string, Map<string, string>> = new Map();
      for (const file of envFiles) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          const creds = new Map<string, string>();
          credPattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = credPattern.exec(content)) !== null) {
            if (!/^\$|^<|^your|^TODO|^REPLACE/i.test(match[2])) creds.set(match[1], match[2].trim());
          }
          fileCredMap.set(file.relativePath, creds);
        } catch { continue; }
      }
      const fileNames = [...fileCredMap.keys()];
      for (let i = 0; i < fileNames.length; i++) {
        for (let j = i + 1; j < fileNames.length; j++) {
          const credsA = fileCredMap.get(fileNames[i])!;
          const credsB = fileCredMap.get(fileNames[j])!;
          for (const [key, val] of credsA) {
            if (credsB.get(key) === val) {
              findings.push({
                id: `AA-IA-037-${findings.length}`, ruleId: 'AA-IA-037',
                title: 'Same credential across environments',
                description: `Credential "${key}" has the same value in ${fileNames[i]} and ${fileNames[j]}.`,
                severity: 'high', confidence: 'medium', domain: 'identity-access',
                location: { file: fileNames[i], line: 1 },
                remediation: 'Use unique credential values per environment. Share credentials via a secret manager, not by copying values.',
                standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-038',
    name: 'No MFA for sensitive operations',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Sensitive operations lack multi-factor authentication (MFA/2FA) verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sensitiveOpPattern = /\b(delete_account|transfer_funds|change_password|reset_password|withdraw|wire_transfer|export_data|bulk_delete)\b/gi;
      const mfaPattern = /\b(mfa|2fa|two_factor|totp|otp|verify_code|second_factor|multi_factor)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sensitiveOpPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sensitiveOpPattern.exec(content)) !== null) {
          const start = Math.max(0, match.index - 500);
          const end = Math.min(content.length, match.index + 500);
          const region = content.substring(start, end);
          if (!mfaPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-038-${findings.length}`, ruleId: 'AA-IA-038',
              title: 'No MFA for sensitive operation',
              description: `Sensitive operation "${match[0]}" in ${file.relativePath} lacks MFA verification.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Require multi-factor authentication for sensitive operations such as fund transfers, account deletion, and password changes.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-039',
    name: 'Wildcard IAM permissions',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'IAM policy uses wildcard Action or Resource, granting excessive permissions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const wildcardPattern = /["'](Action|Resource)["']\s*:\s*["']\*["']/gi;
      for (const file of [...graph.files.json, ...graph.files.yaml, ...graph.files.configs]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        wildcardPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = wildcardPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-039-${findings.length}`, ruleId: 'AA-IA-039',
            title: 'Wildcard IAM permission',
            description: `Wildcard "${match[1]}: *" found in IAM policy in ${file.relativePath}.`,
            severity: 'high', confidence: 'high', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Follow the principle of least privilege. Replace wildcard IAM permissions with specific actions and resources.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-040',
    name: 'Cross-tenant data access possible',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Multi-tenant database queries lack tenant ID filtering, enabling cross-tenant data access.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const queryPattern = /\b(\.find|\.query|\.select|\.where|\.filter|SELECT\s+.*FROM)\b/gi;
      const tenantFilter = /\b(tenant_id|tenantId|organization_id|orgId|org_id|account_id)\b/i;
      const multiTenantIndicator = /\b(tenant|multi.?tenant|organization|org_id)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        if (!multiTenantIndicator.test(content)) continue;
        queryPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = queryPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 300));
          if (!tenantFilter.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-040-${findings.length}`, ruleId: 'AA-IA-040',
              title: 'Cross-tenant data access possible',
              description: `Database query in ${file.relativePath} may lack tenant ID filtering.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Always filter queries by tenant ID in multi-tenant applications to prevent cross-tenant data leakage.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
            break;
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-041',
    name: 'Vercel AI tool without auth check',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Vercel AI SDK tool definition lacks authentication or authorization validation.',
    frameworks: ['vercel-ai'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const toolPattern = /\btool\s*\(\s*\{[^}]*description\s*:/gi;
      const authPattern = /\b(auth|session|user|token|verify|check_permission|requireAuth)\b/i;
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        if (!/ai\/core|@vercel\/ai|ai\/rsc/i.test(content)) continue;
        toolPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = toolPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!authPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-041-${findings.length}`, ruleId: 'AA-IA-041',
              title: 'Vercel AI tool without auth check',
              description: `Vercel AI tool in ${file.relativePath} lacks authentication validation.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add authentication and authorization checks inside Vercel AI tool execute functions to validate the caller.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-042',
    name: 'Bedrock agent with admin IAM role',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'AWS Bedrock agent configuration uses overly permissive IAM roles.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const bedrockRolePattern = /bedrock.*(?:role|arn).*(?:Admin|AdministratorAccess|PowerUser|\*)/gi;
      for (const file of [...graph.files.json, ...graph.files.yaml, ...graph.files.configs, ...graph.files.python, ...graph.files.typescript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        bedrockRolePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = bedrockRolePattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-042-${findings.length}`, ruleId: 'AA-IA-042',
            title: 'Bedrock agent with admin IAM role',
            description: `Bedrock agent in ${file.relativePath} uses an overly permissive IAM role.`,
            severity: 'high', confidence: 'high', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Assign Bedrock agents least-privilege IAM roles scoped to only required actions and resources.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-043',
    name: 'AutoGen agents sharing credentials',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Multiple AutoGen agents share the same credential configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const autogenConfigPattern = /\b(AssistantAgent|UserProxyAgent|GroupChat)\s*\([^)]*(?:api_key|llm_config)/gi;
      const sharedCredPattern = /config_list\s*=\s*(\w+)/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        if (!/autogen|auto_gen/i.test(content)) continue;
        const configVars = new Map<string, number>();
        sharedCredPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sharedCredPattern.exec(content)) !== null) {
          const varName = match[1];
          configVars.set(varName, (configVars.get(varName) ?? 0) + 1);
        }
        for (const [varName, count] of configVars) {
          if (count > 1) {
            const line = content.indexOf(varName);
            const lineNum = content.substring(0, Math.max(0, line)).split('\n').length;
            findings.push({
              id: `AA-IA-043-${findings.length}`, ruleId: 'AA-IA-043',
              title: 'AutoGen agents sharing credentials',
              description: `Config "${varName}" is shared across ${count} AutoGen agents in ${file.relativePath}.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line: lineNum },
              remediation: 'Assign unique credentials to each AutoGen agent. Shared credentials make compromise attribution impossible.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-044',
    name: 'MCP server with excessive secrets',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'MCP server configuration contains many hardcoded secrets, increasing the attack surface.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const secretKeyPattern = /["']?\b\w*(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|API_KEY)\w*["']?\s*[:=]/gi;
      for (const file of [...graph.files.json, ...graph.files.yaml, ...graph.files.configs]) {
        if (!/mcp|server/i.test(file.path)) continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        secretKeyPattern.lastIndex = 0;
        let count = 0;
        while (secretKeyPattern.exec(content) !== null) count++;
        if (count >= 5) {
          findings.push({
            id: `AA-IA-044-${findings.length}`, ruleId: 'AA-IA-044',
            title: 'MCP server with excessive secrets',
            description: `MCP config ${file.relativePath} contains ${count} secret entries. Excessive secrets increase attack surface.`,
            severity: 'high', confidence: 'high', domain: 'identity-access',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Minimize hardcoded secrets in MCP server configs. Use a secret manager and reference secrets by name.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-045',
    name: 'JWT signed with weak algorithm',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'JWT is configured to use a weak signing algorithm such as HS256 or none.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const weakAlgoPattern = /(?:algorithm|alg)\s*[:=]\s*["'](HS256|none)["']/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        weakAlgoPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = weakAlgoPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-045-${findings.length}`, ruleId: 'AA-IA-045',
            title: 'JWT signed with weak algorithm',
            description: `JWT uses weak algorithm "${match[1]}" in ${file.relativePath}.`,
            severity: 'high', confidence: 'high', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Use strong JWT signing algorithms (RS256, ES256) instead of HS256 or none. Never allow "none" algorithm.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-046',
    name: 'API key in URL query parameter',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'API key or secret is passed in a URL query string via string concatenation or template literals.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const urlKeyPatterns = [
        /https?:\/\/[^\s"']*[?&](?:api[_-]?key|secret|access[_-]?token|auth[_-]?token)\s*=/gi,
        /\$\{?[^}]*(?:api[_-]?key|secret|token)\}?\s*(?:&|$)/gi,
        /[`"']\s*\+\s*(?:api[_-]?key|secret|token)\b/gi,
      ];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        for (const pattern of urlKeyPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-046-${findings.length}`, ruleId: 'AA-IA-046',
              title: 'API key in URL query parameter',
              description: `API key passed in URL query string in ${file.relativePath}. URLs are logged and cached.`,
              severity: 'high', confidence: 'high', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Pass API keys in HTTP headers (Authorization, X-API-Key) instead of URL query parameters.',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-047',
    name: 'Credentials in CI/CD pipeline files',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'Secrets or credentials are hardcoded in CI/CD pipeline configuration files.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const ciFilePattern = /(?:\.github\/workflows\/|\.gitlab-ci|Jenkinsfile|\.circleci|\.travis|azure-pipelines|bitbucket-pipelines)/i;
      const secretInCiPattern = /(?:api[_-]?key|secret|token|password|credential)\s*[:=]\s*["']([^"'\s$]{8,})["']/gi;
      for (const file of graph.files.all) {
        if (!ciFilePattern.test(file.path)) continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        secretInCiPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = secretInCiPattern.exec(content)) !== null) {
          if (/^\$\{|\$\(|secrets\.|vault/i.test(match[1])) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-047-${findings.length}`, ruleId: 'AA-IA-047',
            title: 'Credential in CI/CD pipeline file',
            description: `Hardcoded credential found in CI/CD file ${file.relativePath}.`,
            severity: 'high', confidence: 'high', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use CI/CD secret management (GitHub Secrets, GitLab CI variables) instead of hardcoding credentials in pipeline files.',
            standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-048',
    name: 'No credential encryption at rest',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Credentials are stored in plaintext files without encryption.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const credStorePattern = /\b(writeFile|write_file|open\s*\([^)]*["']w["']|fs\.writeFileSync|save_credentials?|store_credentials?)\s*\([^)]*(?:password|secret|token|credential|api_key)/gi;
      const encryptionPattern = /\b(encrypt|cipher|aes|fernet|kms|vault|sealed|crypto\.create)/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        credStorePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = credStorePattern.exec(content)) !== null) {
          const start = Math.max(0, match.index - 500);
          const end = Math.min(content.length, match.index + 500);
          const region = content.substring(start, end);
          if (!encryptionPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-048-${findings.length}`, ruleId: 'AA-IA-048',
              title: 'No credential encryption at rest',
              description: `Credential stored without encryption in ${file.relativePath}.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Encrypt credentials before writing to disk. Use a secret manager, KMS, or encryption library (AES, Fernet).',
              standards: { owaspAgentic: ['ASI03'], aiuc1: ['B001'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  // === Gap-fill rules AA-IA-022 to AA-IA-029 ===
  {
    id: 'AA-IA-022',
    name: 'No session isolation between users',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Shared session state without per-user isolation allows cross-user data leakage.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sessionPattern = /\b(session|state|context|memory)\s*[=:]\s*\{/gi;
      const isolationPattern = /\b(user_id|userId|session_id|sessionId|tenant_id|per_user|user_scope)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sessionPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sessionPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 400));
          if (!isolationPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-022-${findings.length}`, ruleId: 'AA-IA-022',
              title: 'No session isolation between users',
              description: `Shared session state in ${file.relativePath} lacks per-user isolation.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Scope all session/state objects by user_id or session_id to prevent cross-user data leakage.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
            break;
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-023',
    name: 'Delegation without authority verification',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent delegates tasks to other agents without verifying the delegating agent has the required permissions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const delegatePattern = /\b(delegate|handoff|forward|dispatch|transfer|assign_task|send_task)\s*\(/gi;
      const authCheckPattern = /\b(check_permission|has_permission|authorize|can_delegate|verify_authority|is_allowed)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        delegatePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = delegatePattern.exec(content)) !== null) {
          const start = Math.max(0, match.index - 300);
          const region = content.substring(start, Math.min(content.length, match.index + 300));
          if (!authCheckPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-023-${findings.length}`, ruleId: 'AA-IA-023',
              title: 'Delegation without authority verification',
              description: `Delegation call in ${file.relativePath} lacks authority/permission check before delegating.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Verify the delegating agent has appropriate permissions before forwarding tasks to other agents.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-024',
    name: 'No privilege boundary enforcement',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Multiple agents share the same privilege level without boundary enforcement between them.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const privilegePattern = /\b(privilege|permission|access_level|role|scope)\b/i;
      const boundaryPattern = /\b(privilege_boundary|boundary_check|escalation_guard|privilege_level|separate_privilege|least_privilege|sandbo[x])\b/i;
      if (graph.agents.length < 2) return findings;
      let hasPrivilegeRef = false;
      let hasBoundary = false;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (privilegePattern.test(content)) hasPrivilegeRef = true;
          if (boundaryPattern.test(content)) hasBoundary = true;
        } catch { continue; }
      }
      if (hasPrivilegeRef && !hasBoundary) {
        findings.push({
          id: 'AA-IA-024-0', ruleId: 'AA-IA-024',
          title: 'No privilege boundary enforcement',
          description: 'Multi-agent system references privileges but lacks boundary enforcement between agents.',
          severity: 'high', confidence: 'medium', domain: 'identity-access',
          location: { file: graph.files.all[0]?.relativePath ?? 'project', line: 1 },
          remediation: 'Enforce privilege boundaries between agents so each operates at its own privilege level with least-privilege access.',
          standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-025',
    name: 'Token passed between agents without validation',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Tokens or credentials are passed between agents without re-validation at the receiving end.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const tokenPassPattern = /\b(pass_token|forward_token|share_token|token\s*[:=]\s*(?:agent|other|parent|caller)[\w.]*token|propagate_auth|relay_credentials?)\b/gi;
      const validatePattern = /\b(validate_token|verify_token|check_token|token_valid|re_?validate|introspect)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        tokenPassPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = tokenPassPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 400));
          if (!validatePattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-025-${findings.length}`, ruleId: 'AA-IA-025',
              title: 'Token passed between agents without validation',
              description: `Token relay in ${file.relativePath} lacks re-validation at the receiving agent.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Re-validate tokens at each agent boundary. Never trust forwarded tokens without independent verification.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-026',
    name: 'No role-based access control for tools',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'All agents can access all tools without role-based restrictions on tool usage.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const toolRegPattern = /\b(tools?\s*[:=]\s*\[|register_tool|add_tool|tool_list|available_tools)\b/gi;
      const toolRbacPattern = /\b(tool_permission|allowed_tools|tool_access|tool_role|restrict_tool|tool_whitelist|tool_allowlist|can_use_tool)\b/i;
      if (graph.agents.length < 2) return findings;
      let hasToolReg = false;
      let hasToolRbac = false;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (toolRegPattern.test(content)) hasToolReg = true;
          toolRegPattern.lastIndex = 0;
          if (toolRbacPattern.test(content)) hasToolRbac = true;
        } catch { continue; }
      }
      if (hasToolReg && !hasToolRbac) {
        findings.push({
          id: 'AA-IA-026-0', ruleId: 'AA-IA-026',
          title: 'No role-based access control for tools',
          description: 'Tools are registered without per-agent or role-based access restrictions.',
          severity: 'high', confidence: 'medium', domain: 'identity-access',
          location: { file: graph.files.all[0]?.relativePath ?? 'project', line: 1 },
          remediation: 'Restrict tool access per agent role. Not every agent should have access to every tool.',
          standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-027',
    name: 'Impersonation between agents not prevented',
    domain: 'identity-access',
    severity: 'critical',
    confidence: 'medium',
    description: 'No mechanism prevents one agent from impersonating another agent in inter-agent communication.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const agentCommPattern = /\b(send_message|agent_call|invoke_agent|call_agent|agent\.send|inter_agent|a2a_|peer_request)\b/gi;
      const identityVerifyPattern = /\b(verify_identity|authenticate_agent|agent_id_check|mutual_auth|mtls|signed_message|verify_sender|agent_certificate)\b/i;
      if (graph.agents.length < 2) return findings;
      let hasComm = false;
      let hasIdentityVerify = false;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (agentCommPattern.test(content)) hasComm = true;
          agentCommPattern.lastIndex = 0;
          if (identityVerifyPattern.test(content)) hasIdentityVerify = true;
        } catch { continue; }
      }
      if (hasComm && !hasIdentityVerify) {
        findings.push({
          id: 'AA-IA-027-0', ruleId: 'AA-IA-027',
          title: 'Impersonation between agents not prevented',
          description: 'Inter-agent communication lacks identity verification, allowing impersonation.',
          severity: 'critical', confidence: 'medium', domain: 'identity-access',
          location: { file: graph.files.all[0]?.relativePath ?? 'project', line: 1 },
          remediation: 'Implement mutual authentication between agents (mTLS, signed messages, agent certificates) to prevent impersonation.',
          standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-028',
    name: 'Shared service account for all agents',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Multiple agents use a single shared service account or API key, preventing individual accountability.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sharedCredPattern = /\b(shared_key|shared_secret|shared_token|common_api_key|global_api_key|service_account|SHARED_CREDENTIALS?|common_credentials?)\b/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript, ...graph.files.configs]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sharedCredPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sharedCredPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-028-${findings.length}`, ruleId: 'AA-IA-028',
            title: 'Shared service account for all agents',
            description: `Shared credential pattern '${match[0].trim()}' in ${file.relativePath} indicates agents share a service account.`,
            severity: 'high', confidence: 'medium', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Assign individual service accounts or credentials per agent for accountability and least-privilege access.',
            standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-029',
    name: 'No audit trail for privilege changes',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Privilege escalation or role changes are not logged, preventing forensic analysis.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const privChangePattern = /\b(set_role|change_role|update_permission|grant_access|elevate|escalate_privilege|add_role|remove_role|modify_acl)\s*\(/gi;
      const auditPattern = /\b(audit|log_event|log_action|logger\.|logging\.|audit_log|record_change|emit_event)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        privChangePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = privChangePattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 400));
          if (!auditPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-029-${findings.length}`, ruleId: 'AA-IA-029',
              title: 'No audit trail for privilege changes',
              description: `Privilege change in ${file.relativePath} is not accompanied by audit logging.`,
              severity: 'medium', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Log all privilege and role changes with timestamp, actor, and details for audit trail and forensic analysis.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  // === Session Isolation rules AA-IA-049 to AA-IA-060 ===
  {
    id: 'AA-IA-049',
    name: 'Cross-session data leakage',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'No session boundary enforcement allows data from one session to leak into another.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const globalStatePattern = /\b(global_state|shared_dict|shared_memory|global_context|_cache\s*[:=]\s*\{|module_state)\b/gi;
      const sessionScopePattern = /\b(session_id|sessionId|per_session|session_scope|session_key|scoped_session)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        globalStatePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = globalStatePattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 400));
          if (!sessionScopePattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-049-${findings.length}`, ruleId: 'AA-IA-049',
              title: 'Cross-session data leakage',
              description: `Global/shared state in ${file.relativePath} lacks session boundary enforcement.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Scope all shared state by session_id to enforce session boundaries and prevent cross-session data leakage.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
            break;
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-050',
    name: 'Session fixation — session ID not rotated',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Session ID is not rotated after authentication, making the application vulnerable to session fixation attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const loginPattern = /\b(login|authenticate|sign_in|signIn|handleLogin|do_login)\s*\(/gi;
      const rotatePattern = /\b(regenerate|rotate_session|new_session|session\.regenerate|create_session|reset_session_id|cycle_session)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        loginPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = loginPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!rotatePattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-050-${findings.length}`, ruleId: 'AA-IA-050',
              title: 'Session fixation — session ID not rotated',
              description: `Login handler in ${file.relativePath} does not rotate the session ID after authentication.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Regenerate the session ID after successful authentication to prevent session fixation attacks.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-051',
    name: 'Shared session state between agents',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Agents share a single session object without individual session scoping.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sharedSessionPattern = /\b(shared_session|common_session|global_session|session\s*=\s*\w+Session\(\))\b/gi;
      if (graph.agents.length < 2) return findings;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sharedSessionPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sharedSessionPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-051-${findings.length}`, ruleId: 'AA-IA-051',
            title: 'Shared session state between agents',
            description: `Shared session pattern in ${file.relativePath} allows agents to access each other's session data.`,
            severity: 'high', confidence: 'medium', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Create separate session objects per agent to enforce session isolation in multi-agent systems.',
            standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-052',
    name: 'Session timeout not enforced',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Session configuration lacks timeout or expiry settings, allowing sessions to persist indefinitely.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sessionConfigPattern = /\b(session\s*[:=({]|SessionMiddleware|session_config|cookie_session|createSession|express[\-_]session)\b/gi;
      const timeoutPattern = /\b(timeout|ttl|max_age|maxAge|expires|expiry|idle_timeout|session_lifetime|expire_after|cookie.*max)/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript, ...graph.files.configs]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sessionConfigPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sessionConfigPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!timeoutPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-052-${findings.length}`, ruleId: 'AA-IA-052',
              title: 'Session timeout not enforced',
              description: `Session configuration in ${file.relativePath} lacks timeout/expiry settings.`,
              severity: 'medium', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Set session timeout and idle expiry values. Use maxAge, TTL, or expiry configurations to limit session lifetime.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
            break;
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-053',
    name: 'Session token predictability — weak session IDs',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'Session tokens are generated using predictable methods (sequential, timestamp, weak random) instead of cryptographic randomness.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const weakIdPattern = /\b(session_id\s*[:=]\s*(?:str\()?(?:counter|increment|time|datetime|Date\.now|Math\.random|random\.randint|uuid1|sequential|auto_increment))/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        weakIdPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = weakIdPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-053-${findings.length}`, ruleId: 'AA-IA-053',
            title: 'Session token predictability — weak session IDs',
            description: `Weak session ID generation in ${file.relativePath} uses predictable source.`,
            severity: 'high', confidence: 'high', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use cryptographically secure random generators (crypto.randomBytes, secrets.token_hex, uuid4) for session IDs.',
            standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-054',
    name: 'Session hijacking via tool output',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Session tokens or IDs are exposed in tool output, logs, or responses, enabling session hijacking.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const leakPattern = /\b(print|console\.log|logger\.\w+|logging\.\w+|return|response)\s*\(.*\b(session_id|sessionId|session_token|sess_token|sid)\b/gi;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        leakPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = leakPattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-IA-054-${findings.length}`, ruleId: 'AA-IA-054',
            title: 'Session hijacking via tool output',
            description: `Session token exposed in output/log in ${file.relativePath}.`,
            severity: 'high', confidence: 'medium', domain: 'identity-access',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Never expose session tokens in logs, tool output, or API responses. Redact or mask session identifiers.',
            standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-055',
    name: 'No session invalidation on logout',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Logout handler does not destroy or invalidate the session, allowing reuse of old session tokens.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const logoutPattern = /\b(logout|sign_out|signOut|handleLogout|do_logout)\s*\(/gi;
      const destroyPattern = /\b(destroy|invalidate|delete_session|session\.destroy|session\.clear|remove_session|revoke_session|req\.session\s*=\s*null)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        logoutPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = logoutPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!destroyPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-055-${findings.length}`, ruleId: 'AA-IA-055',
              title: 'No session invalidation on logout',
              description: `Logout handler in ${file.relativePath} does not destroy or invalidate the session.`,
              severity: 'medium', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Destroy or invalidate the session on logout. Call session.destroy() or equivalent to prevent session reuse.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-056',
    name: 'Session data stored in shared memory',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Session data is stored in shared memory (global dict, Redis without key prefix, shared DB table) accessible to all agents.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sharedStorePattern = /\b(redis\.(?:set|get|hset|hget)\s*\(\s*["'][^"']*["']|memcached\.\w+\s*\(|global_dict|shared_store|shared_db)\b/gi;
      const prefixPattern = /\b(session:|sess:|user:|prefix|namespace|key_prefix|session_prefix)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sharedStorePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sharedStorePattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 200), Math.min(content.length, match.index + 300));
          if (!prefixPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-056-${findings.length}`, ruleId: 'AA-IA-056',
              title: 'Session data stored in shared memory',
              description: `Session data in ${file.relativePath} is stored in shared memory without key prefixing/namespace.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use session-scoped key prefixes (e.g., session:<id>:) when storing data in Redis, Memcached, or shared stores.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-057',
    name: 'No session scoping for tool access',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool invocations do not include session context, allowing tools to operate outside the caller session scope.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const toolCallPattern = /\b(invoke_tool|run_tool|execute_tool|call_tool|tool\.run|tool\.execute|tool\.invoke)\s*\(/gi;
      const sessionCtxPattern = /\b(session|context|session_id|sessionId|caller_session|request_context)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        toolCallPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = toolCallPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 300));
          if (!sessionCtxPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-057-${findings.length}`, ruleId: 'AA-IA-057',
              title: 'No session scoping for tool access',
              description: `Tool invocation in ${file.relativePath} lacks session context parameter.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Pass session context to all tool invocations so tools can enforce session-scoped access control.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-058',
    name: 'Session replay attack not prevented',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'No nonce, timestamp validation, or replay detection mechanism protects session-bound requests from replay attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sessionReqPattern = /\b(session_request|authenticated_request|agent_request|handle_request)\s*\(/gi;
      const replayGuardPattern = /\b(nonce|replay|idempotency|idempotent_key|request_id|dedup|deduplication|timestamp_valid|anti.?replay)\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        sessionReqPattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sessionReqPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!replayGuardPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-058-${findings.length}`, ruleId: 'AA-IA-058',
              title: 'Session replay attack not prevented',
              description: `Request handler in ${file.relativePath} lacks replay protection (nonce, timestamp, idempotency key).`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Implement replay protection using nonces, timestamp validation, or idempotency keys on session-bound requests.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-059',
    name: 'Cross-origin session sharing',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'medium',
    description: 'Session cookies or tokens are shared across origins without proper domain/path restrictions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const cookiePattern = /\b(set.?cookie|cookie\s*[:=({]|session.*cookie|cookie.*session)\b/gi;
      const restrictPattern = /\b(domain\s*[:=]|path\s*[:=]|sameSite|samesite|httpOnly|httponly|secure\s*[:=])\b/i;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript, ...graph.files.configs]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        cookiePattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = cookiePattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 400));
          if (!restrictPattern.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-IA-059-${findings.length}`, ruleId: 'AA-IA-059',
              title: 'Cross-origin session sharing',
              description: `Cookie/session config in ${file.relativePath} lacks domain, path, or SameSite restrictions.`,
              severity: 'high', confidence: 'medium', domain: 'identity-access',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Set domain, path, SameSite, HttpOnly, and Secure flags on session cookies to prevent cross-origin sharing.',
              standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-IA-060',
    name: 'No session context validation',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Session context (IP, user-agent, fingerprint) is not validated on subsequent requests, weakening session binding.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sessionUsePattern = /\b(req\.session|request\.session|session\[|get_session|load_session)\b/gi;
      const contextCheckPattern = /\b(ip_address|user_agent|fingerprint|device_id|session_binding|context_valid|verify_context|check_ip|check_fingerprint)\b/i;
      let hasSessionUse = false;
      let hasContextCheck = false;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        try {
          const content = fs.readFileSync(file.path, 'utf-8');
          if (sessionUsePattern.test(content)) hasSessionUse = true;
          sessionUsePattern.lastIndex = 0;
          if (contextCheckPattern.test(content)) hasContextCheck = true;
        } catch { continue; }
      }
      if (hasSessionUse && !hasContextCheck) {
        findings.push({
          id: 'AA-IA-060-0', ruleId: 'AA-IA-060',
          title: 'No session context validation',
          description: 'Session usage detected but no context validation (IP, user-agent, fingerprint) is performed.',
          severity: 'medium', confidence: 'medium', domain: 'identity-access',
          location: { file: graph.files.all[0]?.relativePath ?? 'project', line: 1 },
          remediation: 'Validate session context (IP, user-agent, device fingerprint) on each request to detect session theft.',
          standards: { owaspAgentic: ['ASI03'], iso23894: ['R.3', 'R.4'], owaspAivss: ['AIVSS-AC'], a2asBasic: ['AUTH', 'AUTHZ'] },
        });
      }
      return findings;
    },
  },
];
