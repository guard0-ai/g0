import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  isCommentLine,
} from '../ast/index.js';
import { getKeywordArgBool } from '../ast/python.js';

export const toolSafetyRules: Rule[] = [
  {
    id: 'AA-TS-001',
    name: 'Shell execution tool detected',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Agent has access to a shell execution tool, enabling arbitrary command execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['B003', 'D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MAP-2.3', 'MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('shell')) {
          findings.push({
            id: `AA-TS-001-${findings.length}`,
            ruleId: 'AA-TS-001',
            title: 'Shell execution tool detected',
            description: `Tool "${tool.name}" in ${tool.file} provides shell/command execution capability.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Remove shell execution tool or wrap it with strict input validation and allowlisting.',
            standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['B003', 'D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MAP-2.3', 'MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-002',
    name: 'Raw SQL tool without parameterization',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool allows raw SQL execution, risking SQL injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003', 'D002'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('database') && !tool.hasInputValidation) {
          findings.push({
            id: `AA-TS-002-${findings.length}`,
            ruleId: 'AA-TS-002',
            title: 'Database tool without input validation',
            description: `Tool "${tool.name}" in ${tool.file} accesses a database without apparent input validation.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Use parameterized queries and validate all input before database operations.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003', 'D002'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-003',
    name: 'Filesystem tool without path validation',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool accesses the filesystem without validating paths, risking path traversal.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('filesystem') && !tool.hasInputValidation) {
          findings.push({
            id: `AA-TS-003-${findings.length}`,
            ruleId: 'AA-TS-003',
            title: 'Filesystem tool without path validation',
            description: `Tool "${tool.name}" in ${tool.file} accesses the filesystem without input validation.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Validate and sanitize file paths. Use allowlists for permitted directories.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-004',
    name: 'Tool missing input schema',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'high',
    description: 'Tool has no defined input schema, accepting arbitrary input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.parameters.length === 0 && !tool.hasInputValidation && tool.hasSideEffects) {
          findings.push({
            id: `AA-TS-004-${findings.length}`,
            ruleId: 'AA-TS-004',
            title: 'Side-effect tool missing input schema',
            description: `Tool "${tool.name}" in ${tool.file} has side effects but no defined input schema.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Define explicit input schemas with validation for all tool parameters.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-005',
    name: 'Network access tool detected',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'high',
    description: 'Tool makes network requests, potentially to arbitrary URLs.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('network') && !tool.hasInputValidation) {
          findings.push({
            id: `AA-TS-005-${findings.length}`,
            ruleId: 'AA-TS-005',
            title: 'Unrestricted network access tool',
            description: `Tool "${tool.name}" in ${tool.file} makes network requests without URL validation.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Restrict network tools to allowlisted domains and validate URLs.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-006',
    name: 'Email sending tool detected',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool can send emails, which could be abused for phishing or spam.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('email')) {
          findings.push({
            id: `AA-TS-006-${findings.length}`,
            ruleId: 'AA-TS-006',
            title: 'Email sending tool detected',
            description: `Tool "${tool.name}" in ${tool.file} can send emails. This should require human approval.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Gate email sending behind human approval. Validate recipients and content.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-007',
    name: 'Subprocess or os.system call in tool',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool uses subprocess or os.system for command execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
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
          const astPatterns = [
            { pattern: /^subprocess\.(call|run|Popen|check_output)$/, name: 'subprocess' },
            { pattern: /^os\.system$/, name: 'os.system' },
            { pattern: /^os\.popen$/, name: 'os.popen' },
            { pattern: /^child_process\.exec$/, name: 'child_process.exec' },
            { pattern: /^execSync$/, name: 'execSync' },
          ];

          for (const { pattern, name } of astPatterns) {
            const calls = findFunctionCalls(tree, pattern);
            for (const call of calls) {
              const shellEnabled = getKeywordArgBool(call, 'shell') === true;
              const line = call.startPosition.row + 1;
              findings.push({
                id: `AA-TS-007-${findings.length}`,
                ruleId: 'AA-TS-007',
                title: `${name} call detected${shellEnabled ? ' with shell=True' : ''}`,
                description: `${name} used in ${file.relativePath}${shellEnabled ? ' with shell=True, enabling shell injection' : ''}.`,
                severity: shellEnabled ? 'critical' : 'high',
                confidence: 'high',
                domain: 'tool-safety',
                location: { file: file.relativePath, line, snippet: call.text.substring(0, 60) },
                remediation: shellEnabled
                  ? 'Use shell=False and pass arguments as a list to prevent shell injection.'
                  : 'Validate and sanitize all inputs before passing to subprocess.',
                standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        } else {
          const patterns = [
            { regex: /subprocess\.(?:call|run|Popen|check_output)\s*\(/g, name: 'subprocess' },
            { regex: /os\.system\s*\(/g, name: 'os.system' },
            { regex: /os\.popen\s*\(/g, name: 'os.popen' },
            { regex: /child_process\.exec\s*\(/g, name: 'child_process.exec' },
            { regex: /execSync\s*\(/g, name: 'execSync' },
          ];

          for (const { regex, name } of patterns) {
            regex.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = regex.exec(content)) !== null) {
              if (isCommentLine(content, match.index, file.language)) continue;
              const line = content.substring(0, match.index).split('\n').length;
              const region = content.substring(match.index, match.index + 200);
              const shellEnabled = /shell\s*=\s*True/.test(region);

              findings.push({
                id: `AA-TS-007-${findings.length}`,
                ruleId: 'AA-TS-007',
                title: `${name} call detected${shellEnabled ? ' with shell=True' : ''}`,
                description: `${name} used in ${file.relativePath}${shellEnabled ? ' with shell=True, enabling shell injection' : ''}.`,
                severity: shellEnabled ? 'critical' : 'high',
                confidence: 'high',
                domain: 'tool-safety',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: shellEnabled
                  ? 'Use shell=False and pass arguments as a list to prevent shell injection.'
                  : 'Validate and sanitize all inputs before passing to subprocess.',
                standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-008',
    name: 'Too many tools attached to agent',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Agent has excessive number of tools, increasing attack surface.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.tools.length > 15) {
        findings.push({
          id: `AA-TS-008-0`,
          ruleId: 'AA-TS-008',
          title: 'Excessive number of tools',
          description: `Project has ${graph.tools.length} tools defined. Large tool sets increase the attack surface.`,
          severity: 'medium',
          confidence: 'medium',
          domain: 'tool-safety',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Apply principle of least privilege. Only attach tools the agent actually needs.',
          standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-009',
    name: 'Code execution tool without sandboxing',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool executes code without sandboxing.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('code-execution') && !tool.hasSandboxing) {
          findings.push({
            id: `AA-TS-009-${findings.length}`,
            ruleId: 'AA-TS-009',
            title: 'Code execution tool without sandboxing',
            description: `Tool "${tool.name}" in ${tool.file} executes code without sandboxing.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Run code execution in a sandboxed environment (Docker, E2B, subprocess with restrictions).',
            standards: { owaspAgentic: ['ASI02', 'ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-010',
    name: 'Tool with side effects lacks confirmation',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool has side effects but no human confirmation mechanism.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const dangerousCaps: string[] = ['shell', 'database', 'email', 'filesystem'];
      for (const tool of graph.tools) {
        if (tool.hasSideEffects && tool.capabilities.some(c => dangerousCaps.includes(c))) {
          findings.push({
            id: `AA-TS-010-${findings.length}`,
            ruleId: 'AA-TS-010',
            title: 'Dangerous tool lacks human-in-the-loop',
            description: `Tool "${tool.name}" in ${tool.file} has dangerous capabilities (${tool.capabilities.join(', ')}) without human approval gates.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Implement human-in-the-loop confirmation for dangerous tool actions.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-011',
    name: 'Tool with unrestricted network access',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool has network capability without input validation and no URL allowlist in its description.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (
          tool.capabilities.includes('network') &&
          !tool.hasInputValidation &&
          !/(?:allowlist|whitelist|allowed.?url|permitted.?domain)/i.test(tool.description)
        ) {
          findings.push({
            id: `AA-TS-011-${findings.length}`,
            ruleId: 'AA-TS-011',
            title: 'Tool with unrestricted network access',
            description: `Tool "${tool.name}" in ${tool.file} has network capability without input validation or URL allowlist.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add URL allowlisting and input validation to restrict network access to approved domains.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-012',
    name: 'Tool with broad filesystem write',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool has filesystem capability with side effects and no input validation, allowing broad file writes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (
          tool.capabilities.includes('filesystem') &&
          tool.hasSideEffects &&
          !tool.hasInputValidation &&
          /(?:write|create|delete|overwrite|remove)/i.test(tool.description) &&
          !/(?:restrict|limit|only|allowed.?path|permitted.?dir)/i.test(tool.description)
        ) {
          findings.push({
            id: `AA-TS-012-${findings.length}`,
            ruleId: 'AA-TS-012',
            title: 'Tool with broad filesystem write',
            description: `Tool "${tool.name}" in ${tool.file} can write/create/delete files without path restrictions or input validation.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Restrict filesystem writes to specific directories. Validate and sanitize all paths.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-013',
    name: 'Side-effect tool without confirmation',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool with email, API, or database side effects lacks a confirmation or approval mechanism.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sideEffectCaps = ['email', 'api', 'database'];
      for (const tool of graph.tools) {
        if (tool.hasSideEffects && tool.capabilities.some(c => sideEffectCaps.includes(c))) {
          findings.push({
            id: `AA-TS-013-${findings.length}`,
            ruleId: 'AA-TS-013',
            title: 'Side-effect tool without confirmation (graph)',
            description: `Tool "${tool.name}" in ${tool.file} has side effects (${tool.capabilities.join(', ')}) without a confirmation mechanism.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add human-in-the-loop confirmation before executing side-effect actions like email, API calls, or database writes.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }

      // Scan code files for send/post/publish patterns without confirm/approve nearby
      const sideEffectRegex = /(?:send_email|send_message|post_to|publish)\s*\(/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        sideEffectRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = sideEffectRegex.exec(content)) !== null) {
          const start = Math.max(0, match.index - 300);
          const end = Math.min(content.length, match.index + match[0].length + 300);
          const region = content.substring(start, end);
          if (!/(?:confirm|approve|approval|human.?in.?the.?loop|require_confirmation)/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-013-${findings.length}`,
              ruleId: 'AA-TS-013',
              title: 'Side-effect call without confirmation',
              description: `${match[0].replace(/\s*\($/, '')} in ${file.relativePath} performs a side effect without a confirmation pattern nearby.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add confirmation or approval logic before sending emails, messages, or publishing content.',
              standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-014',
    name: 'Tool description too vague',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool has a description shorter than 20 characters, making it hard for the LLM to use correctly.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002'], iso42001: ['A.8.2'], nistAiRmf: ['MAP-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        // Only flag non-empty descriptions that are too short; empty means parser couldn't extract it
        if (tool.description.length > 0 && tool.description.length < 20) {
          findings.push({
            id: `AA-TS-014-${findings.length}`,
            ruleId: 'AA-TS-014',
            title: 'Tool description too vague',
            description: `Tool "${tool.name}" in ${tool.file} has a description of only ${tool.description.length} characters ("${tool.description}"). Vague descriptions cause incorrect tool usage by the LLM.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Provide a detailed description (20+ characters) explaining what the tool does, its inputs, and its side effects.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002'], iso42001: ['A.8.2'], nistAiRmf: ['MAP-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-015',
    name: 'Agent has too many tools (>15)',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'A single agent has more than 15 tools attached, increasing confusion and attack surface.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const agent of graph.agents) {
        if (agent.tools.length > 15) {
          findings.push({
            id: `AA-TS-015-${findings.length}`,
            ruleId: 'AA-TS-015',
            title: 'Agent has too many tools',
            description: `Agent "${agent.name}" in ${agent.file} has ${agent.tools.length} tools attached. Per-agent tool count exceeds 15, increasing attack surface and potential for misuse.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: agent.file, line: agent.line },
            remediation: 'Reduce the number of tools per agent. Split into specialized agents with fewer, focused tools.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-016',
    name: 'Tool lacks input validation',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool has parameters but none are validated, and the tool has side effects.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (
          tool.parameters.length > 0 &&
          !tool.parameters.some(p => p.hasValidation) &&
          tool.hasSideEffects
        ) {
          findings.push({
            id: `AA-TS-016-${findings.length}`,
            ruleId: 'AA-TS-016',
            title: 'Tool lacks input validation',
            description: `Tool "${tool.name}" in ${tool.file} has ${tool.parameters.length} parameter(s) but none are validated, and the tool has side effects.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add input validation (type checks, length limits, allowlists) to all tool parameters, especially for tools with side effects.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['A002', 'B003'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-017',
    name: 'Tool with delete capability',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool name or description indicates destructive delete/remove/drop/destroy capability without confirmation.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const destructivePattern = /(?:delete|remove|drop|destroy|purge)/i;
      const confirmPattern = /(?:confirm|approval|approve|human.?in.?the.?loop)/i;
      for (const tool of graph.tools) {
        const nameOrDesc = `${tool.name} ${tool.description}`;
        if (destructivePattern.test(nameOrDesc) && !confirmPattern.test(tool.description)) {
          findings.push({
            id: `AA-TS-017-${findings.length}`,
            ruleId: 'AA-TS-017',
            title: 'Tool with delete capability',
            description: `Tool "${tool.name}" in ${tool.file} has destructive capability (delete/remove/drop/destroy/purge) without a confirmation mechanism.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Add human confirmation or approval step before executing destructive operations.',
            standards: { owaspAgentic: ['ASI02', 'ASI09'], aiuc1: ['B003'], iso42001: ['A.8.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-018',
    name: 'Tool can modify agent config',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'medium',
    description: 'Tool can write to configuration files, system prompts, or agent settings, risking self-modification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI10'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const configModifyRegex = /(?:write|save|update|modify).*(?:config|prompt|setting|system_message)/gi;
      const toolContextRegex = /(?:tool|function|def\s|@tool|StructuredTool|BaseTool)/;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        configModifyRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = configModifyRegex.exec(content)) !== null) {
          const start = Math.max(0, match.index - 500);
          const end = Math.min(content.length, match.index + match[0].length + 200);
          const region = content.substring(start, end);
          if (toolContextRegex.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-018-${findings.length}`,
              ruleId: 'AA-TS-018',
              title: 'Tool can modify agent config',
              description: `Code in ${file.relativePath} can modify agent configuration/prompts/settings within a tool context.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Prevent tools from modifying agent configuration, system prompts, or settings. Make config read-only to tool execution.',
              standards: { owaspAgentic: ['ASI02', 'ASI10'], aiuc1: ['B003'], iso42001: ['A.6.2'], nistAiRmf: ['MANAGE-2.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-019',
    name: 'HTTP tool without TLS',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'high',
    description: 'Tool or API call uses plain HTTP instead of HTTPS, exposing data in transit.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], aiuc1: ['E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const httpRegex = /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        httpRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = httpRegex.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-019-${findings.length}`,
            ruleId: 'AA-TS-019',
            title: 'HTTP tool without TLS',
            description: `Plain HTTP URL found in ${file.relativePath} at line ${line}. Data in transit is not encrypted.`,
            severity: 'medium',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: content.substring(match.index, match.index + 60) },
            remediation: 'Use HTTPS instead of HTTP for all external URLs to ensure data is encrypted in transit.',
            standards: { owaspAgentic: ['ASI02'], aiuc1: ['E001'], iso42001: ['A.6.3'], nistAiRmf: ['MANAGE-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-020',
    name: 'Tool timeout not configured',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'HTTP/API calls in tool code lack a timeout configuration, risking indefinite hangs.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02', 'ASI08'], aiuc1: ['B003'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const httpCallRegex = /(?:requests\.(?:get|post|put|patch|delete)|fetch|axios)\s*\(/g;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }
        httpCallRegex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = httpCallRegex.exec(content)) !== null) {
          const start = Math.max(0, match.index - 150);
          const end = Math.min(content.length, match.index + match[0].length + 300);
          const region = content.substring(start, end);
          if (!/timeout/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-020-${findings.length}`,
              ruleId: 'AA-TS-020',
              title: 'Tool timeout not configured',
              description: `HTTP/API call in ${file.relativePath} at line ${line} does not configure a timeout, risking indefinite hangs.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add a timeout parameter to all HTTP/API calls (e.g., requests.get(url, timeout=30), fetch with AbortController).',
              standards: { owaspAgentic: ['ASI02', 'ASI08'], aiuc1: ['B003'], iso42001: ['A.9.2'], nistAiRmf: ['MANAGE-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-021',
    name: 'Tool with unrestricted network access',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool has network capabilities but no URL filtering or domain allowlist.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:requests\.(?:get|post|put|delete)|fetch|urllib|httpx\.(?:get|post)|aiohttp)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          if (!/allowlist|whitelist|allowed_url|allowed_domain|url_filter|domain_check/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-021-${findings.length}`, ruleId: 'AA-TS-021',
              title: 'Tool with unrestricted network access',
              description: `Network call in tool code in ${file.relativePath} has no URL filtering or allowlist.`,
              severity: 'high', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add URL allowlisting to restrict network access to approved domains only.',
              standards: { owaspAgentic: ['ASI02'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-022',
    name: 'Tool without timeout',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool function makes external calls without configuring a timeout.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:requests\.(?:get|post|put|delete)|fetch|httpx\.(?:get|post)|urllib\.request\.urlopen)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 300));
          if (!/timeout/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-022-${findings.length}`, ruleId: 'AA-TS-022',
              title: 'Tool without timeout',
              description: `External call in tool code in ${file.relativePath} lacks a timeout parameter.`,
              severity: 'high', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add timeout parameter to all external calls in tools (e.g., timeout=30).',
              standards: { owaspAgentic: ['ASI02'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-023',
    name: 'Tool output not size-limited',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'low',
    description: 'Tool returns unbounded data without size limits, risking context overflow.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool)/;
        if (!toolContext.test(content)) continue;
        const pattern = /return\s+(?:response\.text|response\.json\(\)|result|data|output)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 200));
          if (!/truncat|limit|max_len|[:]\s*\d+|slice|substring|\.head/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-023-${findings.length}`, ruleId: 'AA-TS-023',
              title: 'Tool output not size-limited',
              description: `Tool in ${file.relativePath} returns data without apparent size limits.`,
              severity: 'high', confidence: 'low', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Truncate or limit tool output size to prevent context window overflow.',
              standards: { owaspAgentic: ['ASI02'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-024',
    name: 'Tool with write to shared state',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool modifies global or shared state, risking unintended side effects.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:global\s+\w+|globals\(\)|shared_state|app\.state|os\.environ)\s*[\[=]/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-024-${findings.length}`, ruleId: 'AA-TS-024',
            title: 'Tool with write to shared state',
            description: `Tool code in ${file.relativePath} modifies global or shared state.`,
            severity: 'high', confidence: 'medium', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Avoid modifying global state from tools. Use return values and let the agent framework manage state.',
            standards: { owaspAgentic: ['ASI02'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-025',
    name: 'Tool can invoke other tools (chaining)',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool invokes other tools directly, enabling uncontrolled tool chaining.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool)/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:tool\.run|tool\.invoke|tool\.execute|tools\[\w+\]\.run|\.run_tool\(|agent\.run)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-025-${findings.length}`, ruleId: 'AA-TS-025',
            title: 'Tool can invoke other tools (chaining)',
            description: `Tool in ${file.relativePath} invokes other tools, enabling uncontrolled chaining.`,
            severity: 'high', confidence: 'medium', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Avoid tool-to-tool invocation. Let the agent framework control tool orchestration.',
            standards: { owaspAgentic: ['ASI02'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-026',
    name: 'Tool description mismatch with impl',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'low',
    description: 'Tool description does not match its actual capabilities, misleading the LLM.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        const desc = tool.description.toLowerCase();
        const caps = tool.capabilities;
        // Check if capabilities suggest actions not mentioned in description
        if (caps.includes('shell') && !/shell|command|exec/i.test(desc)) {
          findings.push({
            id: `AA-TS-026-${findings.length}`, ruleId: 'AA-TS-026',
            title: 'Tool description mismatch with impl',
            description: `Tool "${tool.name}" in ${tool.file} has shell capability but description doesn't mention it.`,
            severity: 'medium', confidence: 'low', domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Update tool descriptions to accurately reflect all capabilities, especially dangerous ones.',
            standards: { owaspAgentic: ['ASI02'] },
          });
        }
        if (caps.includes('database') && !/database|sql|db|query/i.test(desc)) {
          findings.push({
            id: `AA-TS-026-${findings.length}`, ruleId: 'AA-TS-026',
            title: 'Tool description mismatch with impl',
            description: `Tool "${tool.name}" in ${tool.file} has database capability but description doesn't mention it.`,
            severity: 'medium', confidence: 'low', domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Update tool descriptions to accurately reflect all capabilities.',
            standards: { owaspAgentic: ['ASI02'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-027',
    name: 'Tool with no rate limiting',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool lacks rate limiting, allowing potential abuse through rapid invocations.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const hasExternalCall = /(?:requests\.|fetch|httpx\.|subprocess|send_email|execute_query)/i.test(content);
        if (hasExternalCall && !/rate.?limit|throttle|RateLimiter|@ratelimit|slowapi|limiter/i.test(content)) {
          findings.push({
            id: `AA-TS-027-${findings.length}`, ruleId: 'AA-TS-027',
            title: 'Tool with no rate limiting',
            description: `Tool code in ${file.relativePath} makes external calls without rate limiting.`,
            severity: 'medium', confidence: 'medium', domain: 'tool-safety',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Add rate limiting to tools that make external calls (e.g., @ratelimit decorator, throttle middleware).',
            standards: { owaspAgentic: ['ASI02'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-028',
    name: 'Tool params without type validation',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool parameters lack type annotations or validation schemas.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /@tool\s*\n\s*def\s+(\w+)\s*\(([^)]*)\)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const params = match[2];
          if (params && params.trim() && !params.includes(':')) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-028-${findings.length}`, ruleId: 'AA-TS-028',
              title: 'Tool params without type validation',
              description: `Tool "${match[1]}" in ${file.relativePath} has parameters without type annotations.`,
              severity: 'medium', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Add type annotations to all tool parameters (e.g., def my_tool(query: str, limit: int)).',
              standards: { owaspAgentic: ['ASI02'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-029',
    name: 'Email tool without recipient filtering',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Email sending tool lacks recipient validation or allowlist filtering.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:send_email|smtp\.send|sendmail|send_mail|\.send\(\s*(?:to|recipient))/gi;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          if (!/allowlist|whitelist|allowed_recipient|validate_recipient|approved_domain|recipient_filter/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-029-${findings.length}`, ruleId: 'AA-TS-029',
              title: 'Email tool without recipient filtering',
              description: `Email sending in ${file.relativePath} lacks recipient validation or allowlist.`,
              severity: 'high', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Add recipient allowlisting or validation to prevent sending emails to unauthorized addresses.',
              standards: { owaspAgentic: ['ASI02'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-030',
    name: 'API tool without response validation',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'API-calling tool does not validate responses before processing them.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:response\s*=\s*(?:requests|httpx|fetch|axios)[\s\S]*?return\s+response)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + match[0].length + 200));
          if (!/validate|schema|assert|status_code|raise_for_status|\.ok\b/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-030-${findings.length}`, ruleId: 'AA-TS-030',
              title: 'API tool without response validation',
              description: `API call in tool in ${file.relativePath} returns response without validation.`,
              severity: 'medium', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: 'response returned without validation' },
              remediation: 'Validate API responses (check status code, validate schema) before returning from tools.',
              standards: { owaspAgentic: ['ASI02'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-031',
    name: 'File system tool without path restrictions',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'File read/write tool lacks allowed_paths or path restriction configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:open\s*\(|readFile|writeFile|fs\.read|fs\.write|pathlib\.Path)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          if (!/allowed_path|restrict_path|base_dir|safe_dir|allowlist|chroot|sandbox_dir/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-031-${findings.length}`, ruleId: 'AA-TS-031',
              title: 'File system tool without path restrictions',
              description: `File operation in tool code in ${file.relativePath} has no allowed_paths or path restriction.`,
              severity: 'high', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Configure allowed_paths or base_dir restrictions on file system tools to prevent path traversal.',
              standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-032',
    name: 'Database tool without query limits',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'SQL/database tool lacks query timeout or row limit configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:execute|query|cursor\.execute|\.raw\(|\.sql\(|sequelize\.query)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 500));
          if (!/timeout|max_rows|row_limit|LIMIT\s+\d|statement_timeout|query_timeout|fetchmany/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-032-${findings.length}`, ruleId: 'AA-TS-032',
              title: 'Database tool without query limits',
              description: `Database query in tool code in ${file.relativePath} has no timeout or row limit.`,
              severity: 'high', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add query timeout and row limits (e.g., LIMIT clause, statement_timeout, max_rows) to database tools.',
              standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-033',
    name: 'HTTP tool follows redirects blindly',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'HTTP requests/fetch calls do not limit redirects, risking SSRF via redirect chains.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:requests\.(?:get|post|put|delete|patch)|httpx\.(?:get|post|put|delete)|fetch)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 400));
          if (!/max_redirect|allow_redirects\s*=\s*False|redirect\s*[:=]\s*["'](?:manual|error)|follow\s*[:=]\s*(?:false|0)/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-033-${findings.length}`, ruleId: 'AA-TS-033',
              title: 'HTTP tool follows redirects blindly',
              description: `HTTP call in tool code in ${file.relativePath} does not limit or disable redirects.`,
              severity: 'medium', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Set max_redirects or disable redirects (allow_redirects=False) and validate redirect targets.',
              standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-034',
    name: 'Tool output used as code input',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'high',
    description: 'Tool result is passed to eval, exec, or Function constructor, enabling code injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:eval|exec|Function)\s*\(\s*(?:tool_output|tool_result|result|response\.text|output)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-034-${findings.length}`, ruleId: 'AA-TS-034',
            title: 'Tool output used as code input',
            description: `Tool output passed to eval/exec/Function in ${file.relativePath}, enabling code injection.`,
            severity: 'critical', confidence: 'high', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Never pass tool outputs to eval/exec/Function. Parse structured data instead of executing it.',
            standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-035',
    name: 'Tool with admin/root privileges',
    domain: 'tool-safety',
    severity: 'critical',
    confidence: 'medium',
    description: 'Tool runs with elevated admin/root permissions, risking full system compromise.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:sudo\s|run_as_root|admin_mode|privilege[ds]?\s*=\s*True|setuid|seteuid|as_superuser|root_access)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-035-${findings.length}`, ruleId: 'AA-TS-035',
            title: 'Tool with admin/root privileges',
            description: `Tool code in ${file.relativePath} uses elevated privileges (${match[0].trim()}).`,
            severity: 'critical', confidence: 'medium', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Run tools with least-privilege permissions. Never grant admin/root access to agent tools.',
            standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-036',
    name: 'Tool modifies agent state',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool can alter agent configuration, memory, or runtime state.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:agent\.(?:config|memory|state|system_prompt)|self\.agent\.|update_agent_config|modify_memory|set_system_prompt)\s*[=(]/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-036-${findings.length}`, ruleId: 'AA-TS-036',
            title: 'Tool modifies agent state',
            description: `Tool code in ${file.relativePath} modifies agent configuration or memory state.`,
            severity: 'high', confidence: 'medium', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Tools should not modify agent state directly. Use immutable agent config and return values for state changes.',
            standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-037',
    name: 'Tool with undocumented side effects',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool description does not mention write, delete, or send operations that the tool performs.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (!tool.hasSideEffects) continue;
        const desc = tool.description.toLowerCase();
        const hasSideEffectMention = /write|delete|send|create|update|modify|remove|post|put|patch|mutate/i.test(desc);
        if (!hasSideEffectMention && desc.length > 0) {
          findings.push({
            id: `AA-TS-037-${findings.length}`, ruleId: 'AA-TS-037',
            title: 'Tool with undocumented side effects',
            description: `Tool "${tool.name}" in ${tool.file} has side effects but description does not mention writes/deletes/sends.`,
            severity: 'high', confidence: 'medium', domain: 'tool-safety',
            location: { file: tool.file, line: tool.line },
            remediation: 'Update tool description to explicitly mention all side effects (write, delete, send, modify).',
            standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-038',
    name: 'Tool spawns subprocesses',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'Tool creates child processes, enabling arbitrary command execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:subprocess\.(?:Popen|run|call|check_output)|child_process\.(?:spawn|exec|fork)|os\.(?:system|popen|exec[lv]?p?e?))\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-038-${findings.length}`, ruleId: 'AA-TS-038',
            title: 'Tool spawns subprocesses',
            description: `Tool code in ${file.relativePath} spawns a child process via ${match[0].replace(/\s*\($/, '')}.`,
            severity: 'high', confidence: 'high', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Avoid spawning subprocesses from tools. Use library APIs instead, or sandbox subprocess execution.',
            standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-039',
    name: 'Tool accesses environment variables',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool reads environment variables, which may contain secrets or sensitive configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /(?:os\.environ|os\.getenv|process\.env)\s*[\[.]/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-TS-039-${findings.length}`, ruleId: 'AA-TS-039',
            title: 'Tool accesses environment variables',
            description: `Tool code in ${file.relativePath} reads environment variables which may contain secrets.`,
            severity: 'medium', confidence: 'medium', domain: 'tool-safety',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Pass configuration explicitly to tools instead of reading env vars. Use a secrets manager for sensitive values.',
            standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-TS-040',
    name: 'Tool output not size-limited',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Tool results have no max_output_length or truncation, risking context window overflow.',
    frameworks: ['all'],
    owaspAgentic: ['ASI02'],
    standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const toolContext = /(?:@tool|def\s+\w+_tool|StructuredTool|BaseTool|\.tool\()/;
        if (!toolContext.test(content)) continue;
        const pattern = /return\s+(?:str\(|json\.dumps\(|\.read\(\)|\.text|\.content|\.decode\(\))/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 500), Math.min(content.length, match.index + 300));
          if (!/max_output|truncat|[:]\s*\d+\]|\.substring\(|\.slice\(|max_len|output_limit/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-TS-040-${findings.length}`, ruleId: 'AA-TS-040',
              title: 'Tool output not size-limited',
              description: `Tool in ${file.relativePath} returns data without output size limiting.`,
              severity: 'medium', confidence: 'medium', domain: 'tool-safety',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add max_output_length or truncation to tool results to prevent context window overflow.',
              standards: { owaspAgentic: ['ASI02'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-TA'], a2asBasic: ['AUTHZ', 'AUDIT'] },
            });
          }
        }
      }
      return findings;
    },
  },
];
