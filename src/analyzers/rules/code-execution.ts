import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  getCallArgument,
  isCommentLine,
} from '../ast/index.js';

export const codeExecutionRules: Rule[] = [
  {
    id: 'AA-CE-001',
    name: 'eval() with dynamic input',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'eval() used with potentially user-controlled input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
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
          const evalCalls = findFunctionCalls(tree, 'eval');
          for (const call of evalCalls) {
            const arg = getCallArgument(call, 0);
            if (arg && (arg.type === 'string' || arg.type === 'string_literal')) continue;

            const line = call.startPosition.row + 1;
            const snippet = call.text.substring(0, 60);
            findings.push({
              id: `AA-CE-001-${findings.length}`,
              ruleId: 'AA-CE-001',
              title: 'eval() with dynamic input',
              description: `eval() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet },
              remediation: 'Remove eval() usage. Use safe alternatives like JSON.parse() or ast.literal_eval().',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        } else {
          const evalPattern = /\beval\s*\(/g;
          let match: RegExpExecArray | null;
          while ((match = evalPattern.exec(content)) !== null) {
            if (isCommentLine(content, match.index, file.language)) continue;
            const line = content.substring(0, match.index).split('\n').length;
            const region = content.substring(match.index, match.index + 200);
            const hasVariable = !/^eval\s*\(\s*["'`]/.test(region);

            if (hasVariable) {
              findings.push({
                id: `AA-CE-001-${findings.length}`,
                ruleId: 'AA-CE-001',
                title: 'eval() with dynamic input',
                description: `eval() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
                severity: 'critical',
                confidence: 'high',
                domain: 'code-execution',
                location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
                remediation: 'Remove eval() usage. Use safe alternatives like JSON.parse() or ast.literal_eval().',
                standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-002',
    name: 'exec() with dynamic input',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'exec() used with potentially user-controlled input (Python).',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const tree = isTreeSitterAvailable() ? getFileTreeForLang(file.path, content, 'python') : null;

        if (tree) {
          const execCalls = findFunctionCalls(tree, 'exec');
          for (const call of execCalls) {
            const arg = getCallArgument(call, 0);
            if (arg && (arg.type === 'string' || arg.type === 'string_literal')) continue;

            const line = call.startPosition.row + 1;
            const snippet = call.text.substring(0, 60);
            findings.push({
              id: `AA-CE-002-${findings.length}`,
              ruleId: 'AA-CE-002',
              title: 'exec() with dynamic input',
              description: `exec() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet },
              remediation: 'Remove exec() usage. Use safe alternatives or sandboxed code execution.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        } else {
          const execPattern = /\bexec\s*\(/g;
          let match: RegExpExecArray | null;
          while ((match = execPattern.exec(content)) !== null) {
            if (isCommentLine(content, match.index, file.language)) continue;
            const line = content.substring(0, match.index).split('\n').length;
            const region = content.substring(match.index, match.index + 200);
            const hasVariable = !/^exec\s*\(\s*["']/.test(region);

            if (hasVariable) {
              findings.push({
                id: `AA-CE-002-${findings.length}`,
                ruleId: 'AA-CE-002',
                title: 'exec() with dynamic input',
                description: `exec() in ${file.relativePath} uses dynamic input that may be user-controlled.`,
                severity: 'critical',
                confidence: 'high',
                domain: 'code-execution',
                location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
                remediation: 'Remove exec() usage. Use safe alternatives or sandboxed code execution.',
                standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-003',
    name: 'new Function() constructor',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'new Function() creates code from strings, similar to eval().',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const funcPattern = /new\s+Function\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = funcPattern.exec(content)) !== null) {
          if (isCommentLine(content, match.index, file.language)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-003-${findings.length}`,
            ruleId: 'AA-CE-003',
            title: 'new Function() constructor used',
            description: `new Function() in ${file.relativePath} creates executable code from strings.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Remove new Function() usage. Use safe alternatives.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-004',
    name: 'Python compile() with dynamic input',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'compile() used with potentially dynamic input in Python.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const compilePattern = /\bcompile\s*\([^)]*,\s*["'][^"']*["']\s*,\s*["']exec["']\s*\)/g;
        let match: RegExpExecArray | null;
        while ((match = compilePattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-004-${findings.length}`,
            ruleId: 'AA-CE-004',
            title: 'compile() with exec mode',
            description: `compile() in ${file.relativePath} used in exec mode to create executable code.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use safe alternatives to compile()+exec. Consider ast.literal_eval() for data parsing.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-005',
    name: 'PythonREPL or code interpreter without sandbox',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Python REPL or code interpreter tool used without sandboxing.',
    frameworks: ['langchain', 'crewai'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.5.4'], nistAiRmf: ['MEASURE-1.1', 'MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const replPatterns = [
          /PythonREPLTool/g,
          /PythonREPL/g,
          /PythonAstREPLTool/g,
          /CodeInterpreterTool/g,
        ];

        for (const pattern of replPatterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            const region = content.substring(Math.max(0, match.index - 500), match.index + 500);
            const hasSandbox = /sandbox|docker|container|e2b|modal/i.test(region);

            if (!hasSandbox) {
              findings.push({
                id: `AA-CE-005-${findings.length}`,
                ruleId: 'AA-CE-005',
                title: 'Code execution tool without sandbox',
                description: `${match[0]} in ${file.relativePath} executes code without apparent sandboxing.`,
                severity: 'critical',
                confidence: 'high',
                domain: 'code-execution',
                location: { file: file.relativePath, line, snippet: match[0] },
                remediation: 'Run code execution tools in a sandboxed environment (Docker, E2B, etc.).',
                standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.5.4'], nistAiRmf: ['MEASURE-1.1', 'MAP-2.3'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-006',
    name: 'pickle.loads or marshal.loads',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Deserialization of untrusted data can lead to arbitrary code execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const deserialPatterns = [
          { regex: /pickle\.loads?\s*\(/g, name: 'pickle.load' },
          { regex: /marshal\.loads?\s*\(/g, name: 'marshal.load' },
          { regex: /shelve\.open\s*\(/g, name: 'shelve.open' },
          { regex: /yaml\.load\s*\(/g, name: 'yaml.load (unsafe)', safeGuard: /SafeLoader|CSafeLoader|yaml\.safe_load/ },
        ];

        for (const { regex, name, safeGuard } of deserialPatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            // For yaml.load, check if SafeLoader is used on the same or next line
            if (safeGuard) {
              const lineStart = content.lastIndexOf('\n', match.index) + 1;
              const nextLineEnd = content.indexOf('\n', content.indexOf('\n', match.index) + 1);
              const region = content.substring(lineStart, nextLineEnd === -1 ? undefined : nextLineEnd);
              if (safeGuard.test(region)) continue;
            }
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-006-${findings.length}`,
              ruleId: 'AA-CE-006',
              title: `Unsafe deserialization: ${name}`,
              description: `${name} in ${file.relativePath} can execute arbitrary code when deserializing untrusted data.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: `Use safe alternatives (json.loads, yaml.safe_load). Never deserialize untrusted data with ${name}.`,
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-007',
    name: 'subprocess.Popen with shell=True',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'subprocess.Popen with shell=True allows shell injection via untrusted input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /subprocess\.Popen\s*\([^)]*shell\s*=\s*True/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-007-${findings.length}`,
            ruleId: 'AA-CE-007',
            title: 'subprocess.Popen with shell=True',
            description: `subprocess.Popen(shell=True) in ${file.relativePath} allows shell injection attacks.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use subprocess.Popen with shell=False (default) and pass arguments as a list.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-008',
    name: 'os.system() call',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'os.system() executes commands via the shell, enabling shell injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /os\.system\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-008-${findings.length}`,
            ruleId: 'AA-CE-008',
            title: 'os.system() call detected',
            description: `os.system() in ${file.relativePath} executes commands via the shell, enabling injection attacks.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Replace os.system() with subprocess.run() using a list of arguments and shell=False.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-009',
    name: 'child_process.exec() in Node',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'child_process.exec() runs commands in a shell, enabling command injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const patterns = [
          /(?:require\s*\(\s*["']child_process["']\s*\)|child_process)\.exec\s*\(/g,
          /\bexecSync\s*\(/g,
        ];

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-009-${findings.length}`,
              ruleId: 'AA-CE-009',
              title: 'child_process.exec() usage detected',
              description: `child_process exec in ${file.relativePath} runs commands in a shell, enabling injection.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use child_process.execFile() or child_process.spawn() instead of exec/execSync to avoid shell injection.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-010',
    name: 'Template injection risk',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Server-side template rendering with potential user input can lead to template injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /Jinja2|Environment\s*\(.*loader|Template\s*\(.*render|Handlebars\.compile/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          const regionStart = Math.max(0, match.index - 500);
          const regionEnd = Math.min(content.length, match.index + 500);
          const region = content.substring(regionStart, regionEnd);
          const hasUserInput = /user_input|request\.|req\.|params|query/i.test(region);

          if (hasUserInput) {
            findings.push({
              id: `AA-CE-010-${findings.length}`,
              ruleId: 'AA-CE-010',
              title: 'Template injection risk',
              description: `Template rendering in ${file.relativePath} may use user-controlled input, risking server-side template injection.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Avoid passing user input directly into templates. Use sandboxed template environments and validate all inputs.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-011',
    name: 'SSRF in requests/fetch',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'HTTP requests using variable URLs may be vulnerable to server-side request forgery (SSRF).',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /(?:requests\.get|requests\.post|fetch|urllib\.request\.urlopen)\s*\(\s*(?!["']https?:)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-011-${findings.length}`,
            ruleId: 'AA-CE-011',
            title: 'Potential SSRF via variable URL',
            description: `HTTP request in ${file.relativePath} uses a variable URL argument, which may allow SSRF attacks.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Validate and allowlist URLs before making HTTP requests. Block internal/private IP ranges.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-012',
    name: 'SQL string concatenation',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'SQL queries built via string concatenation or interpolation are vulnerable to SQL injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        // Logging/print calls are never SQL — skip lines that are clearly log statements
        const loggingPrefixRe = /^\s*(?:logger\.\w+|logging\.\w+|log\.\w+|print\s*\(|console\.(?:log|warn|error|info|debug)|System\.out\.print|println)/;

        // SQL keywords must be standalone words (\b) to avoid matching identifiers
        // like "select_obj", "delete_flag", "update_count", etc.
        // Also require a structural SQL keyword (FROM, INTO, TABLE, WHERE, SET, VALUES)
        // to confirm it's actually a SQL statement.
        const sqlStructuralRe = /\b(?:FROM|INTO|TABLE|WHERE|SET|VALUES|JOIN|HAVING|GROUP\s+BY|ORDER\s+BY)\b/i;

        const patterns: RegExp[] = [];
        if (file.language === 'python') {
          patterns.push(/f["'].*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{/gi);
        }
        if (file.language === 'typescript' || file.language === 'javascript') {
          patterns.push(/`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`]*\$\{/gi);
        }
        patterns.push(/"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^"]*"\s*\+/gi);

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;

            // Extract the full source line for context checks
            const lines = content.split('\n');
            const sourceLine = lines[line - 1] ?? '';

            // Skip logging/print statements — these are never SQL
            if (loggingPrefixRe.test(sourceLine)) continue;

            // Require a structural SQL keyword to confirm it's actually a query
            if (!sqlStructuralRe.test(sourceLine) && !sqlStructuralRe.test(match[0])) continue;

            findings.push({
              id: `AA-CE-012-${findings.length}`,
              ruleId: 'AA-CE-012',
              title: 'SQL injection via string concatenation',
              description: `SQL query in ${file.relativePath} is built using string interpolation or concatenation, risking SQL injection.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use parameterized queries or prepared statements instead of string concatenation for SQL.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-013',
    name: 'XML external entity processing',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'XML parsing without defusedxml may be vulnerable to XXE (XML External Entity) attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /(?:lxml|xml)\.etree/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const hasDefusedxml = /defusedxml/i.test(content);
          if (!hasDefusedxml) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-013-${findings.length}`,
              ruleId: 'AA-CE-013',
              title: 'XML parsing without defusedxml',
              description: `${match[0]} in ${file.relativePath} parses XML without defusedxml, risking XXE attacks.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Use defusedxml instead of lxml.etree or xml.etree to prevent XXE attacks.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['A002'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-014',
    name: 'LLM output executed as code',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'exec() or eval() called on a variable likely containing LLM output enables arbitrary code execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A003'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /(?:exec|eval)\s*\(\s*(?:response|result|output|completion|message|content|answer|reply)/gi;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-014-${findings.length}`,
            ruleId: 'AA-CE-014',
            title: 'LLM output executed as code',
            description: `exec/eval in ${file.relativePath} is called on a variable that likely contains LLM output, enabling arbitrary code execution.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Never pass LLM output to exec() or eval(). Use a sandboxed code interpreter or safe parsing instead.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001', 'A003'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-015',
    name: 'Dynamic import/require',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Dynamic import or require with a variable argument can load arbitrary modules.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const patterns: RegExp[] = [];
        if (file.language === 'python') {
          patterns.push(/importlib\.import_module\s*\(\s*(?!["'])/g);
        }
        if (file.language === 'typescript' || file.language === 'javascript') {
          patterns.push(/require\s*\(\s*(?!["'])/g);
          patterns.push(/import\s*\(\s*(?!["'])/g);
        }

        for (const pattern of patterns) {
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-015-${findings.length}`,
              ruleId: 'AA-CE-015',
              title: 'Dynamic import/require with variable argument',
              description: `Dynamic module loading in ${file.relativePath} uses a variable argument, which can load arbitrary code.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use static imports or maintain an allowlist of permitted modules for dynamic imports.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MAP-2.3'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-016',
    name: 'Unsandboxed Docker socket access',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Direct access to the Docker socket allows arbitrary container and host-level operations.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const pattern = /\/var\/run\/docker\.sock|docker\.from_env|DockerClient/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-016-${findings.length}`,
            ruleId: 'AA-CE-016',
            title: 'Unsandboxed Docker socket access',
            description: `Docker socket access in ${file.relativePath} allows arbitrary container operations without sandboxing.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Avoid mounting the Docker socket directly. Use a restricted Docker API proxy or rootless Docker.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3', 'A.6.2'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-017',
    name: 'pickle.loads with untrusted input',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'pickle.loads() called with a non-literal argument can execute arbitrary code during deserialization.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /pickle\.loads\s*\(\s*(?!b["'])/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-017-${findings.length}`,
            ruleId: 'AA-CE-017',
            title: 'pickle.loads with untrusted input',
            description: `pickle.loads() in ${file.relativePath} deserializes a non-literal value, risking arbitrary code execution.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0] },
            remediation: 'Never unpickle untrusted data. Use json.loads() or a safe serialization format instead.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-018',
    name: 'yaml.load without SafeLoader',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'yaml.load() without Loader=yaml.SafeLoader can execute arbitrary Python objects.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /yaml\.load\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 200));
          if (/SafeLoader|safe_load|CSafeLoader/.test(region)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-018-${findings.length}`,
            ruleId: 'AA-CE-018',
            title: 'yaml.load without SafeLoader',
            description: `yaml.load() in ${file.relativePath} is called without SafeLoader, allowing arbitrary code execution.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
            remediation: 'Use yaml.safe_load() or pass Loader=yaml.SafeLoader to yaml.load().',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-019',
    name: 'Function() constructor with dynamic input',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'new Function() with non-literal arguments creates executable code from dynamic strings.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /new\s+Function\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 200));
          const hasDynamic = !/^new\s+Function\s*\(\s*["'`]/.test(region);
          if (!hasDynamic) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-019-${findings.length}`,
            ruleId: 'AA-CE-019',
            title: 'Function() constructor with dynamic input',
            description: `new Function() in ${file.relativePath} uses a dynamic argument, equivalent to eval().`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
            remediation: 'Avoid new Function() with dynamic input. Use safe alternatives or a sandboxed environment.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-020',
    name: 'child_process.exec with string command',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'child_process.exec() with template literals or concatenated strings enables command injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /\bexec\s*\(\s*(?:`[^`]*\$\{|[a-zA-Z_]\w*\s*\+)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-020-${findings.length}`,
            ruleId: 'AA-CE-020',
            title: 'exec() with dynamic string command',
            description: `exec() in ${file.relativePath} uses template literal or concatenation, enabling command injection.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use execFile() or spawn() with argument arrays instead of exec() with string commands.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-021',
    name: 'Template engine SSTI',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Server-side template injection via render_template_string, Template(), or Jinja2 with user input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /render_template_string\s*\(|Template\s*\(\s*(?!["'])|Jinja2\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const regionStart = Math.max(0, match.index - 300);
          const region = content.substring(regionStart, Math.min(content.length, match.index + 300));
          const hasUserInput = /user_input|request\.|req\.|params|query|input|args/i.test(region);
          if (!hasUserInput) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-021-${findings.length}`,
            ruleId: 'AA-CE-021',
            title: 'Template engine SSTI risk',
            description: `Template rendering in ${file.relativePath} with user input may allow server-side template injection.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Never pass user input directly into template strings. Use render_template() with named templates instead.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-022',
    name: 'SQL string concatenation (broad)',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'SQL queries built with string concatenation or f-strings are vulnerable to SQL injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const patterns: RegExp[] = [
          /(?:execute|query|cursor\.execute)\s*\(\s*f["']/gi,
          /(?:execute|query|cursor\.execute)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"']*["']\s*\+/gi,
          /(?:execute|query|cursor\.execute)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"']*["']\s*%/gi,
          /(?:execute|query|cursor\.execute)\s*\(\s*["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^"']*["']\.format\s*\(/gi,
        ];
        for (const pat of patterns) {
          pat.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pat.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-022-${findings.length}`,
              ruleId: 'AA-CE-022',
              title: 'SQL injection via string construction',
              description: `SQL query in ${file.relativePath} uses string concatenation/interpolation, risking SQL injection.`,
              severity: 'critical',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Use parameterized queries or an ORM instead of string-built SQL.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-023',
    name: 'Shell command string construction',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Building shell commands via string concatenation or interpolation enables command injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:cmd|command|shell_cmd|shell_command)\s*=\s*(?:f["']|["'][^"']*["']\s*\+|`[^`]*\$\{)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-023-${findings.length}`,
            ruleId: 'AA-CE-023',
            title: 'Shell command string construction',
            description: `Shell command in ${file.relativePath} is built via string concatenation or interpolation.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use subprocess with argument lists instead of building shell command strings.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-024',
    name: 'Dynamic import with user path',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: '__import__() or importlib.import_module() with a variable allows loading arbitrary modules.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /__import__\s*\(\s*(?!["'])|importlib\.import_module\s*\(\s*(?!["'])/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-024-${findings.length}`,
            ruleId: 'AA-CE-024',
            title: 'Dynamic import with variable path',
            description: `Dynamic import in ${file.relativePath} uses a variable argument, allowing arbitrary module loading.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use static imports or maintain an allowlist of permitted module names.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-025',
    name: 'Deserialization of untrusted data',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'high',
    description: 'Unsafe deserialization via jsonpickle, dill, or cloudpickle can execute arbitrary code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const deserialPatterns = [
          { regex: /jsonpickle\.decode\s*\(/g, name: 'jsonpickle.decode' },
          { regex: /dill\.loads?\s*\(/g, name: 'dill.load' },
          { regex: /cloudpickle\.loads?\s*\(/g, name: 'cloudpickle.load' },
        ];
        for (const { regex, name } of deserialPatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-025-${findings.length}`,
              ruleId: 'AA-CE-025',
              title: `Unsafe deserialization: ${name}`,
              description: `${name} in ${file.relativePath} deserializes data that may execute arbitrary code.`,
              severity: 'high',
              confidence: 'high',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: `Replace ${name} with json.loads() or another safe serialization format.`,
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-026',
    name: 'Regex from user input (ReDoS)',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Compiling regex from user-controlled input can lead to ReDoS (Regular Expression Denial of Service).',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const patterns: RegExp[] = [];
        if (file.language === 'python') {
          patterns.push(/re\.compile\s*\(\s*(?!r?["'])/g);
        }
        if (file.language === 'typescript' || file.language === 'javascript') {
          patterns.push(/new\s+RegExp\s*\(\s*(?!["'`])/g);
        }
        for (const pat of patterns) {
          pat.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pat.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-CE-026-${findings.length}`,
              ruleId: 'AA-CE-026',
              title: 'Regex compiled from dynamic input (ReDoS risk)',
              description: `Regex in ${file.relativePath} is compiled from a variable, risking ReDoS attacks.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'code-execution',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Validate and sanitize regex patterns from user input. Set timeouts on regex execution.',
              standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-027',
    name: 'LDAP filter string construction',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'LDAP filters built via string concatenation or interpolation enable LDAP injection attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:ldap_filter|filter_str|search_filter)\s*=\s*(?:f["']|["'][^"']*["']\s*\+|`[^`]*\$\{)|\.search(?:_s)?\s*\(\s*[^,]*,\s*(?:f["']|["'][^"']*["']\s*\+)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-027-${findings.length}`,
            ruleId: 'AA-CE-027',
            title: 'LDAP filter string construction',
            description: `LDAP filter in ${file.relativePath} is built with string concatenation, risking LDAP injection.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use parameterized LDAP queries or escape special characters in filter values.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-028',
    name: 'XPath/XML query construction',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'XPath queries built with variable interpolation enable XPath injection attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /\.xpath\s*\(\s*(?:f["']|["'][^"']*["']\s*\+|`[^`]*\$\{)|\.find\s*\(\s*(?:f["'].*\/|["'][^"']*\/[^"']*["']\s*\+)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-028-${findings.length}`,
            ruleId: 'AA-CE-028',
            title: 'XPath query with variable interpolation',
            description: `XPath query in ${file.relativePath} uses variable interpolation, risking XPath injection.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use parameterized XPath queries or escape user input before embedding in XPath expressions.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-029',
    name: 'LLM output piped to exec',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'high',
    description: 'LLM response passed to exec, eval, or os.system enables arbitrary code execution.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:exec|eval|os\.system|subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\(\s*(?:llm_output|ai_response|model_output|generated_code|chat_response|agent_output|llm_result|completion_text)/gi;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-029-${findings.length}`,
            ruleId: 'AA-CE-029',
            title: 'LLM output piped to exec/eval/system',
            description: `LLM output in ${file.relativePath} is passed to a code execution function, enabling arbitrary execution.`,
            severity: 'high',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Never pass LLM output directly to code execution functions. Use a sandboxed interpreter.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-030',
    name: 'Notebook cell execution with untrusted content',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'nbformat or ExecutePreprocessor usage can execute arbitrary notebook cells.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /ExecutePreprocessor|nbformat\.read|nbformat\.writes?\s*\(|nbconvert.*execute/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-030-${findings.length}`,
            ruleId: 'AA-CE-030',
            title: 'Notebook cell execution detected',
            description: `Notebook execution in ${file.relativePath} can run arbitrary code cells from untrusted sources.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Validate notebook content before execution. Run in a sandboxed kernel environment.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-031',
    name: 'WebAssembly from untrusted source',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'WebAssembly.instantiate with a variable source can load and execute untrusted WASM code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /WebAssembly\.(?:instantiate|compile|instantiateStreaming|compileStreaming)\s*\(\s*(?!["'`])/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-031-${findings.length}`,
            ruleId: 'AA-CE-031',
            title: 'WebAssembly from untrusted source',
            description: `WebAssembly in ${file.relativePath} is instantiated with a variable source, risking untrusted code execution.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Validate WASM module sources. Only load WebAssembly from trusted, integrity-checked origins.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-032',
    name: 'os.system() usage (broad)',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'os.system() executes shell commands and is vulnerable to injection. Broader detection than CE-008.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /os\.system\s*\(\s*(?:f["']|[a-zA-Z_]\w*|["'][^"']*["']\s*\+|["'][^"']*["']\s*%|["'][^"']*["']\.format)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-032-${findings.length}`,
            ruleId: 'AA-CE-032',
            title: 'os.system() with dynamic command',
            description: `os.system() in ${file.relativePath} executes a dynamically constructed shell command.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Replace os.system() with subprocess.run() using argument lists and shell=False.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-033',
    name: 'subprocess with shell=True',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'subprocess.run() or subprocess.call() with shell=True enables shell injection attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /subprocess\.(?:run|call|check_output|check_call)\s*\([^)]*shell\s*=\s*True/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-033-${findings.length}`,
            ruleId: 'AA-CE-033',
            title: 'subprocess with shell=True',
            description: `subprocess in ${file.relativePath} uses shell=True, enabling shell injection via untrusted input.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Remove shell=True and pass command arguments as a list to subprocess.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-034',
    name: 'Python exec() usage (broad)',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'medium',
    description: 'All exec() calls in Python are dangerous as they execute arbitrary code strings.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?<!\w)exec\s*\(\s*(?!["'](?:pass|$))/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const lineContent = content.substring(0, match.index).split('\n');
          const line = lineContent.length;
          const currentLine = lineContent[lineContent.length - 1] || '';
          if (/^\s*#/.test(currentLine)) continue;
          findings.push({
            id: `AA-CE-034-${findings.length}`,
            ruleId: 'AA-CE-034',
            title: 'Python exec() usage detected',
            description: `exec() in ${file.relativePath} executes arbitrary code strings and should be avoided.`,
            severity: 'critical',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Remove exec() usage entirely. Use safe alternatives like ast.literal_eval() or structured logic.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-035',
    name: 'compile() with dynamic input',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Python compile() with a non-literal first argument can create executable code from dynamic strings.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?<!\w)compile\s*\(\s*(?!["'])/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 200));
          if (!/["']\s*,\s*["']exec["']/.test(region) && !/["']\s*,\s*["']eval["']/.test(region)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-035-${findings.length}`,
            ruleId: 'AA-CE-035',
            title: 'compile() with dynamic input',
            description: `compile() in ${file.relativePath} uses a dynamic first argument to create executable code objects.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: region.substring(0, 60) },
            remediation: 'Avoid compile() with dynamic input. Use ast.literal_eval() for safe expression evaluation.',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-036',
    name: '__import__() with variable',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'high',
    description: '__import__() with a non-string-literal argument can load arbitrary Python modules.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /__import__\s*\(\s*(?!["'])/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-036-${findings.length}`,
            ruleId: 'AA-CE-036',
            title: '__import__() with variable argument',
            description: `__import__() in ${file.relativePath} uses a variable argument, allowing arbitrary module loading.`,
            severity: 'high',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use static imports or maintain a strict allowlist of module names for __import__().',
            standards: { owaspAgentic: ['ASI05'], aiuc1: ['D001'], iso42001: ['A.5.3'], nistAiRmf: ['MEASURE-1.1'] },
          });
        }
      }
      return findings;
    },
  },
  // ── Sandbox Escape (AA-CE-041 to AA-CE-050) ────────────────────────
  {
    id: 'AA-CE-041',
    name: 'System file access from sandbox',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'medium',
    description: 'Reading or writing system files (/etc/passwd, /etc/shadow, etc.) from code execution context indicates sandbox escape.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:open|readFile|readFileSync|writeFile|writeFileSync)\s*\(\s*["'`]\/etc\/(passwd|shadow|hosts|sudoers|group)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-041-${findings.length}`,
            ruleId: 'AA-CE-041',
            title: 'System file access from sandbox',
            description: `Access to /etc/${match[1]} in ${file.relativePath} indicates potential sandbox escape.`,
            severity: 'critical',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Block access to system files from sandboxed code execution. Use a strict filesystem allowlist.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-042',
    name: 'Unfiltered environment variable access',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Accessing os.environ or process.env without filtering can leak secrets from the host environment.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:os\.environ(?:\b|\.)|process\.env\b)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-042-${findings.length}`,
            ruleId: 'AA-CE-042',
            title: 'Unfiltered environment variable access',
            description: `${match[0]} in ${file.relativePath} accesses environment variables without filtering.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Sanitize or restrict environment variable access. Only expose explicitly allowed variables.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-043',
    name: 'Network access from sandboxed code',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Importing socket, urllib, requests, or using fetch in code execution context can exfiltrate data or reach internal services.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:import\s+(?:socket|urllib|requests|http\.client|aiohttp)|from\s+(?:socket|urllib|requests|http\.client|aiohttp)\s+import|(?:require|import)\s*\(\s*["'](?:node:)?(?:net|http|https|dgram)["']\)|(?<!\w)fetch\s*\()/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-043-${findings.length}`,
            ruleId: 'AA-CE-043',
            title: 'Network access from sandboxed code',
            description: `Network-capable import/call in ${file.relativePath} may allow data exfiltration from sandbox.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Block network access from sandboxed code. Use network namespace isolation or firewall rules.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-044',
    name: 'Persistence after session',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Writing files to /tmp or other shared locations allows code to persist beyond the sandbox session.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:open|writeFile|writeFileSync|write_text|write_bytes)\s*\(\s*["'`](?:\/tmp\/|\/var\/tmp\/|\/dev\/shm\/)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-044-${findings.length}`,
            ruleId: 'AA-CE-044',
            title: 'File persistence after session',
            description: `Writing to shared temp location in ${file.relativePath} allows persistence beyond sandbox session.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use ephemeral filesystems for sandbox execution. Clean up /tmp on session end.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-045',
    name: 'No resource limits on code execution',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Code execution without memory or CPU limits can cause resource exhaustion on the host.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const execPattern = /(?:subprocess\.(?:run|Popen|call)|child_process\.(?:exec|spawn|fork)|exec\s*\(|execSync\s*\()/g;
        let match: RegExpExecArray | null;
        while ((match = execPattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 300));
          if (/(?:timeout|memory|ulimit|cgroup|rlimit|maxBuffer)/i.test(region)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-045-${findings.length}`,
            ruleId: 'AA-CE-045',
            title: 'No resource limits on code execution',
            description: `Code execution in ${file.relativePath} lacks memory/CPU/timeout limits.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Set timeout, memory, and CPU limits for all code execution. Use cgroups or ulimit.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-046',
    name: 'Signal or interrupt sending',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Sending signals (os.kill, process.kill) from sandboxed code can disrupt host processes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:os\.kill\s*\(|os\.killpg\s*\(|signal\.signal\s*\(|process\.kill\s*\()/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-046-${findings.length}`,
            ruleId: 'AA-CE-046',
            title: 'Signal/interrupt sending from sandbox',
            description: `Signal sending via ${match[0].trim()} in ${file.relativePath} can disrupt host processes.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Block signal-sending syscalls from sandboxed code. Use seccomp or AppArmor profiles.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-047',
    name: 'IPC abuse from sandbox',
    domain: 'code-execution',
    severity: 'medium',
    confidence: 'medium',
    description: 'Using shared memory, pipes, or unix sockets for IPC from sandboxed code can leak data or influence host processes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:multiprocessing\.shared_memory|mmap\.mmap|shmget|shm_open|os\.mkfifo|unix.*socket|AF_UNIX)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-047-${findings.length}`,
            ruleId: 'AA-CE-047',
            title: 'IPC mechanism in sandbox context',
            description: `IPC mechanism (${match[0]}) in ${file.relativePath} could be used to escape sandbox boundaries.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Disable IPC mechanisms in sandboxed environments. Use namespace isolation.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-048',
    name: 'ptrace or debugging syscall',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Using ptrace or debugging syscalls from sandboxed code can inspect or control other processes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:ptrace|PTRACE_ATTACH|PTRACE_PEEKDATA|strace|ltrace|ctypes\.CDLL.*libc.*ptrace)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-048-${findings.length}`,
            ruleId: 'AA-CE-048',
            title: 'ptrace/debugging syscall detected',
            description: `Debugging syscall (${match[0]}) in ${file.relativePath} can inspect or hijack host processes.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Block ptrace and debugging syscalls via seccomp profiles. Set Yama ptrace_scope to restricted.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-049',
    name: '/proc or /sys filesystem access',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Accessing /proc or /sys from sandboxed code can reveal host information or modify kernel parameters.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:open|readFile|readFileSync)\s*\(\s*["'`]\/(?:proc|sys)\//g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-049-${findings.length}`,
            ruleId: 'AA-CE-049',
            title: '/proc or /sys access from sandbox',
            description: `Access to /proc or /sys in ${file.relativePath} can leak host info or modify kernel parameters.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Mount /proc and /sys as read-only or block access entirely in sandbox environments.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-050',
    name: 'chroot or namespace escape attempt',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Attempting to escape chroot jails or Linux namespaces indicates a sandbox breakout attempt.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05'],
    standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:os\.chroot|chroot\s*\(|unshare\s*\(|setns\s*\(|nsenter|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWNET)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-050-${findings.length}`,
            ruleId: 'AA-CE-050',
            title: 'chroot/namespace escape attempt',
            description: `Namespace/chroot manipulation (${match[0]}) in ${file.relativePath} indicates sandbox escape attempt.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Run sandboxed code in unprivileged containers. Block namespace syscalls via seccomp.',
            standards: { owaspAgentic: ['ASI05'], iso23894: ['R.3', 'R.5'], owaspAivss: ['AIVSS-SE'], owaspAgenticTop10: ['ISOL'] },
          });
        }
      }
      return findings;
    },
  },
  // ── Slopsquatting (AA-CE-051 to AA-CE-064) ────────────────────────
  {
    id: 'AA-CE-051',
    name: 'LLM-generated pip install',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Dynamically running pip install via subprocess or os.system can install malicious packages suggested by an LLM.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen|check_call|check_output)|os\.system|exec|execSync|child_process\.exec)\s*\(\s*(?:.*?)(?:pip\s+install|pip3\s+install)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-051-${findings.length}`,
            ruleId: 'AA-CE-051',
            title: 'Dynamic pip install from code',
            description: `Dynamic pip install in ${file.relativePath} can install unverified or hallucinated packages.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Never run pip install dynamically. Use a locked requirements.txt with hash verification.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-052',
    name: 'LLM-generated npm install',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Dynamically running npm install via child_process or exec can install malicious packages suggested by an LLM.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen)|os\.system|exec|execSync|child_process\.exec)\s*\(\s*(?:.*?)(?:npm\s+install|yarn\s+add|pnpm\s+add)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-052-${findings.length}`,
            ruleId: 'AA-CE-052',
            title: 'Dynamic npm/yarn/pnpm install from code',
            description: `Dynamic package install in ${file.relativePath} can install unverified or hallucinated npm packages.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Never run npm install dynamically. Use a lockfile with integrity hashes.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-053',
    name: 'Typosquat-prone package name',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Common misspellings of popular packages can lead to typosquatting attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const typosquats = /(?:requets|requsts|reqeusts|numpys|pandsa|scikitlearn|tensoflow|tensroflow|pytorh|flaks|djnago|beautifulsop|selinium|pliotly|matplitlib)/;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = new RegExp(`(?:import|from|require|pip install|npm install)\\s+(?:["']?)(?:${typosquats.source})`, 'g');
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-053-${findings.length}`,
            ruleId: 'AA-CE-053',
            title: 'Possible typosquat package name',
            description: `Suspicious package name in ${file.relativePath} resembles a common typosquat.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Verify package names against the official registry. Use a package allowlist.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-054',
    name: 'Non-existent API or SDK reference',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'low',
    description: 'Importing packages that may be hallucinated by an LLM can lead to installing malicious lookalike packages.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const phantomPkgs = /(?:openai_tools|langchain_agents|anthropic_sdk|gpt_utils|llm_helpers|ai_toolkit|chatgpt_api|bard_sdk|claude_sdk|gemini_tools)/;
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = new RegExp(`(?:import|from|require)\\s*(?:\\(\\s*)?["']?${phantomPkgs.source}`, 'g');
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-054-${findings.length}`,
            ruleId: 'AA-CE-054',
            title: 'Potentially hallucinated package import',
            description: `Import of possibly non-existent package in ${file.relativePath} may be LLM-hallucinated.`,
            severity: 'high',
            confidence: 'low',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Verify all package names exist in the official registry before importing or installing.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-055',
    name: 'Fabricated CLI tool execution',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Executing CLI tools by name from LLM output can run fabricated or malicious binaries.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen)|os\.system|execSync|child_process\.exec)\s*\(\s*(?:[a-zA-Z_]\w*(?:\[|\.))/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-055-${findings.length}`,
            ruleId: 'AA-CE-055',
            title: 'CLI tool execution from variable',
            description: `Command execution from variable in ${file.relativePath} may run fabricated CLI tools.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Validate CLI tool names against an allowlist. Never execute LLM-suggested tool names directly.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-056',
    name: 'Dynamic import from LLM string',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Dynamic import() or require() with LLM-generated strings can load arbitrary malicious modules.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:import|require)\s*\(\s*(?:[a-zA-Z_]\w*(?:\[|\.|`))/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-056-${findings.length}`,
            ruleId: 'AA-CE-056',
            title: 'Dynamic import/require from variable',
            description: `Dynamic import/require with variable in ${file.relativePath} can load arbitrary modules.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use static imports only. If dynamic loading is needed, validate against a strict allowlist.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-057',
    name: 'Version pinning without verification',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Installing specific package versions without hash verification can be exploited via version confusion attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:pip\s+install|npm\s+install|yarn\s+add)\s+\S+==[\d.]+|(?:pip\s+install|npm\s+install|yarn\s+add)\s+\S+@[\d.]+/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 200));
          if (/(?:--hash|--require-hashes|--integrity|--check)/i.test(region)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-057-${findings.length}`,
            ruleId: 'AA-CE-057',
            title: 'Version pinning without hash verification',
            description: `Package install with version pin but no hash verification in ${file.relativePath}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use --require-hashes (pip) or --integrity (npm) to verify package authenticity.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-058',
    name: 'Namespace confusion in packages',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Installing org-scoped packages without verifying the organization can lead to namespace confusion attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:npm\s+install|yarn\s+add|pnpm\s+add)\s+@[a-z][\w-]*\/[a-z][\w-]*/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-058-${findings.length}`,
            ruleId: 'AA-CE-058',
            title: 'Org-scoped package install without verification',
            description: `Scoped package install in ${file.relativePath} without org verification risks namespace confusion.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Verify org-scoped package ownership. Use registry scope configuration and lockfiles.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-059',
    name: 'Phantom build tool execution',
    domain: 'code-execution',
    severity: 'medium',
    confidence: 'medium',
    description: 'Running build tools (make, cmake, gradle) from LLM suggestions can execute malicious build scripts.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen)|os\.system|execSync|child_process\.exec)\s*\(\s*(?:.*?)(?:make\b|cmake\b|gradle\b|mvn\b|cargo\s+build|go\s+build)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-059-${findings.length}`,
            ruleId: 'AA-CE-059',
            title: 'Build tool execution from code',
            description: `Build tool invocation in ${file.relativePath} may execute untrusted build scripts.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Do not run build tools dynamically. Use pre-verified build configurations only.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-060',
    name: 'Non-existent or unknown registry',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'high',
    description: 'Using pip/npm with custom or unknown registries can serve malicious packages.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:--index-url|--extra-index-url|--registry)\s+(?:https?:\/\/(?!pypi\.org|registry\.npmjs\.org|registry\.yarnpkg\.com)\S+)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-060-${findings.length}`,
            ruleId: 'AA-CE-060',
            title: 'Unknown package registry',
            description: `Custom/unknown package registry in ${file.relativePath} may serve malicious packages.`,
            severity: 'high',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Only use official registries (pypi.org, npmjs.org) or verified internal mirrors.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-061',
    name: 'Dynamic module loading with variables',
    domain: 'code-execution',
    severity: 'critical',
    confidence: 'high',
    description: 'Using __import__() or importlib.import_module() with variable arguments can load arbitrary modules.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.python) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /importlib\.import_module\s*\(\s*(?!["'])/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-061-${findings.length}`,
            ruleId: 'AA-CE-061',
            title: 'importlib.import_module with variable',
            description: `Dynamic module import in ${file.relativePath} uses a variable, enabling arbitrary module loading.`,
            severity: 'critical',
            confidence: 'high',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
            remediation: 'Use static imports. If dynamic loading is required, validate module names against an allowlist.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-062',
    name: 'wget/curl to unknown URL',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Using wget or curl with dynamic URLs from code execution context can download malicious payloads.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen)|os\.system|execSync|child_process\.exec)\s*\(\s*(?:.*?)(?:wget|curl)\s/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-062-${findings.length}`,
            ruleId: 'AA-CE-062',
            title: 'wget/curl execution from code',
            description: `wget/curl invocation in ${file.relativePath} can download malicious payloads from untrusted URLs.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Validate download URLs against an allowlist. Use checksums to verify downloaded content.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-063',
    name: 'Git clone from LLM-suggested URL',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Running git clone with LLM-provided URLs can clone malicious repositories with harmful code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen)|os\.system|execSync|child_process\.exec)\s*\(\s*(?:.*?)git\s+clone\s/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-063-${findings.length}`,
            ruleId: 'AA-CE-063',
            title: 'Dynamic git clone from code',
            description: `git clone in ${file.relativePath} may clone malicious repos from LLM-suggested URLs.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Validate repository URLs against an allowlist. Never clone repos from dynamic LLM output.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-CE-064',
    name: 'Docker pull from untrusted registry',
    domain: 'code-execution',
    severity: 'high',
    confidence: 'medium',
    description: 'Running docker pull with unverified image names can pull malicious container images.',
    frameworks: ['all'],
    owaspAgentic: ['ASI05', 'ASI04'],
    standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess\.(?:run|call|Popen)|os\.system|execSync|child_process\.exec)\s*\(\s*(?:.*?)docker\s+(?:pull|run)\s/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 200));
          if (/(?:docker\.io\/library\/|gcr\.io\/|ghcr\.io\/)/.test(region)) continue;
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-CE-064-${findings.length}`,
            ruleId: 'AA-CE-064',
            title: 'Docker pull/run from untrusted source',
            description: `Docker pull/run in ${file.relativePath} may use untrusted container images.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'code-execution',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Only pull from trusted registries. Use image digests instead of tags for verification.',
            standards: { owaspAgentic: ['ASI05', 'ASI04'], iso23894: ['R.3', 'R.6'], owaspAivss: ['AIVSS-SC'], owaspAgenticTop10: ['VLDT'] },
          });
        }
      }
      return findings;
    },
  },
];
