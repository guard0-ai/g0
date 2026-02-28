import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';

export const supplyChainRules: Rule[] = [
  {
    id: 'AA-SC-001',
    name: 'Unpinned Python dependencies',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'Python dependencies are not pinned to specific versions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'requirements.txt') continue;

        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line || line.startsWith('#') || line.startsWith('-')) continue;

          // No version pin (e.g., "langchain" without ==, >=, ~=)
          if (/^[a-zA-Z0-9_-]+\s*$/.test(line)) {
            findings.push({
              id: `AA-SC-001-${findings.length}`,
              ruleId: 'AA-SC-001',
              title: 'Unpinned Python dependency',
              description: `Dependency "${line}" in ${file.relativePath} has no version pin.`,
              severity: 'medium',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: file.relativePath, line: i + 1, snippet: line },
              remediation: `Pin the dependency to a specific version: ${line}==x.y.z`,
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-002',
    name: 'Unpinned npm dependencies',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'npm dependencies use loose version ranges.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'package.json') continue;

        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        let pkg: any;
        try {
          pkg = JSON.parse(content);
        } catch {
          continue;
        }

        const deps = { ...pkg.dependencies, ...pkg.devDependencies };
        for (const [name, version] of Object.entries(deps)) {
          if (typeof version !== 'string') continue;
          // Flag * or latest
          if (version === '*' || version === 'latest') {
            const line = findKeyLine(content, name);
            findings.push({
              id: `AA-SC-002-${findings.length}`,
              ruleId: 'AA-SC-002',
              title: 'Unpinned npm dependency',
              description: `Dependency "${name}" in ${file.relativePath} uses "${version}".`,
              severity: 'medium',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: `"${name}": "${version}"` },
              remediation: `Pin ${name} to a specific version range.`,
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-003',
    name: 'Unverified MCP server',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'MCP server used without version pinning or verification.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const config of graph.configs) {
        for (const issue of config.issues) {
          if (issue.type === 'unpinned-mcp-server') {
            findings.push({
              id: `AA-SC-003-${findings.length}`,
              ruleId: 'AA-SC-003',
              title: 'Unpinned MCP server package',
              description: issue.message,
              severity: 'high',
              confidence: 'medium',
              domain: 'supply-chain',
              location: { file: config.file, line: issue.line },
              remediation: 'Pin MCP server packages to specific versions (e.g., package@1.2.3).',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-004',
    name: 'npx -y without version pinning',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'npx -y auto-installs packages without version pinning.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const config of graph.configs) {
        for (const issue of config.issues) {
          if (issue.type === 'npx-auto-install') {
            findings.push({
              id: `AA-SC-004-${findings.length}`,
              ruleId: 'AA-SC-004',
              title: 'npx -y auto-install without version pin',
              description: issue.message,
              severity: 'high',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: config.file, line: issue.line },
              remediation: 'Pin package versions when using npx (e.g., npx package@1.2.3).',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-005',
    name: 'pip install from URL',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'Package installed from URL without hash verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'requirements.txt') continue;

        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim();
          if (/^(https?:|git\+|git:)/.test(line) && !line.includes('--hash')) {
            findings.push({
              id: `AA-SC-005-${findings.length}`,
              ruleId: 'AA-SC-005',
              title: 'Package installed from URL without hash',
              description: `Dependency from URL in ${file.relativePath} without hash verification.`,
              severity: 'high',
              confidence: 'high',
              domain: 'supply-chain',
              location: { file: file.relativePath, line: i + 1, snippet: line.substring(0, 80) },
              remediation: 'Add --hash verification or use pinned package registry versions.',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-006',
    name: 'Unverified MCP server',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'MCP server package is not from the official @modelcontextprotocol scope, increasing supply chain risk.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.configs, ...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const mcpServerPattern = /"command"\s*:\s*"npx"\s*,\s*"args"\s*:\s*\[([^\]]*)\]/g;
        let match: RegExpExecArray | null;
        while ((match = mcpServerPattern.exec(content)) !== null) {
          const args = match[1];
          if (args && !/@modelcontextprotocol\//.test(args)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-006-${findings.length}`,
              ruleId: 'AA-SC-006',
              title: 'Unverified MCP server package',
              description: `MCP server in ${file.relativePath} uses a package not from @modelcontextprotocol scope.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Use verified MCP servers from the @modelcontextprotocol scope or audit third-party servers.',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.2', 'A.7.3'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-007',
    name: 'Git URL dependency',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'Dependency installed from a Git URL, bypassing package registry integrity checks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const basename = file.relativePath.split('/').pop() ?? '';

        // Check requirements.txt for git URLs
        if (basename === 'requirements.txt') {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (/git\+(?:ssh|https?):\/\//.test(line) || /^git:\/\//.test(line)) {
              findings.push({
                id: `AA-SC-007-${findings.length}`,
                ruleId: 'AA-SC-007',
                title: 'Git URL dependency',
                description: `Dependency in ${file.relativePath} is installed from a Git URL, bypassing registry checks.`,
                severity: 'medium',
                confidence: 'high',
                domain: 'supply-chain',
                location: { file: file.relativePath, line: i + 1, snippet: line.substring(0, 80) },
                remediation: 'Use pinned package registry versions instead of Git URLs. If Git URLs are required, pin to a specific commit hash.',
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }

        // Check package.json for git URL dependencies
        if (basename === 'package.json') {
          let pkg: any;
          try {
            pkg = JSON.parse(content);
          } catch {
            continue;
          }

          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          for (const [name, version] of Object.entries(deps)) {
            if (typeof version !== 'string') continue;
            if (/git\+(?:ssh|https?):\/\//.test(version) || /^git:\/\//.test(version)) {
              const line = findKeyLine(content, name);
              findings.push({
                id: `AA-SC-007-${findings.length}`,
                ruleId: 'AA-SC-007',
                title: 'Git URL dependency',
                description: `Dependency "${name}" in ${file.relativePath} is installed from a Git URL.`,
                severity: 'medium',
                confidence: 'high',
                domain: 'supply-chain',
                location: { file: file.relativePath, line, snippet: `"${name}": "${version}"` },
                remediation: 'Use pinned package registry versions instead of Git URLs. If Git URLs are required, pin to a specific commit hash.',
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001', 'C002'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-008',
    name: 'Missing lockfile',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Project has a dependency manifest but no lockfile, making builds non-deterministic.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const configNames = graph.files.configs.map((f) => f.relativePath.split('/').pop() ?? '');

      const hasPackageJson = configNames.includes('package.json');
      const hasNpmLock = configNames.includes('package-lock.json') ||
        configNames.includes('yarn.lock') ||
        configNames.includes('pnpm-lock.yaml');

      const hasRequirements = configNames.includes('requirements.txt');
      const hasPipLock = configNames.includes('Pipfile.lock') || configNames.includes('poetry.lock') || configNames.includes('uv.lock');

      if (hasPackageJson && !hasNpmLock) {
        const pkgFile = graph.files.configs.find((f) => (f.relativePath.split('/').pop() ?? '') === 'package.json');
        findings.push({
          id: `AA-SC-008-${findings.length}`,
          ruleId: 'AA-SC-008',
          title: 'Missing lockfile for npm project',
          description: `package.json found but no lockfile (package-lock.json, yarn.lock, or pnpm-lock.yaml) detected.`,
          severity: 'medium',
          confidence: 'medium',
          domain: 'supply-chain',
          location: { file: pkgFile?.relativePath ?? 'package.json', line: 1 },
          remediation: 'Run npm install, yarn install, or pnpm install to generate a lockfile and commit it to version control.',
          standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
        });
      }

      if (hasRequirements && !hasPipLock) {
        // Only flag if requirements.txt has unpinned dependencies (no == version pinning)
        const reqFile = graph.files.configs.find((f) => (f.relativePath.split('/').pop() ?? '') === 'requirements.txt');
        let hasUnpinned = false;
        if (reqFile) {
          try {
            const reqContent = fs.readFileSync(reqFile.path, 'utf-8');
            const depLines = reqContent.split('\n').filter(l => l.trim() && !l.trim().startsWith('#') && !l.trim().startsWith('-'));
            hasUnpinned = depLines.some(l => !l.includes('=='));
          } catch { /* ignore */ }
        }
        if (hasUnpinned) {
          findings.push({
            id: `AA-SC-008-${findings.length}`,
            ruleId: 'AA-SC-008',
            title: 'Missing lockfile for Python project',
            description: `requirements.txt found with unpinned dependencies but no lockfile (Pipfile.lock or poetry.lock) detected.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'supply-chain',
            location: { file: reqFile?.relativePath ?? 'requirements.txt', line: 1 },
            remediation: 'Use pip-tools (pip-compile), Pipenv, or Poetry to generate a lockfile with pinned transitive dependencies.',
            standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
          });
        }
      }

      return findings;
    },
  },
  {
    id: 'AA-SC-009',
    name: 'Model loaded from URL',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'ML model is loaded directly from a URL without integrity verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C002'], iso42001: ['A.7.2'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const modelUrlPatterns = [
          { regex: /from_pretrained\s*\(\s*["']https?:/g, name: 'from_pretrained() with URL' },
          { regex: /torch\.hub\.load\s*\(/g, name: 'torch.hub.load()' },
          { regex: /wget\s+.*\.(?:bin|pt|safetensors|gguf)/g, name: 'wget model download' },
        ];

        for (const { regex, name } of modelUrlPatterns) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-009-${findings.length}`,
              ruleId: 'AA-SC-009',
              title: 'Model loaded from URL',
              description: `${name} in ${file.relativePath} loads a model from a URL without integrity verification.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Verify model integrity with checksums or use a trusted model registry with pinned versions.',
              standards: { owaspAgentic: ['ASI04'], aiuc1: ['C002'], iso42001: ['A.7.2'], nistAiRmf: ['MAP-3.1'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-010',
    name: 'Typosquat risk in AI packages',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Dependency name matches a known typosquat of a popular AI package.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const typosquats: Record<string, string> = {
        'langchin': 'langchain',
        'langchian': 'langchain',
        'lanchain': 'langchain',
        'openai-api': 'openai',
        'antropic': 'anthropic',
        'crew-ai': 'crewai',
      };

      for (const file of graph.files.configs) {
        let content: string;
        try {
          content = fs.readFileSync(file.path, 'utf-8');
        } catch {
          continue;
        }

        const basename = file.relativePath.split('/').pop() ?? '';

        if (basename === 'requirements.txt') {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line || line.startsWith('#') || line.startsWith('-')) continue;
            const pkgName = line.split(/[=<>~!]/)[0].trim().toLowerCase();
            if (typosquats[pkgName]) {
              findings.push({
                id: `AA-SC-010-${findings.length}`,
                ruleId: 'AA-SC-010',
                title: 'Potential typosquat package',
                description: `Package "${pkgName}" in ${file.relativePath} may be a typosquat of "${typosquats[pkgName]}".`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'supply-chain',
                location: { file: file.relativePath, line: i + 1, snippet: line },
                remediation: `Verify the package name. Did you mean "${typosquats[pkgName]}"?`,
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }

        if (basename === 'package.json') {
          let pkg: any;
          try {
            pkg = JSON.parse(content);
          } catch {
            continue;
          }

          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          for (const [name] of Object.entries(deps)) {
            const lower = name.toLowerCase();
            if (typosquats[lower]) {
              const line = findKeyLine(content, name);
              findings.push({
                id: `AA-SC-010-${findings.length}`,
                ruleId: 'AA-SC-010',
                title: 'Potential typosquat package',
                description: `Package "${name}" in ${file.relativePath} may be a typosquat of "${typosquats[lower]}".`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'supply-chain',
                location: { file: file.relativePath, line, snippet: `"${name}"` },
                remediation: `Verify the package name. Did you mean "${typosquats[lower]}"?`,
                standards: { owaspAgentic: ['ASI04'], aiuc1: ['C001'], iso42001: ['A.7.3'], nistAiRmf: ['MAP-3.1'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-011',
    name: 'Runtime pip install in agent code',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'Runtime pip/pip3 install executed via subprocess or os.system — downloads and executes arbitrary code from PyPI during agent operation.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript, ...graph.files.configs]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const lines = content.split('\n');

        // Pattern 1: subprocess/os.system running pip install (runtime execution — critical)
        const runtimeExecPatterns = [
          /subprocess\.(?:run|call|check_call|check_output|Popen)\s*\(\s*\[?\s*["'](?:pip|pip3)["']\s*,\s*["']install["']/g,
          /os\.system\s*\(\s*["'](?:pip|pip3)\s+install\b/g,
          /os\.popen\s*\(\s*["'](?:pip|pip3)\s+install\b/g,
          /!pip\s+install\s+(?!-r\s)([a-zA-Z0-9_-]+)/g,  // Jupyter notebook
        ];

        for (const pattern of runtimeExecPatterns) {
          const re = new RegExp(pattern.source, pattern.flags);
          let match: RegExpExecArray | null;
          while ((match = re.exec(content)) !== null) {
            const lineNum = content.substring(0, match.index).split('\n').length;
            const matchLine = lines[lineNum - 1] ?? '';
            // Skip comments
            if (matchLine.trimStart().startsWith('#') || matchLine.trimStart().startsWith('//')) continue;

            const pkgMatch = match[0].match(/install["',\s]+([a-zA-Z0-9_-]+)/);
            const pkg = pkgMatch?.[1] ?? 'unknown';
            findings.push({
              id: `AA-SC-011-${findings.length}`, ruleId: 'AA-SC-011',
              title: 'Runtime pip install in agent code',
              description: `${file.relativePath} runs pip install at runtime to install "${pkg}" — downloads and runs code from PyPI during agent operation.`,
              severity: 'critical', confidence: 'high', domain: 'supply-chain',
              location: { file: file.relativePath, line: lineNum, snippet: match[0].substring(0, 80) },
              remediation: 'Pre-install dependencies in requirements.txt with pinned versions and hash verification. Never run pip install at runtime in agent code.',
              standards: { owaspAgentic: ['ASI04'] },
            });
          }
        }

        // Pattern 2: pip install in shell scripts / Dockerfiles / CI configs (build-time — medium)
        const ext = file.relativePath.split('.').pop()?.toLowerCase() ?? '';
        const isScript = ext === 'sh' || ext === 'bash' || file.relativePath.includes('Dockerfile') || file.relativePath.includes('.yml') || file.relativePath.includes('.yaml');
        if (isScript) {
          const pipPattern = /(?:pip|pip3)\s+install\s+(?!-r\s)(?!--requirement\s)([a-zA-Z0-9_-]+)/g;
          let match: RegExpExecArray | null;
          while ((match = pipPattern.exec(content)) !== null) {
            const lineNum = content.substring(0, match.index).split('\n').length;
            const matchLine = lines[lineNum - 1] ?? '';
            if (matchLine.trimStart().startsWith('#')) continue;

            findings.push({
              id: `AA-SC-011-${findings.length}`, ruleId: 'AA-SC-011',
              title: 'Unpinned pip install in build script',
              description: `${file.relativePath} runs pip install "${match[1]}" without version pinning.`,
              severity: 'medium', confidence: 'medium', domain: 'supply-chain',
              location: { file: file.relativePath, line: lineNum, snippet: match[0].substring(0, 80) },
              remediation: 'Pin package versions (e.g., beautifulsoup4==4.12.3) and use --require-hashes for verification.',
              standards: { owaspAgentic: ['ASI04'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-012',
    name: 'npm package with install scripts',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'package.json contains preinstall/postinstall scripts that execute during npm install.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'package.json') continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        let pkg: any;
        try { pkg = JSON.parse(content); } catch { continue; }
        const dangerousScripts = ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'];
        for (const script of dangerousScripts) {
          if (pkg.scripts && pkg.scripts[script]) {
            const line = findKeyLine(content, script);
            findings.push({
              id: `AA-SC-012-${findings.length}`, ruleId: 'AA-SC-012',
              title: 'npm package with install scripts',
              description: `package.json in ${file.relativePath} has "${script}" script: "${pkg.scripts[script]}".`,
              severity: 'high', confidence: 'high', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: `"${script}": "${pkg.scripts[script]}"` },
              remediation: 'Audit install scripts carefully. Use --ignore-scripts flag or remove unnecessary lifecycle scripts.',
              standards: { owaspAgentic: ['ASI04'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-013',
    name: 'Unpinned dependency version',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'Dependency uses loose version specifiers (>=, *, latest) allowing untested versions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename === 'requirements.txt') {
          const lines = content.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line || line.startsWith('#') || line.startsWith('-')) continue;
            if (/>=|>\s*\d|~=/.test(line) && !line.includes('==')) {
              findings.push({
                id: `AA-SC-013-${findings.length}`, ruleId: 'AA-SC-013',
                title: 'Unpinned dependency version',
                description: `Dependency "${line}" in ${file.relativePath} uses a loose version specifier.`,
                severity: 'high', confidence: 'high', domain: 'supply-chain',
                location: { file: file.relativePath, line: i + 1, snippet: line },
                remediation: 'Pin dependencies to exact versions (==) for reproducible builds.',
                standards: { owaspAgentic: ['ASI04'] },
              });
            }
          }
        }
        if (basename === 'package.json') {
          let pkg: any;
          try { pkg = JSON.parse(content); } catch { continue; }
          const deps = { ...pkg.dependencies, ...pkg.devDependencies };
          for (const [name, version] of Object.entries(deps)) {
            if (typeof version !== 'string') continue;
            if (version === '*' || version === 'latest' || version.startsWith('>=')) {
              const line = findKeyLine(content, name);
              findings.push({
                id: `AA-SC-013-${findings.length}`, ruleId: 'AA-SC-013',
                title: 'Unpinned dependency version',
                description: `Dependency "${name}" in ${file.relativePath} uses "${version}".`,
                severity: 'high', confidence: 'high', domain: 'supply-chain',
                location: { file: file.relativePath, line, snippet: `"${name}": "${version}"` },
                remediation: 'Pin dependencies to exact versions for reproducible builds.',
                standards: { owaspAgentic: ['ASI04'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-014',
    name: 'MCP server from unverified source',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'MCP server configuration points to an unknown or unverified source.',
    frameworks: ['mcp'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.configs, ...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /["']command["']\s*:\s*["'](?:npx|uvx|node|python)["'][\s\S]*?["']args["']\s*:\s*\[([^\]]*)\]/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const args = match[1];
          if (args && !/@modelcontextprotocol\/|@anthropic|@official/i.test(args)) {
            const region = content.substring(Math.max(0, match.index - 200), match.index + match[0].length);
            if (!/verified|trusted|official|audit/i.test(region)) {
              const line = content.substring(0, match.index).split('\n').length;
              findings.push({
                id: `AA-SC-014-${findings.length}`, ruleId: 'AA-SC-014',
                title: 'MCP server from unverified source',
                description: `MCP server config in ${file.relativePath} points to an unverified package.`,
                severity: 'high', confidence: 'medium', domain: 'supply-chain',
                location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
                remediation: 'Use verified MCP servers from trusted sources. Audit third-party server code before use.',
                standards: { owaspAgentic: ['ASI04'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-015',
    name: 'Docker image without digest',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'Dockerfile uses an image without @sha256: digest, allowing mutable tags.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (!/^Dockerfile/i.test(basename)) continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /^FROM\s+(\S+)/gm;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const image = match[1];
          if (!image.includes('@sha256:') && image !== 'scratch') {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-015-${findings.length}`, ruleId: 'AA-SC-015',
              title: 'Docker image without digest',
              description: `Dockerfile in ${file.relativePath} uses image "${image}" without @sha256: digest.`,
              severity: 'high', confidence: 'high', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Pin Docker images using @sha256: digests for reproducible and tamper-proof builds.',
              standards: { owaspAgentic: ['ASI04'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-016',
    name: 'Dynamic package install at runtime',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'Code installs packages at runtime using pip install or npm install.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:subprocess|os\.system|exec|execSync|child_process)\s*[\.(].*(?:pip\s+install|npm\s+install|pip3\s+install)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-SC-016-${findings.length}`, ruleId: 'AA-SC-016',
            title: 'Dynamic package install at runtime',
            description: `Code in ${file.relativePath} installs packages at runtime, risking supply chain attacks.`,
            severity: 'high', confidence: 'high', domain: 'supply-chain',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Install dependencies at build time, not runtime. Use a requirements file with pinned versions.',
            standards: { owaspAgentic: ['ASI04'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-017',
    name: 'No lockfile present',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Project lacks a lockfile (package-lock.json, yarn.lock, poetry.lock), making builds non-deterministic.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const configNames = graph.files.configs.map(f => f.relativePath.split('/').pop() ?? '');
      const hasManifest = configNames.includes('package.json') || configNames.includes('requirements.txt') || configNames.includes('pyproject.toml');
      const hasLockfile = configNames.some(n => /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile\.lock|poetry\.lock|uv\.lock)$/.test(n));
      if (hasManifest && !hasLockfile) {
        findings.push({
          id: 'AA-SC-017-0', ruleId: 'AA-SC-017',
          title: 'No lockfile present',
          description: 'Project has dependency manifests but no lockfile, making builds non-deterministic.',
          severity: 'medium', confidence: 'medium', domain: 'supply-chain',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Generate a lockfile (npm install, yarn install, poetry lock) and commit it to version control.',
          standards: { owaspAgentic: ['ASI04'] },
        });
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-018',
    name: 'Deprecated framework version',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Project uses a known deprecated version of an AI framework.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const deprecated: Record<string, string> = {
        'langchain==0.0': 'langchain 0.0.x is deprecated, upgrade to 0.1+',
        'openai==0.2': 'openai 0.2x is deprecated, upgrade to 1.0+',
        'crewai==0.1': 'crewai 0.1.x is deprecated, upgrade to latest',
      };
      for (const file of graph.files.configs) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        for (const [prefix, message] of Object.entries(deprecated)) {
          if (content.includes(prefix)) {
            const line = content.split('\n').findIndex(l => l.includes(prefix)) + 1;
            findings.push({
              id: `AA-SC-018-${findings.length}`, ruleId: 'AA-SC-018',
              title: 'Deprecated framework version',
              description: `${message} (found in ${file.relativePath}).`,
              severity: 'medium', confidence: 'medium', domain: 'supply-chain',
              location: { file: file.relativePath, line: line || 1, snippet: prefix },
              remediation: 'Upgrade to the latest supported version of the framework.',
              standards: { owaspAgentic: ['ASI04'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-019',
    name: 'Importing from HTTP URL',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'Code imports modules from an HTTP URL, risking man-in-the-middle attacks.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /import\s+.*from\s+["']http:\/\//g;
        const pattern2 = /importlib\.import_module\s*\(\s*["']http/g;
        for (const regex of [pattern, pattern2]) {
          regex.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = regex.exec(content)) !== null) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-019-${findings.length}`, ruleId: 'AA-SC-019',
              title: 'Importing from HTTP URL',
              description: `Code in ${file.relativePath} imports from an HTTP URL, risking MITM attacks.`,
              severity: 'medium', confidence: 'high', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Use HTTPS URLs or install packages from a trusted registry instead of importing from URLs.',
              standards: { owaspAgentic: ['ASI04'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-020',
    name: 'No SBOM generation configured',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'low',
    description: 'Project lacks SBOM (Software Bill of Materials) tooling for supply chain transparency.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const allFiles = [...graph.files.configs, ...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
      const hasSbom = allFiles.some(f => {
        const name = f.relativePath.toLowerCase();
        return /sbom|cyclonedx|spdx|syft|trivy/.test(name);
      });
      if (!hasSbom && allFiles.length > 0) {
        let configContent = '';
        for (const file of graph.files.configs) {
          try { configContent += fs.readFileSync(file.path, 'utf-8'); } catch { /* ignore */ }
        }
        if (!/sbom|cyclonedx|spdx|syft|trivy/i.test(configContent)) {
          findings.push({
            id: 'AA-SC-020-0', ruleId: 'AA-SC-020',
            title: 'No SBOM generation configured',
            description: 'Project lacks SBOM generation tooling (CycloneDX, SPDX, Syft, Trivy).',
            severity: 'medium', confidence: 'low', domain: 'supply-chain',
            location: { file: graph.rootPath, line: 1 },
            remediation: 'Add SBOM generation to your CI/CD pipeline using CycloneDX, SPDX, Syft, or Trivy.',
            standards: { owaspAgentic: ['ASI04'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-021',
    name: 'requirements.txt from untrusted source',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'requirements.txt is downloaded from an external URL, risking supply chain compromise.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript, ...graph.files.configs]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:curl|wget|requests\.get|fetch)\s*\(?.*requirements\.txt/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-SC-021-${findings.length}`, ruleId: 'AA-SC-021',
            title: 'requirements.txt from untrusted source',
            description: `Code in ${file.relativePath} downloads requirements.txt from a URL, risking supply chain compromise.`,
            severity: 'high', confidence: 'medium', domain: 'supply-chain',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Vendor requirements.txt in the repository. Never download dependency lists from external sources at runtime.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-022',
    name: 'npm audit not in CI',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'No npm audit or yarn audit found in package.json scripts, missing vulnerability scanning in CI.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'package.json') continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        let pkg: any;
        try { pkg = JSON.parse(content); } catch { continue; }
        const scripts = pkg.scripts ? Object.values(pkg.scripts).join(' ') : '';
        if (!/npm\s+audit|yarn\s+audit|pnpm\s+audit|snyk\s+test|auditjs/i.test(scripts)) {
          findings.push({
            id: `AA-SC-022-${findings.length}`, ruleId: 'AA-SC-022',
            title: 'npm audit not in CI',
            description: `package.json in ${file.relativePath} has no audit command in scripts for vulnerability scanning.`,
            severity: 'medium', confidence: 'medium', domain: 'supply-chain',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Add "audit": "npm audit" or equivalent to package.json scripts and run it in CI.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-023',
    name: 'Known vulnerable dependency',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'Dependencies with known CVEs detected based on version patterns.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const knownVulnerable: Record<string, string> = {
        'lodash==4.17.11': 'CVE-2019-10744 prototype pollution',
        'requests==2.19': 'CVE-2018-18074 session cookie leak',
        'axios==0.18': 'CVE-2019-10742 SSRF vulnerability',
        'pyyaml==5.3': 'CVE-2020-14343 arbitrary code execution',
        'urllib3==1.24': 'CVE-2019-11324 CRLF injection',
      };
      for (const file of graph.files.configs) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i].trim().toLowerCase();
          for (const [vuln, desc] of Object.entries(knownVulnerable)) {
            if (line.startsWith(vuln.split('==')[0]) && line.includes(vuln.split('==')[1])) {
              findings.push({
                id: `AA-SC-023-${findings.length}`, ruleId: 'AA-SC-023',
                title: 'Known vulnerable dependency',
                description: `Dependency "${lines[i].trim()}" in ${file.relativePath} has known vulnerability: ${desc}.`,
                severity: 'high', confidence: 'medium', domain: 'supply-chain',
                location: { file: file.relativePath, line: i + 1, snippet: lines[i].trim() },
                remediation: `Upgrade ${vuln.split('==')[0]} to a patched version to fix ${desc}.`,
                standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
              });
            }
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-024',
    name: 'Git submodule from untrusted source',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'Git submodule references an external repository that could be compromised.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== '.gitmodules') continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /url\s*=\s*(.+)/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const url = match[1].trim();
          const line = content.substring(0, match.index).split('\n').length;
          findings.push({
            id: `AA-SC-024-${findings.length}`, ruleId: 'AA-SC-024',
            title: 'Git submodule from untrusted source',
            description: `Git submodule in ${file.relativePath} references "${url}". Submodules can be hijacked.`,
            severity: 'high', confidence: 'medium', domain: 'supply-chain',
            location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
            remediation: 'Pin git submodules to specific commit hashes and audit the referenced repositories.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-025',
    name: 'Docker base image not pinned',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'high',
    description: 'Dockerfile FROM directive uses a tag without sha256 digest, allowing mutable base images.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (!/^Dockerfile/i.test(basename) && basename !== 'docker-compose.yml' && basename !== 'docker-compose.yaml') continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:^FROM|image:\s*)\s*(\S+)/gm;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const image = match[1];
          if (!image.includes('@sha256:') && image !== 'scratch' && !/\$\{/.test(image)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-025-${findings.length}`, ruleId: 'AA-SC-025',
              title: 'Docker base image not pinned',
              description: `Image "${image}" in ${file.relativePath} is not pinned with @sha256: digest.`,
              severity: 'high', confidence: 'high', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 80) },
              remediation: 'Pin Docker base images using @sha256: digests (e.g., python:3.11@sha256:abc...).',
              standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-026',
    name: 'Terraform provider not pinned',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'high',
    description: 'Terraform provider block lacks a version constraint, allowing untested provider versions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of graph.files.configs) {
        if (!file.relativePath.endsWith('.tf')) continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /source\s*=\s*"([^"]+)"/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 300));
          if (!/version\s*=/.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-026-${findings.length}`, ruleId: 'AA-SC-026',
              title: 'Terraform provider not pinned',
              description: `Terraform provider "${match[1]}" in ${file.relativePath} has no version constraint.`,
              severity: 'medium', confidence: 'high', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0] },
              remediation: 'Add version constraints to Terraform provider blocks (e.g., version = "~> 4.0").',
              standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-027',
    name: 'AI model download without checksum',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'AI model is loaded from a URL or hub without hash/checksum verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:from_pretrained|load_model|download_model|hf_hub_download|snapshot_download)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(match.index, Math.min(content.length, match.index + 500));
          if (!/checksum|sha256|hash|verify_hash|revision\s*=\s*["'][a-f0-9]{40}/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-027-${findings.length}`, ruleId: 'AA-SC-027',
              title: 'AI model download without checksum',
              description: `Model download in ${file.relativePath} via ${match[0].replace(/\s*\($/, '')} has no checksum verification.`,
              severity: 'high', confidence: 'medium', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Verify model integrity with sha256 checksums or pin to a specific revision hash.',
              standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-028',
    name: 'Plugin/extension not verified',
    domain: 'supply-chain',
    severity: 'high',
    confidence: 'medium',
    description: 'Plugin or extension is loaded without signature or integrity verification.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript]) {
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        const pattern = /(?:load_plugin|register_plugin|import_plugin|load_extension|importlib\.import_module)\s*\(/g;
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const region = content.substring(Math.max(0, match.index - 300), Math.min(content.length, match.index + 500));
          if (!/verify|signature|sign|checksum|hash|trusted|allowlist|whitelist/i.test(region)) {
            const line = content.substring(0, match.index).split('\n').length;
            findings.push({
              id: `AA-SC-028-${findings.length}`, ruleId: 'AA-SC-028',
              title: 'Plugin/extension not verified',
              description: `Plugin loading in ${file.relativePath} via ${match[0].replace(/\s*\($/, '')} has no signature or integrity check.`,
              severity: 'high', confidence: 'medium', domain: 'supply-chain',
              location: { file: file.relativePath, line, snippet: match[0].substring(0, 60) },
              remediation: 'Verify plugin signatures or checksums before loading. Use an allowlist of trusted plugins.',
              standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
            });
          }
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-029',
    name: 'Transitive dependency risk',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Deep dependency trees without a lockfile increase transitive dependency attack surface.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const configNames = graph.files.configs.map(f => f.relativePath.split('/').pop() ?? '');
      const hasLockfile = configNames.some(n => /^(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Pipfile\.lock|poetry\.lock|uv\.lock)$/.test(n));
      if (hasLockfile) return findings;
      for (const file of graph.files.configs) {
        const basename = file.relativePath.split('/').pop() ?? '';
        if (basename !== 'package.json' && basename !== 'requirements.txt') continue;
        let content: string;
        try { content = fs.readFileSync(file.path, 'utf-8'); } catch { continue; }
        let depCount = 0;
        if (basename === 'package.json') {
          try {
            const pkg = JSON.parse(content);
            depCount = Object.keys(pkg.dependencies || {}).length + Object.keys(pkg.devDependencies || {}).length;
          } catch { continue; }
        } else {
          depCount = content.split('\n').filter(l => l.trim() && !l.trim().startsWith('#') && !l.trim().startsWith('-')).length;
        }
        if (depCount > 10) {
          findings.push({
            id: `AA-SC-029-${findings.length}`, ruleId: 'AA-SC-029',
            title: 'Transitive dependency risk',
            description: `${file.relativePath} has ${depCount} dependencies without a lockfile, exposing transitive dependency risk.`,
            severity: 'medium', confidence: 'medium', domain: 'supply-chain',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Generate and commit a lockfile to pin transitive dependencies and reduce attack surface.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
          });
        }
      }
      return findings;
    },
  },
  {
    id: 'AA-SC-030',
    name: 'Build artifact not signed',
    domain: 'supply-chain',
    severity: 'medium',
    confidence: 'medium',
    description: 'Build outputs lack signature verification, risking tampered artifact deployment.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const allFiles = [...graph.files.configs, ...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
      const hasSigning = allFiles.some(f => {
        try {
          const content = fs.readFileSync(f.path, 'utf-8');
          return /cosign|sigstore|gpg\s+--sign|signcode|jarsigner|codesign|artifact.?sign|notary/i.test(content);
        } catch { return false; }
      });
      if (!hasSigning && allFiles.length > 5) {
        const hasBuild = allFiles.some(f => {
          const name = f.relativePath.toLowerCase();
          return /dockerfile|makefile|ci\.yml|ci\.yaml|build\.sh|jenkinsfile|\.github\/workflows/i.test(name);
        });
        if (hasBuild) {
          findings.push({
            id: 'AA-SC-030-0', ruleId: 'AA-SC-030',
            title: 'Build artifact not signed',
            description: 'Project has build configuration but no artifact signing (cosign, sigstore, GPG) detected.',
            severity: 'medium', confidence: 'medium', domain: 'supply-chain',
            location: { file: graph.rootPath, line: 1 },
            remediation: 'Sign build artifacts using cosign, sigstore, or GPG to ensure integrity and provenance.',
            standards: { owaspAgentic: ['ASI04'], iso23894: ['R.4', 'R.7'], owaspAivss: ['AIVSS-SC'], a2asBasic: ['AUTH', 'COMM'] },
          });
        }
      }
      return findings;
    },
  },
];

function findKeyLine(content: string, key: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${key}"`)) return i + 1;
  }
  return 1;
}
