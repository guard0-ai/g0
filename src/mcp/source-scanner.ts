import * as fs from 'node:fs';
import * as path from 'node:path';
import type { MCPToolInfo, MCPFinding } from '../types/mcp-scan.js';

export function scanMCPServerSource(
  serverPath: string,
  serverName: string,
): { tools: MCPToolInfo[]; findings: MCPFinding[] } {
  const tools: MCPToolInfo[] = [];
  const findings: MCPFinding[] = [];

  let content: string;
  try {
    content = fs.readFileSync(serverPath, 'utf-8');
  } catch {
    return { tools, findings };
  }

  const lines = content.split('\n');

  // Extract tools using regex (similar to MCP parser)
  const toolPattern = /(?:@(?:server|mcp)\.tool\s*\(\s*\)|@(?:server|mcp)\.tool\s*\(\s*["']([^"']+)["']\s*\))/g;
  let match: RegExpExecArray | null;

  while ((match = toolPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, Math.min(match.index + 2000, content.length));

    // Get function name
    const funcMatch = region.match(/def\s+(\w+)/);
    const toolName = match[1] ?? funcMatch?.[1] ?? `tool_${line}`;

    // Get docstring
    const docMatch = region.match(/"""([\s\S]*?)"""|'''([\s\S]*?)'''/);
    const description = (docMatch?.[1] ?? docMatch?.[2] ?? '').trim();

    // Detect capabilities
    const funcBody = extractFuncBody(content, line - 1, lines);
    const capabilities = detectCapabilities(funcBody);

    tools.push({
      name: toolName,
      description,
      capabilities,
      hasSideEffects: capabilities.some(c =>
        ['shell', 'filesystem-write', 'database-write', 'network-write', 'code-execution'].includes(c),
      ),
      file: serverPath,
      line,
    });

    // Check for dangerous patterns
    if (/subprocess.*shell\s*=\s*True|os\.system/.test(funcBody)) {
      findings.push({
        severity: 'critical',
        type: 'shell-execution',
        title: 'Shell command execution',
        description: `Tool "${toolName}" executes shell commands with shell=True`,
        server: serverName,
        file: serverPath,
        line,
      });
    }

    if (/eval\(|exec\(/.test(funcBody)) {
      findings.push({
        severity: 'critical',
        type: 'code-execution',
        title: 'Dynamic code execution',
        description: `Tool "${toolName}" uses eval/exec for dynamic code execution`,
        server: serverName,
        file: serverPath,
        line,
      });
    }

    if (/\.execute\(.*\+|\.execute\(.*format|\.execute\(.*%s/.test(funcBody)) {
      findings.push({
        severity: 'high',
        type: 'sql-injection',
        title: 'SQL injection risk',
        description: `Tool "${toolName}" may be vulnerable to SQL injection via string concatenation`,
        server: serverName,
        file: serverPath,
        line,
      });
    }

    // Check for tool description poisoning (overly long description)
    if (description.length > 500) {
      findings.push({
        severity: 'medium',
        type: 'description-poisoning',
        title: 'Suspiciously long tool description',
        description: `Tool "${toolName}" has a ${description.length}-char description that may contain hidden instructions`,
        server: serverName,
        file: serverPath,
        line,
      });
    }

    // Check for lack of input validation
    if (!funcBody.includes('validate') && !funcBody.includes('schema') &&
        !funcBody.includes('pydantic') && !funcBody.includes('typing')) {
      if (capabilities.some(c => c.includes('shell') || c.includes('execution'))) {
        findings.push({
          severity: 'high',
          type: 'no-input-validation',
          title: 'No input validation on dangerous tool',
          description: `Tool "${toolName}" has dangerous capabilities but no apparent input validation`,
          server: serverName,
          file: serverPath,
          line,
        });
      }
    }
  }

  // Check total tool count (>20 tools = potential over-permission)
  if (tools.length > 20) {
    findings.push({
      severity: 'medium',
      type: 'tool-proliferation',
      title: 'Excessive tool count',
      description: `Server has ${tools.length} tools — consider splitting into focused servers`,
      server: serverName,
      file: serverPath,
    });
  }

  return { tools, findings };
}

function extractFuncBody(content: string, startLine: number, lines: string[]): string {
  // Find the function def after the decorator
  let funcStart = startLine;
  for (let i = startLine; i < Math.min(startLine + 5, lines.length); i++) {
    if (/^\s*(?:async\s+)?def\s+/.test(lines[i])) {
      funcStart = i;
      break;
    }
  }

  // Grab up to 50 lines of the function body
  const funcLines: string[] = [];
  const indent = lines[funcStart]?.match(/^(\s*)/)?.[1]?.length ?? 0;

  for (let i = funcStart; i < Math.min(funcStart + 50, lines.length); i++) {
    funcLines.push(lines[i]);
    // Stop if we hit a line with equal or less indentation (end of function)
    if (i > funcStart && lines[i].trim().length > 0) {
      const lineIndent = lines[i].match(/^(\s*)/)?.[1]?.length ?? 0;
      if (lineIndent <= indent && !lines[i].trim().startsWith('#')) break;
    }
  }

  return funcLines.join('\n');
}

function detectCapabilities(body: string): string[] {
  const caps: string[] = [];
  if (/subprocess|os\.system|child_process|spawn\(|execSync/.test(body)) caps.push('shell');
  if (/open\(.*['"]\s*w|writeFile|fs\.write|shutil\.copy/.test(body)) caps.push('filesystem-write');
  if (/open\(|readFile|fs\.read|pathlib/.test(body)) caps.push('filesystem-read');
  if (/fetch\(|requests\.|http\.request|urllib|axios/.test(body)) caps.push('network');
  if (/sqlite|postgres|mysql|mongo|cursor\.execute/.test(body)) caps.push('database');
  if (/eval\(|exec\(|compile\(|new Function/.test(body)) caps.push('code-execution');
  if (/smtp|sendmail|send_email/.test(body)) caps.push('email');
  return caps;
}

/**
 * Scan multiple MCP source files in a directory.
 * Takes the list of MCP-detected file paths and aggregates results.
 */
export function scanMCPSourceDir(
  rootPath: string,
  mcpFiles: string[],
): { tools: MCPToolInfo[]; findings: MCPFinding[] } {
  const allTools: MCPToolInfo[] = [];
  const allFindings: MCPFinding[] = [];

  for (const file of mcpFiles) {
    const fullPath = path.isAbsolute(file) ? file : path.join(rootPath, file);
    const serverName = path.basename(file, path.extname(file));
    const result = scanMCPServerSource(fullPath, serverName);
    allTools.push(...result.tools);
    allFindings.push(...result.findings);
  }

  return { tools: allTools, findings: allFindings };
}
