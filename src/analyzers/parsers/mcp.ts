import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, ToolNode, ConfigNode } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  findNodes,
  type Tree,
} from '../ast/index.js';
import { findDecorators, getDecoratedFunction } from '../ast/python.js';
import { detectCapabilities as sharedDetectCapabilities, looksLikeSecret as sharedLooksLikeSecret } from './shared.js';

const MCP_TOOL_PATTERN = /(?:server\.tool|@(?:mcp\.tool|server\.call_tool))\s*\(\s*(?:["']([^"']+)["'])?/g;

export function parseMCP(graph: AgentGraph, files: FileInventory): void {
  // Parse MCP config files
  for (const file of [...files.json, ...files.configs]) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename === 'mcp.json' || basename === 'claude_desktop_config.json') {
      parseMCPConfig(file.path, file.relativePath, graph);
    }
  }

  // Parse server code
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Tightened gate: require MCP SDK import patterns, not bare 'mcp' substring
    // 'mcp' alone matches Minecraft protocol, multi-carrier protocol, etc.
    if (!content.includes('modelcontextprotocol') &&
        !content.includes('from mcp') &&
        !content.includes('mcp.server') && !content.includes('mcp.tool') &&
        !content.includes('McpServer') && !content.includes('FastMCP') &&
        !content.includes('StdioServerTransport') && !content.includes('SSEServerTransport')) continue;

    const lines = content.split('\n');
    const isPython = file.language === 'python';
    const tree = isPython && isTreeSitterAvailable()
      ? getFileTreeForLang(file.path, content, 'python')
      : null;

    if (tree) {
      extractToolsAST(tree, content, lines, file.relativePath, graph);
    } else {
      extractToolsRegex(content, lines, file.relativePath, graph);
    }
  }
}

function extractToolsAST(
  tree: Tree,
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  // Find @server.tool or @mcp.tool decorated functions
  const toolDecorators = findDecorators(tree, /^(server\.tool|mcp\.tool|server\.call_tool)$/);
  for (const dec of toolDecorators) {
    const func = getDecoratedFunction(dec);
    const funcName = func?.childForFieldName('name')?.text;
    const line = dec.startPosition.row + 1;

    // Extract description from the function's docstring
    const body = func?.childForFieldName('body');
    let description = '';
    if (body) {
      const firstStmt = body.children[0];
      if (firstStmt?.type === 'expression_statement') {
        const expr = firstStmt.children[0];
        if (expr?.type === 'string') {
          description = expr.text.replace(/^["']{1,3}|["']{1,3}$/g, '').trim();
        }
      }
    }

    // Analyze function body for capabilities
    const funcText = func?.text ?? '';
    const capabilities = detectCapabilities(funcText);

    graph.tools.push({
      id: `mcp-tool-${graph.tools.length}`,
      name: funcName ?? `mcp_tool_${line}`,
      framework: 'mcp',
      file: filePath,
      line,
      description,
      parameters: [],
      hasSideEffects: capabilities.length > 0,
      hasInputValidation: /schema|validate|zod|pydantic|typing/i.test(funcText),
      hasSandboxing: /sandbox|container|docker|subprocess.*shell\s*=\s*False/i.test(funcText),
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }

  // Also find server.tool() calls (non-decorator style)
  const serverToolCalls = findFunctionCalls(tree, /^server\.tool$/);
  for (const call of serverToolCalls) {
    // Skip if this is a decorator (already handled)
    if (call.parent?.type === 'decorator') continue;

    const line = call.startPosition.row + 1;
    const args = call.childForFieldName('arguments');
    let toolName: string | undefined;
    if (args) {
      const firstArg = args.children.find(c => c.type === 'string');
      if (firstArg) {
        toolName = firstArg.text.replace(/^["']|["']$/g, '');
      }
    }

    const body = extractFunctionBody(content, call.startPosition.row);
    const capabilities = detectCapabilities(body);

    graph.tools.push({
      id: `mcp-tool-${graph.tools.length}`,
      name: toolName ?? extractNextFunctionName(lines, line) ?? `mcp_tool_${line}`,
      framework: 'mcp',
      file: filePath,
      line,
      description: extractDescription(content, call.startPosition.row * 80),
      parameters: [],
      hasSideEffects: capabilities.length > 0,
      hasInputValidation: /schema|validate|zod|pydantic|typing/i.test(body),
      hasSandboxing: /sandbox|container|docker|subprocess.*shell\s*=\s*False/i.test(body),
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }
}

function extractToolsRegex(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  MCP_TOOL_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = MCP_TOOL_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const toolName = match[1] ?? extractNextFunctionName(lines, line);

    const body = extractFunctionBody(content, match.index);
    const capabilities = detectCapabilities(body);

    graph.tools.push({
      id: `mcp-tool-${graph.tools.length}`,
      name: toolName ?? `mcp_tool_${line}`,
      framework: 'mcp',
      file: filePath,
      line,
      description: extractDescription(content, match.index),
      parameters: [],
      hasSideEffects: capabilities.length > 0,
      hasInputValidation: /schema|validate|zod|pydantic|typing/i.test(body),
      hasSandboxing: /sandbox|container|docker|subprocess.*shell\s*=\s*False/i.test(body),
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }
}

function parseMCPConfig(filePath: string, relativePath: string, graph: AgentGraph): void {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return;
  }

  let parsed: any;
  try {
    parsed = JSON.parse(content);
  } catch {
    return;
  }

  const configNode: ConfigNode = {
    id: `mcp-config-${graph.configs.length}`,
    file: relativePath,
    type: 'json',
    secrets: [],
    issues: [],
  };

  const servers = parsed.mcpServers ?? parsed.servers ?? {};
  for (const [name, config] of Object.entries(servers)) {
    const serverConfig = config as Record<string, any>;

    if (serverConfig.command === 'npx') {
      const args = serverConfig.args ?? [];
      if (args.includes('-y') || args.includes('--yes')) {
        configNode.issues.push({
          type: 'npx-auto-install',
          message: `MCP server "${name}" uses npx -y (auto-install without version pinning)`,
          line: findKeyInJson(content, name),
        });
      }

      const pkgArg = args.find((a: string) => !a.startsWith('-'));
      if (pkgArg && !pkgArg.includes('@')) {
        configNode.issues.push({
          type: 'unpinned-mcp-server',
          message: `MCP server "${name}" uses unpinned package: ${pkgArg}`,
          line: findKeyInJson(content, name),
        });
      }
    }

    const env = serverConfig.env ?? {};
    for (const [key, value] of Object.entries(env)) {
      if (typeof value === 'string' && looksLikeSecret(value)) {
        configNode.secrets.push({
          key,
          line: findKeyInJson(content, key),
          isHardcoded: true,
        });
      }
    }
  }

  graph.configs.push(configNode);
}

function extractNextFunctionName(lines: string[], lineNum: number): string | undefined {
  for (let i = lineNum; i < Math.min(lineNum + 5, lines.length); i++) {
    const funcMatch = lines[i]?.match(/(?:def|function|async\s+function|const)\s+(\w+)/);
    if (funcMatch) return funcMatch[1];
  }
  return undefined;
}

function extractFunctionBody(content: string, startIndex: number): string {
  return content.substring(startIndex, startIndex + 2000);
}

function extractDescription(content: string, index: number): string {
  const region = content.substring(index, index + 500);
  const docMatch = region.match(/"""([\s\S]*?)"""|'''([\s\S]*?)'''|\/\*\*([\s\S]*?)\*\//);
  return (docMatch?.[1] ?? docMatch?.[2] ?? docMatch?.[3] ?? '').trim();
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  return sharedDetectCapabilities(body);
}

function looksLikeSecret(value: string): boolean {
  return sharedLooksLikeSecret(value);
}

function findKeyInJson(content: string, key: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${key}"`)) return i + 1;
  }
  return 1;
}
