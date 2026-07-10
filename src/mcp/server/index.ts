// g0's MCP server: exposes a read-only subset of g0's engine as MCP tools
// over stdio, so agent hosts (Claude Code, Cursor, Windsurf, ...) can run
// `g0 scan`, `g0 inventory`, MCP-package verification, etc. in-process.
//
// STDOUT PURITY: the stdio transport owns stdout for the JSON-RPC protocol.
// Nothing in this module (or anything it calls on the tool-handling paths)
// may write to stdout — no console.log, no chalk, no ora spinners.
// Diagnostics go to console.error (stderr) only. The `@modelcontextprotocol/sdk`
// import is deliberately NOT at the top of this file's callers (see
// src/cli/commands/mcp.ts) so it never loads on the hot CLI startup path for
// other commands — but within this module (loaded only by `g0 mcp serve`) a
// static import is fine.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { G0_VERSION } from '../../utils/version.js';
import type { ToolContext } from './tools/util.js';

import { scanProjectInputShape, scanProjectDescription, scanProject } from './tools/scan-project.js';
import { scanMcpServerInputShape, scanMcpServerDescription, scanMcpServer } from './tools/scan-mcp-server.js';
import { verifyMcpPackageInputShape, verifyMcpPackageDescription, verifyMcpPackage } from './tools/verify-mcp-package.js';
import { inventoryInputShape, inventoryDescription, inventory } from './tools/inventory.js';
import { explainFindingInputShape, explainFindingDescription, explainFinding } from './tools/explain-finding.js';
import { getScoreInputShape, getScoreDescription, getScore } from './tools/get-score.js';

export interface CreateG0McpServerOptions {
  /** Confines path-accepting tools to this directory. Strongly recommended. */
  projectRoot?: string;
}

/**
 * Builds a `McpServer` with g0's 6 read-only tools registered. Does not
 * connect a transport — callers (e.g. `startStdioServer`, or tests using an
 * in-memory transport) own that.
 */
export function createG0McpServer(opts: CreateG0McpServerOptions = {}): McpServer {
  const server = new McpServer({ name: 'g0', version: G0_VERSION });
  const ctx: ToolContext = { projectRoot: opts.projectRoot };

  server.registerTool(
    'scan_project',
    {
      description: scanProjectDescription,
      inputSchema: scanProjectInputShape,
      annotations: { readOnlyHint: true, title: 'Scan an agent project with g0' },
    },
    async (args) => scanProject(args, ctx),
  );

  server.registerTool(
    'scan_mcp_server',
    {
      description: scanMcpServerDescription,
      inputSchema: scanMcpServerInputShape,
      annotations: { readOnlyHint: true, title: 'Scan an MCP server\'s source code' },
    },
    async (args) => scanMcpServer(args, ctx),
  );

  server.registerTool(
    'verify_mcp_package',
    {
      description: verifyMcpPackageDescription,
      inputSchema: verifyMcpPackageInputShape,
      annotations: { readOnlyHint: true, title: 'Verify an npm package before installing it as an MCP server' },
    },
    async (args) => verifyMcpPackage(args),
  );

  server.registerTool(
    'inventory',
    {
      description: inventoryDescription,
      inputSchema: inventoryInputShape,
      annotations: { readOnlyHint: true, title: 'Generate an AI asset inventory / AI-BOM' },
    },
    async (args) => inventory(args, ctx),
  );

  server.registerTool(
    'explain_finding',
    {
      description: explainFindingDescription,
      inputSchema: explainFindingInputShape,
      annotations: { readOnlyHint: true, title: 'Explain a g0 rule or finding' },
    },
    async (args) => explainFinding(args, ctx),
  );

  server.registerTool(
    'get_score',
    {
      description: getScoreDescription,
      inputSchema: getScoreInputShape,
      annotations: { readOnlyHint: true, title: 'Get the g0 score for a project' },
    },
    async (args) => getScore(args, ctx),
  );

  return server;
}

export interface StartStdioServerOptions extends CreateG0McpServerOptions {}

/**
 * Starts `g0 mcp serve`: connects a `StdioServerTransport` and keeps the
 * process alive until stdin closes or the process is signaled. Never writes
 * to stdout outside of the transport itself.
 */
export async function startStdioServer(opts: StartStdioServerOptions = {}): Promise<void> {
  const server = createG0McpServer(opts);
  const transport = new StdioServerTransport();

  let closing = false;
  const shutdown = () => {
    if (closing) return;
    closing = true;
    server.close().finally(() => process.exit(0));
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await server.connect(transport);
}
