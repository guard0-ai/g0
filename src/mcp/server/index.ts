// g0's MCP server: exposes a read-only subset of g0's engine as MCP tools
// over stdio, so agent hosts (Claude Code, Cursor, Windsurf, ...) can run
// `g0 scan`, `g0 inventory`, MCP-package verification, etc. in-process.
//
// STDOUT PURITY: the stdio transport owns stdout for the JSON-RPC protocol.
// Nothing in this module (or anything it calls on the tool-handling paths)
// may write to stdout — no console.log, no chalk, no ora spinners.
// Diagnostics go to console.error (stderr) only.
//
// SDK LOAD IS LAZY, EVEN HERE: this module is only ever reached via the
// dynamic `await import(...)` in `src/cli/commands/mcp.ts`'s `serve` action,
// but tsup's single-file bundle (`splitting: false`) inlines that dynamically
// imported module into the same chunk as everything else. If this file had a
// top-level *static* `import ... from '@modelcontextprotocol/sdk/...'`, ESM
// hoisting would make that import execute at bundle-load time — i.e. on
// EVERY `g0` invocation, not just `g0 mcp serve` — and it would also make
// `@guard0/g0` fail to load as a library for any consumer that doesn't have
// the SDK installed. So the SDK imports below are runtime `await import()`
// calls made from inside the functions that need them. Only *type* imports
// (erased at build, no runtime load) are allowed at module top level.
import { G0_VERSION } from '../../utils/version.js';
import type { ToolContext } from './tools/util.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

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
 *
 * Async because it lazily `import()`s `@modelcontextprotocol/sdk` on first
 * use — see the module-level comment above for why that load must not be a
 * top-level static import.
 */
export async function createG0McpServer(opts: CreateG0McpServerOptions = {}): Promise<McpServer> {
  const { McpServer } = await import('@modelcontextprotocol/sdk/server/mcp.js');
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
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const server = await createG0McpServer(opts);
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
