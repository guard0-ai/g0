import { describe, it, expect, afterEach } from 'vitest';
import * as path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const REPO_ROOT = path.resolve(__dirname, '../..');
const TSX_BIN = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
const FIXTURES = path.resolve(__dirname, '../fixtures');

// This suite spawns the real `g0 mcp serve` CLI subcommand as a child
// process and speaks MCP to it over stdio using the SDK's own Client. This
// is the definitive proof of "stdout purity": the JSON-RPC `initialize`
// handshake is the very first thing written to the child's stdout, so a
// single stray banner/spinner/console.log byte ahead of it breaks framing
// and this test fails.
async function connectClient(projectRoot: string): Promise<{ client: Client; transport: StdioClientTransport }> {
  const transport = new StdioClientTransport({
    command: TSX_BIN,
    args: [path.join(REPO_ROOT, 'bin', 'g0.ts'), 'mcp', 'serve', '--project-root', projectRoot],
    cwd: REPO_ROOT,
    stderr: 'pipe',
  });
  const client = new Client({ name: 'g0-mcp-serve-test', version: '0.0.0' });
  await client.connect(transport);
  return { client, transport };
}

describe('g0 mcp serve (stdio integration)', () => {
  let activeTransport: StdioClientTransport | undefined;

  afterEach(async () => {
    if (activeTransport) {
      await activeTransport.close();
      activeTransport = undefined;
    }
  });

  it('completes the MCP handshake with a clean stdout (no banner/log pollution)', async () => {
    const { client, transport } = await connectClient(path.join(FIXTURES, 'vulnerable-agent'));
    activeTransport = transport;

    const serverInfo = client.getServerVersion();
    expect(serverInfo?.name).toBe('g0');
  }, 30000);

  it('lists all 6 read-only tools with schemas', async () => {
    const { client, transport } = await connectClient(path.join(FIXTURES, 'vulnerable-agent'));
    activeTransport = transport;

    const { tools } = await client.listTools();
    const names = tools.map(t => t.name).sort();

    expect(names).toEqual([
      'explain_finding',
      'get_score',
      'inventory',
      'scan_mcp_server',
      'scan_project',
      'verify_mcp_package',
    ]);

    for (const tool of tools) {
      expect(tool.inputSchema).toBeDefined();
      expect(tool.inputSchema.type).toBe('object');
      expect(tool.annotations?.readOnlyHint).toBe(true);
    }
  }, 30000);

  it('calls scan_project over the wire and gets a well-formed result', async () => {
    const fixtureDir = path.join(FIXTURES, 'vulnerable-agent');
    const { client, transport } = await connectClient(fixtureDir);
    activeTransport = transport;

    const result = await client.callTool({
      name: 'scan_project',
      arguments: { path: fixtureDir },
    });

    expect(result.isError).toBeFalsy();
    expect(Array.isArray(result.content)).toBe(true);
    const textBlock = (result.content as Array<{ type: string; text?: string }>).find(c => c.type === 'text');
    expect(textBlock?.text).toContain('g0 scan result');

    const structured = result.structuredContent as any;
    expect(structured).toBeDefined();
    expect(typeof structured.score).toBe('number');
    expect(structured.grade).toMatch(/^[A-F]$/);
    expect(structured.totalFindings).toBeGreaterThan(0);
  }, 30000);

  it('rejects a scan_project path that escapes --project-root', async () => {
    const fixtureDir = path.join(FIXTURES, 'vulnerable-agent');
    const { client, transport } = await connectClient(fixtureDir);
    activeTransport = transport;

    const result = await client.callTool({
      name: 'scan_project',
      arguments: { path: '../mcp-server' },
    });

    expect(result.isError).toBe(true);
  }, 30000);
});
