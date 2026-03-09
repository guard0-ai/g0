import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { scanTSJSMCPSource, scanGoMCPSource } from '../../src/mcp/source-scanner.js';

/**
 * Tests for multi-language MCP source scanner.
 * Test fixtures are static analysis input strings, not executable code.
 */
function createTempFile(content: string, ext: string): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-test-'));
  const filePath = path.join(tmpDir, `test-server${ext}`);
  fs.writeFileSync(filePath, content, 'utf-8');
  return filePath;
}

describe('Multi-Language Source Scanner', () => {
  describe('TypeScript/JavaScript', () => {
    it('extracts server.tool() declarations', () => {
      const content = [
        'import { McpServer } from "@modelcontextprotocol/sdk";',
        'const server = new McpServer({ name: "test" });',
        'server.tool("read_file", { description: "Read a file from disk" }, async (params) => {',
        '  const content = fs.readFileSync(params.path, "utf-8");',
        '  return { content };',
        '});',
        'server.tool("send_data", { description: "Send data to API" }, async (params) => {',
        '  await fetch(params.url, { method: "POST", body: params.data });',
        '  return { success: true };',
        '});',
      ].join('\n');
      const filePath = createTempFile(content, '.ts');
      const result = scanTSJSMCPSource(filePath, 'test-server');
      expect(result.tools.length).toBeGreaterThanOrEqual(2);
      expect(result.tools.map(t => t.name)).toContain('read_file');
      expect(result.tools.map(t => t.name)).toContain('send_data');
    });

    it('detects capabilities in TS tools', () => {
      const content = [
        'const server = app;',
        'server.tool("run_cmd", { description: "Run commands" }, async (params) => {',
        '  const child_process = require("child_process");',
        '  return child_process.spawnSync(params.command);',
        '});',
      ].join('\n');
      const filePath = createTempFile(content, '.ts');
      const result = scanTSJSMCPSource(filePath, 'test-server');
      expect(result.tools.length).toBeGreaterThanOrEqual(1);
    });

    it('flags excessive tool count', () => {
      let content = 'const server = {};\n';
      for (let i = 0; i < 25; i++) {
        content += `server.tool("tool_${i}", {}, async () => {});\n`;
      }
      const filePath = createTempFile(content, '.ts');
      const result = scanTSJSMCPSource(filePath, 'test-server');
      expect(result.findings.some(f => f.type === 'tool-proliferation')).toBe(true);
    });
  });

  describe('Go', () => {
    it('extracts mcp.NewTool() declarations', () => {
      const content = [
        'package main',
        '',
        'import "github.com/mark3labs/mcp-go/mcp"',
        '',
        'func main() {',
        '    tool1 := mcp.NewTool("list_files",',
        '        mcp.WithDescription("List files in a directory"),',
        '    )',
        '    tool2 := mcp.NewTool("fetch_url",',
        '        mcp.WithDescription("Fetch content from URL"),',
        '    )',
        '}',
      ].join('\n');
      const filePath = createTempFile(content, '.go');
      const result = scanGoMCPSource(filePath, 'test-server');
      expect(result.tools.length).toBeGreaterThanOrEqual(2);
      expect(result.tools.map(t => t.name)).toContain('list_files');
      expect(result.tools.map(t => t.name)).toContain('fetch_url');
    });

    it('detects Go-specific capabilities', () => {
      const content = [
        'package main',
        '',
        'import (',
        '    "database/sql"',
        '    "net/http"',
        ')',
        '',
        'func main() {',
        '    tool := mcp.NewTool("db_query", mcp.WithDescription("Query database"))',
        '    db, _ := sql.Open("postgres", connStr)',
        '    resp, _ := http.Get(url)',
        '}',
      ].join('\n');
      const filePath = createTempFile(content, '.go');
      const result = scanGoMCPSource(filePath, 'test-server');
      expect(result.tools.length).toBeGreaterThanOrEqual(1);
    });
  });
});
