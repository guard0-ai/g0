import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

const MCP_PATTERNS = [
  /from\s+mcp\s+import/,
  /from\s+mcp\.server/,
  /@mcp\.tool/,
  /McpServer/,
  /FastMCP/,
  /require\s*\(\s*['"]@modelcontextprotocol/,
  /from\s+['"]@modelcontextprotocol/,
  /import.*@modelcontextprotocol/,
  /mcp_server\s*=\s*Server/,
  /StdioServerTransport/,
  /SSEServerTransport/,
  /StreamableHTTPServerTransport/,
];

const MCP_CONFIG_FILES = ['mcp.json', 'claude_desktop_config.json'];

export function detectMCP(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check for MCP config files (low weight — many repos include these as examples)
  for (const file of [...files.json, ...files.configs]) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (MCP_CONFIG_FILES.includes(basename)) {
      evidence.push(`${file.relativePath}: MCP config file`);
      matchedFiles.push(file.relativePath);
      confidence += 0.15;
    }
  }

  // Check code files
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    for (const pattern of MCP_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        break;
      }
    }
  }

  // Check deps
  for (const file of files.configs) {
    // Skip lock files — transitive deps cause false detection
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (content.includes('@modelcontextprotocol')) {
      evidence.push(`${file.relativePath}: depends on MCP SDK`);
      confidence += 0.3;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'mcp',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.3,
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
