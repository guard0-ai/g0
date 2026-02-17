import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { DetectionResult } from '../detector.js';

// High-confidence patterns — specific to MCP SDK
const MCP_SPECIFIC_PATTERNS = [
  /from\s+mcp\.server/,
  /@mcp\.tool/,
  /\bMcpServer\b/,
  /\bFastMCP\b/,
  /require\s*\(\s*['"]@modelcontextprotocol/,
  /from\s+['"]@modelcontextprotocol/,
  /import.*@modelcontextprotocol/,
  /mcp_server\s*=\s*Server/,
  /\bStdioServerTransport\b/,
  /\bSSEServerTransport\b/,
  /\bStreamableHTTPServerTransport\b/,
];

// Lower-confidence: 'from mcp import' — only if corroborated by dep
const MCP_IMPORT_PATTERN = /from\s+mcp\s+import/;

const MCP_CONFIG_FILES = ['mcp.json', 'claude_desktop_config.json'];

export function detectMCP(files: FileInventory): DetectionResult | null {
  const evidence: string[] = [];
  const matchedFiles: string[] = [];
  let confidence = 0;

  // Check deps first (needed to validate 'from mcp import')
  let hasMCPDep = false;
  for (const file of files.configs) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename.endsWith('.lock')) continue;

    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (content.includes('@modelcontextprotocol')) {
      hasMCPDep = true;
      evidence.push(`${file.relativePath}: depends on MCP SDK`);
      confidence += 0.3;
    }
    // Check for Python mcp package in requirements
    if (/\bmcp\b/.test(content) && (basename.includes('requirements') || basename === 'pyproject.toml')) {
      hasMCPDep = true;
      evidence.push(`${file.relativePath}: depends on mcp`);
      confidence += 0.3;
    }
  }

  // Check for MCP config files (low weight — many repos include these as examples)
  for (const file of [...files.json, ...files.configs]) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (MCP_CONFIG_FILES.includes(basename)) {
      // Verify the config actually has mcpServers or servers key
      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        continue;
      }
      if (content.includes('mcpServers') || content.includes('"servers"')) {
        evidence.push(`${file.relativePath}: MCP config file (verified)`);
        matchedFiles.push(file.relativePath);
        confidence += 0.15;
      }
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

    let matched = false;

    // Check specific patterns (high confidence)
    for (const pattern of MCP_SPECIFIC_PATTERNS) {
      if (pattern.test(content)) {
        matchedFiles.push(file.relativePath);
        evidence.push(`${file.relativePath}: matches ${pattern.source}`);
        confidence += 0.2;
        matched = true;
        break;
      }
    }

    // 'from mcp import' only counts if MCP dep is confirmed
    if (!matched && hasMCPDep && MCP_IMPORT_PATTERN.test(content)) {
      matchedFiles.push(file.relativePath);
      evidence.push(`${file.relativePath}: matches from mcp import (dep confirmed)`);
      confidence += 0.2;
    }
  }

  if (confidence === 0) return null;

  return {
    framework: 'mcp',
    confidence: Math.min(confidence, 1),
    rawConfidence: confidence,
    specificity: 0.8,  // raised from 0.3 — transport patterns are very specific
    evidence,
    files: [...new Set(matchedFiles)],
  };
}
