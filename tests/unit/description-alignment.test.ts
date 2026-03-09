import { describe, it, expect } from 'vitest';
import { checkDescriptionAlignment, detectOverprivilegedDescriptions } from '../../src/mcp/description-alignment.js';
import type { MCPToolInfo } from '../../src/types/mcp-scan.js';

function makeTool(name: string, description: string, capabilities: string[]): MCPToolInfo {
  return {
    name,
    description,
    capabilities,
    hasSideEffects: false,
    file: 'test.py',
    line: 1,
  };
}

describe('Description-Behavior Alignment', () => {
  it('flags read-only description with write capabilities', () => {
    const tools = [makeTool('reader', 'A read-only tool for viewing data', ['filesystem-read', 'filesystem-write'])];
    const results = checkDescriptionAlignment(tools);
    expect(results).toHaveLength(1);
    expect(results[0].toolName).toBe('reader');
    expect(results[0].undisclosedCapabilities).toContain('filesystem-write');
    expect(results[0].aligned).toBe(false);
  });

  it('flags no-network description with network capability', () => {
    const tools = [makeTool('local-tool', 'A local-only tool that does not access the network', ['network'])];
    const results = checkDescriptionAlignment(tools);
    expect(results).toHaveLength(1);
    expect(results[0].undisclosedCapabilities).toContain('network');
  });

  it('flags read-only description with shell capability', () => {
    const tools = [makeTool('viewer', 'Only reads files, no execution', ['filesystem-read', 'shell'])];
    const results = checkDescriptionAlignment(tools);
    expect(results).toHaveLength(1);
    expect(results[0].undisclosedCapabilities).toContain('shell');
    expect(results[0].severity).toBe('high'); // shell is high severity
  });

  it('passes when description matches capabilities', () => {
    const tools = [makeTool('fetcher', 'Fetches data from URLs', ['network', 'filesystem-read'])];
    const results = checkDescriptionAlignment(tools);
    expect(results).toHaveLength(0);
  });

  it('passes for tools without restrictive claims', () => {
    const tools = [makeTool('multi-tool', 'A versatile tool', ['shell', 'network', 'filesystem-write'])];
    const results = checkDescriptionAlignment(tools);
    expect(results).toHaveLength(0); // no restrictive claims to contradict
  });

  describe('Overprivileged Descriptions', () => {
    it('detects "any file" language', () => {
      const tools = [makeTool('admin-tool', 'Can access any file on the system', ['filesystem-read'])];
      const findings = detectOverprivilegedDescriptions(tools);
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe('overprivileged-description');
    });

    it('detects "full access" language', () => {
      const tools = [makeTool('super-tool', 'Provides full access to the database', ['database'])];
      const findings = detectOverprivilegedDescriptions(tools);
      expect(findings).toHaveLength(1);
    });

    it('passes for bounded descriptions', () => {
      const tools = [makeTool('scoped-tool', 'Reads files from the data directory only', ['filesystem-read'])];
      const findings = detectOverprivilegedDescriptions(tools);
      expect(findings).toHaveLength(0);
    });
  });
});
