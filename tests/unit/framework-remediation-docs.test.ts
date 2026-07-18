import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

describe('framework remediation docs', () => {
  it('links the MCP remediation guide from the docs index', () => {
    const docsIndex = readFileSync('docs/README.md', 'utf8');
    const frameworksGuide = readFileSync('docs/frameworks.md', 'utf8');

    expect(docsIndex).toContain('frameworks/');
    expect(frameworksGuide).toContain('frameworks/mcp.md');
  });

  it('covers key MCP remediation patterns', () => {
    const guide = readFileSync('docs/frameworks/mcp.md', 'utf8');

    expect(guide).toContain('inputSchema');
    expect(guide).toContain('additionalProperties');
    expect(guide).toContain('Pin server packages');
    expect(guide).toContain('tool-call audit event');
    expect(guide).toContain('Human review');
  });
});
