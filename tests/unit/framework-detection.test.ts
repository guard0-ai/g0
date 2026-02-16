import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { walkDirectory } from '../../src/discovery/walker.js';
import { detectFrameworks } from '../../src/discovery/detector.js';
import { runScan } from '../../src/pipeline.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('Vercel AI SDK detection', () => {
  it('detects Vercel AI framework from fixture', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'vercel-ai-agent'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('vercel-ai');
  });

  it('scans Vercel AI agent and finds issues', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'vercel-ai-agent') });
    expect(result.graph.primaryFramework).toBe('vercel-ai');
    expect(result.findings.length).toBeGreaterThan(0);

    // Should detect agents from generateText/streamText calls
    expect(result.graph.agents.length).toBeGreaterThan(0);

    // Should detect tools
    expect(result.graph.tools.length).toBeGreaterThan(0);
  });
});

describe('AWS Bedrock detection', () => {
  it('detects Bedrock framework from fixture', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'bedrock-agent'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('bedrock');
  });

  it('scans Bedrock agent and finds issues', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'bedrock-agent') });
    expect(result.graph.primaryFramework).toBe('bedrock');
    expect(result.findings.length).toBeGreaterThan(0);

    // Should detect agents
    expect(result.graph.agents.length).toBeGreaterThan(0);

    // Should detect models
    expect(result.graph.models.length).toBeGreaterThan(0);
  });
});

describe('AutoGen detection', () => {
  it('detects AutoGen framework from fixture', async () => {
    const inventory = await walkDirectory(path.join(FIXTURES, 'autogen-group'));
    const result = detectFrameworks(inventory);
    expect(result.primary).toBe('autogen');
  });

  it('scans AutoGen group and finds issues', async () => {
    const result = await runScan({ includeTests: true, showAll: true, targetPath: path.join(FIXTURES, 'autogen-group') });
    expect(result.graph.primaryFramework).toBe('autogen');
    expect(result.findings.length).toBeGreaterThan(0);

    // Should detect multiple agents (coder, executor, planner, researcher)
    expect(result.graph.agents.length).toBeGreaterThanOrEqual(3);

    // Should detect tools registered with decorators
    expect(result.graph.tools.length).toBeGreaterThan(0);
  });
});
