import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { runScan } from '../../src/pipeline.js';
import { runDiscovery, runGraphBuild } from '../../src/pipeline.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('Vercel AI: completions are not counted as agents', () => {
  it('counts only tool/step-using calls as agents, not bare completions', async () => {
    // Fixture has 3 LLM calls: 2 bare completions + 1 with tools/maxSteps.
    const root = path.join(FIXTURES, 'vercel-completion');
    const discovery = await runDiscovery(root);
    const graph = runGraphBuild(root, discovery, true);
    expect(graph.primaryFramework).toBe('vercel-ai');
    expect(graph.agents.length).toBe(1);
    // The bare completions still register a model / prompt, just not an agent.
    expect(graph.models.length).toBeGreaterThan(0);
  });

  it('still detects a genuine tool-calling agent in the vercel-ai-agent fixture', async () => {
    const root = path.join(FIXTURES, 'vercel-ai-agent');
    const discovery = await runDiscovery(root);
    const graph = runGraphBuild(root, discovery, true);
    expect(graph.agents.length).toBeGreaterThan(0);
  });
});

describe('Hardcoded secrets surface regardless of reachability', () => {
  it('does not reachability-suppress a hardcoded key in a utility file', async () => {
    // The project has an agent (so utility-code suppression is active), and a
    // standalone helper that hardcodes an OpenAI key.
    const result = await runScan({ targetPath: path.join(FIXTURES, 'secret-in-util') });
    const secret = result.findings.find(f => f.ruleId === 'AA-IA-001');
    expect(secret).toBeDefined();
    expect(secret!.severity).toBe('critical');
    // It is utility-code, yet still present in the default (non --show-all) output.
    expect(secret!.reachability).toBe('utility-code');
  });
});
