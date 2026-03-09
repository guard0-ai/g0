import { describe, it, expect } from 'vitest';
import { detectDangerousToolCombinations, convertToolComboToFindings } from '../../src/analyzers/cross-tool-correlation.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';

function makeGraph(agents: any[], tools: any[]): AgentGraph {
  return {
    agents,
    tools,
    models: [],
    prompts: [],
    files: { all: [], python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [] },
    rootPath: '/test',
    primaryFramework: 'generic',
    secondaryFrameworks: [],
    frameworkVersions: [],
    edges: [],
    interAgentLinks: [],
    vectorDBs: [],
    apiEndpoints: [],
    databaseAccesses: [],
    authFlows: [],
    permissionChecks: [],
    permissions: [],
    piiReferences: [],
    messageQueues: [],
    rateLimits: [],
    callGraph: [],
  } as any;
}

describe('Cross-Tool Correlation', () => {
  it('detects read-then-exfil combination', () => {
    const graph = makeGraph(
      [{ name: 'agent1', tools: ['file-reader', 'http-sender'] }],
      [
        { name: 'file-reader', id: 'file-reader', capabilities: ['filesystem'], hasInputValidation: false, hasSandboxing: false, hasSideEffects: false },
        { name: 'http-sender', id: 'http-sender', capabilities: ['network'], hasInputValidation: false, hasSandboxing: false, hasSideEffects: true },
      ],
    );
    const risks = detectDangerousToolCombinations(graph);
    expect(risks.length).toBeGreaterThanOrEqual(1);
    expect(risks[0].riskType).toBe('read-then-exfil');
    expect(risks[0].agentName).toBe('agent1');
  });

  it('detects fetch-then-exec combination', () => {
    const graph = makeGraph(
      [{ name: 'agent2', tools: ['downloader', 'code-runner'] }],
      [
        { name: 'downloader', id: 'downloader', capabilities: ['network'], hasInputValidation: false, hasSandboxing: false, hasSideEffects: false },
        { name: 'code-runner', id: 'code-runner', capabilities: ['code-execution'], hasInputValidation: false, hasSandboxing: false, hasSideEffects: true },
      ],
    );
    const risks = detectDangerousToolCombinations(graph);
    expect(risks.some(r => r.riskType === 'fetch-then-exec')).toBe(true);
  });

  it('does not flag single-tool capabilities', () => {
    const graph = makeGraph(
      [{ name: 'agent3', tools: ['swiss-army'] }],
      [
        { name: 'swiss-army', id: 'swiss-army', capabilities: ['filesystem-read', 'network'], hasInputValidation: true, hasSandboxing: true, hasSideEffects: true },
      ],
    );
    const risks = detectDangerousToolCombinations(graph);
    // Single tool = not cross-tool, should not flag
    expect(risks).toHaveLength(0);
  });

  it('does not flag non-dangerous combinations', () => {
    const graph = makeGraph(
      [{ name: 'agent4', tools: ['reader', 'writer'] }],
      [
        { name: 'reader', id: 'reader', capabilities: ['filesystem'], hasInputValidation: true, hasSandboxing: false, hasSideEffects: false },
        { name: 'writer', id: 'writer', capabilities: ['filesystem'], hasInputValidation: true, hasSandboxing: false, hasSideEffects: true },
      ],
    );
    const risks = detectDangerousToolCombinations(graph);
    // filesystem-read + filesystem-write is not in the dangerous combos
    expect(risks).toHaveLength(0);
  });

  it('converts risks to findings', () => {
    const risks = [{
      agentName: 'test-agent',
      tools: ['reader', 'sender'],
      riskType: 'read-then-exfil',
      description: 'Test description',
      severity: 'high' as const,
    }];
    const findings = convertToolComboToFindings(risks);
    expect(findings).toHaveLength(1);
    expect(findings[0].domain).toBe('tool-safety');
    expect(findings[0].severity).toBe('high');
    expect(findings[0].ruleId).toBe('AA-TS-CROSS-001');
  });
});
