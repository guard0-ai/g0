import { describe, it, expect } from 'vitest';
import * as path from 'node:path';
import { runDiscovery, runGraphBuild } from '../../src/pipeline.js';
import { analyzeFlows } from '../../src/flows/analyzer.js';
import { buildFlowGraph } from '../../src/flows/graph-builder.js';
import { enumeratePaths } from '../../src/flows/path-finder.js';
import { scorePaths } from '../../src/flows/scorer.js';
import { reportFlowsJson } from '../../src/reporters/flows-json.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');

describe('buildFlowGraph', () => {
  it('creates user_input node', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const { nodes } = buildFlowGraph(graph);

    const userNode = nodes.find(n => n.id === 'user_input');
    expect(userNode).toBeTruthy();
    expect(userNode?.trust).toBe('untrusted');
  });

  it('creates agent nodes', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const { nodes } = buildFlowGraph(graph);

    const agentNodes = nodes.filter(n => n.type === 'agent');
    expect(agentNodes.length).toBeGreaterThanOrEqual(2);
  });

  it('creates tool nodes with scope', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const { nodes } = buildFlowGraph(graph);

    const toolNodes = nodes.filter(n => n.type === 'tool');
    expect(toolNodes.length).toBeGreaterThan(0);
    expect(toolNodes.some(t => t.scope !== undefined)).toBe(true);
  });

  it('creates edges between agents and tools', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const { edges } = buildFlowGraph(graph);

    expect(edges.length).toBeGreaterThan(0);
    expect(edges.some(e => e.label === 'invokes')).toBe(true);
  });
});

describe('enumeratePaths', () => {
  it('finds paths from user_input to tools', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const { nodes, edges } = buildFlowGraph(graph);
    const paths = enumeratePaths(nodes, edges);

    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].nodes[0]).toBe('user_input');
  });

  it('handles empty graph', () => {
    const paths = enumeratePaths([], []);
    expect(paths).toEqual([]);
  });
});

describe('scorePaths', () => {
  it('identifies toxic flows for dangerous tools', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const { nodes, edges } = buildFlowGraph(graph);
    const paths = enumeratePaths(nodes, edges);
    const toxicFlows = scorePaths(paths, nodes);

    expect(toxicFlows.length).toBeGreaterThan(0);
  });
});

describe('analyzeFlows', () => {
  it('produces full analysis for flow-agent', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const result = analyzeFlows(graph);

    expect(result.nodes.length).toBeGreaterThan(0);
    expect(result.edges.length).toBeGreaterThan(0);
    expect(result.paths.length).toBeGreaterThan(0);
    expect(result.toxicFlows.length).toBeGreaterThan(0);
    expect(result.summary.riskLevel).not.toBe('safe');
  });

  it('produces full analysis for vulnerable-agent', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'vulnerable-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'vulnerable-agent'), discovery, true);
    const result = analyzeFlows(graph);

    expect(result.toxicFlows.length).toBeGreaterThan(0);
    const critFlows = result.toxicFlows.filter(t => t.severity === 'critical');
    expect(critFlows.length).toBeGreaterThan(0);
  });

  it('produces JSON output', async () => {
    const discovery = await runDiscovery(path.join(FIXTURES, 'flow-agent'));
    const graph = runGraphBuild(path.join(FIXTURES, 'flow-agent'), discovery, true);
    const result = analyzeFlows(graph);

    const json = reportFlowsJson(result);
    const parsed = JSON.parse(json);
    expect(parsed.nodes).toBeInstanceOf(Array);
    expect(parsed.toxicFlows).toBeInstanceOf(Array);
    expect(parsed.summary).toBeTruthy();
  });
});

describe('Edge cases', () => {
  it('handles project with no agents gracefully', async () => {
    // Create a minimal graph with no agents
    const emptyGraph: AgentGraph = {
      id: 'test',
      rootPath: '/tmp',
      primaryFramework: 'generic',
      secondaryFrameworks: [],
      agents: [],
      tools: [],
      prompts: [],
      configs: [],
      models: [],
      vectorDBs: [],
      frameworkVersions: [],
      files: { all: [], python: [], typescript: [], javascript: [], yaml: [], json: [], configs: [] },
    };

    const result = analyzeFlows(emptyGraph);
    expect(result.nodes.length).toBe(1); // just user_input
    expect(result.toxicFlows.length).toBe(0);
    expect(result.summary.riskLevel).toBe('safe');
  });
});
