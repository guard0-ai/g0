import { describe, it, expect } from 'vitest';
import type { AgentGraph } from '../../src/types/agent-graph.js';
import { buildReachabilityIndex } from '../../src/analyzers/reachability.js';

function makeMinimalGraph(overrides?: Partial<AgentGraph>): AgentGraph {
  return {
    id: 'test',
    rootPath: '/test',
    primaryFramework: 'langchain',
    secondaryFrameworks: [],
    agents: [],
    tools: [],
    prompts: [],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files: {
      all: [],
      python: [],
      typescript: [],
      javascript: [],
      yaml: [],
      json: [],
      configs: [],
    },
    ...overrides,
  };
}

describe('Reachability Index', () => {
  it('marks agent files as agent-reachable', () => {
    const graph = makeMinimalGraph({
      agents: [{
        id: 'a1', name: 'TestAgent', framework: 'langchain',
        file: '/test/agent.py', line: 10, tools: [],
      }],
    });

    const index = buildReachabilityIndex(graph);
    expect(index.getReachability('/test/agent.py', 15)).toBe('agent-reachable');
    expect(index.agentFiles.has('/test/agent.py')).toBe(true);
  });

  it('marks tool files as tool-reachable', () => {
    const graph = makeMinimalGraph({
      tools: [{
        id: 't1', name: 'SearchTool', framework: 'langchain',
        file: '/test/tools/search.py', line: 5, description: 'Search',
        parameters: [], hasSideEffects: true, hasInputValidation: false,
        hasSandboxing: false, capabilities: ['network'],
      }],
    });

    const index = buildReachabilityIndex(graph);
    expect(index.getReachability('/test/tools/search.py', 10)).toBe('tool-reachable');
    expect(index.toolFiles.has('/test/tools/search.py')).toBe(true);
  });

  it('marks utility files as utility-code', () => {
    const graph = makeMinimalGraph({
      agents: [{
        id: 'a1', name: 'Agent', framework: 'langchain',
        file: '/test/agent.py', line: 10, tools: [],
      }],
    });

    const index = buildReachabilityIndex(graph);
    expect(index.getReachability('/test/utils/helper.py', 5)).toBe('utility-code');
  });

  it('marks endpoint files as endpoint-reachable', () => {
    const graph = makeMinimalGraph({
      files: {
        all: [
          { path: '/test/routes/api.ts', relativePath: 'routes/api.ts', language: 'typescript', size: 1000 },
        ],
        python: [], typescript: [], javascript: [], yaml: [], json: [], configs: [],
      },
    });

    const index = buildReachabilityIndex(graph);
    expect(index.getReachability('/test/routes/api.ts', 10)).toBe('endpoint-reachable');
  });

  it('agent files take priority over endpoint patterns', () => {
    const graph = makeMinimalGraph({
      agents: [{
        id: 'a1', name: 'APIAgent', framework: 'langchain',
        file: '/test/api/agent.py', line: 10, tools: [],
      }],
      files: {
        all: [
          { path: '/test/api/agent.py', relativePath: 'api/agent.py', language: 'python', size: 1000 },
        ],
        python: [], typescript: [], javascript: [], yaml: [], json: [], configs: [],
      },
    });

    const index = buildReachabilityIndex(graph);
    expect(index.getReachability('/test/api/agent.py', 15)).toBe('agent-reachable');
  });
});
