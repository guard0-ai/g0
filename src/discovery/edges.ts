/**
 * Phase 2: Build typed edges from existing graph data.
 *
 * This populates graph.edges by examining agent-tool bindings,
 * inter-agent links, database accesses, API endpoints, and call graph
 * to create explicit typed relationships between graph nodes.
 */

import * as crypto from 'node:crypto';
import type { AgentGraph, GraphEdge, DataStoreNode, APICallNode } from '../types/agent-graph.js';

function edgeId(): string {
  return crypto.randomUUID().slice(0, 8);
}

/**
 * Build typed edges from existing flat arrays in the agent graph.
 * Called after all parsers have populated the graph.
 */
export function buildGraphEdges(graph: AgentGraph): void {
  const edges: GraphEdge[] = [];

  // 1. Agent → Tool bindings (binds_tool)
  for (const agent of graph.agents) {
    for (const toolName of agent.tools) {
      const tool = graph.tools.find(t => t.name === toolName);
      if (tool) {
        edges.push({
          id: edgeId(),
          source: agent.id,
          target: tool.id,
          type: 'binds_tool',
          tainted: false,
          validated: tool.hasInputValidation,
          file: agent.file,
          line: agent.line,
        });
      }
    }
  }

  // 2. Inter-agent links (delegates_to)
  for (const link of graph.interAgentLinks) {
    const fromAgent = graph.agents.find(a => a.name === link.fromAgent);
    const toAgent = graph.agents.find(a => a.name === link.toAgent);
    if (fromAgent && toAgent) {
      edges.push({
        id: edgeId(),
        source: fromAgent.id,
        target: toAgent.id,
        type: 'delegates_to',
        tainted: !link.hasAuthentication,
        validated: link.hasAuthentication,
      });
    }
  }

  // 3. Database accesses → DataStoreNode + reads_db/writes_db edges
  const dbMap = new Map<string, DataStoreNode>();
  for (const access of graph.databaseAccesses) {
    const key = `${access.type}-${access.table ?? 'unknown'}`;
    if (!dbMap.has(key)) {
      const node: DataStoreNode = {
        id: edgeId(),
        type: access.type === 'orm' ? 'sql' : access.type,
        name: access.table,
        file: access.file,
        line: access.line,
        operations: [],
        hasParameterizedQueries: access.hasParameterizedQuery,
      };
      dbMap.set(key, node);
    }
    const node = dbMap.get(key)!;
    if (!node.operations.includes(access.operation)) {
      node.operations.push(access.operation);
    }
    // Update parameterization status (false wins — any unparameterized is a risk)
    if (!access.hasParameterizedQuery) {
      node.hasParameterizedQueries = false;
    }
  }
  graph.dataStores = [...dbMap.values()];

  // Create DB edges: tools with database capability → DataStoreNode
  for (const tool of graph.tools) {
    if (tool.capabilities.includes('database')) {
      for (const ds of graph.dataStores) {
        const edgeType = ds.operations.includes('write') || ds.operations.includes('delete')
          ? 'writes_db' : 'reads_db';
        edges.push({
          id: edgeId(),
          source: tool.id,
          target: ds.id,
          type: edgeType as GraphEdge['type'],
          tainted: !ds.hasParameterizedQueries,
          validated: ds.hasParameterizedQueries,
          file: tool.file,
          line: tool.line,
        });
      }
    }
  }

  // 4. API endpoints → APICallNode + calls_api edges
  for (const endpoint of graph.apiEndpoints) {
    const apiNode: APICallNode = {
      id: edgeId(),
      url: endpoint.url,
      method: endpoint.method,
      file: endpoint.file,
      line: endpoint.line,
      authenticated: false, // enriched later from authFlows
      isExternal: endpoint.isExternal,
    };
    graph.apiCalls.push(apiNode);

    // Find tool in same file that likely makes this API call
    const callingTool = graph.tools.find(t =>
      t.file === endpoint.file && t.capabilities.includes('network'));
    if (callingTool) {
      edges.push({
        id: edgeId(),
        source: callingTool.id,
        target: apiNode.id,
        type: 'calls_api',
        tainted: endpoint.isExternal,
        validated: false,
        file: endpoint.file,
        line: endpoint.line,
      });
    }
  }

  // 5. Vector DB connections (queries_vectordb)
  for (const vdb of graph.vectorDBs) {
    // Find tools/agents in same file
    const relatedTool = graph.tools.find(t => t.file === vdb.file);
    if (relatedTool) {
      edges.push({
        id: edgeId(),
        source: relatedTool.id,
        target: vdb.id,
        type: 'queries_vectordb',
        tainted: true, // RAG retrieval is untrusted by default
        validated: false,
        file: vdb.file,
        line: vdb.line,
      });
    }
  }

  // 6. Call graph edges (taint flow)
  for (const call of graph.callGraph) {
    if (call.taintFlow) {
      edges.push({
        id: edgeId(),
        source: call.caller,
        target: call.callee,
        type: 'feeds_context',
        tainted: true,
        validated: false,
        file: call.file,
        line: call.line,
      });
    }
  }

  graph.edges = edges;
}

/**
 * Find toxic paths: sequences of tainted edges without validation.
 * Returns human-readable descriptions of each toxic flow.
 */
export function findToxicPaths(graph: AgentGraph): string[] {
  const toxicPaths: string[] = [];

  // Find edges that are tainted and unvalidated
  const dangerousEdges = graph.edges.filter(e => e.tainted && !e.validated);

  for (const edge of dangerousEdges) {
    const sourceName = findNodeName(graph, edge.source);
    const targetName = findNodeName(graph, edge.target);
    if (sourceName && targetName) {
      toxicPaths.push(`${sourceName} →[${edge.type}]→ ${targetName} (unvalidated, ${edge.file ?? 'unknown'})`);
    }
  }

  return toxicPaths;
}

function findNodeName(graph: AgentGraph, nodeId: string): string | undefined {
  const agent = graph.agents.find(a => a.id === nodeId);
  if (agent) return `agent:${agent.name}`;
  const tool = graph.tools.find(t => t.id === nodeId);
  if (tool) return `tool:${tool.name}`;
  const ds = graph.dataStores.find(d => d.id === nodeId);
  if (ds) return `db:${ds.name ?? ds.type}`;
  const api = graph.apiCalls.find(a => a.id === nodeId);
  if (api) return `api:${api.url ?? api.method ?? 'unknown'}`;
  const vdb = graph.vectorDBs.find(v => v.id === nodeId);
  if (vdb) return `vectordb:${vdb.name}`;
  return undefined;
}
