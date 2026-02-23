import type { AgentGraph } from '../types/agent-graph.js';
import type { Reachability } from '../types/finding.js';
import { findEnclosingFunctionByLine } from './ast/queries.js';

/**
 * Reachability index: O(1) lookup to determine if a finding is
 * in agent-reachable, tool-reachable, endpoint-reachable, or utility code.
 */
export interface ReachabilityIndex {
  getReachability(file: string, line: number): Reachability;
  /** Set of all files that contain agent definitions */
  agentFiles: Set<string>;
  /** Set of all files that contain tool definitions */
  toolFiles: Set<string>;
}

interface LineRange {
  start: number;
  end: number;
  type: 'agent' | 'tool' | 'endpoint';
}

/**
 * Build a reachability index from the agent graph.
 *
 * Strategy:
 * 1. Collect all file:line locations from agents and tools
 * 2. Mark the enclosing region (±50 lines heuristic for function scope)
 * 3. Files that contain agents/tools are marked as agent/tool-reachable
 * 4. Files matching endpoint patterns (routes, handlers) are endpoint-reachable
 * 5. Everything else is utility-code
 */
export function buildReachabilityIndex(graph: AgentGraph): ReachabilityIndex {
  const fileRanges = new Map<string, LineRange[]>();
  const agentFiles = new Set<string>();
  const toolFiles = new Set<string>();

  const astStore = graph.astStore;

  // Collect agent locations — use AST function boundaries when available
  for (const agent of graph.agents) {
    agentFiles.add(agent.file);
    const tree = astStore?.getTree(agent.file);
    if (tree) {
      const func = findEnclosingFunctionByLine(tree, agent.line);
      if (func) {
        addRange(fileRanges, agent.file, {
          start: func.startPosition.row + 1,
          end: func.endPosition.row + 1,
          type: 'agent',
        });
      } else {
        // Module-level — mark entire file
        addRange(fileRanges, agent.file, { start: 1, end: 99999, type: 'agent' });
      }
    } else {
      // Fallback to ±50 line heuristic
      addRange(fileRanges, agent.file, {
        start: Math.max(1, agent.line - 10),
        end: agent.line + 50,
        type: 'agent',
      });
    }
  }

  // Collect tool locations — use AST function boundaries when available
  for (const tool of graph.tools) {
    toolFiles.add(tool.file);
    const tree = astStore?.getTree(tool.file);
    if (tree) {
      const func = findEnclosingFunctionByLine(tree, tool.line);
      if (func) {
        addRange(fileRanges, tool.file, {
          start: func.startPosition.row + 1,
          end: func.endPosition.row + 1,
          type: 'tool',
        });
      } else {
        addRange(fileRanges, tool.file, { start: 1, end: 99999, type: 'tool' });
      }
    } else {
      addRange(fileRanges, tool.file, {
        start: Math.max(1, tool.line - 10),
        end: tool.line + 50,
        type: 'tool',
      });
    }
  }

  // Detect endpoint files (route handlers, API definitions)
  const endpointPatterns = [
    /\/routes?\//i, /\/handlers?\//i, /\/controllers?\//i,
    /\/api\//i, /\/endpoints?\//i, /\/views?\//i,
    /app\.(get|post|put|delete|patch)\b/,
    /router\.(get|post|put|delete|patch)\b/,
  ];

  for (const fileInfo of graph.files.all) {
    const isEndpoint = endpointPatterns.some(p => p.test(fileInfo.path));
    if (isEndpoint && !agentFiles.has(fileInfo.path) && !toolFiles.has(fileInfo.path)) {
      addRange(fileRanges, fileInfo.path, {
        start: 1,
        end: 99999,
        type: 'endpoint',
      });
    }
  }

  return {
    agentFiles,
    toolFiles,
    getReachability(file: string, line: number): Reachability {
      // Direct file match (agent or tool is defined in this file)
      if (agentFiles.has(file)) return 'agent-reachable';
      if (toolFiles.has(file)) return 'tool-reachable';

      // Check line ranges
      const ranges = fileRanges.get(file);
      if (ranges) {
        for (const range of ranges) {
          if (line >= range.start && line <= range.end) {
            switch (range.type) {
              case 'agent': return 'agent-reachable';
              case 'tool': return 'tool-reachable';
              case 'endpoint': return 'endpoint-reachable';
            }
          }
        }
        // File has some ranges but this line isn't in any
        // Still mark as tool/agent reachable if the file contains definitions
        if (ranges.some(r => r.type === 'agent')) return 'agent-reachable';
        if (ranges.some(r => r.type === 'tool')) return 'tool-reachable';
        if (ranges.some(r => r.type === 'endpoint')) return 'endpoint-reachable';
      }

      return 'utility-code';
    },
  };
}

function addRange(
  map: Map<string, LineRange[]>,
  file: string,
  range: LineRange,
): void {
  const existing = map.get(file) ?? [];
  existing.push(range);
  map.set(file, existing);
}
