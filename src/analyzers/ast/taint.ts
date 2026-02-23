import type { SyntaxNode, Tree } from './parser.js';
import { findNodes, findAssignments, findEnclosingFunctionByLine } from './queries.js';
import type { ASTStore } from './store.js';
import type { ModuleGraph } from './module-graph.js';

export interface MatchLocation {
  line: number;      // 0-indexed
  column: number;
  endColumn: number;
  text: string;
  node?: SyntaxNode;
}

/**
 * Find all regex pattern matches in source content, returning their locations.
 * If an AST tree is available, associates each match with its nearest AST node.
 */
export function findPatternMatches(
  content: string,
  patterns: RegExp[],
  tree?: Tree | null,
): MatchLocation[] {
  const matches: MatchLocation[] = [];
  const lines = content.split('\n');

  for (const pattern of patterns) {
    // Clone regex to avoid shared state
    const regex = new RegExp(pattern.source, 'gm');
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      // Calculate line/column from offset
      const offset = match.index;
      let line = 0;
      let col = offset;
      for (let i = 0; i < lines.length; i++) {
        if (col <= lines[i].length) {
          line = i;
          break;
        }
        col -= lines[i].length + 1; // +1 for \n
      }

      const loc: MatchLocation = {
        line,
        column: col,
        endColumn: col + match[0].length,
        text: match[0],
      };

      // Associate with AST node if tree available
      if (tree) {
        loc.node = findDeepestNodeAt(tree.rootNode, line, col);
      }

      matches.push(loc);
    }
  }

  return matches;
}

/**
 * Find the deepest AST node containing a given position.
 */
function findDeepestNodeAt(root: SyntaxNode, row: number, col: number): SyntaxNode {
  let current = root;
  for (const child of root.children) {
    const s = child.startPosition;
    const e = child.endPosition;
    if (
      (row > s.row || (row === s.row && col >= s.column)) &&
      (row < e.row || (row === e.row && col <= e.column))
    ) {
      return findDeepestNodeAt(child, row, col);
    }
  }
  return current;
}

/**
 * Find the enclosing function node for a given position.
 */
export function findEnclosingFunction(node: SyntaxNode): SyntaxNode | null {
  const functionTypes = new Set([
    'function_definition',     // Python
    'function_declaration',    // JS/TS
    'arrow_function',          // JS/TS
    'method_definition',       // JS/TS class methods
    'method',                  // Python
  ]);

  let current: SyntaxNode | null = node;
  while (current) {
    if (functionTypes.has(current.type)) return current;
    current = current.parent;
  }
  return null;
}

/**
 * Check if a source match can flow to a sink match within the same function scope,
 * without passing through a sanitizer.
 *
 * This is a lightweight intraprocedural taint analysis:
 * 1. Source and sink must be in the same function (or module-level)
 * 2. Source must appear before sink (line-order)
 * 3. No sanitizer pattern appears between them on the data flow path
 * 4. Variable assignments are tracked to follow taint propagation
 */
export function canFlowWithinScope(
  tree: Tree,
  source: MatchLocation,
  sink: MatchLocation,
  sanitizers: MatchLocation[],
): boolean {
  // Source must appear before or at sink (line-order heuristic)
  if (source.line > sink.line) return false;

  // Check scope: both must be in the same function (or both at module level)
  if (source.node && sink.node) {
    const sourceFunc = findEnclosingFunction(source.node);
    const sinkFunc = findEnclosingFunction(sink.node);

    // Both at module level → OK
    // Both in the same function → OK
    // Different functions → no flow (intraprocedural only)
    if (sourceFunc !== sinkFunc) {
      if (sourceFunc === null && sinkFunc === null) {
        // both module-level, OK
      } else if (sourceFunc && sinkFunc) {
        // Check if they're the same function by position
        if (
          sourceFunc.startPosition.row !== sinkFunc.startPosition.row ||
          sourceFunc.startPosition.column !== sinkFunc.startPosition.column
        ) {
          return false;
        }
      } else {
        return false; // one module-level, one in function
      }
    }
  }

  // Check if any sanitizer appears between source and sink
  for (const sanitizer of sanitizers) {
    if (sanitizer.line >= source.line && sanitizer.line <= sink.line) {
      return false; // sanitizer on the path → no taint flow
    }
  }

  // If source and sink are within reasonable proximity (same scope),
  // and no sanitizer is between them, consider it a flow.
  // For AST-based: also check variable propagation
  if (tree && source.node && sink.node) {
    return checkVariableFlow(tree, source, sink);
  }

  // Fallback: proximity-based (source before sink, same scope, no sanitizer)
  return true;
}

/**
 * Check if there's a variable-level data flow from source to sink.
 * Tracks assignments to see if tainted data propagates.
 */
function checkVariableFlow(tree: Tree, source: MatchLocation, sink: MatchLocation): boolean {
  // Extract identifiers near the source and sink
  const sourceIdentifiers = extractNearbyIdentifiers(source.node!);
  const sinkIdentifiers = extractNearbyIdentifiers(sink.node!);

  if (sourceIdentifiers.size === 0 || sinkIdentifiers.size === 0) {
    // Can't determine variable names → use proximity heuristic
    // If within 30 lines, consider it a potential flow
    return (sink.line - source.line) <= 30;
  }

  // Track taint through assignments
  const tainted = new Set(sourceIdentifiers);
  const assignments = findAssignments(tree);

  // Sort assignments by line order
  const sortedAssignments = assignments.sort(
    (a, b) => a.startPosition.row - b.startPosition.row,
  );

  for (const assignment of sortedAssignments) {
    const row = assignment.startPosition.row;
    if (row < source.line || row > sink.line) continue;

    const leftNode =
      assignment.type === 'variable_declarator'
        ? assignment.childForFieldName('name')
        : assignment.childForFieldName('left');
    const rightNode =
      assignment.type === 'variable_declarator'
        ? assignment.childForFieldName('value')
        : assignment.childForFieldName('right');

    if (!leftNode || !rightNode) continue;

    // Check if the right side references any tainted variable
    const rightIdentifiers = new Set<string>();
    collectIdentifiers(rightNode, rightIdentifiers);

    let isTainted = false;
    for (const id of rightIdentifiers) {
      if (tainted.has(id)) {
        isTainted = true;
        break;
      }
    }

    if (isTainted) {
      tainted.add(leftNode.text);
    }
  }

  // Check if any sink identifier is tainted
  for (const id of sinkIdentifiers) {
    if (tainted.has(id)) return true;
  }

  // Fallback: if close proximity and same scope, still flag
  return (sink.line - source.line) <= 15;
}

/**
 * Extract identifier names near a syntax node (in its immediate vicinity).
 */
function extractNearbyIdentifiers(node: SyntaxNode): Set<string> {
  const ids = new Set<string>();
  collectIdentifiers(node, ids);

  // Also check parent's arguments/parameters
  if (node.parent) {
    for (const child of node.parent.children) {
      if (child.type === 'identifier') {
        ids.add(child.text);
      }
    }
  }

  return ids;
}

/**
 * Recursively collect all identifier names within a subtree.
 */
function collectIdentifiers(node: SyntaxNode, ids: Set<string>): void {
  if (node.type === 'identifier') {
    ids.add(node.text);
  }
  for (const child of node.children) {
    collectIdentifiers(child, ids);
  }
}

/**
 * Regex fallback for taint flow: check if source and sink patterns
 * appear within proximity in the same function-like block.
 */
export function checkProximityFlow(
  lines: string[],
  sourcePatterns: RegExp[],
  sinkPatterns: RegExp[],
  sanitizerPatterns: RegExp[],
  maxDistance: number = 30,
): { sourceLine: number; sinkLine: number; sourceText: string; sinkText: string }[] {
  const flows: { sourceLine: number; sinkLine: number; sourceText: string; sinkText: string }[] = [];

  // Find all source and sink line locations
  const sources: { line: number; text: string }[] = [];
  const sinks: { line: number; text: string }[] = [];
  const sanitizerLines = new Set<number>();

  for (let i = 0; i < lines.length; i++) {
    for (const sp of sourcePatterns) {
      const re = new RegExp(sp.source, 'g');
      const m = re.exec(lines[i]);
      if (m) sources.push({ line: i, text: m[0] });
    }
    for (const sp of sinkPatterns) {
      const re = new RegExp(sp.source, 'g');
      const m = re.exec(lines[i]);
      if (m) sinks.push({ line: i, text: m[0] });
    }
    for (const sp of sanitizerPatterns) {
      const re = new RegExp(sp.source, 'g');
      if (re.test(lines[i])) sanitizerLines.add(i);
    }
  }

  // Check each source-sink pair
  for (const source of sources) {
    for (const sink of sinks) {
      if (sink.line <= source.line) continue;
      if (sink.line - source.line > maxDistance) continue;

      // Check for sanitizer between source and sink
      let sanitized = false;
      for (let l = source.line; l <= sink.line; l++) {
        if (sanitizerLines.has(l)) {
          sanitized = true;
          break;
        }
      }

      if (!sanitized) {
        flows.push({
          sourceLine: source.line,
          sinkLine: sink.line,
          sourceText: source.text,
          sinkText: sink.text,
        });
      }
    }
  }

  return flows;
}

/**
 * Assess exploitability of a finding based on whether untrusted input
 * can reach the flagged code location through function parameters.
 */
export type Exploitability = 'confirmed' | 'likely' | 'unlikely' | 'not-assessed';

export function assessExploitability(
  tree: Tree | null,
  filePath: string,
  line: number,
  agentFiles: Set<string>,
  toolFiles: Set<string>,
): Exploitability {
  if (!tree) return 'not-assessed';

  // Find the node at the finding location
  const node = findDeepestNodeAt(tree.rootNode, line - 1, 0);
  if (!node) return 'not-assessed';

  // Find enclosing function
  const func = findEnclosingFunction(node);
  if (!func) {
    // Module level code — if in an agent/tool file, it's likely exploitable
    if (agentFiles.has(filePath) || toolFiles.has(filePath)) return 'likely';
    return 'unlikely';
  }

  // Check if the function has parameters (potential external input)
  const params = func.childForFieldName('parameters');
  if (!params || params.children.length <= 2) {
    // No parameters (or just parens) — less likely to receive tainted input
    return 'unlikely';
  }

  // Extract parameter names
  const paramNames = new Set<string>();
  for (const child of params.children) {
    if (child.type === 'identifier' || child.type === 'typed_parameter' || child.type === 'required_parameter') {
      const nameNode = child.childForFieldName('name') ?? child;
      if (nameNode.type === 'identifier') paramNames.add(nameNode.text);
    }
  }

  if (paramNames.size === 0) return 'unlikely';

  // Check if any parameter name appears between func start and finding line
  // indicating the parameter data flows toward the finding location
  const funcBody = func.childForFieldName('body') ?? func;
  const bodyIdentifiers = new Set<string>();
  collectIdentifiersInRange(funcBody, bodyIdentifiers, func.startPosition.row, line - 1);

  let paramUsed = false;
  for (const pname of paramNames) {
    if (bodyIdentifiers.has(pname)) {
      paramUsed = true;
      break;
    }
  }

  if (paramUsed) {
    // Parameter is used in the function body before the finding → likely exploitable
    if (agentFiles.has(filePath) || toolFiles.has(filePath)) return 'confirmed';
    return 'likely';
  }

  return 'unlikely';
}

function collectIdentifiersInRange(
  node: SyntaxNode,
  ids: Set<string>,
  startRow: number,
  endRow: number,
): void {
  if (node.startPosition.row > endRow) return;
  if (node.endPosition.row < startRow) return;

  if (node.type === 'identifier' && node.startPosition.row >= startRow && node.startPosition.row <= endRow) {
    ids.add(node.text);
  }
  for (const child of node.children) {
    collectIdentifiersInRange(child, ids, startRow, endRow);
  }
}

/**
 * Get a scope key for deduplication: `filePath:functionStartLine` or `filePath:module`.
 * Uses AST to find the enclosing function for a given line.
 */
export function getFunctionScopeKey(tree: Tree | null, filePath: string, line: number): string {
  if (!tree) return `${filePath}:module`;
  const node = findDeepestNodeAt(tree.rootNode, line - 1, 0);
  if (!node) return `${filePath}:module`;
  const func = findEnclosingFunction(node);
  if (!func) return `${filePath}:module`;
  return `${filePath}:${func.startPosition.row}`;
}

// ─── Function Summaries for Cross-File Taint ────────────────────────

export interface FunctionSummary {
  name: string;
  file: string;
  line: number;
  /** Parameter indices that flow to return value */
  paramToReturn: Set<number>;
  /** Parameter indices that flow to sink calls (evaluate, query, etc.) */
  paramToSink: Map<number, string[]>; // paramIndex -> sink names
  /** Parameter indices that are sanitized before use */
  sanitizedParams: Set<number>;
}

const SINK_PATTERNS = /^(evaluate|compile|query|run_query|raw|run|system|popen|subprocess|spawn|os\.system)$/i;
const SANITIZER_PATTERNS = /^(sanitize|validate|escape|encode|filter|clean|parseInt|parseFloat|JSON\.parse)$/i;

/**
 * Compute a summary for a function: which params flow to returns/sinks.
 */
export function summarizeFunction(tree: Tree, funcNode: SyntaxNode): FunctionSummary | null {
  const nameNode = funcNode.childForFieldName('name');
  if (!nameNode) return null;

  const params = funcNode.childForFieldName('parameters');
  if (!params) return null;

  // Extract parameter names
  const paramNames: string[] = [];
  for (const child of params.namedChildren) {
    const pname = child.childForFieldName('name') ?? child;
    if (pname.type === 'identifier') paramNames.push(pname.text);
  }

  if (paramNames.length === 0) return null;

  const summary: FunctionSummary = {
    name: nameNode.text,
    file: '',
    line: funcNode.startPosition.row + 1,
    paramToReturn: new Set(),
    paramToSink: new Map(),
    sanitizedParams: new Set(),
  };

  // Track taint through the function body
  const body = funcNode.childForFieldName('body') ?? funcNode;
  const tainted = new Map<string, Set<number>>(); // varName -> param indices

  // Initialize taint: each param taints itself
  for (let i = 0; i < paramNames.length; i++) {
    tainted.set(paramNames[i], new Set([i]));
  }

  // Walk assignments to propagate taint
  const assignments = findAssignments({ rootNode: body });
  for (const assignment of assignments) {
    const leftNode = assignment.type === 'variable_declarator'
      ? assignment.childForFieldName('name')
      : assignment.childForFieldName('left');
    const rightNode = assignment.type === 'variable_declarator'
      ? assignment.childForFieldName('value')
      : assignment.childForFieldName('right');

    if (!leftNode || !rightNode) continue;

    // Collect taint sources from right side
    const rightIds = new Set<string>();
    collectIdentifiers(rightNode, rightIds);

    const paramIndices = new Set<number>();
    for (const id of rightIds) {
      const t = tainted.get(id);
      if (t) for (const idx of t) paramIndices.add(idx);
    }

    if (paramIndices.size > 0) {
      // Check if right side is a sanitizer call
      if (rightNode.type === 'call_expression' || rightNode.type === 'call') {
        const callee = rightNode.childForFieldName('function');
        if (callee && SANITIZER_PATTERNS.test(callee.text)) {
          for (const idx of paramIndices) summary.sanitizedParams.add(idx);
          continue; // Don't propagate taint through sanitizer
        }
      }
      tainted.set(leftNode.text, paramIndices);
    }
  }

  // Check return statements for tainted values
  const returns = findNodes({ rootNode: body }, (n) => n.type === 'return_statement');
  for (const ret of returns) {
    const retIds = new Set<string>();
    collectIdentifiers(ret, retIds);
    for (const id of retIds) {
      const t = tainted.get(id);
      if (t) for (const idx of t) summary.paramToReturn.add(idx);
    }
  }

  // Check sink calls for tainted arguments
  const calls = findNodes({ rootNode: body }, (n) =>
    n.type === 'call_expression' || n.type === 'call',
  );
  for (const call of calls) {
    const callee = call.childForFieldName('function');
    if (!callee) continue;
    if (!SINK_PATTERNS.test(callee.text)) continue;

    const args = call.childForFieldName('arguments');
    if (!args) continue;

    for (const arg of args.namedChildren) {
      const argIds = new Set<string>();
      collectIdentifiers(arg, argIds);
      for (const id of argIds) {
        const t = tainted.get(id);
        if (t) {
          for (const idx of t) {
            if (!summary.paramToSink.has(idx)) summary.paramToSink.set(idx, []);
            summary.paramToSink.get(idx)!.push(callee.text);
          }
        }
      }
    }
  }

  return summary;
}

/**
 * Build function summaries for all functions in all parsed files.
 */
export function buildFunctionSummaries(astStore: ASTStore): Map<string, FunctionSummary> {
  const summaries = new Map<string, FunctionSummary>();
  const funcTypes = new Set([
    'function_definition', 'function_declaration', 'method_definition', 'method',
  ]);

  for (const [filePath, entry] of astStore.entries()) {
    const funcNodes = findNodes(entry.tree, (n) => funcTypes.has(n.type));
    for (const funcNode of funcNodes) {
      const summary = summarizeFunction(entry.tree, funcNode);
      if (summary) {
        summary.file = filePath;
        const key = `${filePath}:${summary.name}`;
        summaries.set(key, summary);
      }
    }
  }

  return summaries;
}

export interface CrossFileTaintResult {
  sourceFile: string;
  sourceLine: number;
  sourceText: string;
  sinkFile: string;
  sinkLine: number;
  sinkText: string;
  callChain: string[];
}

/**
 * Cross-file taint analysis: find data flows that cross file boundaries.
 *
 * @param sourcePattern - Regex to match taint sources
 * @param sinkPattern - Regex to match taint sinks
 * @param astStore - Pre-parsed AST store
 * @param moduleGraph - Module dependency graph
 * @param maxDepth - Maximum call chain depth
 */
export function crossFileTaint(
  sourcePattern: RegExp,
  sinkPattern: RegExp,
  astStore: ASTStore,
  moduleGraph: ModuleGraph,
  maxDepth = 3,
): CrossFileTaintResult[] {
  const results: CrossFileTaintResult[] = [];
  const summaries = buildFunctionSummaries(astStore);

  // For each file, find source patterns and trace through call chains
  for (const [filePath, entry] of astStore.entries()) {
    const content = entry.content;
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const sourceRe = new RegExp(sourcePattern.source, 'g');
      const match = sourceRe.exec(lines[i]);
      if (!match) continue;

      // Find what function this source is in
      const funcNode = findEnclosingFunctionByLine(entry.tree, i + 1);
      if (!funcNode) continue;

      // Check if the source flows to a call that crosses files
      const callsInFunc = findNodes({ rootNode: funcNode }, (n) =>
        n.type === 'call_expression' || n.type === 'call',
      );

      for (const call of callsInFunc) {
        if (call.startPosition.row < i) continue; // Only forward flow
        const callee = call.childForFieldName('function');
        if (!callee) continue;

        // Check if the callee is a cross-file function
        const deps = moduleGraph.getDependenciesOf(filePath);
        for (const depFile of deps) {
          const key = `${depFile}:${callee.text}`;
          const summary = summaries.get(key);
          if (!summary) continue;

          // Check if any tainted parameter flows to a sink
          for (const [paramIdx, sinkNames] of summary.paramToSink) {
            if (summary.sanitizedParams.has(paramIdx)) continue;

            for (const sinkName of sinkNames) {
              if (sinkPattern.test(sinkName)) {
                results.push({
                  sourceFile: filePath,
                  sourceLine: i + 1,
                  sourceText: match[0],
                  sinkFile: depFile,
                  sinkLine: summary.line,
                  sinkText: sinkName,
                  callChain: [filePath, depFile],
                });
              }
            }
          }
        }
      }
    }

    if (results.length >= 50) break; // Cap results
  }

  return results;
}
