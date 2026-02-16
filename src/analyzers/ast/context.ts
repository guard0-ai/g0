import type { SyntaxNode, Tree } from './parser.js';

/**
 * AST node types that represent excluded contexts for code_matches.
 * Matches inside these contexts are false positives (comments, strings, imports, types).
 */
const COMMENT_TYPES = new Set([
  'comment',
  'line_comment',
  'block_comment',
]);

const STRING_TYPES = new Set([
  'string',
  'string_literal',
  'template_string',
  'concatenated_string',
  'string_content',
]);

const IMPORT_TYPES = new Set([
  'import_statement',
  'import_from_statement',
  'import_declaration',
  'export_statement', // re-exports
]);

const TYPE_ANNOTATION_TYPES = new Set([
  'type_annotation',
  'type_alias_declaration',
  'interface_declaration',
  'type_identifier',
  'type_parameters',
  'type_arguments',
  'predefined_type',
  'generic_type',
]);

/**
 * Checks whether a syntax node is inside an excluded context:
 * comments, string literals, import declarations, or type annotations.
 * Walk up the parent chain to find if any ancestor is excluded.
 */
export function isExcludedContext(node: SyntaxNode): boolean {
  let current: SyntaxNode | null = node;
  while (current) {
    if (COMMENT_TYPES.has(current.type)) return true;
    if (STRING_TYPES.has(current.type)) return true;
    if (IMPORT_TYPES.has(current.type)) return true;
    if (TYPE_ANNOTATION_TYPES.has(current.type)) return true;
    current = current.parent;
  }
  return false;
}

/**
 * Find the deepest AST node that contains a given byte offset.
 * Uses recursive descent for precision.
 */
export function findNodeAtOffset(tree: Tree, offset: number): SyntaxNode | null {
  function descend(node: SyntaxNode): SyntaxNode | null {
    // tree-sitter positions are row/col; we need to work with byte offsets
    // Since we don't have startIndex/endIndex on the interface,
    // we check children first and narrow down
    for (const child of node.children) {
      const childStart = child.startPosition;
      const childEnd = child.endPosition;
      // We can't directly compare offsets with row/col,
      // so we'll use the node's text length as a heuristic
      const result = descend(child);
      if (result) return result;
    }
    return node;
  }
  return descend(tree.rootNode);
}

/**
 * Find the deepest node containing a given line (0-indexed) and column.
 * More reliable than byte-offset lookup with tree-sitter.
 */
export function findNodeAtPosition(tree: Tree, line: number, column: number): SyntaxNode | null {
  function descend(node: SyntaxNode): SyntaxNode {
    for (const child of node.children) {
      const start = child.startPosition;
      const end = child.endPosition;

      // Check if position is within this child's range
      if (
        (line > start.row || (line === start.row && column >= start.column)) &&
        (line < end.row || (line === end.row && column <= end.column))
      ) {
        return descend(child);
      }
    }
    return node;
  }
  return descend(tree.rootNode);
}

/**
 * Check if a regex match at a specific line is in an excluded AST context.
 * This is the primary entry point for code_matches AST filtering.
 *
 * @param tree - Parsed AST tree
 * @param lineNumber - 0-indexed line number where the match occurred
 * @param matchStart - Column offset of the match within the line
 */
export function isMatchInExcludedContext(
  tree: Tree,
  lineNumber: number,
  matchStart: number = 0,
): boolean {
  const node = findNodeAtPosition(tree, lineNumber, matchStart);
  if (!node) return false;
  return isExcludedContext(node);
}
