import { describe, it, expect } from 'vitest';

describe('AST Context Filtering', () => {
  it('isExcludedContext exists and is exported', async () => {
    const mod = await import('../../src/analyzers/ast/context.js');
    expect(typeof mod.isExcludedContext).toBe('function');
    expect(typeof mod.findNodeAtPosition).toBe('function');
    expect(typeof mod.isMatchInExcludedContext).toBe('function');
  });

  it('isMatchInExcludedContext filters comment lines via AST', async () => {
    const { isTreeSitterAvailable, parseCode } = await import('../../src/analyzers/ast/parser.js');
    const { isMatchInExcludedContext } = await import('../../src/analyzers/ast/context.js');

    if (!isTreeSitterAvailable()) {
      console.log('  Skipping AST test (tree-sitter not available)');
      return;
    }

    const code = `
// This is a comment with eval in it
const x = eval(userInput);
const y = "eval is mentioned in a string";
import { eval as safeEval } from 'safe-eval';
`;

    const tree = parseCode(code, 'javascript');
    expect(tree).not.toBeNull();

    // Line 1 (comment) — should be excluded
    expect(isMatchInExcludedContext(tree!, 1, 0)).toBe(true);

    // Line 2 (actual code) — should NOT be excluded
    expect(isMatchInExcludedContext(tree!, 2, 10)).toBe(false);

    // Line 3 (string literal) — should be excluded
    expect(isMatchInExcludedContext(tree!, 3, 12)).toBe(true);

    // Line 4 (import) — should be excluded
    expect(isMatchInExcludedContext(tree!, 4, 0)).toBe(true);
  });

  it('isMatchInExcludedContext filters Python comments', async () => {
    const { isTreeSitterAvailable, parseCode } = await import('../../src/analyzers/ast/parser.js');
    const { isMatchInExcludedContext } = await import('../../src/analyzers/ast/context.js');

    if (!isTreeSitterAvailable()) return;

    const code = `
# This is a comment with exec
result = exec(user_input)
message = "exec is in this string"
from os import system
`;

    const tree = parseCode(code, 'python');
    expect(tree).not.toBeNull();

    // Comment line
    expect(isMatchInExcludedContext(tree!, 1, 0)).toBe(true);

    // Actual exec call
    expect(isMatchInExcludedContext(tree!, 2, 10)).toBe(false);

    // String literal
    expect(isMatchInExcludedContext(tree!, 3, 14)).toBe(true);

    // Import
    expect(isMatchInExcludedContext(tree!, 4, 0)).toBe(true);
  });
});
