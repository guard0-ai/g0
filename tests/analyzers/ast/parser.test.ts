import { describe, it, expect, beforeAll } from 'vitest';
import { initTreeSitter, isTreeSitterAvailable, parseCode, getASTLanguage } from '../../../src/analyzers/ast/parser.js';

describe('web-tree-sitter parser', () => {
  beforeAll(async () => {
    await initTreeSitter();
  });

  it('reports available after init', () => {
    expect(isTreeSitterAvailable()).toBe(true);
  });

  it('parses python synchronously into a module tree', () => {
    const tree = parseCode('def f():\n    return 1\n', 'python');
    expect(tree).not.toBeNull();
    expect(tree!.rootNode.type).toBe('module');
  });

  it('parses typescript', () => {
    const tree = parseCode('const x: number = 1;', 'typescript');
    expect(tree).not.toBeNull();
    expect(tree!.rootNode.type).toBe('program');
  });

  it('exposes navigable named children with positions', () => {
    const tree = parseCode('def f():\n    return 1\n', 'python');
    const fn = tree!.rootNode.namedChildren[0];
    expect(fn.type).toBe('function_definition');
    expect(fn.startPosition.row).toBe(0);
    expect(fn.childForFieldName('name')?.text).toBe('f');
  });

  it('maps extensions to languages', () => {
    expect(getASTLanguage('a.py')).toBe('python');
    expect(getASTLanguage('a.tsx')).toBe('tsx');
    expect(getASTLanguage('a.d.ts')).toBeNull();
  });

  it('init is idempotent', async () => {
    const a = await initTreeSitter();
    const b = await initTreeSitter();
    expect(a).toBe(true);
    expect(b).toBe(true);
  });
});
