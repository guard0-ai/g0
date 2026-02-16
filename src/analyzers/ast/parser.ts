import { createRequire } from 'node:module';

export interface SyntaxNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  children: SyntaxNode[];
  namedChildren: SyntaxNode[];
  parent: SyntaxNode | null;
  childForFieldName(name: string): SyntaxNode | null;
}

export interface Tree {
  rootNode: SyntaxNode;
}

export type ASTLanguage = 'python' | 'typescript' | 'javascript' | 'tsx' | 'jsx' | 'java' | 'go';

let _available: boolean | null = null;
let _Parser: any = null;
let _Python: any = null;
let _TypeScript: any = null;
let _JavaScript: any = null;
let _Java: any = null;
let _Go: any = null;

const parsers: Map<string, any> = new Map();

function init(): boolean {
  if (_available !== null) return _available;
  try {
    const require = createRequire(import.meta.url);
    _Parser = require('tree-sitter');
    _Python = require('tree-sitter-python');
    _TypeScript = require('tree-sitter-typescript');
    _JavaScript = require('tree-sitter-javascript');
    _available = true;
  } catch {
    _available = false;
  }
  // Load Java/Go grammars independently — optional
  if (_available && _Parser) {
    const require = createRequire(import.meta.url);
    try { _Java = require('tree-sitter-java'); } catch { /* optional */ }
    try { _Go = require('tree-sitter-go'); } catch { /* optional */ }
  }
  return _available;
}

export function isTreeSitterAvailable(): boolean {
  return init();
}

function getParser(language: ASTLanguage): any | null {
  if (!init()) return null;
  if (parsers.has(language)) return parsers.get(language)!;

  const parser = new _Parser();
  try {
    switch (language) {
      case 'python':
        parser.setLanguage(_Python);
        break;
      case 'typescript':
        parser.setLanguage(_TypeScript.typescript);
        break;
      case 'tsx':
        parser.setLanguage(_TypeScript.tsx);
        break;
      case 'javascript':
      case 'jsx':
        parser.setLanguage(_JavaScript);
        break;
      case 'java':
        if (!_Java) return null;
        parser.setLanguage(_Java);
        break;
      case 'go':
        if (!_Go) return null;
        parser.setLanguage(_Go);
        break;
      default:
        return null;
    }
    parsers.set(language, parser);
    return parser;
  } catch {
    return null;
  }
}

export function parseCode(code: string, language: ASTLanguage): Tree | null {
  const parser = getParser(language);
  if (!parser) return null;
  try {
    return parser.parse(code) as Tree;
  } catch {
    return null;
  }
}

export function getASTLanguage(filePath: string): ASTLanguage | null {
  if (filePath.endsWith('.py')) return 'python';
  if (filePath.endsWith('.ts') && !filePath.endsWith('.d.ts')) return 'typescript';
  if (filePath.endsWith('.tsx')) return 'tsx';
  if (filePath.endsWith('.js') || filePath.endsWith('.mjs')) return 'javascript';
  if (filePath.endsWith('.jsx')) return 'jsx';
  if (filePath.endsWith('.java')) return 'java';
  if (filePath.endsWith('.go')) return 'go';
  return null;
}
