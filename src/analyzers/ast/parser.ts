import { resolveWasmFile } from './wasm-paths.js';

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

const GRAMMAR_FILE: Record<ASTLanguage, string> = {
  python: 'tree-sitter-python.wasm',
  typescript: 'tree-sitter-typescript.wasm',
  tsx: 'tree-sitter-tsx.wasm',
  javascript: 'tree-sitter-javascript.wasm',
  jsx: 'tree-sitter-javascript.wasm',
  java: 'tree-sitter-java.wasm',
  go: 'tree-sitter-go.wasm',
};

let _initPromise: Promise<boolean> | null = null;
let _available = false;
let _Parser: any = null;
const _languages = new Map<ASTLanguage, any>();
const _parsers = new Map<ASTLanguage, any>();

/**
 * Preload the WASM core + all grammars once. Async because web-tree-sitter's
 * Parser.init() and Language.load() are async; call this before any parseCode().
 * Idempotent and never throws — resolves false if WASM is unavailable.
 */
export async function initTreeSitter(): Promise<boolean> {
  if (_initPromise) return _initPromise;
  _initPromise = (async () => {
    try {
      const { Parser, Language } = await import('web-tree-sitter');
      await Parser.init({ locateFile: (f: string) => resolveWasmFile(f) });
      _Parser = Parser;
      for (const lang of ['python', 'typescript', 'tsx', 'javascript', 'java', 'go'] as ASTLanguage[]) {
        try {
          const language = await Language.load(resolveWasmFile(GRAMMAR_FILE[lang]));
          _languages.set(lang, language);
        } catch {
          /* individual grammar optional */
        }
      }
      const js = _languages.get('javascript');
      if (js) _languages.set('jsx', js);
      _available = _languages.size > 0;
    } catch {
      _available = false;
    }
    return _available;
  })();
  return _initPromise;
}

export function isTreeSitterAvailable(): boolean {
  return _available;
}

function getParser(language: ASTLanguage): any | null {
  const lang = _languages.get(language);
  if (!lang || !_Parser) return null;
  let parser = _parsers.get(language);
  if (!parser) {
    parser = new _Parser();
    parser.setLanguage(lang);
    _parsers.set(language, parser);
  }
  return parser;
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
