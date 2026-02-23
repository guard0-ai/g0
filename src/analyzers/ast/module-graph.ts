import * as path from 'node:path';
import * as fs from 'node:fs';
import type { Tree, ASTLanguage, SyntaxNode } from './parser.js';
import { findNodes } from './queries.js';
import type { ASTStore } from './store.js';

export interface ImportTarget {
  source: string;        // raw import string (e.g., './foo', 'os', 'com.example.Foo')
  resolved: string | null; // resolved file path, or null if unresolved
  line: number;
}

/**
 * Directed module dependency graph.
 * Tracks which files import which other files.
 */
export class ModuleGraph {
  /** file -> list of files it imports */
  private dependencies = new Map<string, Set<string>>();
  /** file -> list of files that import it */
  private importers = new Map<string, Set<string>>();

  /**
   * Build the module graph from an ASTStore.
   */
  static build(astStore: ASTStore, rootPath: string): ModuleGraph {
    const graph = new ModuleGraph();

    for (const [filePath, entry] of astStore.entries()) {
      const imports = resolveImports(filePath, entry.tree, entry.language, rootPath);
      for (const imp of imports) {
        if (imp.resolved) {
          graph.addEdge(filePath, imp.resolved);
        }
      }
    }

    return graph;
  }

  addEdge(from: string, to: string): void {
    let deps = this.dependencies.get(from);
    if (!deps) { deps = new Set(); this.dependencies.set(from, deps); }
    deps.add(to);

    let imps = this.importers.get(to);
    if (!imps) { imps = new Set(); this.importers.set(to, imps); }
    imps.add(from);
  }

  /** Who imports this file */
  getImportersOf(filePath: string): string[] {
    return [...(this.importers.get(filePath) ?? [])];
  }

  /** What files does this file import */
  getDependenciesOf(filePath: string): string[] {
    return [...(this.dependencies.get(filePath) ?? [])];
  }

  /** Transitive closure with depth limit */
  getTransitiveDeps(filePath: string, maxDepth = 5): Set<string> {
    const visited = new Set<string>();
    const queue: { file: string; depth: number }[] = [{ file: filePath, depth: 0 }];

    while (queue.length > 0) {
      const { file, depth } = queue.shift()!;
      if (visited.has(file) || depth > maxDepth) continue;
      visited.add(file);

      const deps = this.dependencies.get(file);
      if (deps) {
        for (const dep of deps) {
          if (!visited.has(dep)) {
            queue.push({ file: dep, depth: depth + 1 });
          }
        }
      }
    }

    visited.delete(filePath); // Don't include the file itself
    return visited;
  }

  /** Get all files in the module graph */
  get files(): string[] {
    const allFiles = new Set<string>();
    for (const [from, deps] of this.dependencies) {
      allFiles.add(from);
      for (const dep of deps) allFiles.add(dep);
    }
    return [...allFiles];
  }

  /** Total edge count */
  get edgeCount(): number {
    let count = 0;
    for (const deps of this.dependencies.values()) {
      count += deps.size;
    }
    return count;
  }
}

/**
 * Extract and resolve imports from an AST tree.
 */
export function resolveImports(
  filePath: string,
  tree: Tree,
  language: ASTLanguage,
  rootPath: string,
): ImportTarget[] {
  const results: ImportTarget[] = [];
  const dir = path.dirname(filePath);

  switch (language) {
    case 'python':
      results.push(...resolvePythonImports(tree, dir, rootPath));
      break;
    case 'typescript':
    case 'tsx':
    case 'javascript':
    case 'jsx':
      results.push(...resolveJsImports(tree, dir));
      break;
    case 'java':
      results.push(...resolveJavaImports(tree, rootPath));
      break;
    case 'go':
      results.push(...resolveGoImports(tree, rootPath));
      break;
  }

  return results;
}

// ─── Python ─────────────────────────────────────────────────────────

function resolvePythonImports(tree: Tree, dir: string, rootPath: string): ImportTarget[] {
  const results: ImportTarget[] = [];

  const importNodes = findNodes(tree, (n) =>
    n.type === 'import_statement' || n.type === 'import_from_statement',
  );

  for (const node of importNodes) {
    const line = node.startPosition.row + 1;

    if (node.type === 'import_from_statement') {
      // `from foo.bar import baz`
      const moduleNode = node.childForFieldName('module_name') ??
        node.children.find(c => c.type === 'dotted_name' || c.type === 'relative_import');
      if (moduleNode) {
        const source = moduleNode.text;
        const resolved = resolvePythonModule(source, dir, rootPath);
        results.push({ source, resolved, line });
      }
    } else {
      // `import foo.bar`
      const nameNodes = node.children.filter(c => c.type === 'dotted_name' || c.type === 'aliased_import');
      for (const nameNode of nameNodes) {
        const source = nameNode.type === 'aliased_import'
          ? (nameNode.childForFieldName('name')?.text ?? nameNode.text)
          : nameNode.text;
        const resolved = resolvePythonModule(source, dir, rootPath);
        results.push({ source, resolved, line });
      }
    }
  }

  return results;
}

function resolvePythonModule(modulePath: string, dir: string, rootPath: string): string | null {
  // Handle relative imports (leading dots)
  const dotMatch = modulePath.match(/^(\.+)(.*)/);
  let baseDir = rootPath;
  let modPath = modulePath;

  if (dotMatch) {
    const dots = dotMatch[1].length;
    baseDir = dir;
    for (let i = 1; i < dots; i++) {
      baseDir = path.dirname(baseDir);
    }
    modPath = dotMatch[2];
  }

  // Convert foo.bar -> foo/bar
  const parts = modPath.split('.').filter(Boolean);
  if (parts.length === 0) return null;

  const candidates = [
    path.join(baseDir, ...parts) + '.py',
    path.join(baseDir, ...parts, '__init__.py'),
  ];

  for (const candidate of candidates) {
    if (fileExists(candidate)) return candidate;
  }

  // Also try from root
  if (!dotMatch) {
    const rootCandidates = [
      path.join(rootPath, ...parts) + '.py',
      path.join(rootPath, ...parts, '__init__.py'),
    ];
    for (const candidate of rootCandidates) {
      if (fileExists(candidate)) return candidate;
    }
  }

  return null;
}

// ─── JavaScript / TypeScript ────────────────────────────────────────

function resolveJsImports(tree: Tree, dir: string): ImportTarget[] {
  const results: ImportTarget[] = [];

  const importNodes = findNodes(tree, (n) =>
    n.type === 'import_statement' || n.type === 'import_declaration' ||
    // require() calls
    (n.type === 'call_expression' && n.childForFieldName('function')?.text === 'require'),
  );

  for (const node of importNodes) {
    const line = node.startPosition.row + 1;
    let source: string | null = null;

    if (node.type === 'call_expression') {
      // require('foo')
      const args = node.childForFieldName('arguments');
      const firstArg = args?.namedChildren[0];
      source = firstArg ? extractStringContent(firstArg) : null;
    } else {
      // import ... from 'foo'
      const sourceNode = node.childForFieldName('source') ??
        node.children.find(c => c.type === 'string' || c.type === 'string_literal');
      source = sourceNode ? extractStringContent(sourceNode) : null;
    }

    if (!source) continue;

    // Only resolve relative imports
    if (source.startsWith('.')) {
      const resolved = resolveJsModule(source, dir);
      results.push({ source, resolved, line });
    } else {
      results.push({ source, resolved: null, line });
    }
  }

  return results;
}

function resolveJsModule(importPath: string, dir: string): string | null {
  const base = path.resolve(dir, importPath);

  const extensions = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.mts'];
  const candidates: string[] = [];

  // Try exact path (if it has an extension)
  if (path.extname(base)) {
    candidates.push(base);
  }

  // Try with extensions
  for (const ext of extensions) {
    candidates.push(base + ext);
  }

  // Try index files
  for (const ext of extensions) {
    candidates.push(path.join(base, 'index' + ext));
  }

  for (const candidate of candidates) {
    if (fileExists(candidate)) return candidate;
  }

  return null;
}

// ─── Java ───────────────────────────────────────────────────────────

function resolveJavaImports(tree: Tree, rootPath: string): ImportTarget[] {
  const results: ImportTarget[] = [];

  const importNodes = findNodes(tree, (n) => n.type === 'import_declaration');
  for (const node of importNodes) {
    const line = node.startPosition.row + 1;
    // Extract the import path: import com.example.Foo;
    const scopeNode = node.children.find(c =>
      c.type === 'scoped_identifier' || c.type === 'identifier',
    );
    if (!scopeNode) continue;

    const source = scopeNode.text;
    // Convert com.example.Foo -> com/example/Foo.java
    const filePart = source.replace(/\./g, '/');

    // Search common Java source roots
    const srcRoots = ['src/main/java', 'src', 'app/src/main/java'];
    let resolved: string | null = null;
    for (const srcRoot of srcRoots) {
      const candidate = path.join(rootPath, srcRoot, filePart + '.java');
      if (fileExists(candidate)) {
        resolved = candidate;
        break;
      }
    }

    results.push({ source, resolved, line });
  }

  return results;
}

// ─── Go ─────────────────────────────────────────────────────────────

function resolveGoImports(tree: Tree, rootPath: string): ImportTarget[] {
  const results: ImportTarget[] = [];

  const importNodes = findNodes(tree, (n) =>
    n.type === 'import_declaration' || n.type === 'import_spec',
  );

  for (const node of importNodes) {
    if (node.type === 'import_declaration') {
      // Multi-import block: process import_spec children
      for (const child of node.namedChildren) {
        if (child.type === 'import_spec_list') {
          for (const spec of child.namedChildren) {
            if (spec.type === 'import_spec') {
              processGoImportSpec(spec, rootPath, results);
            }
          }
        } else if (child.type === 'import_spec') {
          processGoImportSpec(child, rootPath, results);
        }
      }
    } else {
      processGoImportSpec(node, rootPath, results);
    }
  }

  return results;
}

function processGoImportSpec(node: SyntaxNode, rootPath: string, results: ImportTarget[]): void {
  const line = node.startPosition.row + 1;
  const pathNode = node.children.find(c =>
    c.type === 'interpreted_string_literal' || c.type === 'raw_string_literal',
  );
  if (!pathNode) return;

  const source = pathNode.text.replace(/["`]/g, '');
  // Only resolve local packages (not stdlib or external)
  // Check if the path exists relative to the go module root
  const candidate = path.join(rootPath, source);
  if (directoryExists(candidate)) {
    results.push({ source, resolved: candidate, line });
  } else {
    results.push({ source, resolved: null, line });
  }
}

// ─── Helpers ────────────────────────────────────────────────────────

function extractStringContent(node: SyntaxNode): string | null {
  const text = node.text;
  if (!text) return null;
  if (text.startsWith('"') || text.startsWith("'")) return text.slice(1, -1);
  if (text.startsWith('`')) return text.slice(1, -1);
  return text;
}

const fileExistsCache = new Map<string, boolean>();

function fileExists(filePath: string): boolean {
  if (fileExistsCache.has(filePath)) return fileExistsCache.get(filePath)!;
  try {
    const result = fs.statSync(filePath).isFile();
    fileExistsCache.set(filePath, result);
    return result;
  } catch {
    fileExistsCache.set(filePath, false);
    return false;
  }
}

function directoryExists(dirPath: string): boolean {
  try {
    return fs.statSync(dirPath).isDirectory();
  } catch {
    return false;
  }
}
