import type { Tree, ASTLanguage } from './parser.js';
import { parseCode, getASTLanguage } from './parser.js';
import type { FileInfo } from '../../types/common.js';
import * as fs from 'node:fs';

export interface ASTStoreEntry {
  tree: Tree;
  language: ASTLanguage;
  content: string;
}

/**
 * Pre-parsed AST store with LRU eviction.
 * Parses each file once and shares the tree across all rules and enrichment extractors.
 */
export class ASTStore {
  private cache = new Map<string, ASTStoreEntry | null>();
  private accessOrder: string[] = [];
  private maxSize: number;

  constructor(maxSize = 500) {
    this.maxSize = maxSize;
  }

  /**
   * Get a cached tree for a file path. Returns null if the file
   * has no tree-sitter support or failed to parse.
   */
  getTree(filePath: string): Tree | null {
    const entry = this.cache.get(filePath);
    if (entry === undefined) return null;
    if (entry === null) return null;
    // Move to end of access order (LRU)
    this.touchAccess(filePath);
    return entry.tree;
  }

  /**
   * Get the full entry (tree + language + content) for a file path.
   */
  getEntry(filePath: string): ASTStoreEntry | null {
    const entry = this.cache.get(filePath);
    if (!entry) return null;
    this.touchAccess(filePath);
    return entry;
  }

  /**
   * Get the cached content for a file path.
   */
  getContent(filePath: string): string | null {
    const entry = this.cache.get(filePath);
    if (!entry) return null;
    return entry.content;
  }

  /**
   * Check if a file has been parsed (even if the result was null).
   */
  has(filePath: string): boolean {
    return this.cache.has(filePath);
  }

  /**
   * Parse a single file and store the result.
   */
  parseFile(filePath: string, content?: string): Tree | null {
    if (this.cache.has(filePath)) {
      const entry = this.cache.get(filePath);
      return entry?.tree ?? null;
    }

    const lang = getASTLanguage(filePath);
    if (!lang) {
      this.cache.set(filePath, null);
      return null;
    }

    let src = content;
    if (!src) {
      try {
        src = fs.readFileSync(filePath, 'utf-8');
      } catch {
        this.cache.set(filePath, null);
        return null;
      }
    }

    // Skip very large files (likely generated/bundled)
    if (src.length > 500_000) {
      this.cache.set(filePath, null);
      return null;
    }

    const tree = parseCode(src, lang);
    if (tree) {
      this.evictIfNeeded();
      this.cache.set(filePath, { tree, language: lang, content: src });
      this.accessOrder.push(filePath);
    } else {
      this.cache.set(filePath, null);
    }

    return tree;
  }

  /**
   * Batch-parse all files during graph build.
   * Only parses files with tree-sitter language support.
   */
  parseAll(files: FileInfo[]): void {
    for (const file of files) {
      if (!this.cache.has(file.path)) {
        this.parseFile(file.path);
      }
    }
  }

  /**
   * Get the number of successfully parsed entries.
   */
  get size(): number {
    let count = 0;
    for (const entry of this.cache.values()) {
      if (entry !== null) count++;
    }
    return count;
  }

  /**
   * Iterate over all successfully parsed entries.
   */
  entries(): IterableIterator<[string, ASTStoreEntry]> {
    const self = this;
    return (function* () {
      for (const [filePath, entry] of self.cache) {
        if (entry !== null) yield [filePath, entry] as [string, ASTStoreEntry];
      }
    })();
  }

  /**
   * Clear all cached entries.
   */
  clear(): void {
    this.cache.clear();
    this.accessOrder = [];
  }

  private touchAccess(filePath: string): void {
    const idx = this.accessOrder.lastIndexOf(filePath);
    if (idx !== -1) {
      this.accessOrder.splice(idx, 1);
    }
    this.accessOrder.push(filePath);
  }

  private evictIfNeeded(): void {
    while (this.accessOrder.length >= this.maxSize) {
      const oldest = this.accessOrder.shift();
      if (oldest) {
        this.cache.delete(oldest);
      }
    }
  }
}
