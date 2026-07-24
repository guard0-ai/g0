import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Directory containing the vendored tree-sitter wasm files.
 *
 * The parser bundles into several layouts (dev tsx `src/analyzers/ast/`,
 * built bundles `dist/bin/`, `dist/src/`, `dist/src/daemon/`, and the
 * published package where only `dist/assets/wasm` ships). Rather than hardcode
 * fragile `../../..` hops per layout, walk up from the module directory and at
 * each level check for `assets/wasm/tree-sitter.wasm` and
 * `dist/assets/wasm/tree-sitter.wasm`. The SEA-binary branch is added in the
 * packaging task.
 */
/**
 * Optional override for locating individual wasm files by name. Set by the Bun
 * single-binary entry, which embeds each wasm and knows its per-file embedded
 * path (there is no shared directory in a compiled binary). Node/dev leaves this
 * unset and falls back to the directory walk below.
 */
let _fileResolver: ((name: string) => string) | null = null;

export function setWasmFileResolver(fn: (name: string) => string): void {
  _fileResolver = fn;
}

/** Full path (or embedded path) for a single wasm file by basename. */
export function resolveWasmFile(name: string): string {
  if (_fileResolver) return _fileResolver(name);
  return path.join(resolveWasmDir(), name);
}

export function resolveWasmDir(): string {
  let dir = path.dirname(fileURLToPath(import.meta.url));
  const marker = 'tree-sitter.wasm';
  for (let i = 0; i < 8; i++) {
    const a = path.join(dir, 'assets', 'wasm');
    if (fs.existsSync(path.join(a, marker))) return a;
    const b = path.join(dir, 'dist', 'assets', 'wasm');
    if (fs.existsSync(path.join(b, marker))) return b;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // Last resort: a plausible dev path; init() fails gracefully if absent.
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../assets/wasm');
}
