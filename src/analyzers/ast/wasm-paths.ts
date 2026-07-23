import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Directory containing the vendored tree-sitter wasm files.
 * Checks candidate locations in order: built dist copy, then the source
 * assets dir (dev/tsx). The SEA-binary branch is added in the packaging task.
 */
export function resolveWasmDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, '../../../assets/wasm'), // dev: src/analyzers/ast -> repo/assets/wasm
    path.resolve(here, '../../assets/wasm'), // built: dist/src/... layout
    path.resolve(here, 'assets/wasm'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'tree-sitter.wasm'))) return c;
  }
  // Last resort: return the dev path; init() will fail gracefully if absent.
  return candidates[0];
}
