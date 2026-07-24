import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect, beforeAll } from 'vitest';
import { copyWasmToDist } from '../../scripts/copy-wasm.mjs';

describe('dist ships wasm', () => {
  // Run the same copy step the build uses, so this test does not depend on
  // whether `npm run build` ran first (CI runs `npm test` before the build).
  beforeAll(() => {
    copyWasmToDist();
  });

  it('copies the core + grammar wasm into dist/assets/wasm', () => {
    const dir = path.resolve('dist/assets/wasm');
    for (const f of ['tree-sitter.wasm', 'tree-sitter-python.wasm', 'tree-sitter-typescript.wasm']) {
      expect(fs.existsSync(path.join(dir, f))).toBe(true);
    }
  });
});
