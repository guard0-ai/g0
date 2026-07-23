import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';

describe('dist ships wasm', () => {
  it('has the core wasm in dist/assets/wasm after build', () => {
    const p = path.resolve('dist/assets/wasm/tree-sitter.wasm');
    expect(fs.existsSync(p)).toBe(true);
  });
});
