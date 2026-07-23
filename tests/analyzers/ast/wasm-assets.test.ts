import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';

const dir = path.resolve(__dirname, '../../../assets/wasm');
const expected = [
  'tree-sitter.wasm',
  'tree-sitter-python.wasm',
  'tree-sitter-typescript.wasm',
  'tree-sitter-tsx.wasm',
  'tree-sitter-javascript.wasm',
  'tree-sitter-java.wasm',
  'tree-sitter-go.wasm',
];

describe('vendored wasm assets', () => {
  for (const f of expected) {
    it(`${f} exists and is non-empty`, () => {
      const p = path.join(dir, f);
      expect(fs.existsSync(p)).toBe(true);
      expect(fs.statSync(p).size).toBeGreaterThan(1000);
    });
  }
});
