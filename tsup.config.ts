import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    'bin/g0': 'bin/g0.ts',
    'src/index': 'src/index.ts',
    'src/daemon/runner': 'src/daemon/runner.ts',
  },
  format: ['esm'],
  target: 'node20',
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  external: [
    'tree-sitter',
    'tree-sitter-python',
    'tree-sitter-typescript',
    'tree-sitter-javascript',
    'tree-sitter-java',
    'tree-sitter-go',
  ],
  banner: {
    js: '#!/usr/bin/env node',
  },
});
