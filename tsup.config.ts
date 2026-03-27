import { defineConfig } from 'tsup';

export default defineConfig([
  // CLI entry point — needs shebang, no splitting (single executable)
  {
    entry: { 'bin/g0': 'bin/g0.ts' },
    format: ['esm'],
    target: 'node20',
    sourcemap: true,
    splitting: false,
    external: [
      'tree-sitter', 'tree-sitter-python', 'tree-sitter-typescript',
      'tree-sitter-javascript', 'tree-sitter-java', 'tree-sitter-go',
    ],
    banner: { js: '#!/usr/bin/env node' },
  },
  // SDK + daemon — code-split for smaller imports
  {
    entry: {
      'src/index': 'src/index.ts',
      'src/daemon/runner': 'src/daemon/runner.ts',
    },
    format: ['esm'],
    target: 'node20',
    dts: true,
    sourcemap: true,
    clean: true,
    splitting: true,
    external: [
      'tree-sitter', 'tree-sitter-python', 'tree-sitter-typescript',
      'tree-sitter-javascript', 'tree-sitter-java', 'tree-sitter-go',
    ],
  },
]);
