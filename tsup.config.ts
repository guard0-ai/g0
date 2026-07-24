import { defineConfig } from 'tsup';
import { copyWasmToDist } from './scripts/copy-wasm.mjs';

export default defineConfig({
  entry: {
    'bin/g0': 'bin/g0.ts',
    'src/index': 'src/index.ts',
    'src/daemon/runner': 'src/daemon/runner.ts',
    'src/hook-main': 'src/hook-main.ts',
  },
  format: ['esm'],
  target: 'node20',
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  banner: {
    js: '#!/usr/bin/env node',
  },
  async onSuccess() {
    copyWasmToDist();
  },
});
