import { defineConfig } from 'tsup';
import * as fs from 'node:fs';
import * as path from 'node:path';

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
    const src = path.resolve('assets/wasm');
    const dest = path.resolve('dist/assets/wasm');
    fs.mkdirSync(dest, { recursive: true });
    for (const f of fs.readdirSync(src)) {
      if (f.endsWith('.wasm')) fs.copyFileSync(path.join(src, f), path.join(dest, f));
    }
  },
});
