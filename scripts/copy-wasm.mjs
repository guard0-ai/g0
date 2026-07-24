// Copy the vendored grammar wasm from assets/wasm into dist/assets/wasm so the
// built/published package can resolve them. Shared by tsup.config.ts (build) and
// tests/build/dist-wasm.test.ts (so the test doesn't depend on build order).
import * as fs from 'node:fs';
import * as path from 'node:path';

export function copyWasmToDist(root = process.cwd()) {
  const src = path.join(root, 'assets', 'wasm');
  const dest = path.join(root, 'dist', 'assets', 'wasm');
  fs.mkdirSync(dest, { recursive: true });
  for (const f of fs.readdirSync(src)) {
    if (f.endsWith('.wasm')) fs.copyFileSync(path.join(src, f), path.join(dest, f));
  }
  return dest;
}
