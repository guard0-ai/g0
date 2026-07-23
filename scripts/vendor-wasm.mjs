// Copies the WASM core + prebuilt grammar wasm into assets/wasm/ so they can be
// committed and bundled. Grammars come from tree-sitter-wasms (MIT); the core
// tree-sitter.wasm ships inside web-tree-sitter (MIT).
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'assets', 'wasm');
fs.mkdirSync(outDir, { recursive: true });

const grammarsDir = path.join(root, 'node_modules', 'tree-sitter-wasms', 'out');
const coreWasm = path.join(root, 'node_modules', 'web-tree-sitter', 'tree-sitter.wasm');

const grammars = [
  'tree-sitter-python.wasm',
  'tree-sitter-typescript.wasm',
  'tree-sitter-tsx.wasm',
  'tree-sitter-javascript.wasm',
  'tree-sitter-java.wasm',
  'tree-sitter-go.wasm',
];

function copy(src, destName) {
  if (!fs.existsSync(src)) {
    console.error(`MISSING: ${src}`);
    console.error('If a grammar is absent from tree-sitter-wasms/out, build it with:');
    console.error('  npx tree-sitter build --wasm <grammar-repo>');
    process.exit(1);
  }
  fs.copyFileSync(src, path.join(outDir, destName));
  console.log(`vendored ${destName}`);
}

copy(coreWasm, 'tree-sitter.wasm');
for (const g of grammars) copy(path.join(grammarsDir, g), g);
console.log(`\nVendored ${grammars.length + 1} wasm files to assets/wasm/`);
