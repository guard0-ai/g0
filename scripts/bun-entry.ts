// Bun single-binary entry. Compiled ONLY by `bun build --compile` — never by
// tsup/Node — so the Bun-specific `with { type: 'file' }` import attributes here
// never reach the Node build graph. Bun embeds each referenced wasm into the
// compiled binary and the imported value is a path that resolves to the embedded
// bytes at runtime. We register those paths so the parser's WASM loader finds
// them with no external files.
import coreWasm from '../assets/wasm/tree-sitter.wasm' with { type: 'file' };
import pythonWasm from '../assets/wasm/tree-sitter-python.wasm' with { type: 'file' };
import tsWasm from '../assets/wasm/tree-sitter-typescript.wasm' with { type: 'file' };
import tsxWasm from '../assets/wasm/tree-sitter-tsx.wasm' with { type: 'file' };
import jsWasm from '../assets/wasm/tree-sitter-javascript.wasm' with { type: 'file' };
import javaWasm from '../assets/wasm/tree-sitter-java.wasm' with { type: 'file' };
import goWasm from '../assets/wasm/tree-sitter-go.wasm' with { type: 'file' };

import pkg from '../package.json' with { type: 'json' };
import { setWasmFileResolver } from '../src/analyzers/ast/wasm-paths.js';
import { setVersionOverride } from '../src/utils/version-override.js';

// Set the real version before any module that reads it loads (the compiled
// binary cannot require package.json at runtime).
setVersionOverride((pkg as { version?: string }).version ?? '');

const EMBEDDED: Record<string, string> = {
  'tree-sitter.wasm': coreWasm as unknown as string,
  'tree-sitter-python.wasm': pythonWasm as unknown as string,
  'tree-sitter-typescript.wasm': tsWasm as unknown as string,
  'tree-sitter-tsx.wasm': tsxWasm as unknown as string,
  'tree-sitter-javascript.wasm': jsWasm as unknown as string,
  'tree-sitter-java.wasm': javaWasm as unknown as string,
  'tree-sitter-go.wasm': goWasm as unknown as string,
};

setWasmFileResolver((name) => EMBEDDED[name] ?? name);

// Mirror bin/g0.ts's dispatch (top-level await is fine under Bun).
const { runProxyFromArgvOverride } = await import('../src/cli/commands/proxy.js');
const handled = await runProxyFromArgvOverride(process.argv.slice(2));
if (!handled) {
  const { createCli } = await import('../src/cli/index.js');
  createCli().parse();
}
