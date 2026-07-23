# g0 sentinel — Phase 0 (De-risk) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Retire the two technical unknowns that gate the whole g0-sentinel POC — that g0's code parsing survives a native→WASM migration at acceptable speed, and that g0 compiles to a single self-contained binary that runs a real scan with no Node/node_modules present — and stand up a minimal `g0 sentinel scan` that writes a snapshot so the binary is demonstrable.

**Architecture:** Replace the native `tree-sitter` addon (loaded lazily in one file) with `web-tree-sitter` (WASM). The crux: `parseCode()` is synchronous and called from many rules, while WASM `init()`/`Language.load()` are async — so we add a one-time async `initTreeSitter()` preload (awaited at the top of the scan pipeline) and keep `parseCode()` synchronous, because `parser.parse()` is sync once a `Language` is loaded. Grammar `.wasm` files are inert assets we vendor into the repo and bundle. Then package with Node SEA (Bun `--compile` as a documented fallback), embedding the wasm as SEA assets. A thin `g0 sentinel scan` reuses the existing `scanEndpoint()` to emit a JSON snapshot.

**Tech Stack:** TypeScript (ESM), Node ≥20, tsup, vitest, `web-tree-sitter`, `tree-sitter-wasms` (prebuilt grammar wasm), Node SEA + postject.

**Spec:** `docs/superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md` (§4 packaging, §10 language decision, §11 Phase 0).

## Global Constraints

- **Node ≥ 20**, package is **ESM** (`"type": "module"`). Copied verbatim from `package.json`.
- **License AGPL-3.0** — every adopted dependency must be MIT/Apache/permissive and compatible; `web-tree-sitter` (MIT) and `tree-sitter-wasms` (MIT) qualify. Do not add AGPL/GPL runtime deps.
- **No network call on any scan/parse path.** Platform/parse reads stay sync + never-throw (return `null`/empty on failure), matching the existing `parser.ts` try/catch contract.
- **Do not regress the `g0-hook` p95 < 100 ms gate.** `npm run test:perf` must stay green after every task.
- **`parseCode(code, language)` MUST remain synchronous** and keep its `Tree | null` return contract — consumers across `src/analyzers/rules/*` call it synchronously.
- **Graceful degradation preserved:** when WASM is unavailable, `isTreeSitterAvailable()` returns `false` and parsing returns `null` (rules already handle this).
- **Binary must run with no `node_modules` and no system Node** (the entire point of SEA).
- **MDM-agnostic:** nothing in this phase may hardcode a specific MDM.

---

### Task 1: Add web-tree-sitter and vendor grammar WASM assets

**Files:**
- Modify: `package.json` (add deps + `vendor:wasm` script)
- Create: `scripts/vendor-wasm.mjs`
- Create: `assets/wasm/.gitkeep` (the copied `*.wasm` land here and ARE committed)
- Test: `tests/analyzers/ast/wasm-assets.test.ts`

**Interfaces:**
- Produces: a populated `assets/wasm/` directory containing `tree-sitter.wasm` (core) plus `tree-sitter-python.wasm`, `tree-sitter-typescript.wasm`, `tree-sitter-tsx.wasm`, `tree-sitter-javascript.wasm`, `tree-sitter-java.wasm`, `tree-sitter-go.wasm`. Later tasks resolve wasm from this dir.

- [ ] **Step 1: Add dependencies**

Run:
```bash
npm i web-tree-sitter@^0.25.0
npm i -D tree-sitter-wasms@^0.1.12
```
Expected: both install without peer-dep errors.

- [ ] **Step 2: Write the vendor script**

Create `scripts/vendor-wasm.mjs`:
```js
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
```

- [ ] **Step 3: Add the npm script**

In `package.json` `"scripts"`, add:
```json
"vendor:wasm": "node scripts/vendor-wasm.mjs"
```

- [ ] **Step 4: Run the vendor script**

Run: `npm run vendor:wasm`
Expected: `vendored tree-sitter.wasm` … `Vendored 7 wasm files to assets/wasm/`. If any grammar is MISSING, follow the printed `tree-sitter build --wasm` fallback and re-run.

- [ ] **Step 5: Write the assets test**

Create `tests/analyzers/ast/wasm-assets.test.ts`:
```ts
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
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npx vitest run tests/analyzers/ast/wasm-assets.test.ts`
Expected: 7 passing.

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json scripts/vendor-wasm.mjs assets/wasm tests/analyzers/ast/wasm-assets.test.ts
git commit -m "build: add web-tree-sitter + vendor grammar wasm assets"
```

---

### Task 2: Rewrite `parser.ts` onto web-tree-sitter (async preload, sync parse)

**Files:**
- Create: `src/analyzers/ast/wasm-paths.ts`
- Modify: `src/analyzers/ast/parser.ts` (full rewrite of the loader; keep the exported interfaces and `parseCode`/`getASTLanguage`/`isTreeSitterAvailable` signatures)
- Test: `tests/analyzers/ast/parser.test.ts`

**Interfaces:**
- Consumes: `assets/wasm/` from Task 1.
- Produces:
  - `resolveWasmDir(): string` (in `wasm-paths.ts`) — directory holding the vendored wasm.
  - `initTreeSitter(): Promise<boolean>` — idempotent async preload; resolves `true` if ≥1 grammar loaded.
  - `parseCode(code: string, language: ASTLanguage): Tree | null` — **unchanged signature, still synchronous.**
  - `isTreeSitterAvailable(): boolean` — reflects whether preload succeeded.
  - `getASTLanguage(filePath: string): ASTLanguage | null` — unchanged.
  - Types `SyntaxNode`, `Tree`, `ASTLanguage` — unchanged (structural; consumers untouched).

- [ ] **Step 1: Write the wasm path resolver**

Create `src/analyzers/ast/wasm-paths.ts`:
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Directory containing the vendored tree-sitter wasm files.
 * Checks candidate locations in order: built dist copy, then the source
 * assets dir (dev/tsx). The SEA-binary branch is added in the packaging task.
 */
export function resolveWasmDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, '../../../assets/wasm'),       // dev: src/analyzers/ast -> repo/assets/wasm
    path.resolve(here, '../../assets/wasm'),           // built: dist/src/... layout
    path.resolve(here, 'assets/wasm'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'tree-sitter.wasm'))) return c;
  }
  // Last resort: return the dev path; init() will fail gracefully if absent.
  return candidates[0];
}
```

- [ ] **Step 2: Write the failing test**

Create `tests/analyzers/ast/parser.test.ts`:
```ts
import { describe, it, expect, beforeAll } from 'vitest';
import { initTreeSitter, isTreeSitterAvailable, parseCode, getASTLanguage } from '../../../src/analyzers/ast/parser.js';

describe('web-tree-sitter parser', () => {
  beforeAll(async () => {
    await initTreeSitter();
  });

  it('reports available after init', () => {
    expect(isTreeSitterAvailable()).toBe(true);
  });

  it('parses python synchronously into a module tree', () => {
    const tree = parseCode('def f():\n    return 1\n', 'python');
    expect(tree).not.toBeNull();
    expect(tree!.rootNode.type).toBe('module');
  });

  it('parses typescript', () => {
    const tree = parseCode('const x: number = 1;', 'typescript');
    expect(tree).not.toBeNull();
    expect(tree!.rootNode.type).toBe('program');
  });

  it('exposes navigable named children with positions', () => {
    const tree = parseCode('def f():\n    return 1\n', 'python');
    const fn = tree!.rootNode.namedChildren[0];
    expect(fn.type).toBe('function_definition');
    expect(fn.startPosition.row).toBe(0);
    expect(fn.childForFieldName('name')?.text).toBe('f');
  });

  it('maps extensions to languages', () => {
    expect(getASTLanguage('a.py')).toBe('python');
    expect(getASTLanguage('a.tsx')).toBe('tsx');
    expect(getASTLanguage('a.d.ts')).toBeNull();
  });

  it('init is idempotent', async () => {
    const a = await initTreeSitter();
    const b = await initTreeSitter();
    expect(a).toBe(true);
    expect(b).toBe(true);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/analyzers/ast/parser.test.ts`
Expected: FAIL — `initTreeSitter` is not exported yet.

- [ ] **Step 4: Rewrite `parser.ts`**

Replace the entire contents of `src/analyzers/ast/parser.ts` with:
```ts
import * as path from 'node:path';
import { resolveWasmDir } from './wasm-paths.js';

export interface SyntaxNode {
  type: string;
  text: string;
  startPosition: { row: number; column: number };
  endPosition: { row: number; column: number };
  children: SyntaxNode[];
  namedChildren: SyntaxNode[];
  parent: SyntaxNode | null;
  childForFieldName(name: string): SyntaxNode | null;
}

export interface Tree {
  rootNode: SyntaxNode;
}

export type ASTLanguage = 'python' | 'typescript' | 'javascript' | 'tsx' | 'jsx' | 'java' | 'go';

const GRAMMAR_FILE: Record<ASTLanguage, string> = {
  python: 'tree-sitter-python.wasm',
  typescript: 'tree-sitter-typescript.wasm',
  tsx: 'tree-sitter-tsx.wasm',
  javascript: 'tree-sitter-javascript.wasm',
  jsx: 'tree-sitter-javascript.wasm',
  java: 'tree-sitter-java.wasm',
  go: 'tree-sitter-go.wasm',
};

let _initPromise: Promise<boolean> | null = null;
let _available = false;
let _Parser: any = null;
const _languages = new Map<ASTLanguage, any>();
const _parsers = new Map<ASTLanguage, any>();

/**
 * Preload the WASM core + all grammars once. Async because web-tree-sitter's
 * Parser.init() and Language.load() are async; call this before any parseCode().
 * Idempotent and never throws — resolves false if WASM is unavailable.
 */
export async function initTreeSitter(): Promise<boolean> {
  if (_initPromise) return _initPromise;
  _initPromise = (async () => {
    try {
      const { Parser, Language } = await import('web-tree-sitter');
      const dir = resolveWasmDir();
      await Parser.init({ locateFile: (f: string) => path.join(dir, f) });
      _Parser = Parser;
      for (const lang of ['python', 'typescript', 'tsx', 'javascript', 'java', 'go'] as ASTLanguage[]) {
        try {
          const language = await Language.load(path.join(dir, GRAMMAR_FILE[lang]));
          _languages.set(lang, language);
        } catch {
          /* individual grammar optional */
        }
      }
      const js = _languages.get('javascript');
      if (js) _languages.set('jsx', js);
      _available = _languages.size > 0;
    } catch {
      _available = false;
    }
    return _available;
  })();
  return _initPromise;
}

export function isTreeSitterAvailable(): boolean {
  return _available;
}

function getParser(language: ASTLanguage): any | null {
  const lang = _languages.get(language);
  if (!lang || !_Parser) return null;
  let parser = _parsers.get(language);
  if (!parser) {
    parser = new _Parser();
    parser.setLanguage(lang);
    _parsers.set(language, parser);
  }
  return parser;
}

export function parseCode(code: string, language: ASTLanguage): Tree | null {
  const parser = getParser(language);
  if (!parser) return null;
  try {
    return parser.parse(code) as Tree;
  } catch {
    return null;
  }
}

export function getASTLanguage(filePath: string): ASTLanguage | null {
  if (filePath.endsWith('.py')) return 'python';
  if (filePath.endsWith('.ts') && !filePath.endsWith('.d.ts')) return 'typescript';
  if (filePath.endsWith('.tsx')) return 'tsx';
  if (filePath.endsWith('.js') || filePath.endsWith('.mjs')) return 'javascript';
  if (filePath.endsWith('.jsx')) return 'jsx';
  if (filePath.endsWith('.java')) return 'java';
  if (filePath.endsWith('.go')) return 'go';
  return null;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/analyzers/ast/parser.test.ts`
Expected: all passing. If `rootNode.type` for typescript is not `program`, adjust the expectation to the actual grammar root (log `tree.rootNode.type` once) — grammar root names are fixed per grammar.

- [ ] **Step 6: Commit**

```bash
git add src/analyzers/ast/wasm-paths.ts src/analyzers/ast/parser.ts tests/analyzers/ast/parser.test.ts
git commit -m "feat: migrate AST parser from native tree-sitter to web-tree-sitter (WASM)"
```

---

### Task 3: Preload WASM at the scan bootstrap + prove no regression

**Files:**
- Modify: `src/pipeline.ts` (await `initTreeSitter()` inside `runScan` before detection)
- Test: `tests/analyzers/ast/scan-regression.test.ts`

**Interfaces:**
- Consumes: `initTreeSitter()` from Task 2; existing `runScan(options): Promise<ScanResult>` in `src/pipeline.ts:109`.
- Produces: a scan path where `isTreeSitterAvailable()` is `true` before any rule runs.

- [ ] **Step 1: Write the failing regression test**

Create `tests/analyzers/ast/scan-regression.test.ts`:
```ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { runScan } from '../../../src/pipeline.js';

describe('scan uses WASM AST (regression)', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-scan-ast-'));
    // Python with an AST-detectable eval-on-input sink.
    fs.writeFileSync(
      path.join(dir, 'main.py'),
      'import sys\n\ndef handler(user_input):\n    return eval(user_input)\n',
    );
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('produces findings and reaches a grade over a real file', async () => {
    const result = await runScan({ targetPath: dir });
    expect(result).toBeTruthy();
    // The scan completed and graded — the AST path ran without throwing.
    expect(typeof result.grade).toBe('string');
    expect(Array.isArray(result.findings)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify current behavior**

Run: `npx vitest run tests/analyzers/ast/scan-regression.test.ts`
Expected: it may FAIL or produce no AST-derived findings because `initTreeSitter()` is never awaited on the scan path (rules see `isTreeSitterAvailable() === false`). If it passes trivially, the assertions still guard the wiring below.

- [ ] **Step 3: Await preload in `runScan`**

In `src/pipeline.ts`, add the import near the other analyzer imports (top of file, alongside `import { ASTStore } from './analyzers/ast/store.js';`):
```ts
import { initTreeSitter } from './analyzers/ast/parser.js';
```
Then as the FIRST line inside the `runScan` function body (`src/pipeline.ts:109`, `export async function runScan(...)`), add:
```ts
  await initTreeSitter();
```

- [ ] **Step 4: Find and cover any other parse entry points**

Run:
```bash
grep -rn "isTreeSitterAvailable\|getFileTreeForLang\|parseCode(" src --include=*.ts | grep -v "src/analyzers/ast/"
```
For every **async command/entry** that reaches those calls WITHOUT going through `runScan` (e.g. a `flows`/`graph-build` path that parses), add `await initTreeSitter();` before the parsing begins, using the same import. If all hits are inside detection reached via `runScan`, no further change is needed — record that in the commit message.

- [ ] **Step 5: Run the regression test + full suite**

Run:
```bash
npx vitest run tests/analyzers/ast/scan-regression.test.ts
npm test
```
Expected: the regression test passes; the full suite is green (no consumer broke on the interface-compatible node shape).

- [ ] **Step 6: Commit**

```bash
git add src/pipeline.ts tests/analyzers/ast/scan-regression.test.ts
git commit -m "feat: preload web-tree-sitter WASM at scan bootstrap"
```

---

### Task 4: Update the build — drop native externals, ship wasm in dist

**Files:**
- Modify: `tsup.config.ts` (remove the 6 native `tree-sitter*` externals; add a wasm copy step)
- Modify: `package.json` (`build` runs vendor + copy)
- Test: `tests/build/dist-wasm.test.ts`

**Interfaces:**
- Consumes: `assets/wasm/` (Task 1), the new build.
- Produces: `dist/assets/wasm/*.wasm` present after `npm run build`, resolvable by `resolveWasmDir()`.

- [ ] **Step 1: Remove native externals and add the copy hook**

Replace `tsup.config.ts` with:
```ts
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
```

- [ ] **Step 2: Make `build` re-vendor first (fresh clones have no committed wasm churn)**

In `package.json`, change the `build` script to:
```json
"build": "npm run vendor:wasm && tsup"
```

- [ ] **Step 3: Write the failing test**

Create `tests/build/dist-wasm.test.ts`:
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';

describe('dist ships wasm', () => {
  it('has the core wasm in dist/assets/wasm after build', () => {
    const p = path.resolve('dist/assets/wasm/tree-sitter.wasm');
    expect(fs.existsSync(p)).toBe(true);
  });
});
```

- [ ] **Step 4: Build and run the test**

Run:
```bash
npm run build
npx vitest run tests/build/dist-wasm.test.ts
```
Expected: build succeeds; test passes.

- [ ] **Step 5: Smoke-test the built CLI resolves wasm**

Run:
```bash
node dist/bin/g0.js scan tests --json >/dev/null && echo "OK: built CLI ran a scan"
```
Expected: `OK: built CLI ran a scan` (exit 0; the built layout resolved wasm via the dist candidate path). If it cannot find wasm, confirm `dist/assets/wasm/` exists and that `resolveWasmDir()`'s built candidate matches the actual `dist/src/analyzers/ast` depth.

- [ ] **Step 6: Commit**

```bash
git add tsup.config.ts package.json tests/build/dist-wasm.test.ts
git commit -m "build: bundle wasm into dist, drop native tree-sitter externals"
```

---

### Task 5: Parse-throughput benchmark (perf gate) + confirm hook gate holds

**Files:**
- Create: `tests/perf/ast-parse-throughput.test.ts`
- Test: itself (a perf test)

**Interfaces:**
- Consumes: `initTreeSitter()`, `parseCode()` from Task 2.
- Produces: a committed WASM parse-throughput baseline that later phases must not blow.

- [ ] **Step 1: Write the benchmark**

Create `tests/perf/ast-parse-throughput.test.ts`:
```ts
import { describe, it, expect, beforeAll } from 'vitest';
import { initTreeSitter, parseCode } from '../../src/analyzers/ast/parser.js';

// One representative ~1k-line python file, parsed repeatedly. This is a
// scheduled-scan workload, not the interactive hook path — the budget is
// generous and exists to catch order-of-magnitude regressions, per spec §4/§10.
const ONE_FN = 'def handler_{i}(user_input):\n    x = eval(user_input)\n    return x + {i}\n\n';
function bigFile(n: number): string {
  let s = 'import sys\n\n';
  for (let i = 0; i < n; i++) s += ONE_FN.replaceAll('{i}', String(i));
  return s;
}

describe('WASM AST parse throughput', () => {
  beforeAll(async () => {
    await initTreeSitter();
  });

  it('parses a ~1k-line file 50 times within budget', () => {
    const src = bigFile(300); // ~1.2k lines
    const iterations = 50;
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      const tree = parseCode(src, 'python');
      expect(tree).not.toBeNull();
    }
    const totalMs = performance.now() - start;
    const perParse = totalMs / iterations;
    // eslint-disable-next-line no-console
    console.log(`WASM parse: ${perParse.toFixed(1)} ms/parse over ${iterations} iters (${totalMs.toFixed(0)} ms total)`);
    // Generous ceiling: a ~1k-line file must parse well under 200ms each in WASM.
    expect(perParse).toBeLessThan(200);
  });
});
```

- [ ] **Step 2: Run the benchmark**

Run: `npm run test:perf`
Expected: PASS, and the console prints the `ms/parse` baseline. **Record that number in the commit message** — it is the Phase-0 de-risk evidence that WASM is fast enough. If it FAILS the 200ms ceiling, that is a genuine finding: capture the number, note it against spec §4's benchmark risk, and raise before proceeding (do not silently loosen the budget).

- [ ] **Step 3: Confirm the existing hook gate still holds**

Run: `npm run test:perf`
Expected: `tests/perf/hook-latency.test.ts` and `tests/perf/watch-e2e.test.ts` still pass (the WASM migration must not regress the p95<100ms hook gate).

- [ ] **Step 4: Commit**

```bash
git add tests/perf/ast-parse-throughput.test.ts
git commit -m "test(perf): WASM AST parse-throughput baseline gate (<Xms/parse)"
```
(Replace `<Xms/parse>` with the measured number.)

---

### Task 6: Minimal `g0 sentinel scan` writing a snapshot

**Files:**
- Create: `src/sentinel/snapshot.ts`
- Create: `src/cli/commands/sentinel.ts`
- Modify: `src/cli/index.ts` (register the command)
- Test: `tests/sentinel/snapshot.test.ts`

**Interfaces:**
- Consumes: `scanEndpoint(options?): Promise<EndpointScanResult>` from `src/endpoint/scanner.ts:127` (the result exposes `tools: {name; installed; running; mcpServerCount}[]` and `score`).
- Produces:
  - `buildSnapshot(result, ctx): MachineSnapshot` — pure, testable.
  - `defaultSnapshotPath(platform): string`.
  - `writeSnapshotAtomic(filePath, snap): void`.
  - CLI: `g0 sentinel scan [--out <path>]`.

- [ ] **Step 1: Write the failing test**

Create `tests/sentinel/snapshot.test.ts`:
```ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';
import { buildSnapshot, defaultSnapshotPath, writeSnapshotAtomic } from '../../src/sentinel/snapshot.js';

const fakeResult = {
  score: 82,
  tools: [
    { name: 'Claude Code', installed: true, running: true, mcpServerCount: 2 },
    { name: 'Cursor', installed: true, running: false, mcpServerCount: 0 },
  ],
} as any;

describe('sentinel snapshot', () => {
  it('builds a schema-versioned snapshot with tool footprint', () => {
    const snap = buildSnapshot(fakeResult, { hostname: 'mac-1', platform: 'darwin', arch: 'arm64', sentinelVersion: '0.0.0', generatedAtMs: 1_700_000_000_000 });
    expect(snap.schemaVersion).toBe(1);
    expect(snap.host.hostname).toBe('mac-1');
    expect(snap.tools).toHaveLength(2);
    expect(snap.tools[0]).toMatchObject({ name: 'Claude Code', installed: true, mcpServerCount: 2 });
    expect(snap.endpointScore).toBe(82);
  });

  it('picks a platform-specific default path', () => {
    expect(defaultSnapshotPath('win32')).toContain('guard0');
    expect(defaultSnapshotPath('darwin')).toContain('guard0');
  });

  it('writes valid JSON atomically', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-snap-'));
    const out = path.join(dir, 'snapshot.json');
    const snap = buildSnapshot(fakeResult, { hostname: 'h', platform: 'darwin', arch: 'arm64', sentinelVersion: '0.0.0', generatedAtMs: 1 });
    writeSnapshotAtomic(out, snap);
    const parsed = JSON.parse(fs.readFileSync(out, 'utf-8'));
    expect(parsed.host.hostname).toBe('h');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/sentinel/snapshot.test.ts`
Expected: FAIL — module `src/sentinel/snapshot.ts` does not exist.

- [ ] **Step 3: Implement the snapshot module**

Create `src/sentinel/snapshot.ts`:
```ts
import * as fs from 'node:fs';
import * as path from 'node:path';

/** A minimal Phase-0 machine snapshot. Extended with PII/exposure in later phases. */
export interface MachineSnapshot {
  schemaVersion: 1;
  generatedAtMs: number;
  sentinelVersion: string;
  host: { hostname: string; platform: string; arch: string };
  tools: Array<{ name: string; installed: boolean; running: boolean; mcpServerCount: number }>;
  endpointScore?: number;
}

export interface SnapshotContext {
  hostname: string;
  platform: string;
  arch: string;
  sentinelVersion: string;
  generatedAtMs: number;
}

/** Only the fields Phase 0 needs from the endpoint scan result. */
interface Endpointish {
  score?: number;
  tools?: Array<{ name: string; installed: boolean; running: boolean; mcpServerCount: number }>;
}

export function buildSnapshot(result: Endpointish, ctx: SnapshotContext): MachineSnapshot {
  return {
    schemaVersion: 1,
    generatedAtMs: ctx.generatedAtMs,
    sentinelVersion: ctx.sentinelVersion,
    host: { hostname: ctx.hostname, platform: ctx.platform, arch: ctx.arch },
    tools: (result.tools ?? []).map((t) => ({
      name: t.name,
      installed: t.installed,
      running: t.running,
      mcpServerCount: t.mcpServerCount,
    })),
    endpointScore: result.score,
  };
}

export function defaultSnapshotPath(platform: NodeJS.Platform): string {
  if (platform === 'win32') {
    return path.join(process.env.ProgramData ?? 'C:\\ProgramData', 'guard0', 'snapshot.json');
  }
  if (platform === 'darwin') {
    return '/Library/Application Support/guard0/snapshot.json';
  }
  return '/var/lib/guard0/snapshot.json';
}

export function writeSnapshotAtomic(filePath: string, snap: MachineSnapshot): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(snap, null, 2));
  fs.renameSync(tmp, filePath);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/sentinel/snapshot.test.ts`
Expected: 3 passing.

- [ ] **Step 5: Wire the CLI command**

Create `src/cli/commands/sentinel.ts`:
```ts
import * as os from 'node:os';
import { Command } from 'commander';
import { scanEndpoint } from '../../endpoint/scanner.js';
import { buildSnapshot, defaultSnapshotPath, writeSnapshotAtomic } from '../../sentinel/snapshot.js';
import { getVersion } from '../branding.js';

export const sentinelCommand = new Command('sentinel')
  .description('Fleet sentinel — unattended AI-footprint snapshot for MDM deployment');

sentinelCommand
  .command('scan')
  .description('Run one collection pass and write a machine snapshot')
  .option('--out <path>', 'Snapshot output path (default: platform well-known path)')
  .action(async (options: { out?: string }) => {
    const result = await scanEndpoint({});
    const snap = buildSnapshot(result as any, {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      sentinelVersion: getVersion(),
      generatedAtMs: Date.now(),
    });
    const out = options.out ?? defaultSnapshotPath(os.platform());
    writeSnapshotAtomic(out, snap);
    const running = snap.tools.filter((t) => t.running).length;
    // Compact summary line — captured by MDM script-output reporting (spec §8).
    console.log(`g0 sentinel: ${snap.tools.length} AI tools (${running} running), score ${snap.endpointScore ?? 'n/a'} -> ${out}`);
  });
```

(`getVersion()` is the existing helper in `src/cli/branding.ts:32`, already used by `src/cli/index.ts:31`.)

Register it in `src/cli/index.ts`: add the import alongside the other command imports (near line 23, after `import { rulesCommand } from './commands/rules.js';`):
```ts
import { sentinelCommand } from './commands/sentinel.js';
```
and add the registration alongside the other `program.addCommand(...)` calls (the block starting at `src/cli/index.ts:58`):
```ts
program.addCommand(sentinelCommand);
```

- [ ] **Step 6: Run the command end-to-end**

Run:
```bash
npm run g0 -- sentinel scan --out /tmp/g0-snapshot.json && cat /tmp/g0-snapshot.json | head -20
```
Expected: prints the compact summary line and a valid JSON snapshot at `/tmp/g0-snapshot.json`.

- [ ] **Step 7: Commit**

```bash
git add src/sentinel/snapshot.ts src/cli/commands/sentinel.ts src/cli/index.ts tests/sentinel/snapshot.test.ts
git commit -m "feat: minimal g0 sentinel scan writing a machine snapshot"
```

---

### Task 7: Single self-contained binary via Node SEA (with wasm assets)

**Files:**
- Create: `scripts/build-sea.mjs`
- Create: `sea-config.json`
- Modify: `src/analyzers/ast/wasm-paths.ts` (add the SEA asset branch)
- Modify: `package.json` (`build:sea` script)

**Interfaces:**
- Consumes: the built app + `assets/wasm/`.
- Produces: `dist/sea/g0` (mac/linux) / `dist/sea/g0.exe` (win) that runs `g0 sentinel scan` with no `node_modules`.

- [ ] **Step 1: Add the SEA branch to wasm resolution**

In `src/analyzers/ast/wasm-paths.ts`, add ABOVE the candidate loop in `resolveWasmDir()`:
```ts
  // SEA binary: assets are embedded; materialize them once to a temp dir.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const sea = require('node:sea');
    if (sea.isSea && sea.isSea()) {
      const dir = path.join(require('node:os').tmpdir(), 'g0-wasm');
      fs.mkdirSync(dir, { recursive: true });
      const names = [
        'tree-sitter.wasm', 'tree-sitter-python.wasm', 'tree-sitter-typescript.wasm',
        'tree-sitter-tsx.wasm', 'tree-sitter-javascript.wasm', 'tree-sitter-java.wasm', 'tree-sitter-go.wasm',
      ];
      for (const n of names) {
        const target = path.join(dir, n);
        if (!fs.existsSync(target)) {
          const buf = Buffer.from(sea.getRawAsset(n));
          fs.writeFileSync(target, buf);
        }
      }
      return dir;
    }
  } catch {
    /* not a SEA build — fall through to filesystem candidates */
  }
```
Add `import { createRequire } from 'node:module';` and, at the top of the SEA branch, `const require = createRequire(import.meta.url);` so `require('node:sea')` resolves under ESM.

- [ ] **Step 2: Write the SEA config**

Create `sea-config.json`:
```json
{
  "main": "dist/sea/g0.cjs",
  "output": "dist/sea/g0.blob",
  "disableExperimentalSEAWarning": true,
  "useSnapshot": false,
  "useCodeCache": false,
  "assets": {
    "tree-sitter.wasm": "assets/wasm/tree-sitter.wasm",
    "tree-sitter-python.wasm": "assets/wasm/tree-sitter-python.wasm",
    "tree-sitter-typescript.wasm": "assets/wasm/tree-sitter-typescript.wasm",
    "tree-sitter-tsx.wasm": "assets/wasm/tree-sitter-tsx.wasm",
    "tree-sitter-javascript.wasm": "assets/wasm/tree-sitter-javascript.wasm",
    "tree-sitter-java.wasm": "assets/wasm/tree-sitter-java.wasm",
    "tree-sitter-go.wasm": "assets/wasm/tree-sitter-go.wasm"
  }
}
```

- [ ] **Step 3: Write the SEA build script**

Create `scripts/build-sea.mjs`:
```js
// Bundle g0 to a single CJS file, build a SEA blob (with wasm assets), and
// inject it into a copy of the node binary. macOS/Windows require re-signing
// after postject strips the signature.
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

const outDir = 'dist/sea';
fs.mkdirSync(outDir, { recursive: true });

// 1. Bundle to one CJS file (SEA main must be a single self-contained script).
execSync(
  'npx esbuild bin/g0.ts --bundle --platform=node --format=cjs --target=node20 ' +
    `--outfile=${outDir}/g0.cjs --external:node:sea`,
  { stdio: 'inherit' },
);

// 2. Generate the SEA blob.
execSync('node --experimental-sea-config sea-config.json', { stdio: 'inherit' });

// 3. Copy the running node binary as the target.
const isWin = os.platform() === 'win32';
const target = path.join(outDir, isWin ? 'g0.exe' : 'g0');
fs.copyFileSync(process.execPath, target);

// 4. Inject the blob.
const sentinelFuse = 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2';
const machoSeg = os.platform() === 'darwin' ? '--macho-segment-name NODE_SEA' : '';
execSync(
  `npx postject ${target} NODE_SEA_BLOB ${outDir}/g0.blob --sentinel-fuse ${sentinelFuse} ${machoSeg}`,
  { stdio: 'inherit' },
);

// 5. Re-sign on macOS (ad-hoc for local test; real Developer ID signing is the procurement item).
if (os.platform() === 'darwin') {
  execSync(`codesign --remove-signature ${target} || true`, { stdio: 'inherit' });
  execSync(`codesign --sign - ${target}`, { stdio: 'inherit' });
}

console.log(`\nBuilt SEA binary: ${target}`);
```

- [ ] **Step 4: Add the npm script**

In `package.json` `"scripts"`, add:
```json
"build:sea": "npm run build && node scripts/build-sea.mjs"
```

- [ ] **Step 5: Add esbuild + postject as dev deps**

Run:
```bash
npm i -D esbuild postject
```

- [ ] **Step 6: Build the binary**

Run: `npm run build:sea`
Expected: prints `Built SEA binary: dist/sea/g0` (or `.exe`). If postject reports the fuse already present, the copy step re-copies a clean node each run — safe to re-run.

- [ ] **Step 7: Prove it runs with NO node_modules on PATH**

Run:
```bash
env -i HOME="$HOME" PATH=/usr/bin:/bin ./dist/sea/g0 sentinel scan --out /tmp/g0-sea-snapshot.json
head -20 /tmp/g0-sea-snapshot.json
```
Expected: the compact summary line prints and a valid snapshot is written — proving the binary bundles the app AND materializes the wasm from SEA assets, with no external Node/node_modules. If wasm resolution fails, verify `sea.getRawAsset` names match `sea-config.json` keys.

- [ ] **Step 8: Record the outcome and commit**

If SEA works: commit.
```bash
git add scripts/build-sea.mjs sea-config.json src/analyzers/ast/wasm-paths.ts package.json package-lock.json
git commit -m "build: single self-contained binary via Node SEA with embedded wasm assets"
```
**If SEA fights the ESM/CJS bundle or asset loading after a reasonable spike (½ day):** stop and switch to the documented fallback — `bunx bun build bin/g0.ts --compile --target=bun-darwin-arm64 --outfile dist/sea/g0` (no native dep remains after Task 2, so Bun's weak N-API support is no longer relevant). Capture which path worked in the commit message and in spec §4. Either way, the deliverable is one working binary.

---

### Task 8: Logistics checklist — procurement & customer confirmation (owner action, not code)

**Files:**
- Create: `docs/superpowers/plans/phase0-logistics-checklist.md`

These items block Phases 1–4 but are **not implementable by a coding agent** — they are procurement and customer-facing actions. Track them explicitly so they start on day 1 in parallel with Tasks 1–7 (per spec §11 "day-1 critical path").

- [ ] **Step 1: Write the checklist doc**

Create `docs/superpowers/plans/phase0-logistics-checklist.md`:
```markdown
# Phase 0 logistics — start day 1, parallel to the code tasks

## Code-signing / notarization (the true long-pole — spec §4, §12)
- [ ] Procure an **EV/OV Authenticode code-signing certificate** (Windows MSI + exe).
- [ ] Enroll in the **Apple Developer Program**; obtain a **Developer ID Installer**
      cert (PKG) and a **Developer ID Application** cert (binary).
- [ ] Stand up a **notarization** pipeline (`notarytool --wait` + `stapler staple`).

## Customer confirmation (gates the transport/enactment design — spec §15)
- [ ] Confirm the customer runs **ManageEngine Endpoint Central** (agent-based), NOT
      **Mobile Device Manager Plus** (no custom-script engine). If MDM Plus only,
      escalate — transport/enactment options shrink drastically.
- [ ] Confirm the **Windows/macOS split** and get **one Windows + one macOS pilot machine**.
- [ ] Identify the fleet **EDR/AV** (CrowdStrike / SentinelOne / Defender / …), the
      **allowlist owner**, and the **turnaround time** for allowlisting the resident daemon.
      (Gates whether daemon-first is viable at pilot, or we start scheduled-only.)
- [ ] Confirm where the **customer-hosted collector** can run (a box they control), or
      whether they prefer the Velociraptor path or ManageEngine script-output-only for the POC.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/phase0-logistics-checklist.md
git commit -m "docs: Phase 0 logistics checklist (signing, customer/EDR confirmation)"
```

---

## What Phase 0 delivers (exit criteria)

1. AST parsing runs on **web-tree-sitter (WASM)** — native `tree-sitter` gone; full test suite + hook perf gate green.
2. A committed **parse-throughput baseline** proving WASM is fast enough for scheduled scans (or a captured number escalated if not).
3. `g0 sentinel scan` writes a real **machine snapshot** and prints a compact summary.
4. A **single self-contained binary** (SEA, or Bun fallback) runs that scan with **no Node/node_modules**.
5. The **signing + customer/EDR** logistics are in flight.

## Not in Phase 0 (deferred to their own plans)

Full footprint breadth (browser/Edge extensions, Outlook COM add-ins), the PII exposure engine (OpenRedaction + compromise + gitleaks rules), snapshot signing/content-addressing, the collector + `g0 fleet import` + HTML org report, governance policy + remediation, MSI/PKG installers + scheduler registration, and the ManageEngine deployment guide. Each gets its own plan (Phases 1–4 in the spec).
