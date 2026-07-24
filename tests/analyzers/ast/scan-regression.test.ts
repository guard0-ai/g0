import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { runScan, runDiscovery } from '../../../src/pipeline.js';
import { isTreeSitterAvailable } from '../../../src/analyzers/ast/parser.js';

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
    expect(typeof result.score.grade).toBe('string');
    expect(Array.isArray(result.findings)).toBe(true);
  });

  it('runDiscovery preloads WASM and produces a real AST tree (no silent skip)', async () => {
    const discovery = await runDiscovery(dir);
    // The preload inside runDiscovery must have made WASM available...
    expect(isTreeSitterAvailable()).toBe(true);
    // ...and the shared ASTStore must hold a parsed tree for the python file.
    const tree = discovery.astStore.getTree(path.join(dir, 'main.py'));
    expect(tree).not.toBeNull();
    expect(tree!.rootNode.type).toBe('module');
  });
});
