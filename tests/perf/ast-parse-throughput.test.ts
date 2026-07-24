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
