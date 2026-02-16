import { describe, it, expect } from 'vitest';

describe('Taint Flow Analysis', () => {
  it('findPatternMatches locates regex matches with positions', async () => {
    const { findPatternMatches } = await import('../../src/analyzers/ast/taint.js');

    const content = `
const userInput = req.body.name;
const result = eval(userInput);
const safe = sanitize(data);
`;
    const patterns = [/eval\(/gm, /req\.body/gm];
    const matches = findPatternMatches(content, patterns);

    expect(matches.length).toBe(2);
    expect(matches.some(m => m.text === 'eval(')).toBe(true);
    expect(matches.some(m => m.text === 'req.body')).toBe(true);
  });

  it('checkProximityFlow detects source-sink proximity', async () => {
    const { checkProximityFlow } = await import('../../src/analyzers/ast/taint.js');

    const lines = [
      'const input = req.body.data;',    // source
      'const processed = input.trim();',
      'eval(processed);',                // sink
    ];

    const flows = checkProximityFlow(
      lines,
      [/req\.body/],
      [/eval\(/],
      [/sanitize/],
    );

    expect(flows.length).toBe(1);
    expect(flows[0].sourceLine).toBe(0);
    expect(flows[0].sinkLine).toBe(2);
  });

  it('checkProximityFlow respects sanitizers', async () => {
    const { checkProximityFlow } = await import('../../src/analyzers/ast/taint.js');

    const lines = [
      'const input = req.body.data;',    // source
      'const safe = sanitize(input);',    // sanitizer
      'eval(safe);',                      // sink
    ];

    const flows = checkProximityFlow(
      lines,
      [/req\.body/],
      [/eval\(/],
      [/sanitize/],
    );

    // Should find no flows because sanitizer is between source and sink
    expect(flows.length).toBe(0);
  });

  it('checkProximityFlow respects max distance', async () => {
    const { checkProximityFlow } = await import('../../src/analyzers/ast/taint.js');

    const lines: string[] = [];
    lines.push('const input = req.body.data;'); // line 0: source
    for (let i = 0; i < 50; i++) lines.push('// padding');
    lines.push('eval(input);'); // line 51: sink — too far

    const flows = checkProximityFlow(
      lines,
      [/req\.body/],
      [/eval\(/],
      [],
      30, // max distance
    );

    expect(flows.length).toBe(0);
  });

  it('taint_flow rules load and compile from YAML', async () => {
    const { getAllRules } = await import('../../src/analyzers/rules/index.js');

    const rules = getAllRules();
    const taintRules = rules.filter(r => r.id.startsWith('AA-CE-05'));

    expect(taintRules.length).toBeGreaterThanOrEqual(8);

    // Each taint rule should have a check function
    for (const rule of taintRules) {
      expect(typeof rule.check).toBe('function');
    }
  });

  it('canFlowWithinScope with AST tree', async () => {
    const { isTreeSitterAvailable, parseCode } = await import('../../src/analyzers/ast/parser.js');
    const { findPatternMatches, canFlowWithinScope } = await import('../../src/analyzers/ast/taint.js');

    if (!isTreeSitterAvailable()) {
      console.log('  Skipping AST taint test (tree-sitter not available)');
      return;
    }

    const code = `
function handleRequest(req) {
  const userInput = req.body.data;
  const result = eval(userInput);
  return result;
}
`;

    const tree = parseCode(code, 'javascript');
    expect(tree).not.toBeNull();

    const sources = findPatternMatches(code, [/req\.body/gm], tree);
    const sinks = findPatternMatches(code, [/eval\(/gm], tree);
    const sanitizers = findPatternMatches(code, [/sanitize/gm], tree);

    expect(sources.length).toBe(1);
    expect(sinks.length).toBe(1);

    const flows = canFlowWithinScope(tree!, sources[0], sinks[0], sanitizers);
    expect(flows).toBe(true);
  });
});
