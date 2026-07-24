import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect } from 'vitest';
import { parsePolicy, evaluatePolicy, loadPolicy } from '../../src/sentinel/governance.js';

describe('sentinel governance', () => {
  const yaml = `
name: baseline
default: monitor
rules:
  - match: "Claude Code"
    verdict: allow
  - match: "category:desktop-app"
    verdict: deny
  - match: "Cursor*"
    verdict: allow
`;

  it('parses a policy', () => {
    const p = parsePolicy(yaml);
    expect(p.name).toBe('baseline');
    expect(p.default).toBe('monitor');
    expect(p.rules).toHaveLength(3);
  });

  it('evaluates per-tool verdicts (exact, category, glob, default) and compliance', () => {
    const p = parsePolicy(yaml);
    const g = evaluatePolicy(p, [
      { name: 'Claude Code', category: 'coding-agent' },
      { name: 'Claude Desktop', category: 'desktop-app' },
      { name: 'Cursor', category: 'coding-agent' },
      { name: 'Ollama', category: 'ai-tool' },
    ]);
    const byTool = Object.fromEntries(g.verdicts.map((v) => [v.tool, v.verdict]));
    expect(byTool['Claude Code']).toBe('allow');
    expect(byTool['Claude Desktop']).toBe('deny'); // category match
    expect(byTool['Cursor']).toBe('allow'); // glob match
    expect(byTool['Ollama']).toBe('monitor'); // default
    expect(g.compliant).toBe(false); // a deny is present
  });

  it('is compliant when no tool is denied', () => {
    const p = parsePolicy('default: allow\nrules: []');
    const g = evaluatePolicy(p, [{ name: 'Claude Code', category: 'coding-agent' }]);
    expect(g.compliant).toBe(true);
  });

  it('loads a policy from a file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-pol-'));
    const f = path.join(dir, 'p.yaml');
    fs.writeFileSync(f, yaml);
    expect(loadPolicy(f).name).toBe('baseline');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
