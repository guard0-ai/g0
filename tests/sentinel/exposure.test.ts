import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  toolCategory,
  toolArtifactPaths,
  scanArtifactsForPii,
  scoreExposure,
  buildToolExposures,
} from '../../src/sentinel/exposure.js';

describe('sentinel exposure engine', () => {
  it('categorizes known tools', () => {
    expect(toolCategory('Claude Code')).toBe('coding-agent');
    expect(toolCategory('Cursor')).toBe('coding-agent');
    expect(toolCategory('Claude Desktop')).toBe('desktop-app');
    expect(toolCategory('Something Unknown')).toBe('ai-tool');
  });

  it('maps a coding agent to its local artifact paths under HOME', () => {
    const paths = toolArtifactPaths('Codex', '/home/u');
    expect(paths.some((p) => p.includes('.codex'))).toBe(true);
  });

  describe('scanArtifactsForPii', () => {
    let dir: string;
    beforeEach(() => {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-exp-'));
    });
    afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('classifies PII across artifacts, returns counts + locators, no raw values', () => {
      const f1 = path.join(dir, 'history.jsonl');
      fs.writeFileSync(f1, 'user: email me at a@x.com\nassistant: sure, also b@y.io\n');
      const f2 = path.join(dir, 'session.log');
      fs.writeFileSync(f2, 'card 4111 1111 1111 1111 ssn 123-45-6789');
      const res = scanArtifactsForPii([f1, f2, path.join(dir, 'missing.log')]);
      expect(res.counts.email).toBe(2);
      expect(res.counts.credit_card).toBe(1);
      expect(res.counts.us_ssn).toBe(1);
      // locators list scanned files with per-file counts, never raw values
      expect(res.locators.length).toBe(2);
      const blob = JSON.stringify(res);
      expect(blob).not.toContain('a@x.com');
      expect(blob).not.toContain('4111');
    });
  });

  it('scores exposure higher when secrets/cards are present and reach is broad', () => {
    const low = scoreExposure({ mcpServers: [], network: false }, { email: 1 });
    const high = scoreExposure({ mcpServers: ['github', 'postgres'], network: true }, { credit_card: 2, api_token: 3 });
    expect(high).toBeGreaterThan(low);
    expect(high).toBeLessThanOrEqual(100);
    expect(low).toBeGreaterThanOrEqual(0);
  });

  it('builds exposure records for tools over a sandbox HOME', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-home-'));
    fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
    fs.writeFileSync(path.join(home, '.codex', 'history.jsonl'), 'contact a@x.com and c@z.dev');
    const recs = buildToolExposures(
      [{ name: 'Codex', mcpServerCount: 1, servers: [{ name: 'github' }] }],
      home,
    );
    expect(recs).toHaveLength(1);
    expect(recs[0].tool).toBe('Codex');
    expect(recs[0].category).toBe('coding-agent');
    expect(recs[0].evidenced.email).toBe(2);
    expect(recs[0].reach.mcpServers).toContain('github');
    expect(typeof recs[0].riskScore).toBe('number');
    fs.rmSync(home, { recursive: true, force: true });
  });
});
