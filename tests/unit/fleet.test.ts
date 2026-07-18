import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  computeAssetId,
  assetIdentity,
  writeSnapshot,
  getSnapshots,
  latestSnapshot,
  listAssetIds,
  computeFleetSummary,
  computeDrift,
  type FleetSnapshot,
} from '../../src/platform/fleet.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fleet-'));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function snap(assetId: string, timestamp: string, over: Partial<FleetSnapshot> = {}): FleetSnapshot {
  return {
    schema: 'g0-fleet-snapshot/1',
    assetId,
    kind: 'repo',
    name: over.name ?? assetId,
    path: `/x/${assetId}`,
    machine: { machineId: 'm', hostname: 'h', platform: 'darwin' },
    timestamp,
    score: over.score ?? 70,
    grade: over.grade ?? 'C',
    findings: over.findings ?? { total: 0, bySeverity: {}, fingerprints: [] },
    inventory: over.inventory ?? { agents: 0, tools: 0, models: 0, mcpServers: 0, vectorDBs: 0, frameworks: [] },
    ecosystems: over.ecosystems ?? [],
    ...over,
  };
}

describe('computeAssetId', () => {
  it('normalizes git@ and https remotes to the same id', () => {
    const a = computeAssetId('repo', 'git@github.com:acme/agent.git');
    const b = computeAssetId('repo', 'https://github.com/acme/agent');
    expect(a).toBe(b);
  });

  it('produces different ids for different repos', () => {
    expect(computeAssetId('repo', 'https://github.com/a/x'))
      .not.toBe(computeAssetId('repo', 'https://github.com/a/y'));
  });
});

describe('assetIdentity', () => {
  it('falls back to the absolute path when there is no remote', () => {
    expect(assetIdentity('/tmp/proj')).toBe(path.resolve('/tmp/proj'));
  });

  it('uses the remote when the path is not inside a git repo', () => {
    // No git toplevel for an arbitrary tmp dir → identity is the bare remote.
    expect(assetIdentity(dir, 'https://github.com/acme/agent')).toBe('https://github.com/acme/agent');
  });
});

describe('snapshot store', () => {
  it('writes and reads snapshots ordered oldest to newest', () => {
    writeSnapshot(snap('asset-1', '2026-01-02T00:00:00.000Z'), dir);
    writeSnapshot(snap('asset-1', '2026-01-01T00:00:00.000Z'), dir);
    const snaps = getSnapshots('asset-1', dir);
    expect(snaps.map(s => s.timestamp)).toEqual([
      '2026-01-01T00:00:00.000Z', '2026-01-02T00:00:00.000Z',
    ]);
    expect(latestSnapshot('asset-1', dir)!.timestamp).toBe('2026-01-02T00:00:00.000Z');
  });
});

describe('computeFleetSummary', () => {
  it('rolls up latest snapshot per asset and sorts worst first', () => {
    writeSnapshot(snap('good', '2026-01-01T00:00:00.000Z', {
      name: 'good', score: 90, grade: 'A', owner: 'team-a',
      findings: { total: 1, bySeverity: { high: 1 }, fingerprints: ['f1'] },
      inventory: { agents: 2, tools: 1, models: 1, mcpServers: 0, vectorDBs: 0, frameworks: ['langchain'] },
      ecosystems: ['langchain'],
    }), dir);
    writeSnapshot(snap('bad', '2026-01-01T00:00:00.000Z', {
      name: 'bad', score: 40, grade: 'F', owner: 'team-a',
      findings: { total: 5, bySeverity: { critical: 3, high: 2 }, fingerprints: ['a', 'b', 'c', 'd', 'e'] },
      inventory: { agents: 4, tools: 3, models: 2, mcpServers: 1, vectorDBs: 0, frameworks: ['crewai'] },
      ecosystems: ['crewai'],
    }), dir);

    const summary = computeFleetSummary(dir);
    expect(summary.assetCount).toBe(2);
    expect(summary.totals.agents).toBe(6);
    expect(summary.totals.criticals).toBe(3);
    expect(summary.totals.mcpServers).toBe(1);
    expect(summary.assets[0].name).toBe('bad'); // worst first
    expect(summary.owners['team-a']).toBe(2);
    expect(summary.ecosystems.langchain).toBe(1);
    expect(summary.ecosystems.crewai).toBe(1);
  });
});

describe('computeDrift', () => {
  it('reports new and resolved findings between the two latest snapshots', () => {
    writeSnapshot(snap('a', '2026-01-01T00:00:00.000Z', {
      score: 80, grade: 'B',
      findings: { total: 2, bySeverity: {}, fingerprints: ['keep', 'gone'] },
      inventory: { agents: 2, tools: 1, models: 0, mcpServers: 0, vectorDBs: 0, frameworks: [] },
    }), dir);
    writeSnapshot(snap('a', '2026-01-02T00:00:00.000Z', {
      score: 66, grade: 'D',
      findings: { total: 2, bySeverity: {}, fingerprints: ['keep', 'new'] },
      inventory: { agents: 3, tools: 1, models: 0, mcpServers: 0, vectorDBs: 0, frameworks: [] },
    }), dir);

    const drift = computeDrift('a', dir)!;
    expect(drift.newFindings).toBe(1);      // 'new'
    expect(drift.resolvedFindings).toBe(1); // 'gone'
    expect(drift.scoreDelta).toBe(-14);
    expect(drift.gradeFrom).toBe('B');
    expect(drift.gradeTo).toBe('D');
    expect(drift.inventoryDelta.agents).toBe(1);
  });

  it('returns a baseline-only drift when a single snapshot exists', () => {
    writeSnapshot(snap('solo', '2026-01-01T00:00:00.000Z'), dir);
    const drift = computeDrift('solo', dir)!;
    expect(drift.from).toBeUndefined();
    expect(drift.newFindings).toBe(0);
  });

  it('lists all asset ids', () => {
    writeSnapshot(snap('one', '2026-01-01T00:00:00.000Z'), dir);
    writeSnapshot(snap('two', '2026-01-01T00:00:00.000Z'), dir);
    expect(listAssetIds(dir).sort()).toEqual(['one', 'two']);
  });
});
