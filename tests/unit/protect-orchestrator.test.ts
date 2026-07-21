import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  resolveSurfaces, protectPlan, protectApply, protectOff,
} from '../../src/protect/orchestrator.js';
import { readLatestManifest } from '../../src/protect/manifest.js';
import type { ProtectAdapter } from '../../src/protect/types.js';

function fakeAdapter(overrides: Partial<ProtectAdapter> = {}): ProtectAdapter {
  return {
    surface: 'mcp',
    plan: async () => ({ surface: 'mcp', steps: [{ id: 's1', description: 'd', files: [] }], advisories: [] }),
    apply: async () => ({ surface: 'mcp', applied: ['s1'], skipped: [], errors: [], undo: { quarantineManifestPath: '/q.json' } }),
    status: async () => ({ surface: 'mcp', protected: true, summary: '', detail: [] }),
    undo: async () => ({ surface: 'mcp', restored: ['s1'], skipped: [], errors: [] }),
    ...overrides,
  };
}

describe('protect orchestrator', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-orch-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('resolveSurfaces filters and rejects unknowns', () => {
    const adapter = fakeAdapter();
    expect(resolveSurfaces(undefined, [adapter])).toEqual([adapter]);
    expect(resolveSurfaces('mcp', [adapter])).toEqual([adapter]);
    expect(() => resolveSurfaces('mcp,browser', [adapter])).toThrow(/unknown surface/);
  });

  it('apply writes a manifest with each surface undo handle', async () => {
    const { results, manifestPath } = await protectApply({ stateDir: tmpDir }, [fakeAdapter()]);
    expect(results[0].applied).toEqual(['s1']);
    expect(fs.existsSync(manifestPath)).toBe(true);
    expect(readLatestManifest(tmpDir)?.manifest.surfaces.mcp?.quarantineManifestPath).toBe('/q.json');
  });

  it('a throwing adapter is recorded, not propagated', async () => {
    const boom = fakeAdapter({ apply: async () => { throw new Error('kaboom'); } });
    const { results } = await protectApply({ stateDir: tmpDir }, [boom]);
    expect(results[0].errors.join(' ')).toContain('kaboom');
    expect(results[0].applied).toEqual([]);
  });

  it('off passes the recorded handle back to undo', async () => {
    let seenHandle: unknown;
    const adapter = fakeAdapter({
      undo: async (_ctx, handle) => { seenHandle = handle; return { surface: 'mcp', restored: [], skipped: [], errors: [] }; },
    });
    await protectApply({ stateDir: tmpDir }, [adapter]);
    await protectOff({ stateDir: tmpDir }, {}, [adapter]);
    expect(seenHandle).toEqual({ quarantineManifestPath: '/q.json' });
  });

  it('plan aggregates surface plans', async () => {
    const plans = await protectPlan({ stateDir: tmpDir }, [fakeAdapter()]);
    expect(plans).toHaveLength(1);
    expect(plans[0].steps[0].id).toBe('s1');
  });
});
