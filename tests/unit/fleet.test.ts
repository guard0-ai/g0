import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Mock the G0 dir to use a temp directory
const tmpDir = path.join(os.tmpdir(), `g0-fleet-test-${Date.now()}`);
vi.mock('node:os', async () => {
  const actual = await vi.importActual('node:os');
  return {
    ...actual,
    homedir: () => tmpDir,
  };
});

const {
  loadFleetState,
  saveFleetState,
  registerMember,
  pruneStaleMembers,
  getFleetSummary,
  findCommonFailures,
} = await import('../../src/daemon/fleet.js');

describe('Fleet Management', () => {
  beforeEach(() => {
    fs.mkdirSync(path.join(tmpDir, '.g0'), { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('should return empty state when no file exists', () => {
    const state = loadFleetState();
    expect(state.members).toEqual([]);
  });

  it('should register and persist a fleet member', () => {
    const member = registerMember('machine-001', {
      endpointScore: 85,
      endpointGrade: 'B',
    }, { group: 'engineering', tags: ['dev'] });

    expect(member.machineId).toBe('machine-001');
    expect(member.scores.endpointScore).toBe(85);
    expect(member.group).toBe('engineering');

    // Verify persistence
    const state = loadFleetState();
    expect(state.members).toHaveLength(1);
    expect(state.members[0].machineId).toBe('machine-001');
  });

  it('should update existing member on re-registration', () => {
    registerMember('machine-001', { endpointScore: 70, endpointGrade: 'C' });
    registerMember('machine-001', { endpointScore: 90, endpointGrade: 'A' });

    const state = loadFleetState();
    expect(state.members).toHaveLength(1);
    expect(state.members[0].scores.endpointScore).toBe(90);
  });

  it('should prune stale members', () => {
    const state = loadFleetState();
    state.members = [
      {
        machineId: 'old-machine',
        hostname: 'old',
        platform: 'darwin-arm64',
        tags: [],
        lastSeen: new Date(Date.now() - 100 * 60 * 60 * 1000).toISOString(), // 100h ago
        scores: {},
      },
      {
        machineId: 'new-machine',
        hostname: 'new',
        platform: 'darwin-arm64',
        tags: [],
        lastSeen: new Date().toISOString(),
        scores: {},
      },
    ];
    saveFleetState(state);

    const pruned = pruneStaleMembers(72);
    expect(pruned).toBe(1);

    const updated = loadFleetState();
    expect(updated.members).toHaveLength(1);
    expect(updated.members[0].machineId).toBe('new-machine');
  });

  it('should compute fleet summary with aggregate scoring', () => {
    registerMember('m1', { endpointScore: 90, endpointGrade: 'A' }, { group: 'eng' });
    registerMember('m2', { endpointScore: 70, endpointGrade: 'C' }, { group: 'eng' });
    registerMember('m3', { endpointScore: 50, endpointGrade: 'D', openclawStatus: 'critical' }, { group: 'ops' });

    const summary = getFleetSummary();
    expect(summary.totalMembers).toBe(3);
    expect(summary.byGroup).toEqual({ eng: 2, ops: 1 });
    expect(summary.avgEndpointScore).toBe(70); // (90+70+50)/3 ≈ 70
    expect(summary.worstGrade).toBe('D');
    expect(summary.criticalMembers).toHaveLength(1);
    expect(summary.aggregateScore).toBeLessThan(70); // penalized by critical member
  });

  it('should find common failures across fleet', () => {
    registerMember('m1', { openclawStatus: 'critical', hostHardeningFailed: 3 });
    registerMember('m2', { openclawStatus: 'critical', hostHardeningFailed: 2 });
    registerMember('m3', { openclawStatus: 'warn' });

    const failures = findCommonFailures();
    expect(failures.length).toBeGreaterThan(0);

    const critical = failures.find(f => f.issue === 'openclaw-critical');
    expect(critical).toBeDefined();
    expect(critical!.affectedCount).toBe(2);

    const hardening = failures.find(f => f.issue === 'host-hardening-failures');
    expect(hardening).toBeDefined();
    expect(hardening!.affectedCount).toBe(2);
  });

  it('should return no common failures with single member', () => {
    registerMember('m1', { openclawStatus: 'critical' });

    const failures = findCommonFailures();
    // Single member can't have cross-machine issues
    expect(failures).toEqual([]);
  });
});
