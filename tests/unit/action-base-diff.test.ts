import { describe, it, expect, vi } from 'vitest';
import { computeScoreDiff, runBaseDiff, type GitRunner } from '../../action/src/base-diff.js';
import type { Finding } from '../../src/types/finding.js';
import type { Severity } from '../../src/types/common.js';

function makeFinding(ruleId: string, severity: Severity, title = 'a finding', file = 'a.py'): Finding {
  return {
    id: `${ruleId}-${Math.random().toString(36).slice(2)}`,
    ruleId,
    title,
    description: 'desc',
    severity,
    confidence: 'high',
    domain: 'tool-safety',
    location: { file, line: 1 },
    remediation: 'fix it',
    standards: { owaspAgentic: ['ASI02'] },
  };
}

describe('computeScoreDiff (pure math, no git)', () => {
  it('computes a positive scoreDelta when the current score improved', () => {
    const result = computeScoreDiff([], 90, [], 80, '2.0.0', '2026-01-01T00:00:00.000Z');
    expect(result.scoreDelta).toBe(10);
  });

  it('computes a negative scoreDelta when the current score regressed', () => {
    const result = computeScoreDiff([], 60, [], 80, '2.0.0', '2026-01-01T00:00:00.000Z');
    expect(result.scoreDelta).toBe(-20);
  });

  it('counts findings present now but not in the base as new', () => {
    const base = [makeFinding('AA-TS-001', 'high', 'known finding')];
    const current = [
      makeFinding('AA-TS-001', 'high', 'known finding'), // same fingerprint as base — not new
      makeFinding('AA-IA-002', 'critical', 'brand new finding'), // new
    ];
    const result = computeScoreDiff(current, 70, base, 85, '2.0.0', '2026-01-01T00:00:00.000Z');
    expect(result.newFindingsCount).toBe(1);
    expect(result.newFindings[0].ruleId).toBe('AA-IA-002');
    expect(result.baseScore).toBe(85);
  });

  it('reports zero new findings when current findings are a subset of base', () => {
    const shared = makeFinding('AA-TS-001', 'medium', 'shared');
    const result = computeScoreDiff([shared], 90, [shared], 90, '2.0.0', '2026-01-01T00:00:00.000Z');
    expect(result.newFindingsCount).toBe(0);
    expect(result.scoreDelta).toBe(0);
  });

  it('is line-independent — a finding that only shifted lines is not counted as new', () => {
    const base = [makeFinding('AA-TS-001', 'high', 'same finding', 'a.py')];
    const current = [{ ...makeFinding('AA-TS-001', 'high', 'same finding', 'a.py'), location: { file: 'a.py', line: 99 } }];
    const result = computeScoreDiff(current, 80, base, 80, '2.0.0', '2026-01-01T00:00:00.000Z');
    expect(result.newFindingsCount).toBe(0);
  });
});

describe('runBaseDiff (orchestration, injected git + scan)', () => {
  it('drives git worktree add/remove and diffs the injected scan results', async () => {
    const calls: string[][] = [];
    const git: GitRunner = vi.fn(async (args) => {
      calls.push(args);
      return '';
    });
    const baseFindings = [makeFinding('AA-TS-001', 'high')];
    const scanFn = vi.fn().mockResolvedValue({ findings: baseFindings, score: 75 });

    const result = await runBaseDiff({
      baseSha: 'abc123',
      repoRoot: '/repo',
      targetSubPath: '.',
      toolVersion: '2.0.0',
      now: '2026-01-01T00:00:00.000Z',
      currentFindings: [makeFinding('AA-TS-001', 'high'), makeFinding('AA-IA-002', 'critical')],
      currentScore: 85,
      scanFn,
      git,
    });

    expect(result).not.toBeNull();
    expect(result?.scoreDelta).toBe(10);
    expect(result?.newFindingsCount).toBe(1);

    // worktree add, then worktree remove --force, both against repoRoot.
    expect(calls[0][0]).toBe('worktree');
    expect(calls[0][1]).toBe('add');
    expect(calls[0]).toContain('abc123');
    const removeCall = calls.find(c => c[1] === 'remove');
    expect(removeCall).toBeDefined();
    expect(removeCall).toContain('--force');
    expect(scanFn).toHaveBeenCalledTimes(1);
  });

  it('always removes the worktree even when the scan throws', async () => {
    const calls: string[][] = [];
    const git: GitRunner = vi.fn(async (args) => {
      calls.push(args);
      return '';
    });
    const scanFn = vi.fn().mockRejectedValue(new Error('scan blew up'));
    const warn = vi.fn();

    const result = await runBaseDiff({
      baseSha: 'abc123',
      repoRoot: '/repo',
      targetSubPath: '.',
      toolVersion: '2.0.0',
      now: '2026-01-01T00:00:00.000Z',
      currentFindings: [],
      currentScore: 90,
      scanFn,
      git,
      warn,
    });

    expect(result).toBeNull();
    expect(warn).toHaveBeenCalledTimes(1);
    const removeCall = calls.find(c => c[1] === 'remove');
    expect(removeCall).toBeDefined();
  });

  it('soft-fails to null (never throws) when git itself fails, e.g. a shallow clone missing the base ref', async () => {
    const git: GitRunner = vi.fn(async (args) => {
      if (args[1] === 'add') {
        throw new Error("fatal: reference is not a tree: abc123");
      }
      return '';
    });
    const warn = vi.fn();
    const scanFn = vi.fn();

    const result = await runBaseDiff({
      baseSha: 'abc123',
      repoRoot: '/repo',
      targetSubPath: '.',
      toolVersion: '2.0.0',
      now: '2026-01-01T00:00:00.000Z',
      currentFindings: [],
      currentScore: 90,
      scanFn,
      git,
      warn,
    });

    expect(result).toBeNull();
    expect(scanFn).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn.mock.calls[0][0]).toContain('fetch-depth: 0');
  });

  it('does not throw even when the worktree-remove cleanup call itself fails', async () => {
    const git: GitRunner = vi.fn(async (args) => {
      if (args[1] === 'remove') throw new Error('worktree already gone');
      return '';
    });
    const scanFn = vi.fn().mockResolvedValue({ findings: [], score: 90 });

    await expect(
      runBaseDiff({
        baseSha: 'abc123',
        repoRoot: '/repo',
        targetSubPath: '.',
        toolVersion: '2.0.0',
        now: '2026-01-01T00:00:00.000Z',
        currentFindings: [],
        currentScore: 90,
        scanFn,
        git,
      }),
    ).resolves.not.toBeNull();
  });
});
