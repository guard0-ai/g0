/**
 * Base-branch diff: scores the PR's base commit in a throwaway git worktree
 * and diffs it against the current (head) scan, producing a score delta and
 * a new-findings count for the PR comment/summary.
 *
 * Split into a pure diff-math function (`computeScoreDiff`, no git, no I/O —
 * directly unit-testable on fixture findings) and an orchestrator
 * (`runBaseDiff`) that drives `git worktree` + an injected scan function.
 * Both `git` and `scanFn` are injectable so tests never need real git or a
 * real scan.
 *
 * `runBaseDiff` NEVER throws: any failure (shallow clone, missing base ref,
 * scan error) is soft-failed via `warn(...)` and a `null` return, and the
 * worktree is always removed in a `finally`.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import type { Finding } from '../../src/types/finding.js';
import { buildBaseline, diffAgainstBaseline } from '../../src/ci/baseline.js';

const execFileAsync = promisify(execFile);

export interface ScoreDiffResult {
  scoreDelta: number;
  newFindings: Finding[];
  newFindingsCount: number;
  baseScore: number;
}

/**
 * Pure diff math: no git, no filesystem. Reuses the same fingerprinting the
 * CI baseline gate uses (rule + file + normalized title, line-independent)
 * so "new" here means the same thing it means everywhere else in g0.
 */
export function computeScoreDiff(
  currentFindings: Finding[],
  currentScore: number,
  baseFindings: Finding[],
  baseScore: number,
  toolVersion: string,
  now: string,
): ScoreDiffResult {
  const baseline = buildBaseline(baseFindings, toolVersion, now);
  const diff = diffAgainstBaseline(currentFindings, baseline);
  return {
    scoreDelta: currentScore - baseScore,
    newFindings: diff.newFindings,
    newFindingsCount: diff.newFindings.length,
    baseScore,
  };
}

/** Runs `git` with the given args in `cwd`, returning stdout. Throws on non-zero exit. */
export type GitRunner = (args: string[], cwd: string) => Promise<string>;

export const defaultGitRunner: GitRunner = async (args, cwd) => {
  const { stdout } = await execFileAsync('git', args, { cwd, maxBuffer: 64 * 1024 * 1024 });
  return stdout;
};

export interface BaseScanResult {
  findings: Finding[];
  score: number;
}

export interface RunBaseDiffOptions {
  /** The PR base branch commit to compare against (`payload.pull_request.base.sha`). */
  baseSha: string;
  /** Working directory for `git worktree` commands — the checked-out repo. */
  repoRoot: string;
  /** Path (relative to the worktree root) to scan — mirrors the action's `path` input. */
  targetSubPath: string;
  toolVersion: string;
  now: string;
  currentFindings: Finding[];
  currentScore: number;
  /** Scans the given worktree path and returns findings + overall score. */
  scanFn: (worktreePath: string) => Promise<BaseScanResult>;
  git?: GitRunner;
  warn?: (message: string) => void;
}

/**
 * Checks out the PR base commit into a temporary git worktree, scans it with
 * `scanFn`, and diffs the result against the current (head) findings/score.
 * Soft-fails to `null` on any error (shallow clone, unknown base ref, scan
 * failure) — callers render the comment/summary without a base-diff section
 * rather than crashing the whole action run.
 */
export async function runBaseDiff(opts: RunBaseDiffOptions): Promise<ScoreDiffResult | null> {
  const git = opts.git ?? defaultGitRunner;
  const warn = opts.warn ?? (() => {});
  let worktreeDir: string | null = null;
  let tmpParent: string | null = null;

  try {
    tmpParent = await fs.mkdtemp(path.join(os.tmpdir(), 'g0-base-'));
    // `git worktree add` requires the target path to not already exist —
    // mkdtemp() creates it, so nest one level deeper under the temp dir.
    worktreeDir = path.join(tmpParent, 'worktree');

    await git(['worktree', 'add', '--detach', worktreeDir, opts.baseSha], opts.repoRoot);

    const scanTarget = path.join(worktreeDir, opts.targetSubPath);
    const base = await opts.scanFn(scanTarget);

    return computeScoreDiff(
      opts.currentFindings,
      opts.currentScore,
      base.findings,
      base.score,
      opts.toolVersion,
      opts.now,
    );
  } catch (err) {
    warn(
      `g0: base-branch comparison skipped (${err instanceof Error ? err.message : String(err)}). ` +
        'Ensure the checkout step uses "fetch-depth: 0" so the base commit history is available.',
    );
    return null;
  } finally {
    if (worktreeDir) {
      try {
        await git(['worktree', 'remove', '--force', worktreeDir], opts.repoRoot);
      } catch {
        // Best-effort cleanup — a leftover temp worktree must not fail the run.
      }
    }
    if (tmpParent) {
      try {
        await fs.rm(tmpParent, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup — an empty leftover temp dir must not fail the run.
      }
    }
  }
}
