/**
 * g0 GitHub Action entry point.
 *
 * Bundles g0's own TypeScript source (no `npm install -g` / shell-out) to
 * run a scan in-process, evaluate the gate, upload SARIF, post a sticky PR
 * comment, and write a job summary.
 *
 * ORDERING IS LOAD-BEARING: the PR comment, job summary, and SARIF upload
 * must all be attempted BEFORE `core.setFailed` is called for a gate
 * failure, so those artifacts land on the PR even when the gate fails.
 * `core.setFailed` for the gate verdict is therefore the very last thing
 * this file does on the happy path.
 */
import * as core from '@actions/core';
import * as github from '@actions/github';
import * as path from 'node:path';

import { runScan } from '../../src/pipeline.js';
import { loadConfig } from '../../src/config/loader.js';
import { reportSarif } from '../../src/reporters/sarif.js';
import { evaluateGate } from '../../src/ci/thresholds.js';
import { buildBaseline, diffAgainstBaseline, loadBaseline } from '../../src/ci/baseline.js';
import { G0_VERSION } from '../../src/utils/version.js';
import type { Finding } from '../../src/types/finding.js';
import type { Grade, Severity } from '../../src/types/common.js';

import { countBySeverity, renderReportBody, type BaseDiffSummary } from './render.js';
import { postStickyComment } from './comment.js';
import { writeJobSummary } from './summary.js';
import { uploadSarifResults } from './sarif-upload.js';
import { runBaseDiff } from './base-diff.js';

function getBooleanInput(name: string, def: boolean): boolean {
  const raw = core.getInput(name);
  if (raw === '') return def;
  return raw.toLowerCase() === 'true';
}

function mapFailOn(failOn: string): { failCritical: boolean; failHigh: boolean } {
  if (failOn === 'critical') return { failCritical: true, failHigh: false };
  if (failOn === 'high') return { failCritical: false, failHigh: true };
  return { failCritical: false, failHigh: false };
}

async function run(): Promise<void> {
  try {
    // ── 1. Parse inputs ────────────────────────────────────────────────
    const targetPath = core.getInput('path') || '.';
    const resolvedPath = path.resolve(targetPath);
    const ruleset = (core.getInput('ruleset') || undefined) as 'recommended' | 'extended' | 'all' | undefined;
    const configPath = core.getInput('config') || undefined;
    const baselinePath = core.getInput('baseline') || undefined;
    const compareToBase = getBooleanInput('compare-to-base', true);
    const wantSarif = getBooleanInput('sarif', true);
    const wantSarifUpload = getBooleanInput('upload-sarif', true);
    const wantPrComment = getBooleanInput('pr-comment', true);
    const commentMode = core.getInput('comment-mode') || 'update';
    const signupCta = getBooleanInput('signup-cta', true);
    const token = core.getInput('github-token') || process.env.GITHUB_TOKEN || '';
    const failOnInput = core.getInput('fail-on') || 'high';
    const { failCritical, failHigh } = mapFailOn(failOnInput);

    const context = github.context;

    // ── 2. Load config + run the scan ─────────────────────────────────
    let config;
    try {
      config = loadConfig(resolvedPath, configPath) ?? undefined;
    } catch (err) {
      core.warning(`g0: config error (${err instanceof Error ? err.message : String(err)}) — continuing without it`);
    }

    const minScore = parseInt(core.getInput('min-score') || String(config?.min_score ?? 70), 10);
    const minGrade = (core.getInput('min-grade') || config?.min_grade || undefined) as Grade | undefined;

    const result = await runScan({ targetPath: resolvedPath, config, ruleset });

    // Regression mode: evaluate only findings new relative to a committed baseline file.
    let evalFindings: Finding[] = result.findings;
    const inBaselineMode = Boolean(baselinePath);
    if (baselinePath) {
      const baseline = loadBaseline(baselinePath);
      if (baseline) {
        evalFindings = diffAgainstBaseline(result.findings, baseline).newFindings;
      } else {
        core.warning(`g0: baseline file not found or unreadable: ${baselinePath} — evaluating all findings`);
      }
    }

    // ── 3. Base-branch diff (live PR-vs-base score delta) ─────────────
    let baseDiff: BaseDiffSummary | null = null;
    const baseSha = context.payload.pull_request?.base?.sha as string | undefined;
    if (compareToBase && context.eventName === 'pull_request' && baseSha) {
      const diff = await runBaseDiff({
        baseSha,
        repoRoot: process.cwd(),
        targetSubPath: targetPath,
        toolVersion: G0_VERSION,
        now: new Date().toISOString(),
        currentFindings: result.findings,
        currentScore: result.score.overall,
        scanFn: async worktreePath => {
          const baseConfig = loadConfig(worktreePath, configPath) ?? undefined;
          const baseResult = await runScan({ targetPath: worktreePath, config: baseConfig, ruleset });
          return { findings: baseResult.findings, score: baseResult.score.overall };
        },
        warn: core.warning,
      });
      if (diff) {
        baseDiff = { scoreDelta: diff.scoreDelta, newFindingsCount: diff.newFindingsCount };
      }
    }

    // ── 4. Evaluate the gate ───────────────────────────────────────────
    const gateResult = evaluateGate({
      result,
      evalFindings,
      minScore,
      minGrade,
      failCritical,
      failHigh,
      failOn: config?.fail_on as Severity | undefined,
      inBaselineMode,
    });

    // ── 5. SARIF: write the file, then (optionally) upload it ─────────
    let sarifPath: string | undefined;
    if (wantSarif) {
      sarifPath = path.join(process.cwd(), 'g0-results.sarif');
      try {
        reportSarif(result, sarifPath);
      } catch (err) {
        core.warning(`g0: failed to write SARIF file (${err instanceof Error ? err.message : String(err)})`);
        sarifPath = undefined;
      }

      if (sarifPath && wantSarifUpload) {
        try {
          const octokit = github.getOctokit(token);
          const commitSha = (context.payload.pull_request?.head?.sha as string | undefined) ?? context.sha;
          await uploadSarifResults({
            octokit,
            owner: context.repo.owner,
            repo: context.repo.repo,
            commitSha,
            ref: context.ref,
            sarifFilePath: sarifPath,
            logger: core,
          });
        } catch (err) {
          core.warning(`g0: SARIF upload skipped (${err instanceof Error ? err.message : String(err)})`);
        }
      }
    }

    // ── 6. Sticky PR comment ───────────────────────────────────────────
    if (wantPrComment) {
      try {
        const octokit = github.getOctokit(token);
        const body = renderReportBody({
          score: result.score.overall,
          grade: result.score.grade,
          passed: gateResult.passed,
          failures: gateResult.failures,
          findings: result.findings,
          baseDiff,
          signupCta,
        });
        await postStickyComment({ octokit, context, body, commentMode, logger: core });
      } catch (err) {
        core.warning(`g0: PR comment skipped (${err instanceof Error ? err.message : String(err)})`);
      }
    }

    // ── 7. Job summary (works on push too, no PR required) ────────────
    try {
      await writeJobSummary(core.summary, {
        score: result.score.overall,
        grade: result.score.grade,
        passed: gateResult.passed,
        failures: gateResult.failures,
        findings: result.findings,
        baseDiff,
        signupCta,
      });
    } catch (err) {
      core.warning(`g0: job summary skipped (${err instanceof Error ? err.message : String(err)})`);
    }

    // ── 8. Outputs ──────────────────────────────────────────────────────
    const counts = countBySeverity(result.findings);
    core.setOutput('score', String(result.score.overall));
    core.setOutput('grade', result.score.grade);
    core.setOutput('passed', String(gateResult.passed));
    core.setOutput('critical', String(counts.critical));
    core.setOutput('high', String(counts.high));
    core.setOutput('medium', String(counts.medium));
    core.setOutput('low', String(counts.low));
    const newFindingsCount = baseDiff?.newFindingsCount ?? (inBaselineMode ? evalFindings.length : undefined);
    core.setOutput('new-findings', newFindingsCount === undefined ? '' : String(newFindingsCount));
    core.setOutput('sarif-file', sarifPath ?? '');

    // ── 9. Fail the check LAST — artifacts above have already landed ──
    if (!gateResult.passed) {
      core.setFailed(`g0 gate failed: ${gateResult.failures.join('; ')}`);
    }
  } catch (err) {
    core.setFailed(err instanceof Error ? err.message : String(err));
  }
}

run();
