/**
 * Job summary rendering (`GITHUB_STEP_SUMMARY`). Takes an INJECTED summary
 * builder matching `@actions/core`'s `core.summary` API so it's testable
 * without a real Actions runtime. Runs on every event (push included) — no
 * pull_request is required, unlike the sticky PR comment.
 */
import {
  countBySeverity,
  renderCtaLine,
  renderFindingsSection,
  renderScoreLine,
  renderVerdict,
  type BaseDiffSummary,
} from './render.js';
import type { Finding } from '../../src/types/finding.js';

export type SummaryTableCell = { data: string; header?: boolean } | string;
export type SummaryTableRow = SummaryTableCell[];

/** The subset of `@actions/core`'s `Summary` class this module needs. */
export interface SummaryLike {
  addHeading(text: string, level?: number | string): SummaryLike;
  addTable(rows: SummaryTableRow[]): SummaryLike;
  addRaw(text: string, addEOL?: boolean): SummaryLike;
  write(options?: { overwrite?: boolean }): Promise<unknown>;
}

export interface WriteJobSummaryInput {
  score: number;
  grade: string;
  passed: boolean;
  failures: string[];
  findings: Finding[];
  baseDiff?: BaseDiffSummary | null;
  signupCta: boolean;
  findingsLimit?: number;
}

/** Writes the g0 scan report to the job summary via the injected `summary` builder. */
export async function writeJobSummary(summary: SummaryLike, input: WriteJobSummaryInput): Promise<void> {
  const counts = countBySeverity(input.findings);

  summary.addHeading('g0 security scan', 2);
  summary.addRaw(renderScoreLine(input.score, input.grade, input.baseDiff ?? null), true);
  summary.addRaw('', true);
  summary.addTable([
    [{ data: 'Severity', header: true }, { data: 'Count', header: true }],
    ['Critical', String(counts.critical)],
    ['High', String(counts.high)],
    ['Medium', String(counts.medium)],
    ['Low', String(counts.low)],
  ]);
  summary.addRaw('### Findings', true);
  summary.addRaw(renderFindingsSection(input.findings, input.findingsLimit ?? 10), true);
  summary.addRaw('', true);
  summary.addRaw(renderVerdict(input.passed, input.failures), true);

  const cta = input.signupCta ? renderCtaLine(true) : null;
  if (cta) {
    summary.addRaw('', true);
    summary.addRaw(cta, true);
  }

  await summary.write();
}
