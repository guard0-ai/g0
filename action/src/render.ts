/**
 * Pure markdown/table rendering for the g0 GitHub Action's PR comment and job
 * summary. No GitHub API, no filesystem — everything here is a plain
 * function of its inputs so it can be unit-tested without a real Action run.
 */
import type { Finding } from '../../src/types/finding.js';

/**
 * HTML marker embedded at the top of every PR comment g0 posts. `comment.ts`
 * searches existing comments for this marker to find-and-update in place
 * instead of spamming a new comment on every run.
 */
export const REPORT_MARKER = '<!-- g0-scan-report -->';

/** Static, self-contained UTM signup line — no dependency on the CLI's cta module. */
export const STATIC_CTA_LINE =
  '— See findings across every repo in your org → https://guard0.ai/signup?utm_source=github&utm_medium=pr_comment&utm_campaign=g0_action';

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

const SEVERITY_RANK: Record<Finding['severity'], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    counts[f.severity] += 1;
  }
  return counts;
}

export function renderSeverityTable(counts: SeverityCounts): string {
  return [
    '| Severity | Count |',
    '| --- | --- |',
    `| Critical | ${counts.critical} |`,
    `| High | ${counts.high} |`,
    `| Medium | ${counts.medium} |`,
    `| Low | ${counts.low} |`,
  ].join('\n');
}

export interface BaseDiffSummary {
  scoreDelta: number;
  newFindingsCount: number;
}

function arrow(delta: number): string {
  if (delta > 0) return `▲ +${delta}`;
  if (delta < 0) return `▼ ${delta}`;
  return '± 0';
}

/** e.g. "Score 78/100 (B)" or, with a base diff, "Score 78/100 (B) (▲ +4 vs base) · 2 new findings". */
export function renderScoreLine(score: number, grade: string, baseDiff: BaseDiffSummary | null | undefined): string {
  const base = `Score ${score}/100 (${grade})`;
  if (!baseDiff) return base;
  const findingWord = baseDiff.newFindingsCount === 1 ? 'finding' : 'findings';
  return `${base} (${arrow(baseDiff.scoreDelta)} vs base) · ${baseDiff.newFindingsCount} new ${findingWord}`;
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]);
}

function renderFindingLine(f: Finding): string {
  const loc = f.location ? `${f.location.file}:${f.location.line}` : 'unknown location';
  return `- **${f.severity.toUpperCase()}** \`${loc}\` — ${f.title}${f.remediation ? `. ${f.remediation}` : ''}`;
}

/**
 * Renders up to `limit` findings as a flat list (most severe first), with any
 * remaining findings tucked into a collapsible `<details>` block so the
 * comment stays readable on large scans.
 */
export function renderFindingsSection(findings: Finding[], limit = 10): string {
  if (findings.length === 0) return '_No findings._';

  const sorted = sortBySeverity(findings);
  const visible = sorted.slice(0, limit);
  const rest = sorted.slice(limit);

  let out = visible.map(renderFindingLine).join('\n');

  if (rest.length > 0) {
    const restLines = rest.map(renderFindingLine).join('\n');
    const noun = rest.length === 1 ? 'finding' : 'findings';
    out += `\n\n<details>\n<summary>${rest.length} more ${noun}</summary>\n\n${restLines}\n\n</details>`;
  }

  return out;
}

export function renderVerdict(passed: boolean, failures: string[]): string {
  if (passed) return '**Gate: PASSED** ✅';
  const reasons = failures.map(f => `- ${f}`).join('\n');
  return `**Gate: FAILED** ❌\n${reasons}`;
}

export function renderCtaLine(enabled: boolean): string | null {
  return enabled ? STATIC_CTA_LINE : null;
}

export interface ReportInput {
  score: number;
  grade: string;
  passed: boolean;
  failures: string[];
  findings: Finding[];
  baseDiff?: BaseDiffSummary | null;
  signupCta: boolean;
  findingsLimit?: number;
}

/** Full markdown body for the sticky PR comment, including the tracking marker. */
export function renderReportBody(input: ReportInput): string {
  const counts = countBySeverity(input.findings);
  const parts: string[] = [
    REPORT_MARKER,
    '## g0 security scan',
    '',
    renderScoreLine(input.score, input.grade, input.baseDiff ?? null),
    '',
    renderSeverityTable(counts),
    '',
    '### Findings',
    renderFindingsSection(input.findings, input.findingsLimit ?? 10),
    '',
    renderVerdict(input.passed, input.failures),
  ];

  const cta = input.signupCta ? renderCtaLine(true) : null;
  if (cta) {
    parts.push('', cta);
  }

  return parts.join('\n');
}
