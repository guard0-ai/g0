// Formats a g0 `ScanResult` into the markdown + structured-content shape
// returned by the `scan_project` / `get_score` MCP tools.
import type { ScanResult } from '../../types/score.js';
import type { Finding } from '../../types/finding.js';
import type { Severity, Confidence, Grade } from '../../types/common.js';

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const CONFIDENCE_ORDER: Confidence[] = ['high', 'medium', 'low'];

// Soft cap on markdown size so a huge finding set never blows past
// reasonable MCP tool-result / context-window budgets.
const MAX_MARKDOWN_BYTES = 20 * 1024;

const DEFAULT_MAX_FINDINGS = 30;

export interface FormattedFinding {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  domain: string;
  file: string;
  line: number;
  remediation: string;
}

export interface FormatScanResultOptions {
  maxFindings?: number;
}

export interface FormatScanResultStructured {
  score: number;
  grade: Grade;
  capReason?: string;
  countsBySeverity: Record<Severity, number>;
  topFindings: FormattedFinding[];
  suppressedCount: number;
  duration: number;
  totalFindings: number;
  truncated: boolean;
}

export interface FormatScanResultOutput {
  markdown: string;
  structured: FormatScanResultStructured;
}

/** Sorts findings critical→low, then by confidence (high→low) within a severity. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sevDiff = SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
    if (sevDiff !== 0) return sevDiff;
    return CONFIDENCE_ORDER.indexOf(a.confidence) - CONFIDENCE_ORDER.indexOf(b.confidence);
  });
}

function toFormattedFinding(f: Finding): FormattedFinding {
  return {
    id: f.id,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severity,
    confidence: f.confidence,
    domain: f.domain,
    file: f.location.file,
    line: f.location.line,
    remediation: f.remediation,
  };
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/**
 * Renders a `ScanResult` as an MCP-friendly markdown summary plus a compact
 * structured object. Truncates when either `maxFindings` (default 30) or a
 * ~20KB markdown budget is hit, whichever comes first — the caller (an
 * agent) is pointed at `g0 scan .` for the full list.
 */
export function formatScanResult(
  result: ScanResult,
  options: FormatScanResultOptions = {},
): FormatScanResultOutput {
  const maxFindings = options.maxFindings ?? DEFAULT_MAX_FINDINGS;
  const sorted = sortFindings(result.findings);
  const countsBySeverity = countBySeverity(result.findings);

  const lines: string[] = [];
  // Running byte total that always equals `Buffer.byteLength(lines.join('\n'))`,
  // maintained incrementally so the truncation check below never has to
  // re-serialize the whole (growing) array — that rejoin-every-iteration
  // approach was O(n^2) in the finding count.
  let byteTotal = 0;
  const pushLine = (line: string): void => {
    // A '\n' separator is only introduced between lines, so the first push
    // doesn't pay for one.
    if (lines.length > 0) byteTotal += 1;
    byteTotal += Buffer.byteLength(line, 'utf-8');
    lines.push(line);
  };

  pushLine('# g0 scan result');
  pushLine('');
  pushLine(`**Score:** ${result.score.overall}/100 (${result.score.grade})`);
  if (result.score.capReason) {
    pushLine(`**Grade capped:** ${result.score.capReason}`);
  }
  pushLine(
    `**Findings:** ${result.findings.length} total — ` +
    `${countsBySeverity.critical} critical, ${countsBySeverity.high} high, ` +
    `${countsBySeverity.medium} medium, ${countsBySeverity.low} low` +
    (countsBySeverity.info ? `, ${countsBySeverity.info} info` : ''),
  );
  if (result.suppressedCount) {
    pushLine(`**Suppressed:** ${result.suppressedCount} additional finding(s) suppressed (accepted risk / config)`);
  }

  const topFindings: FormattedFinding[] = [];
  let truncated = false;

  if (sorted.length > 0) {
    pushLine('');
    pushLine('## Findings');
  }

  for (const f of sorted) {
    if (topFindings.length >= maxFindings) {
      truncated = true;
      break;
    }

    const entryLines = [
      '',
      `### ${topFindings.length + 1}. [${f.severity.toUpperCase()}] ${f.title}`,
      `- Rule: \`${f.ruleId}\` (${f.domain}, confidence: ${f.confidence})`,
      `- Location: ${f.location.file}:${f.location.line}`,
      `- Remediation: ${f.remediation}`,
    ];
    const entryText = entryLines.join('\n');

    // Matches the original check exactly: `byteTotal` here equals what
    // `Buffer.byteLength(lines.join('\n'))` would have measured.
    if (byteTotal + Buffer.byteLength(entryText, 'utf-8') > MAX_MARKDOWN_BYTES) {
      truncated = true;
      break;
    }

    for (const line of entryLines) pushLine(line);
    topFindings.push(toFormattedFinding(f));
  }

  if (truncated) {
    const remaining = sorted.length - topFindings.length;
    const remainingCritical = sorted.slice(topFindings.length).filter(f => f.severity === 'critical').length;
    lines.push('');
    lines.push(`…and ${remaining} more findings (${remainingCritical} critical). Run 'g0 scan .' locally for the full list.`);
  }

  const markdown = lines.join('\n').trimEnd() + '\n';

  return {
    markdown,
    structured: {
      score: result.score.overall,
      grade: result.score.grade,
      capReason: result.score.capReason,
      countsBySeverity,
      topFindings,
      suppressedCount: result.suppressedCount ?? 0,
      duration: result.duration,
      totalFindings: result.findings.length,
      truncated,
    },
  };
}
