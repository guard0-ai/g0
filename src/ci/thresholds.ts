/**
 * Shared CI gate threshold evaluation.
 *
 * Pure decision logic for whether a scan result passes the configured quality
 * gate — extracted from `g0 gate` (src/cli/commands/gate.ts) so the same
 * behavior can be reused by non-CLI callers (the GitHub Action) without
 * duplicating it. `evaluateGate` takes no dependency on I/O, process exit
 * codes, spinners, or console output — those stay in the CLI command.
 */
import type { ScanResult } from '../types/score.js';
import type { Finding } from '../types/finding.js';
import type { Grade, Severity } from '../types/common.js';

export interface GateEvalInput {
  /** Full scan result — used for the absolute score/grade gates. */
  result: ScanResult;
  /**
   * Findings to evaluate the finding-count gates (critical/high/fail-on)
   * against. This is `result.findings` in normal mode, or only the findings
   * new relative to a baseline in regression mode.
   */
  evalFindings: Finding[];
  /** Minimum overall score (0-100). Skipped when `inBaselineMode`. */
  minScore?: number;
  /** Minimum grade (A-F). Skipped when `inBaselineMode`. */
  minGrade?: Grade | string;
  /** Fail if any critical finding is present in `evalFindings`. */
  failCritical?: boolean;
  /** Fail if any critical or high finding is present in `evalFindings`. */
  failHigh?: boolean;
  /** Fail if any finding at or above this severity is present in `evalFindings`. */
  failOn?: Severity;
  /**
   * True when evaluating against a baseline (regression mode). Absolute
   * score/grade gates are skipped — pre-existing debt is intentionally
   * tolerated — and, absent an explicit finding-count gate, the gate
   * defaults to failing on any new critical/high finding so it remains
   * meaningful out of the box.
   */
  inBaselineMode: boolean;
}

export interface GateEvalResult {
  passed: boolean;
  failures: string[];
}

const GRADE_ORDER: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };
const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Evaluate a scan result against gate thresholds. Behavior-preserving
 * extraction of the logic that used to live inline in `g0 gate`.
 */
export function evaluateGate(input: GateEvalInput): GateEvalResult {
  const {
    result,
    evalFindings,
    minScore,
    minGrade,
    failCritical,
    failHigh,
    failOn,
    inBaselineMode,
  } = input;

  const failures: string[] = [];

  // Absolute posture gates (score/grade) apply to the whole project, so they
  // are skipped in regression mode where pre-existing debt is intentionally
  // tolerated. Finding-count gates apply to the evaluated set (new-only in
  // baseline mode, all findings otherwise).
  if (!inBaselineMode && minScore !== undefined && result.score.overall < minScore) {
    failures.push(`Score ${result.score.overall} is below minimum ${minScore}`);
  }

  if (!inBaselineMode && minGrade) {
    const requiredLevel = GRADE_ORDER[minGrade.toUpperCase()] ?? 3;
    const actualLevel = GRADE_ORDER[result.score.grade] ?? 1;
    if (actualLevel < requiredLevel) {
      failures.push(`Grade ${result.score.grade} is below minimum ${minGrade.toUpperCase()}`);
    }
  }

  const newLabel = inBaselineMode ? 'new ' : '';

  if (failCritical) {
    const criticalCount = evalFindings.filter(f => f.severity === 'critical').length;
    if (criticalCount > 0) {
      failures.push(`${criticalCount} ${newLabel}critical finding(s) detected`);
    }
  }

  if (failHigh) {
    const highCount = evalFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
    if (highCount > 0) {
      failures.push(`${highCount} ${newLabel}high/critical finding(s) detected`);
    }
  }

  if (failOn) {
    const threshold = SEVERITY_ORDER[failOn] ?? 0;
    const violating = evalFindings.filter(f => (SEVERITY_ORDER[f.severity] ?? 4) <= threshold);
    if (violating.length > 0) {
      failures.push(`${violating.length} ${newLabel}finding(s) at or above ${failOn} severity`);
    }
  }

  // In baseline mode with no explicit finding gate, default to failing on any
  // new critical/high so the gate is meaningful out of the box.
  if (inBaselineMode && !failCritical && !failHigh && !failOn) {
    const newSevere = evalFindings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
    if (newSevere > 0) {
      failures.push(`${newSevere} new high/critical finding(s) introduced`);
    }
  }

  return { passed: failures.length === 0, failures };
}
