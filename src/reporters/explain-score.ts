import chalk from 'chalk';
import type { ScanScore } from '../types/score.js';

export interface ScoreBreakdownRow {
  domain: string;
  label: string;
  score: number;
  weight: number;
  weightedContribution: number;
  contributionPct: number;
}

export interface ExplainScoreData {
  rows: ScoreBreakdownRow[];
  overall: number;
  totalWeight: number;
  topImprovements: Array<{
    domain: string;
    label: string;
    score: number;
    potentialGain: number;
  }>;
}

/**
 * Build the score breakdown data from a ScanScore.
 */
export function buildExplainScoreData(score: ScanScore): ExplainScoreData {
  const totalWeight = score.domains.reduce((sum, d) => sum + d.weight, 0);

  const rows: ScoreBreakdownRow[] = score.domains.map(d => {
    const weightedContribution = d.score * d.weight;
    return {
      domain: d.domain,
      label: d.label,
      score: d.score,
      weight: d.weight,
      weightedContribution,
      contributionPct: (weightedContribution / (score.overall * totalWeight)) * 100,
    };
  });

  // Sort by score ascending for improvements
  const sorted = [...score.domains].sort((a, b) => a.score - b.score);
  const topImprovements = sorted.slice(0, 3).map(d => ({
    domain: d.domain,
    label: d.label,
    score: d.score,
    potentialGain: Math.round(((100 - d.score) * d.weight) / totalWeight),
  }));

  return { rows, overall: score.overall, totalWeight, topImprovements };
}

/**
 * Render the score breakdown table to the terminal.
 */
export function reportExplainScore(score: ScanScore): void {
  const data = buildExplainScoreData(score);

  console.log(chalk.bold('\n  Score Breakdown'));
  console.log(chalk.dim('  ' + '\u2500'.repeat(74)));

  // Header
  console.log(
    '  ' +
    chalk.dim('Domain'.padEnd(24)) +
    chalk.dim('Score'.padStart(7)) +
    chalk.dim('Weight'.padStart(8)) +
    chalk.dim('Weighted'.padStart(10)) +
    chalk.dim('Contribution'.padStart(14))
  );
  console.log(chalk.dim('  ' + '\u2500'.repeat(74)));

  // Rows sorted by weighted contribution descending
  const sorted = [...data.rows].sort((a, b) => b.weightedContribution - a.weightedContribution);
  for (const row of sorted) {
    const scoreColor = row.score >= 90 ? chalk.green :
                       row.score >= 70 ? chalk.yellow :
                       chalk.red;
    const pct = isFinite(row.contributionPct) ? `${row.contributionPct.toFixed(1)}%` : '\u2014';
    console.log(
      '  ' +
      row.label.padEnd(24) +
      scoreColor(String(row.score).padStart(7)) +
      String(row.weight.toFixed(1)).padStart(8) +
      String(row.weightedContribution.toFixed(1)).padStart(10) +
      pct.padStart(14)
    );
  }

  console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
  console.log(
    '  ' +
    chalk.bold('Overall'.padEnd(24)) +
    chalk.bold(String(data.overall).padStart(7)) +
    String(data.totalWeight.toFixed(1)).padStart(8)
  );

  // Top 3 improvements
  if (data.topImprovements.length > 0 && data.topImprovements[0].potentialGain > 0) {
    console.log(chalk.bold('\n  Top 3 Improvements'));
    console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
    for (let i = 0; i < data.topImprovements.length; i++) {
      const imp = data.topImprovements[i];
      if (imp.potentialGain <= 0) continue;
      console.log(
        `  ${chalk.yellow(`${i + 1}.`)} ${chalk.bold(imp.label)} \u2014 ` +
        `score ${chalk.red(String(imp.score))}/100, ` +
        `fixing could improve overall by ${chalk.green(`+${imp.potentialGain}`)} points`
      );
    }
  }

  console.log('');
}
