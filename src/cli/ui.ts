import chalk from 'chalk';
import ora from 'ora';
import type { Severity, Grade } from '../types/common.js';
import type { Finding } from '../types/finding.js';
import type { ScanScore, DomainScore } from '../types/score.js';

export function createSpinner(text: string) {
  return ora({ text, color: 'cyan' });
}

export function severityColor(severity: Severity): (text: string) => string {
  switch (severity) {
    case 'critical': return chalk.bgRed.white.bold;
    case 'high': return chalk.red.bold;
    case 'medium': return chalk.yellow;
    case 'low': return chalk.blue;
    case 'info': return chalk.dim;
  }
}

export function severityBadge(severity: Severity): string {
  const label = severity.toUpperCase().padEnd(8);
  return severityColor(severity)(` ${label} `);
}

export function gradeColor(grade: Grade): (text: string) => string {
  switch (grade) {
    case 'A': return chalk.green.bold;
    case 'B': return chalk.green;
    case 'C': return chalk.yellow;
    case 'D': return chalk.red;
    case 'F': return chalk.bgRed.white.bold;
  }
}

export function printFinding(finding: Finding, index: number): void {
  const badge = severityBadge(finding.severity);
  const loc = chalk.dim(`${finding.location.file}:${finding.location.line}`);
  const rule = chalk.dim(`[${finding.ruleId}]`);

  // Build efficacy badges
  const badges: string[] = [];
  if (finding.reachability && finding.reachability !== 'unknown') {
    const reachLabel = finding.reachability.toUpperCase().replace('-', ' ');
    const reachColor = finding.reachability === 'agent-reachable' || finding.reachability === 'tool-reachable'
      ? chalk.bgMagenta.white : finding.reachability === 'utility-code' ? chalk.dim : chalk.cyan;
    badges.push(reachColor(`[${reachLabel}]`));
  }
  if (finding.exploitability && finding.exploitability !== 'not-assessed') {
    const exploitColor = finding.exploitability === 'confirmed' ? chalk.bgRed.white
      : finding.exploitability === 'likely' ? chalk.red
      : chalk.dim;
    badges.push(exploitColor(`[${finding.exploitability.toUpperCase()}]`));
  }
  const badgeSuffix = badges.length > 0 ? ' ' + badges.join(' ') : '';

  console.log(`\n  ${badge} ${chalk.bold(finding.title)} ${rule}${badgeSuffix}`);
  console.log(`    ${finding.description}`);
  console.log(`    ${loc}`);

  if (finding.location.snippet) {
    console.log(chalk.dim(`    > ${finding.location.snippet.trim()}`));
  }

  if (finding.remediation) {
    console.log(chalk.cyan(`    Fix: ${finding.remediation}`));
  }

  // Show standards mapping
  const refs: string[] = [];
  if (finding.standards.owaspAgentic?.length) refs.push(`OWASP:${finding.standards.owaspAgentic.join(',')}`);
  if (finding.standards.aiuc1?.length) refs.push(`AIUC-1:${finding.standards.aiuc1.join(',')}`);
  if (finding.standards.iso42001?.length) refs.push(`ISO42001:${finding.standards.iso42001.join(',')}`);
  if (finding.standards.nistAiRmf?.length) refs.push(`NIST:${finding.standards.nistAiRmf.join(',')}`);
  if (refs.length > 0) {
    console.log(chalk.dim(`    Standards: ${refs.join(' | ')}`));
  }
}

export function printScoreBar(score: number, width = 30): string {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const color = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
  return color('█'.repeat(filled)) + chalk.dim('░'.repeat(empty)) + ` ${score}`;
}

export function printDomainScores(domains: DomainScore[]): void {
  console.log(chalk.bold('\n  Domain Scores'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  for (const d of domains) {
    const label = d.label.padEnd(22);
    const bar = printScoreBar(d.score);
    const findings = d.findings > 0 ? chalk.dim(` (${d.findings} findings)`) : '';
    console.log(`  ${label} ${bar}${findings}`);
  }
}

export function printOverallScore(score: ScanScore): void {
  const gc = gradeColor(score.grade);
  console.log(chalk.bold('\n  Overall Score'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`  ${gc(score.grade)}  ${printScoreBar(score.overall, 40)}`);
}

export function printSummary(findings: Finding[]): void {
  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
  };

  console.log(chalk.bold('\n  Findings Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`  ${chalk.bgRed.white.bold(' CRIT ')} ${counts.critical}  ${chalk.red.bold(' HIGH ')} ${counts.high}  ${chalk.yellow(' MED  ')} ${counts.medium}  ${chalk.blue(' LOW  ')} ${counts.low}  ${chalk.dim(' INFO ')} ${counts.info}`);
  console.log(`  ${chalk.bold(`Total: ${findings.length} findings`)}\n`);
}
