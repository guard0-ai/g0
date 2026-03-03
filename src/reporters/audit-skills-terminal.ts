import chalk from 'chalk';
import type { BulkAuditResult, SkillAuditResult, TrustLevel } from '../mcp/clawhub-auditor.js';

function trustBadge(level: TrustLevel): string {
  switch (level) {
    case 'trusted':   return chalk.green.bold('TRUSTED  ');
    case 'caution':   return chalk.yellow.bold('CAUTION  ');
    case 'untrusted': return chalk.red.bold('UNTRUSTED');
    case 'malicious': return chalk.bgRed.white.bold('MALICIOUS');
  }
}

function severityColor(sev: string): (s: string) => string {
  if (sev === 'critical') return chalk.red.bold;
  if (sev === 'high')     return chalk.red;
  if (sev === 'medium')   return chalk.yellow;
  return chalk.dim;
}

function reportSkill(skill: SkillAuditResult): void {
  const badge = trustBadge(skill.trustLevel);
  const scoreColor = skill.trustScore >= 80 ? chalk.green
    : skill.trustScore >= 50 ? chalk.yellow
    : chalk.red;

  console.log('');
  console.log(`  ${badge}  ${chalk.bold(skill.skillName)}  ${scoreColor(`(score: ${skill.trustScore}/100)`)}`);

  if (skill.filePath) {
    console.log(`  ${chalk.dim('File:')} ${skill.filePath}`);
  }

  if (skill.registryInfo) {
    const ri = skill.registryInfo;
    console.log(`  ${chalk.dim('Registry:')} ${ri.registry}`);
    if (ri.found) {
      console.log(`  ${chalk.dim('Publisher:')} ${ri.publisher ?? 'unknown'} ${ri.verified ? chalk.green('✓ verified') : chalk.yellow('⚠ unverified')}`);
      if (ri.downloads !== undefined) {
        console.log(`  ${chalk.dim('Downloads:')} ${ri.downloads.toLocaleString()}`);
      }
      if (ri.ageInDays !== undefined) {
        console.log(`  ${chalk.dim('Age:')} ${ri.ageInDays} days`);
      }
    } else {
      console.log(`  ${chalk.red('Skill not found in registry')}`);
    }
  }

  if (skill.risks.length > 0) {
    console.log(`  ${chalk.dim('Risks:')}`);
    for (const risk of skill.risks) {
      console.log(`    ${chalk.yellow('•')} ${risk}`);
    }
  }

  if (skill.staticFindings.length > 0) {
    console.log(`  ${chalk.dim('Findings:')}`);
    for (const f of skill.staticFindings) {
      const color = severityColor(f.severity);
      console.log(`    ${color(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
    }
  }
}

export function reportAuditSkillsTerminal(result: BulkAuditResult): void {
  const s = result.summary;

  console.log('');
  console.log(chalk.bold('  OpenClaw Skill Audit (ClawHub Supply-Chain)'));
  console.log(chalk.dim('  ' + '─'.repeat(55)));

  if (result.skills.length === 0) {
    console.log(chalk.dim('  No OpenClaw skills found.'));
    console.log('');
    return;
  }

  for (const skill of result.skills) {
    reportSkill(skill);
  }

  console.log('');
  console.log(chalk.bold('  Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(55)));
  console.log(`  Skills audited:  ${s.total}`);
  console.log(`  ${chalk.green(`Trusted:          ${s.trusted}`)}`);
  console.log(`  ${chalk.yellow(`Caution:          ${s.caution}`)}`);
  console.log(`  ${chalk.red(`Untrusted:        ${s.untrusted}`)}`);
  if (s.malicious > 0) {
    console.log(`  ${chalk.bgRed.white(`Malicious:        ${s.malicious}`)}`);
  } else {
    console.log(`  ${chalk.dim(`Malicious:        0`)}`);
  }
  console.log(`  Total findings:  ${s.totalFindings}`);
  if (s.totalFindings > 0) {
    const sb = s.findingsBySeverity;
    const parts: string[] = [];
    if (sb.critical > 0) parts.push(chalk.red.bold(`${sb.critical} critical`));
    if (sb.high > 0)     parts.push(chalk.red(`${sb.high} high`));
    if (sb.medium > 0)   parts.push(chalk.yellow(`${sb.medium} medium`));
    if (sb.low > 0)      parts.push(chalk.dim(`${sb.low} low`));
    console.log(`    ${parts.join('  ')}`);
  }
  console.log('');
}
