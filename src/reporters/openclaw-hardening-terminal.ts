import chalk from 'chalk';
import type { OpenClawHardeningResult, HardeningCheckStatus, HardeningSeverity } from '../mcp/openclaw-hardening.js';

function statusIcon(status: HardeningCheckStatus): string {
  switch (status) {
    case 'pass':  return chalk.green('PASS');
    case 'fail':  return chalk.red.bold('FAIL');
    case 'error': return chalk.dim('ERR ');
    case 'skip':  return chalk.dim('SKIP');
  }
}

function severityLabel(sev: HardeningSeverity): string {
  switch (sev) {
    case 'critical': return chalk.red.bold('[CRITICAL]');
    case 'high':     return chalk.red('[HIGH]    ');
    case 'medium':   return chalk.yellow('[MEDIUM]  ');
    case 'low':      return chalk.dim('[LOW]     ');
  }
}

export function reportOpenClawHardeningTerminal(result: OpenClawHardeningResult): void {
  console.log('');
  console.log(chalk.bold(`  OpenClaw Live Hardening Audit`));
  console.log(`  ${chalk.dim('Target:')} ${result.targetUrl}`);
  console.log(chalk.dim('  ' + '─'.repeat(70)));

  const colW = { id: 10, name: 42, sev: 12, status: 6 };

  for (const check of result.checks) {
    const row = [
      check.id.padEnd(colW.id),
      check.name.padEnd(colW.name).substring(0, colW.name),
      severityLabel(check.severity),
      statusIcon(check.status),
    ].join('  ');
    console.log(`  ${row}`);
    if (check.status === 'fail') {
      console.log(`      ${chalk.dim(check.detail)}`);
    }
  }

  const s = result.summary;
  const overallColor = s.overallStatus === 'secure' ? chalk.green
    : s.overallStatus === 'warn' ? chalk.yellow
    : chalk.red.bold;

  console.log('');
  console.log(chalk.bold('  Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(70)));
  console.log(`  Overall: ${overallColor(s.overallStatus.toUpperCase())}`);
  console.log(`  ${chalk.green(`Passed: ${s.passed}`)}  ${chalk.red(`Failed: ${s.failed}`)}  ${chalk.dim(`Errors: ${s.errors}`)}`);
  console.log('');
}
