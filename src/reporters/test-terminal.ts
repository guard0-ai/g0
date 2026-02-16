import chalk from 'chalk';
import type { TestRunResult, AttackCategory, Verdict } from '../types/test.js';

const CATEGORY_LABELS: Record<AttackCategory, string> = {
  'prompt-injection': 'Prompt Injection',
  'data-exfiltration': 'Data Exfiltration',
  'tool-abuse': 'Tool Abuse',
  'jailbreak': 'Jailbreak',
  'goal-hijacking': 'Goal Hijacking',
  'authorization': 'Authorization',
  'indirect-injection': 'Indirect Injection',
  'encoding-bypass': 'Encoding Bypass',
  'harmful-content': 'Harmful Content',
  'mcp-attack': 'MCP Attack',
  'rag-poisoning': 'RAG Poisoning',
  'multi-agent': 'Multi-Agent',
  'compliance': 'Compliance',
  'domain-specific': 'Domain-Specific',
  'content-safety': 'Content Safety',
  'bias-detection': 'Bias Detection',
  'pii-probing': 'PII Probing',
  'agentic-attacks': 'Agentic Attacks',
  'jailbreak-advanced': 'Jailbreak Advanced',
};

export function reportTestTerminal(result: TestRunResult): void {
  console.log(chalk.bold('\n  Adversarial Test Results'));
  console.log(chalk.dim('  ' + '='.repeat(60)));

  // Target info
  const targetName = result.target.name ?? result.target.endpoint;
  console.log(`  Target: ${chalk.cyan(targetName)}`);
  console.log(`  Duration: ${chalk.dim((result.durationMs / 1000).toFixed(1) + 's')}`);
  if (result.staticContext) {
    console.log(`  Mode: ${chalk.yellow('Smart targeting (static-informed)')}`);
  }

  // Results grouped by category
  const categories: AttackCategory[] = [
    'prompt-injection', 'data-exfiltration', 'tool-abuse', 'jailbreak', 'goal-hijacking',
    'authorization', 'indirect-injection', 'encoding-bypass', 'harmful-content',
    'mcp-attack', 'rag-poisoning', 'multi-agent', 'compliance', 'domain-specific',
  ];

  for (const cat of categories) {
    const catResults = result.results.filter(r => r.category === cat);
    if (catResults.length === 0) continue;

    console.log(chalk.bold.cyan(`\n  ${CATEGORY_LABELS[cat]}`));
    console.log(chalk.dim('  ' + '-'.repeat(60)));

    for (const r of catResults) {
      const badge = verdictBadge(r.verdict);
      const sev = severityTag(r.severity);
      const judge = chalk.dim(`[${r.judgeLevel}]`);
      console.log(`  ${badge} ${sev} ${r.payloadName} ${judge}`);

      if (r.verdict === 'vulnerable' || r.verdict === 'error') {
        console.log(`    ${chalk.dim('Evidence: ' + truncate(r.evidence, 80))}`);
      }
    }
  }

  // Summary
  console.log(chalk.bold('\n  Summary'));
  console.log(chalk.dim('  ' + '-'.repeat(60)));

  const s = result.summary;
  const statusBadge = s.overallStatus === 'fail'
    ? chalk.bgRed.white.bold(' FAIL ')
    : s.overallStatus === 'warn'
      ? chalk.bgYellow.black.bold(' WARN ')
      : chalk.bgGreen.white.bold(' PASS ');

  console.log(`  Status: ${statusBadge}`);
  console.log(
    `  ${chalk.red(`Vulnerable: ${s.vulnerable}`)}  ` +
    `${chalk.green(`Resistant: ${s.resistant}`)}  ` +
    `${chalk.yellow(`Inconclusive: ${s.inconclusive}`)}  ` +
    `${chalk.dim(`Errors: ${s.errors}`)}`,
  );
  console.log(`  ${chalk.bold(`Total: ${s.total} tests`)}`);
  console.log('');
}

function verdictBadge(verdict: Verdict): string {
  switch (verdict) {
    case 'vulnerable': return chalk.bgRed.white.bold(' VULN ');
    case 'resistant': return chalk.bgGreen.white.bold(' SAFE ');
    case 'inconclusive': return chalk.bgYellow.black(' ???? ');
    case 'error': return chalk.bgMagenta.white(' ERR  ');
  }
}

function severityTag(severity: string): string {
  switch (severity) {
    case 'critical': return chalk.red.bold('[CRIT]');
    case 'high': return chalk.red('[HIGH]');
    case 'medium': return chalk.yellow('[MED] ');
    case 'low': return chalk.blue('[LOW] ');
    default: return chalk.dim('[INFO]');
  }
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + '...';
}
