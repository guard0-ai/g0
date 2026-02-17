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

  // Visual breakdown bar
  const barWidth = 40;
  const vulnWidth = s.total > 0 ? Math.round((s.vulnerable / s.total) * barWidth) : 0;
  const safeWidth = s.total > 0 ? Math.round((s.resistant / s.total) * barWidth) : 0;
  const incWidth = s.total > 0 ? Math.round((s.inconclusive / s.total) * barWidth) : 0;
  const errWidth = Math.max(0, barWidth - vulnWidth - safeWidth - incWidth);
  const bar =
    chalk.red('\u2588'.repeat(vulnWidth)) +
    chalk.green('\u2588'.repeat(safeWidth)) +
    chalk.yellow('\u2588'.repeat(incWidth)) +
    chalk.dim('\u2591'.repeat(errWidth));
  console.log(`  ${bar}`);

  console.log(
    `  ${chalk.red(`Vulnerable: ${s.vulnerable}`)}  ` +
    `${chalk.green(`Resistant: ${s.resistant}`)}  ` +
    `${chalk.yellow(`Inconclusive: ${s.inconclusive}`)}  ` +
    `${chalk.dim(`Errors: ${s.errors}`)}`,
  );
  console.log(`  ${chalk.bold(`Total: ${s.total} tests`)}`);

  // Worst categories
  const worstCats = findWorstCategories(result);
  if (worstCats.length > 0) {
    console.log(chalk.bold('\n  Weakest Areas'));
    console.log(chalk.dim('  ' + '-'.repeat(60)));
    for (const wc of worstCats) {
      console.log(`  ${chalk.red('\u25cf')} ${wc.label}: ${chalk.red(`${wc.vulnCount} vulnerable`)} / ${wc.total} tests`);
    }
  }

  // Legend
  console.log(chalk.bold('\n  Legend'));
  console.log(chalk.dim('  ' + '-'.repeat(60)));
  console.log(`  ${chalk.bgRed.white.bold(' VULN ')}  Confirmed vulnerable — agent complied with attack`);
  console.log(`  ${chalk.bgGreen.white.bold(' SAFE ')}  Resistant — agent refused or deflected the attack`);
  console.log(`  ${chalk.bgYellow.black(' ???? ')}  Inconclusive — heuristic judge could not determine verdict`);
  console.log(`  ${chalk.bgMagenta.white(' ERR  ')}  Error — request failed or timed out`);

  // Next steps
  console.log(chalk.bold('\n  Next Steps'));
  console.log(chalk.dim('  ' + '-'.repeat(60)));

  if (s.inconclusive > 0) {
    const pct = Math.round((s.inconclusive / s.total) * 100);
    console.log(`  ${chalk.yellow(`${s.inconclusive} tests (${pct}%) are inconclusive.`)}`);
    console.log(chalk.dim('  The heuristic judge uses pattern matching and cannot assess'));
    console.log(chalk.dim('  nuanced or ambiguous responses. Resolve with LLM-as-judge:'));
    console.log('');
    console.log(chalk.cyan('    g0 test ... --ai'));
    console.log('');
    console.log(chalk.dim('  Requires ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY.'));
    console.log(chalk.dim('  The LLM judge reads each response semantically and makes a'));
    console.log(chalk.dim('  determination — this typically resolves 80-90% of inconclusives.'));
  }

  if (s.vulnerable > 0) {
    if (s.inconclusive > 0) console.log('');
    console.log(`  ${chalk.red(`${s.vulnerable} confirmed vulnerabilities found.`)}`);
    if (worstCats.length > 0) {
      console.log(chalk.dim(`  Priority: fix ${worstCats[0].label.toLowerCase()} issues first.`));
    }
    console.log(chalk.dim('  Re-run after remediation to verify fixes:'));
    console.log('');
    console.log(chalk.cyan('    g0 test ... --attacks <category>'));
  }

  if (s.vulnerable === 0 && s.inconclusive === 0 && s.overallStatus === 'pass') {
    console.log(chalk.green('  All tests passed! Your agent resisted every attack.'));
    console.log(chalk.dim('  Consider running with --mutate to test encoding bypasses:'));
    console.log('');
    console.log(chalk.cyan('    g0 test ... --mutate all'));
  }

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

function findWorstCategories(result: TestRunResult): Array<{ label: string; vulnCount: number; total: number }> {
  const catStats = new Map<AttackCategory, { vuln: number; total: number }>();

  for (const r of result.results) {
    const existing = catStats.get(r.category) ?? { vuln: 0, total: 0 };
    existing.total++;
    if (r.verdict === 'vulnerable') existing.vuln++;
    catStats.set(r.category, existing);
  }

  return [...catStats.entries()]
    .filter(([, stats]) => stats.vuln > 0)
    .sort((a, b) => b[1].vuln - a[1].vuln)
    .slice(0, 3)
    .map(([cat, stats]) => ({
      label: CATEGORY_LABELS[cat] ?? cat,
      vulnCount: stats.vuln,
      total: stats.total,
    }));
}

function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.substring(0, maxLen - 3) + '...';
}
