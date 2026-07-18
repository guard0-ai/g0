import { Command } from 'commander';
import chalk from 'chalk';
import { getAllRules } from '../../analyzers/rules/index.js';
import { severityColor } from '../ui.js';
import type { Rule } from '../../types/control.js';

function formatStandards(standards: Rule['standards']): string[] {
  const refs: string[] = [];
  if (standards.owaspAgentic?.length) refs.push(`OWASP Agentic: ${standards.owaspAgentic.join(', ')}`);
  if (standards.nistAiRmf?.length) refs.push(`NIST AI RMF: ${standards.nistAiRmf.join(', ')}`);
  if (standards.iso42001?.length) refs.push(`ISO 42001: ${standards.iso42001.join(', ')}`);
  if (standards.iso23894?.length) refs.push(`ISO 23894: ${standards.iso23894.join(', ')}`);
  if (standards.aiuc1?.length) refs.push(`AIUC-1: ${standards.aiuc1.join(', ')}`);
  if (standards.euAiAct?.length) refs.push(`EU AI Act: ${standards.euAiAct.join(', ')}`);
  if (standards.mitreAtlas?.length) refs.push(`MITRE ATLAS: ${standards.mitreAtlas.join(', ')}`);
  if (standards.owaspLlmTop10?.length) refs.push(`OWASP LLM Top 10: ${standards.owaspLlmTop10.join(', ')}`);
  if (standards.owaspAgenticTop10?.length) refs.push(`OWASP Agentic Top 10: ${standards.owaspAgenticTop10.join(', ')}`);
  return refs;
}

function listRules(options: { domain?: string; severity?: string; search?: string; json?: boolean; rulesDir?: string }): void {
  let rules = getAllRules(options.rulesDir);
  if (options.domain) rules = rules.filter(r => r.domain === options.domain);
  if (options.severity) rules = rules.filter(r => r.severity === options.severity);
  if (options.search) {
    const term = options.search.toLowerCase();
    rules = rules.filter(r =>
      r.id.toLowerCase().includes(term) ||
      r.name.toLowerCase().includes(term) ||
      r.description.toLowerCase().includes(term)
    );
  }

  if (options.json) {
    const output = rules.map(r => ({
      id: r.id, name: r.name, domain: r.domain, severity: r.severity,
      confidence: r.confidence, description: r.description, frameworks: r.frameworks, standards: r.standards,
    }));
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  if (rules.length === 0) {
    console.log(chalk.yellow('No rules found matching the given filters.'));
    return;
  }

  const idW = 12; const domW = 20; const sevW = 10; const nameW = 50;
  console.log(chalk.bold(`\n  ${'ID'.padEnd(idW)} ${'Domain'.padEnd(domW)} ${'Severity'.padEnd(sevW)} Title`));
  console.log(chalk.dim(`  ${'─'.repeat(idW)} ${'─'.repeat(domW)} ${'─'.repeat(sevW)} ${'─'.repeat(nameW)}`));

  for (const r of rules) {
    const sev = severityColor(r.severity)(r.severity.padEnd(sevW));
    const name = r.name.length > nameW ? r.name.slice(0, nameW - 1) + '…' : r.name;
    console.log(`  ${chalk.cyan(r.id.padEnd(idW))} ${r.domain.padEnd(domW)} ${sev} ${name}`);
  }
  console.log(chalk.dim(`\n  Total: ${rules.length} rules\n`));
}

function describeRule(ruleId: string, options: { json?: boolean; rulesDir?: string }): void {
  const rules = getAllRules(options.rulesDir);
  const rule = rules.find(r => r.id === ruleId);
  if (!rule) { console.error(chalk.red(`Rule not found: ${ruleId}`)); process.exit(1); }

  if (options.json) {
    console.log(JSON.stringify({
      id: rule.id, name: rule.name, domain: rule.domain, severity: rule.severity,
      confidence: rule.confidence, description: rule.description, frameworks: rule.frameworks, standards: rule.standards,
    }, null, 2));
    return;
  }

  const sev = severityColor(rule.severity)(rule.severity.toUpperCase());
  console.log(chalk.bold(`\n  ${rule.name}`));
  console.log(chalk.dim(`  ${'─'.repeat(60)}`));
  console.log(`  ${chalk.dim('ID:')}          ${chalk.cyan(rule.id)}`);
  console.log(`  ${chalk.dim('Domain:')}      ${rule.domain}`);
  console.log(`  ${chalk.dim('Severity:')}    ${sev}`);
  console.log(`  ${chalk.dim('Confidence:')}  ${rule.confidence}`);
  console.log(`  ${chalk.dim('Frameworks:')}  ${rule.frameworks.join(', ')}`);
  console.log(`\n  ${chalk.dim('Description:')}`);
  console.log(`  ${rule.description}`);

  const stdRefs = formatStandards(rule.standards);
  if (stdRefs.length > 0) {
    console.log(`\n  ${chalk.dim('Standards:')}`);
    for (const ref of stdRefs) console.log(`    • ${ref}`);
  }
  console.log();
}

const listCommand = new Command('list')
  .description('List all security rules')
  .option('--domain <domain>', 'Filter by security domain')
  .option('--severity <level>', 'Filter by severity (critical|high|medium|low|info)')
  .option('--search <text>', 'Search rules by ID, name, or description')
  .option('--json', 'Output as JSON')
  .option('--rules-dir <path>', 'Directory of custom YAML rules')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options) => { listRules(options); });

const describeCommand = new Command('describe')
  .description('Show detailed information about a specific rule')
  .argument('<id>', 'Rule ID (e.g., AA-GI-001)')
  .option('--json', 'Output as JSON')
  .option('--rules-dir <path>', 'Directory of custom YAML rules')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((id: string, options) => { describeRule(id, options); });

export const rulesCommand = new Command('rules')
  .description('Browse and inspect security rules')
  .addCommand(listCommand)
  .addCommand(describeCommand);
