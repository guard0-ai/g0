import chalk from 'chalk';
import type { CheckResult } from '../check/runner.js';
import type { EndpointGrade } from '../types/endpoint.js';

function gradeColor(grade: EndpointGrade): (s: string) => string {
  if (grade === 'A') return chalk.green.bold;
  if (grade === 'B') return chalk.green;
  if (grade === 'C') return chalk.yellow.bold;
  if (grade === 'D') return chalk.red;
  return chalk.bgRed.black.bold;
}

function scoreBar(score: number, width = 36): string {
  const filled = Math.round((Math.max(0, Math.min(100, score)) / 100) * width);
  return '█'.repeat(filled) + '░'.repeat(width - filled);
}

const MAX_DEDUCTIONS_SHOWN = 3;
const MAX_TOOL_NAMES_SHOWN = 8;

function shortenPath(p: string): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  if (home && p.startsWith(home)) return '~' + p.slice(home.length);
  return p;
}

export function reportCheckTerminal(result: CheckResult): void {
  const { skills, infostealerIOCs, maliciousServers, verdict, endpoint } = result;

  console.log('');
  console.log(chalk.bold('  Background Check'));
  console.log(chalk.dim('  ' + '─'.repeat(55)));

  // Malicious and untrusted components first — the reason this command exists.
  const flaggedSkills = skills.skills.filter(s => s.trustLevel === 'malicious' || s.trustLevel === 'untrusted');
  for (const skill of flaggedSkills) {
    const badge = skill.trustLevel === 'malicious'
      ? chalk.bgRed.black.bold('MALICIOUS')
      : chalk.red.bold('UNTRUSTED');
    console.log('');
    console.log(`  ${badge}  ${chalk.bold(skill.skillName)}`);
    if (skill.filePath) {
      console.log(`             ${chalk.dim(shortenPath(skill.filePath))}`);
    }
    for (const f of skill.staticFindings) {
      console.log(`             ${chalk.red(`[${f.severity.toUpperCase()}]`)} ${f.title}`);
    }
  }

  for (const server of maliciousServers) {
    console.log('');
    console.log(`  ${chalk.bgRed.black.bold('MALICIOUS')}  ${chalk.bold(server.serverName)}  ${chalk.dim(`(${server.client} MCP server)`)}`);
    console.log(`             ${chalk.dim(shortenPath(server.configPath))}`);
    for (const m of server.matches) {
      console.log(`             ${chalk.red(`[${m.severity.toUpperCase()}]`)} ${m.description}`);
    }
  }

  for (const ioc of infostealerIOCs) {
    console.log('');
    console.log(`  ${chalk.bgRed.black.bold('INFOSTEALER')}  ${ioc.description}`);
    console.log(`             ${chalk.dim(ioc.matched)}`);
  }

  // Claude-native supply chain (skills/plugins/agents/hooks/extensions).
  // Defensive `?? []`: older serialized results may predate this field.
  for (const component of result.claudeEstate?.components ?? []) {
    if (component.findings.length === 0) continue;
    const critical = component.findings.some((f) => f.severity === 'critical');
    const badge = critical ? chalk.bgRed.black.bold(' FLAGGED ') : chalk.bgYellow.black.bold(' REVIEW ');
    console.log('');
    console.log(`  ${badge}  ${chalk.bold(component.name)}  ${chalk.dim(`(Claude ${component.kind})`)}`);
    console.log(`             ${chalk.dim(shortenPath(component.path))}`);
    for (const f of component.findings.slice(0, 3)) {
      console.log(`             ${chalk.red(`[${f.severity.toUpperCase()}]`)} ${f.rule}: ${f.detail}`);
    }
  }

  console.log('');
  const s = skills.summary;
  const skillParts = [`${s.total} audited`];
  if (s.malicious > 0) skillParts.push(chalk.red.bold(`${s.malicious} malicious`));
  if (s.untrusted > 0) skillParts.push(chalk.red(`${s.untrusted} untrusted`));
  if (s.caution > 0) skillParts.push(chalk.yellow(`${s.caution} caution`));
  console.log(`  Skills:    ${skillParts.join(' · ')}`);

  if (endpoint) {
    console.log(`  Endpoint:  ${endpoint.tools.length} AI tools · ${endpoint.mcp.servers.length} MCP servers   ${chalk.dim('(details: g0 endpoint)')}`);
    if (endpoint.tools.length > 0) {
      const names = endpoint.tools.map(t => t.name);
      const shown = names.slice(0, MAX_TOOL_NAMES_SHOWN).join(', ');
      const more = names.length > MAX_TOOL_NAMES_SHOWN ? ` +${names.length - MAX_TOOL_NAMES_SHOWN} more` : '';
      console.log(`             ${chalk.dim(shown + more)}`);
    }

    // A grade below A must justify itself on screen — top deductions, worst
    // first. When the grade is capped, the malicious blocks above already ARE
    // the explanation, so the breakdown would be noise.
    if (endpoint.score.grade !== 'A' && !verdict.capped) {
      const deductions = Object.entries(endpoint.score.categories)
        .flatMap(([category, cat]) => cat.deductions.map(d => ({ ...d, category })))
        .sort((a, b) => b.points - a.points)
        .slice(0, MAX_DEDUCTIONS_SHOWN);
      if (deductions.length > 0) {
        console.log('');
        console.log(chalk.bold('  Why not an A?'));
        for (const d of deductions) {
          console.log(`    ${chalk.red(`-${d.points}`.padStart(3))}  ${d.finding}  ${chalk.dim(`(${d.category})`)}`);
        }
      }
    }
  }

  console.log('');
  console.log(chalk.dim('  ' + '─'.repeat(55)));
  const color = gradeColor(verdict.grade);
  console.log(`  ${color(` ${verdict.grade} `)}  ${scoreBar(verdict.score)}  ${verdict.score}`);
  console.log(`  ${verdict.capped ? chalk.red(verdict.headline) : chalk.green(verdict.headline)}`);
  if (verdict.capped) {
    console.log(`  ${chalk.yellow('⚠')}  ${chalk.yellow('Grade capped: known-malicious components present')}`);
    if (skills.summary.malicious > 0) {
      console.log(`  ${chalk.dim('Fix:')} Remove the skill directory above, then re-run g0 check`);
    }
    if (maliciousServers.length > 0) {
      console.log(`  ${chalk.dim('Fix:')} g0 endpoint quarantine --apply`);
    }
  }
  console.log('');
}
