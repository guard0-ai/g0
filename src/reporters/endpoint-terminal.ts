import chalk from 'chalk';
import type { EndpointScanResult, EndpointGrade } from '../types/endpoint.js';
import type { MCPFindingSeverity } from '../types/mcp-scan.js';

export function reportEndpointTerminal(result: EndpointScanResult): void {
  // ── Score Header ──
  reportScore(result);

  // ── AI Developer Tools ──
  reportTools(result);

  // ── MCP Security ──
  reportMCPFindings(result);

  // ── Network Discovery ──
  if (result.layersRun.includes('network')) {
    reportNetwork(result);
  }

  // ── Credentials ──
  if (result.layersRun.includes('artifacts')) {
    reportCredentials(result);
    reportDataStores(result);
  }

  // ── Forensics ──
  if (result.forensics) {
    reportForensics(result);
  }

  // ── Browser History ──
  if (result.browser) {
    reportBrowser(result);
  }

  // ── Remediation ──
  if (result.remediation) {
    reportRemediation(result);
  }

  // ── Duration ──
  console.log(chalk.dim(`\n  Scanned in ${(result.duration / 1000).toFixed(1)}s\n`));
}

// ─── Score Display ───────────────────────────────────────────────────────────

function reportScore(result: EndpointScanResult): void {
  const { score } = result;
  const gradeColor = gradeToColor(score.grade);
  const barWidth = 30;
  const filled = Math.round((score.total / 100) * barWidth);
  const bar = gradeColor('━'.repeat(filled)) + chalk.dim('━'.repeat(barWidth - filled));

  console.log(chalk.bold('\n  Endpoint Security Score'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`\n  ${gradeColor(chalk.bold(String(score.total)))} / 100  ${bar}  ${gradeColor(chalk.bold(score.grade))}`);

  const cats = score.categories;
  console.log(
    `  ${catLabel('Config', cats.configuration)} ${chalk.dim('│')} ` +
    `${catLabel('Creds', cats.credentials)} ${chalk.dim('│')} ` +
    `${catLabel('Network', cats.network)} ${chalk.dim('│')} ` +
    `${catLabel('Discovery', cats.discovery)}`,
  );
}

function catLabel(name: string, cat: { score: number; max: number }): string {
  const color = cat.score >= cat.max * 0.8 ? chalk.green :
    cat.score >= cat.max * 0.5 ? chalk.yellow : chalk.red;
  return `${name} ${color(`${cat.score}`)}${chalk.dim(`/${cat.max}`)}`;
}

function gradeToColor(grade: EndpointGrade): (text: string) => string {
  switch (grade) {
    case 'A': return chalk.green;
    case 'B': return chalk.green;
    case 'C': return chalk.yellow;
    case 'D': return chalk.red;
    case 'F': return chalk.red;
  }
}

// ─── AI Developer Tools ──────────────────────────────────────────────────────

function reportTools(result: EndpointScanResult): void {
  const visibleTools = result.tools.filter(t => t.installed || t.running);

  const countText = `${visibleTools.length} detected, ${result.summary.runningTools} running`;
  console.log(chalk.bold(`\n  AI Developer Tools`) + chalk.dim(`  ${' '.repeat(Math.max(0, 38 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  if (visibleTools.length === 0) {
    console.log(chalk.dim('  No AI developer tools detected on this machine.'));
    return;
  }

  for (const tool of visibleTools) {
    const icon = tool.running ? chalk.green('●') : chalk.dim('○');
    const status = tool.running
      ? chalk.green('running  ')
      : chalk.dim('installed');
    const serverCount = tool.mcpServerCount === 1
      ? '1 server '
      : `${tool.mcpServerCount} servers`;
    const configShort = shortenPath(tool.configPath);
    console.log(`  ${icon} ${chalk.bold(tool.name.padEnd(20))} ${status} ${chalk.cyan(serverCount.padEnd(10))} ${chalk.dim(configShort)}`);
  }
}

// ─── MCP Security ────────────────────────────────────────────────────────────

function reportMCPFindings(result: EndpointScanResult): void {
  const { mcp } = result;
  const findingCount = mcp.findings.length;

  const countText = `${mcp.summary.totalServers} servers, ${findingCount} findings`;
  console.log(chalk.bold(`\n  MCP Security`) + chalk.dim(`  ${' '.repeat(Math.max(0, 44 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  if (findingCount === 0) {
    console.log(chalk.green('  All MCP servers passed security checks.'));
    return;
  }

  for (const finding of mcp.findings) {
    const badge = severityBadge(finding.severity);
    const server = finding.server ? chalk.dim(` (${finding.server})`) : '';
    console.log(`  ${badge}  ${finding.title}${server}`);
  }
}

// ─── Network Discovery ──────────────────────────────────────────────────────

function reportNetwork(result: EndpointScanResult): void {
  const { network } = result;
  const aiCount = network.summary.aiServices;

  const countText = `${aiCount} AI services on ${network.summary.totalListening} ports`;
  console.log(chalk.bold(`\n  Network`) + chalk.dim(`  ${' '.repeat(Math.max(0, 49 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  if (aiCount === 0) {
    console.log(chalk.green('  No AI services detected on network ports.'));
    return;
  }

  // Show discovered services, sorted by severity
  const sorted = [...network.services]
    .filter(s => s.type !== 'non-http' && s.type !== 'unknown-http')
    .sort((a, b) => {
      // Shadow + unauth first, then shadow, then exposed, then rest
      const scoreA = (!a.declaredInConfig ? 100 : 0) + (a.authenticated === false ? 50 : 0) + (a.bindAddress === '0.0.0.0' ? 25 : 0);
      const scoreB = (!b.declaredInConfig ? 100 : 0) + (b.authenticated === false ? 50 : 0) + (b.bindAddress === '0.0.0.0' ? 25 : 0);
      return scoreB - scoreA;
    });

  for (const svc of sorted) {
    const severity = !svc.declaredInConfig || svc.authenticated === false
      ? (svc.bindAddress === '0.0.0.0' ? 'critical' : 'high')
      : svc.bindAddress === '0.0.0.0' ? 'medium' : 'low';
    const badge = severityBadge(severity as MCPFindingSeverity);

    const typeLabel = serviceTypeLabel(svc.type);
    const bind = svc.bindAddress === '0.0.0.0' ? chalk.red('0.0.0.0  ') : chalk.dim('127.0.0.1');
    const auth = svc.authenticated === true
      ? chalk.green('auth')
      : svc.authenticated === false
        ? chalk.red('no auth')
        : chalk.dim('unknown');

    const shadow = !svc.declaredInConfig ? chalk.red(' ← shadow') : '';
    const proc = svc.process ? chalk.dim(` ${svc.process}`) : '';

    console.log(`  ${badge}  :${String(svc.port).padEnd(5)} ${typeLabel.padEnd(24)} ${bind}  ${auth}${shadow}${proc}`);
  }
}

function serviceTypeLabel(type: string): string {
  switch (type) {
    case 'mcp-sse': return 'MCP SSE server';
    case 'mcp-streamable': return 'MCP Streamable HTTP';
    case 'openai-compatible': return 'OpenAI-compatible';
    case 'a2a': return 'A2A agent';
    case 'ollama': return 'Ollama';
    case 'lm-studio': return 'LM Studio';
    case 'vllm': return 'vLLM';
    case 'llama-cpp': return 'llama.cpp';
    case 'jan': return 'Jan';
    default: return type;
  }
}

// ─── Credentials ─────────────────────────────────────────────────────────────

function reportCredentials(result: EndpointScanResult): void {
  const { artifacts } = result;
  const credCount = artifacts.credentials.length;

  const countText = `${credCount} exposure${credCount !== 1 ? 's' : ''}`;
  console.log(chalk.bold(`\n  Credentials`) + chalk.dim(`  ${' '.repeat(Math.max(0, 45 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  if (credCount === 0) {
    console.log(chalk.green('  No exposed credentials detected.'));
    return;
  }

  for (const cred of artifacts.credentials) {
    const badge = severityBadge(cred.severity);
    const typeLabel = cred.keyType === 'other' ? 'Auth file' : `${cred.keyType.toUpperCase()} key`;
    const loc = shortenPath(cred.location);

    if (cred.issue === 'bad-permissions') {
      console.log(`  ${badge}  ${loc} permissions ${chalk.red(cred.filePermissions || '?')} (should be 600)`);
    } else {
      console.log(`  ${badge}  ${typeLabel} in ${loc} ${chalk.dim(`(${cred.redactedValue})`)}`);
    }
  }
}

// ─── Data Stores ─────────────────────────────────────────────────────────────

function reportDataStores(result: EndpointScanResult): void {
  const { artifacts } = result;
  const stores = artifacts.dataStores;

  if (stores.length === 0) return;

  const totalSize = formatBytes(artifacts.summary.totalDataSizeBytes);
  const countText = `${stores.length} stores, ${totalSize} total`;
  console.log(chalk.bold(`\n  Data Stores`) + chalk.dim(`  ${' '.repeat(Math.max(0, 45 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  for (const store of stores) {
    const sizeMB = store.sizeBytes / (1024 * 1024);
    const isModelCache = store.storeType === 'model-cache';

    const severity: MCPFindingSeverity = isModelCache ? 'low' :
      parseInt(store.permissions, 8) & 0o004 ? 'high' :
      sizeMB > 50 ? 'medium' : 'low';

    const badge = severity === 'low' ? chalk.dim('  OK  ') : severityBadge(severity);
    const size = formatBytes(store.sizeBytes).padEnd(7);
    const enc = !isModelCache && !store.encrypted
      ? chalk.dim('unencrypted')
      : '';

    console.log(`  ${badge}  ${chalk.bold(store.tool.padEnd(18))} ${chalk.dim(store.storeType.padEnd(12))} ${chalk.cyan(size)} ${enc}`);
  }
}

// ─── Forensics ──────────────────────────────────────────────────────────────

function reportForensics(result: EndpointScanResult): void {
  const { forensics } = result;
  if (!forensics || forensics.stores.length === 0) return;

  const { summary } = forensics;
  const countText = `${summary.totalStores} stores, ${summary.totalConversations} conversations`;
  console.log(chalk.bold(`\n  Conversation Stores`) + chalk.dim(`  ${' '.repeat(Math.max(0, 38 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  for (const store of forensics.stores) {
    const size = formatBytes(store.sizeBytes).padEnd(7);
    const convCount = store.conversationCount > 0 ? `${store.conversationCount} convs` : 'unknown';
    const msgCount = store.messageCount > 0 ? `, ${store.messageCount} msgs` : '';
    const enc = store.encrypted ? chalk.green('encrypted') : chalk.dim('unencrypted');
    const dateRange = store.newestDate
      ? chalk.dim(` (last: ${store.newestDate.split('T')[0]})`)
      : '';

    console.log(`  ${chalk.dim('  ●   ')} ${chalk.bold(store.tool.padEnd(18))} ${chalk.cyan(size)} ${convCount}${msgCount}  ${enc}${dateRange}`);
  }

  if (summary.oldestActivity && summary.newestActivity) {
    console.log(chalk.dim(`\n  Activity range: ${summary.oldestActivity.split('T')[0]} → ${summary.newestActivity.split('T')[0]}`));
  }
}

// ─── Browser History ────────────────────────────────────────────────────────

function reportBrowser(result: EndpointScanResult): void {
  const { browser } = result;
  if (!browser || browser.entries.length === 0) return;

  const { summary } = browser;
  const serviceList = Object.entries(summary.services)
    .sort(([, a], [, b]) => b - a)
    .map(([svc, count]) => `${svc}: ${count}`)
    .join(', ');

  const countText = `${summary.totalEntries} AI URLs across ${summary.browsers.length} browsers`;
  console.log(chalk.bold(`\n  AI Browser Activity`) + chalk.dim(`  ${' '.repeat(Math.max(0, 38 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  // Show by service
  const byService = new Map<string, typeof browser.entries>();
  for (const entry of browser.entries) {
    const arr = byService.get(entry.service) || [];
    arr.push(entry);
    byService.set(entry.service, arr);
  }

  for (const [service, entries] of byService) {
    const totalVisits = entries.reduce((s, e) => s + e.visitCount, 0);
    const browsers = [...new Set(entries.map(e => e.browser))].join(', ');
    const latest = entries.reduce((a, b) => a.lastVisit > b.lastVisit ? a : b);

    console.log(
      `  ${chalk.dim('  ●   ')} ${chalk.bold(service.padEnd(14))} ` +
      `${chalk.cyan(String(totalVisits).padStart(4))} visits  ` +
      `${chalk.dim(browsers.padEnd(16))} ` +
      `${chalk.dim(`last: ${latest.lastVisit.split('T')[0]}`)}`,
    );
  }

  if (summary.dateRange.oldest && summary.dateRange.newest) {
    console.log(chalk.dim(`\n  Date range: ${summary.dateRange.oldest.split('T')[0]} → ${summary.dateRange.newest.split('T')[0]}`));
  }
}

// ─── Remediation ────────────────────────────────────────────────────────────

function reportRemediation(result: EndpointScanResult): void {
  const { remediation } = result;
  if (!remediation || remediation.steps.length === 0) return;

  const { summary } = remediation;
  const countText = `${summary.applied} applied, ${summary.skipped + summary.failed} manual`;
  console.log(chalk.bold(`\n  Remediation`) + chalk.dim(`  ${' '.repeat(Math.max(0, 45 - countText.length))}${countText}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  for (const step of remediation.steps) {
    const icon = step.applied
      ? chalk.green('✓')
      : step.error?.startsWith('Manual')
        ? chalk.yellow('→')
        : chalk.red('✗');

    const actionLabel = step.action.replace(/-/g, ' ');
    console.log(`  ${icon}  ${chalk.bold(actionLabel.padEnd(18))} ${step.description}`);

    if (step.command && !step.applied) {
      console.log(chalk.dim(`     Run: ${step.command}`));
    }
    if (step.error && !step.error.startsWith('Manual')) {
      console.log(chalk.red(`     Error: ${step.error}`));
    }
  }
}

// ─── Shared Helpers ──────────────────────────────────────────────────────────

function severityBadge(severity: MCPFindingSeverity): string {
  switch (severity) {
    case 'critical': return chalk.bgRed.white.bold(' CRIT ');
    case 'high': return chalk.red.bold(' HIGH ');
    case 'medium': return chalk.yellow(' MED  ');
    case 'low': return chalk.blue(' LOW  ');
  }
}

function shortenPath(p: string): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  if (home && p.startsWith(home)) {
    return '~' + p.slice(home.length);
  }
  return p;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)}MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`;
}
