import chalk from 'chalk';
import type { EndpointScanResult } from '../types/endpoint.js';
import type { MCPFindingSeverity } from '../types/mcp-scan.js';

export function reportEndpointTerminal(result: EndpointScanResult): void {
  // AI Developer Tools
  const visibleTools = result.tools.filter(t => t.installed || t.running);

  if (visibleTools.length > 0) {
    console.log(chalk.bold('\n  AI Developer Tools'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const tool of visibleTools) {
      const icon = tool.running ? chalk.green('●') : chalk.dim('○');
      const status = tool.running
        ? chalk.green('running  ')
        : chalk.dim('installed');
      const serverCount = tool.mcpServerCount === 1
        ? '1 MCP server '
        : `${tool.mcpServerCount} MCP servers`;
      const configShort = shortenPath(tool.configPath);
      console.log(`  ${icon} ${chalk.bold(tool.name.padEnd(18))} ${status} ${chalk.cyan(serverCount.padEnd(14))} ${chalk.dim(configShort)}`);
    }
  } else {
    console.log(chalk.bold('\n  AI Developer Tools'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    console.log(chalk.dim('  No AI developer tools detected on this machine.'));
  }

  // MCP Servers
  if (result.mcp.servers.length > 0) {
    console.log(chalk.bold('\n  MCP Servers'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const server of result.mcp.servers) {
      const statusBadge = server.status === 'critical'
        ? chalk.bgRed.white.bold(' CRIT ')
        : server.status === 'warn'
          ? chalk.bgYellow.black(' WARN ')
          : chalk.bgGreen.white(' OK   ');
      const cmd = [server.command, ...server.args].join(' ');
      console.log(`  ${statusBadge} ${chalk.bold(server.name)}  ${chalk.dim(cmd)}`);
      console.log(`    ${chalk.dim(`Client: ${server.client} | Config: ${shortenPath(server.configFile)}`)}`);
    }
  }

  // Findings
  if (result.mcp.findings.length > 0) {
    console.log(chalk.bold('\n  Findings'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const finding of result.mcp.findings) {
      const badge = findingBadge(finding.severity);
      const server = finding.server ? chalk.dim(` [${finding.server}]`) : '';
      const client = finding.client ? chalk.dim(` via ${finding.client}`) : '';
      console.log(`  ${badge} ${chalk.bold(finding.title)}${server}${client}`);
      console.log(`    ${finding.description}`);
      if (finding.file) {
        console.log(`    ${chalk.dim(shortenPath(finding.file))}${finding.line ? chalk.dim(`:${finding.line}`) : ''}`);
      }
    }
  }

  // Summary
  console.log(chalk.bold('\n  Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  const s = result.summary;
  const statusBadge = s.overallStatus === 'critical'
    ? chalk.bgRed.white.bold(' CRITICAL ')
    : s.overallStatus === 'warn'
      ? chalk.bgYellow.black.bold(' WARNING ')
      : chalk.bgGreen.white.bold(' OK ');

  console.log(`  ${statusBadge}  AI Tools: ${s.totalTools} detected, ${s.runningTools} running   MCP Servers: ${s.totalServers}   Findings: ${s.totalFindings}`);
  if (s.totalFindings > 0) {
    const sev = s.findingsBySeverity;
    console.log(`  ${chalk.bgRed.white.bold(' CRIT ')} ${sev.critical ?? 0}  ${chalk.red.bold(' HIGH ')} ${sev.high ?? 0}  ${chalk.yellow(' MED  ')} ${sev.medium ?? 0}  ${chalk.blue(' LOW  ')} ${sev.low ?? 0}`);
  }
  console.log(chalk.dim(`\n  Scanned in ${(result.duration / 1000).toFixed(1)}s\n`));
}

function findingBadge(severity: MCPFindingSeverity): string {
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
