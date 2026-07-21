import chalk from 'chalk';
import type { MCPScanResult, MCPFindingSeverity } from '../types/mcp-scan.js';

export function reportMCPTerminal(result: MCPScanResult): void {
  console.log(chalk.bold('\n  MCP Security Scanner'));
  console.log(chalk.dim('  ' + '═'.repeat(60)));

  // Sources
  if (result.clients.length > 0) {
    console.log(chalk.bold.cyan('\n  Detected MCP Sources'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const client of result.clients) {
      console.log(`  ${chalk.bold(client.name)} ${chalk.dim(client.configPath)}`);
    }
  }

  // Servers
  if (result.servers.length > 0) {
    console.log(chalk.bold.cyan('\n  MCP Servers'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const server of result.servers) {
      const statusBadge = server.status === 'critical'
        ? chalk.bgRed.black.bold(' CRIT ')
        : server.status === 'warn'
          ? chalk.bgYellow.black(' WARN ')
          : chalk.bgGreen.white(' OK   ');
      const cmd = [server.command, ...server.args].join(' ');
      console.log(`  ${statusBadge} ${chalk.bold(server.name)} ${chalk.dim(cmd)}`);
      console.log(`    ${chalk.dim(`Client: ${server.client} | Config: ${server.configFile}`)}`);
    }
  }

  // Tools
  if (result.tools.length > 0) {
    console.log(chalk.bold.cyan('\n  Tools'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const tool of result.tools) {
      const caps = tool.capabilities.join(', ');
      const sideEffect = tool.hasSideEffects ? chalk.red(' [side-effects]') : '';
      console.log(`  ${chalk.bold(tool.name)} ${chalk.dim(`(${caps})`)}${sideEffect}`);
      if (tool.description) {
        const desc = tool.description.substring(0, 80);
        console.log(`    ${chalk.dim(desc)}${tool.description.length > 80 ? '...' : ''}`);
      }
    }
  }

  // Findings
  if (result.findings.length > 0) {
    console.log(chalk.bold.red('\n  Findings'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const finding of result.findings) {
      const badge = findingBadge(finding.severity);
      const server = finding.server ? chalk.dim(` [${finding.server}]`) : '';
      const client = finding.client ? chalk.dim(` via ${finding.client}`) : '';
      console.log(`\n  ${badge} ${chalk.bold(finding.title)}${server}${client}`);
      console.log(`    ${finding.description}`);
      if (finding.file) {
        console.log(`    ${chalk.dim(finding.file)}${finding.line ? chalk.dim(`:${finding.line}`) : ''}`);
      }
    }
  } else {
    console.log(chalk.green.bold('\n  No MCP security findings detected.'));
  }

  // Summary
  console.log(chalk.bold('\n  Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  const s = result.summary;
  const statusBadge = s.overallStatus === 'critical'
    ? chalk.bgRed.black.bold(' CRITICAL ')
    : s.overallStatus === 'warn'
      ? chalk.bgYellow.black.bold(' WARNING ')
      : chalk.bgGreen.white.bold(' OK ');
  console.log(`  Status: ${statusBadge}  Clients: ${s.totalClients}  Servers: ${s.totalServers}  Tools: ${s.totalTools}  Findings: ${s.totalFindings}`);
  console.log('');
}

function findingBadge(severity: MCPFindingSeverity): string {
  switch (severity) {
    case 'critical': return chalk.bgRed.black.bold(' CRIT ');
    case 'high': return chalk.red.bold(' HIGH ');
    case 'medium': return chalk.yellow(' MED  ');
    case 'low': return chalk.blue(' LOW  ');
  }
}
