import * as os from 'node:os';
import chalk from 'chalk';
import { Command } from 'commander';
import { loadDaemonConfig } from '../../daemon/config.js';
import { readPid } from '../../daemon/process.js';
import { getMachineId } from '../../platform/machine-id.js';
import { isAuthenticated } from '../../platform/auth.js';
import { collectMachineMeta, shouldUpload, uploadResults } from '../../platform/upload.js';
import { listMCPServers } from '../../mcp/analyzer.js';
import { scanEndpoint } from '../../endpoint/scanner.js';
import { reportEndpointTerminal } from '../../reporters/endpoint-terminal.js';
import { createSpinner } from '../ui.js';
import type { EndpointStatusResult } from '../../types/endpoint.js';

// ─── Shared scan action ────────────────────────────────────────────────────

async function runEndpointScan(options: {
  json?: boolean;
  upload?: boolean;
  banner?: boolean;
}) {
  const spinner = !options.json ? createSpinner('Scanning AI developer tools...').start() : null;

  const result = scanEndpoint();

  spinner?.stop();

  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    reportEndpointTerminal(result);
  }

  // Upload
  const { upload } = await shouldUpload(options.upload);
  if (upload) {
    const machine = collectMachineMeta();
    await uploadResults({ type: 'mcp', machine, result: result.mcp });
    if (!options.json) {
      console.log(chalk.dim('  Results uploaded to Guard0 platform.\n'));
    }
  }
}

// ─── g0 endpoint (default = scan) ──────────────────────────────────────────

export const endpointCommand = new Command('endpoint')
  .description('Discover AI developer tools and assess endpoint security')
  .option('--json', 'Output as JSON')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-upload', 'Disable upload')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: {
    json?: boolean;
    upload?: boolean;
    banner?: boolean;
  }) => {
    await runEndpointScan(options);
  });

// ─── g0 endpoint scan (alias) ──────────────────────────────────────────────

const scanSubcommand = new Command('scan')
  .description('Discover AI developer tools and assess endpoint security')
  .option('--json', 'Output as JSON')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-upload', 'Disable upload')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: {
    json?: boolean;
    upload?: boolean;
    banner?: boolean;
  }) => {
    await runEndpointScan(options);
  });

// ─── g0 endpoint status ─────────────────────────────────────────────────────

const statusSubcommand = new Command('status')
  .description('Show machine info, daemon health, and configuration')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: { json?: boolean; banner?: boolean }) => {
    const machineId = getMachineId();
    const config = loadDaemonConfig();
    const pid = readPid(config.pidFile);
    const authed = isAuthenticated();

    let mcpServerCount = 0;
    try {
      const mcp = listMCPServers();
      mcpServerCount = mcp.summary.totalServers;
    } catch { /* ignore */ }

    const result: EndpointStatusResult = {
      machineId,
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      nodeVersion: process.version,
      daemon: pid ? { running: true, pid } : { running: false },
      auth: { authenticated: authed },
      watchPaths: config.watchPaths,
      mcpServers: mcpServerCount,
      daemonConfig: {
        intervalMinutes: config.intervalMinutes,
        upload: config.upload,
        mcpScan: config.mcpScan,
      },
    };

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    console.log(chalk.bold('\n  Endpoint Status'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    console.log(`  Machine ID:   ${machineId}`);
    console.log(`  Hostname:     ${os.hostname()}`);
    console.log(`  Platform:     ${os.platform()} / ${os.arch()}`);
    console.log(`  Node:         ${process.version}`);

    console.log(chalk.bold('\n  Daemon'));
    if (pid) {
      console.log(chalk.green(`  Status:       running (PID ${pid})`));
    } else {
      console.log(chalk.yellow('  Status:       stopped'));
    }
    console.log(`  Interval:     ${config.intervalMinutes} min`);
    console.log(`  Upload:       ${config.upload ? 'enabled' : 'disabled'}`);
    console.log(`  MCP scan:     ${config.mcpScan ? 'enabled' : 'disabled'}`);

    console.log(chalk.bold('\n  Auth'));
    console.log(`  Authenticated: ${authed ? chalk.green('yes') : chalk.yellow('no')}`);

    console.log(chalk.bold('\n  Watch Paths'));
    if (config.watchPaths.length === 0) {
      console.log(chalk.dim('  (none configured)'));
    } else {
      for (const p of config.watchPaths) {
        console.log(`    ${chalk.cyan('●')} ${p}`);
      }
    }

    console.log(`\n  MCP servers:  ${mcpServerCount}\n`);
  });

endpointCommand.addCommand(scanSubcommand);
endpointCommand.addCommand(statusSubcommand);
