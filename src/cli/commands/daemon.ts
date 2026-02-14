import chalk from 'chalk';
import { Command } from 'commander';
import { loadDaemonConfig, saveDaemonConfig } from '../../daemon/config.js';
import { DaemonLogger } from '../../daemon/logger.js';
import { readPid, forkDaemon, stopDaemon } from '../../daemon/process.js';
import { getMachineId } from '../../platform/machine-id.js';

export const daemonCommand = new Command('daemon')
  .description('Manage the g0 background daemon for continuous monitoring');

// ─── g0 daemon start ─────────────────────────────────────────────────────────

const startCommand = new Command('start')
  .description('Start the background daemon')
  .option('--interval <minutes>', 'Scan interval in minutes (default: 30)')
  .option('--watch <paths>', 'Comma-separated paths to watch for inventory changes')
  .option('--no-upload', 'Disable uploading results to platform')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: {
    interval?: string;
    watch?: string;
    upload?: boolean;
    banner?: boolean;
  }) => {
    const config = loadDaemonConfig();

    // Apply overrides
    if (options.interval) {
      config.intervalMinutes = parseInt(options.interval, 10);
    }
    if (options.watch) {
      config.watchPaths = options.watch.split(',').map(p => p.trim());
    }
    if (options.upload === false) {
      config.upload = false;
    }

    // Save config so daemon process picks it up
    saveDaemonConfig(config);

    try {
      const pid = forkDaemon(config.pidFile);
      console.log(chalk.green(`\n  Daemon started (PID ${pid})`));
      console.log(chalk.dim(`  Machine ID: ${getMachineId()}`));
      console.log(chalk.dim(`  Interval: ${config.intervalMinutes} minutes`));
      console.log(chalk.dim(`  Log file: ${config.logFile}`));
      if (config.watchPaths.length > 0) {
        console.log(chalk.dim(`  Watch paths: ${config.watchPaths.join(', ')}`));
      }
      console.log(chalk.dim(`  Upload: ${config.upload ? 'enabled' : 'disabled'}`));
      console.log('');
    } catch (err) {
      console.error(chalk.red(`  ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
  });

// ─── g0 daemon stop ──────────────────────────────────────────────────────────

const stopCommand = new Command('stop')
  .description('Stop the background daemon')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(() => {
    const config = loadDaemonConfig();
    const stopped = stopDaemon(config.pidFile);

    if (stopped) {
      console.log(chalk.green('  Daemon stopped.'));
    } else {
      console.log(chalk.yellow('  Daemon is not running.'));
    }
  });

// ─── g0 daemon status ────────────────────────────────────────────────────────

const statusCommand = new Command('status')
  .description('Show daemon status')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(() => {
    const config = loadDaemonConfig();
    const pid = readPid(config.pidFile);

    console.log(chalk.bold('\n  Daemon Status\n'));

    if (pid) {
      console.log(chalk.green('  Status: running'));
      console.log(`  PID:    ${pid}`);
    } else {
      console.log(chalk.yellow('  Status: stopped'));
    }

    console.log(`  Interval:    ${config.intervalMinutes} minutes`);
    console.log(`  Upload:      ${config.upload ? 'enabled' : 'disabled'}`);
    console.log(`  MCP scan:    ${config.mcpScan ? 'enabled' : 'disabled'}`);
    console.log(`  Pin check:   ${config.mcpPinCheck ? 'enabled' : 'disabled'}`);
    console.log(`  Inv. diff:   ${config.inventoryDiff ? 'enabled' : 'disabled'}`);
    if (config.watchPaths.length > 0) {
      console.log(`  Watch paths: ${config.watchPaths.join(', ')}`);
    }
    console.log(`  Log file:    ${config.logFile}`);
    console.log('');
  });

// ─── g0 daemon logs ──────────────────────────────────────────────────────────

const logsCommand = new Command('logs')
  .description('Show recent daemon log entries')
  .option('-n, --lines <count>', 'Number of lines to show', '50')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: { lines?: string; banner?: boolean }) => {
    const config = loadDaemonConfig();
    const logger = new DaemonLogger(config.logFile);
    const lines = logger.tail(parseInt(options.lines ?? '50', 10));

    if (lines.length === 0) {
      console.log(chalk.dim('  No log entries found.'));
      return;
    }

    for (const line of lines) {
      // Colorize log levels
      if (line.includes('[ERROR]')) {
        console.log(chalk.red(line));
      } else if (line.includes('[WARN]')) {
        console.log(chalk.yellow(line));
      } else {
        console.log(chalk.dim(line));
      }
    }
  });

daemonCommand.addCommand(startCommand);
daemonCommand.addCommand(stopCommand);
daemonCommand.addCommand(statusCommand);
daemonCommand.addCommand(logsCommand);
