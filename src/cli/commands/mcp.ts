import * as path from 'node:path';
import * as fs from 'node:fs';
import chalk from 'chalk';
import { Command } from 'commander';
import {
  scanAllMCPConfigs,
  scanMCPConfigFile,
  scanMCPServer,
  listMCPServers,
} from '../../mcp/analyzer.js';
import { reportMCPTerminal } from '../../reporters/mcp-terminal.js';
import { reportMCPJson } from '../../reporters/mcp-json.js';
import { generatePins, savePinFile, loadPinFile, checkPins } from '../../mcp/hash-pinning.js';
import { verifyNpmPackage } from '../../mcp/npm-verify.js';
import { reportMCPVerifyTerminal } from '../../reporters/mcp-verify-terminal.js';
import { watchMCPConfigs } from '../../mcp/watcher.js';
import { isRemoteUrl, parseTarget, cloneRepo } from '../../remote/clone.js';
import { runDiscovery } from '../../pipeline.js';
import { scanMCPSourceDir } from '../../mcp/source-scanner.js';
import { createSpinner } from '../ui.js';
import type { MCPScanResult, MCPFindingSeverity } from '../../types/mcp-scan.js';

export const mcpCommand = new Command('mcp')
  .description('Assess MCP server configurations and source code for security issues')
  .argument('[path]', 'Path to project or remote URL (omit to scan local MCP configs)')
  .option('--json', 'Output as JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--pin [file]', 'Generate tool description pins (.g0-pins.json)')
  .option('--check [file]', 'Verify tools against pinned descriptions')
  .option('--watch', 'Watch MCP config files for changes and re-scan')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (targetPath: string | undefined, options: {
    json?: boolean;
    output?: string;
    pin?: string | boolean;
    check?: string | boolean;
    watch?: boolean;
    upload?: boolean;
    banner?: boolean;
  }) => {
    // Watch mode (local only)
    if (options.watch) {
      console.log(chalk.bold('\n  Watching MCP config files for changes...'));
      console.log(chalk.dim('  Press Ctrl+C to stop.\n'));

      const initial = scanAllMCPConfigs();
      if (options.json) {
        console.log(reportMCPJson(initial));
      } else {
        reportMCPTerminal(initial);
      }

      watchMCPConfigs({
        onUpdate: (result) => {
          console.log(chalk.yellow('\n  [change detected] Re-scanning...\n'));
          if (options.json) {
            console.log(reportMCPJson(result));
          } else {
            reportMCPTerminal(result);
          }
        },
        onError: (err) => {
          console.error(chalk.red(`  Watch error: ${err.message}`));
        },
      });
      return;
    }

    // Determine scan mode: remote URL, local path, or local configs
    const isRemote = targetPath && isRemoteUrl(targetPath);
    const isLocalPath = targetPath && !isRemote;

    let resolvedPath: string | undefined;
    let cleanup: (() => void) | undefined;

    if (isRemote) {
      const target = parseTarget(targetPath);
      const cloneSpinner = createSpinner(`Cloning ${target.owner}/${target.repo}...`);
      cloneSpinner.start();
      try {
        const result = await cloneRepo(target);
        resolvedPath = result.tempDir;
        cleanup = result.cleanup;
        cloneSpinner.stop();
      } catch (err) {
        cloneSpinner.stop();
        console.error(`Clone failed: ${err instanceof Error ? err.message : err}`);
        process.exit(1);
      }
    } else if (isLocalPath) {
      resolvedPath = path.resolve(targetPath);
      if (!fs.existsSync(resolvedPath)) {
        console.error(`Error: Path does not exist: ${resolvedPath}`);
        process.exit(1);
      }
    }

    const spinner = createSpinner('Scanning MCP configurations...');
    spinner.start();

    try {
      let result: MCPScanResult;

      if (resolvedPath) {
        // Path-based scan: discover MCP source files + scan them
        const discovery = await runDiscovery(resolvedPath);
        const mcpDetection = discovery.detection.results.find(r => r.framework === 'mcp');
        const mcpFiles = mcpDetection?.files ?? [];

        // Source-scan MCP files
        const sourceResult = scanMCPSourceDir(resolvedPath, mcpFiles);

        // Build MCPScanResult from source scanning
        const findingsBySeverity: Record<MCPFindingSeverity, number> = {
          critical: 0, high: 0, medium: 0, low: 0,
        };
        for (const f of sourceResult.findings) {
          findingsBySeverity[f.severity]++;
        }

        const worstSeverity = sourceResult.findings.reduce<MCPFindingSeverity>((worst, f) => {
          const order: MCPFindingSeverity[] = ['critical', 'high', 'medium', 'low'];
          return order.indexOf(f.severity) < order.indexOf(worst) ? f.severity : worst;
        }, 'low');

        result = {
          clients: [],
          servers: mcpFiles.map(f => ({
            name: path.basename(f, path.extname(f)),
            command: '',
            args: [],
            env: {},
            client: 'source-code',
            configFile: f,
            status: (worstSeverity === 'critical' ? 'critical' : worstSeverity === 'high' ? 'warn' : 'ok') as 'ok' | 'warn' | 'critical',
          })),
          tools: sourceResult.tools,
          findings: sourceResult.findings,
          summary: {
            totalClients: 0,
            totalServers: mcpFiles.length,
            totalTools: sourceResult.tools.length,
            totalFindings: sourceResult.findings.length,
            findingsBySeverity,
            overallStatus: sourceResult.findings.some(f => f.severity === 'critical')
              ? 'critical'
              : sourceResult.findings.some(f => f.severity === 'high')
                ? 'warn'
                : 'ok',
          },
        };
      } else {
        // No path: scan local machine MCP configs (existing behavior)
        result = scanAllMCPConfigs();
      }

      spinner.stop();

      // Pin generation mode
      if (options.pin !== undefined) {
        const pinPath = typeof options.pin === 'string' ? options.pin : '.g0-pins.json';
        if (result.tools.length === 0) {
          console.log(chalk.yellow('No MCP tools found to pin.'));
          return;
        }
        const pins = generatePins(result.tools);
        savePinFile(pins, pinPath);
        console.log(chalk.green(`Pinned ${pins.pins.length} tool descriptions to ${pinPath}`));
        return;
      }

      // Pin check mode
      if (options.check !== undefined) {
        const pinPath = typeof options.check === 'string' ? options.check : '.g0-pins.json';
        const pinFile = loadPinFile(pinPath);
        if (!pinFile) {
          console.error(`Pin file not found or invalid: ${pinPath}`);
          process.exit(1);
        }
        if (result.tools.length === 0) {
          console.log(chalk.yellow('No MCP tools found to check.'));
          return;
        }
        const check = checkPins(result.tools, pinFile);
        console.log(chalk.bold('\n  Pin Check Results'));
        console.log(chalk.dim('  ' + '─'.repeat(50)));
        console.log(`  ${chalk.green(`${check.matches} matched`)}  ${chalk.red(`${check.mismatches.length} mismatched`)}  ${chalk.yellow(`${check.newTools.length} new`)}  ${chalk.dim(`${check.removedTools.length} removed`)}`);
        for (const m of check.mismatches) {
          console.log(chalk.red(`\n  MISMATCH: ${m.toolName}`));
          console.log(chalk.dim(`    Previous: ${m.previousDescription.substring(0, 80)}...`));
          console.log(chalk.dim(`    Current:  ${m.currentDescription.substring(0, 80)}...`));
        }
        for (const t of check.newTools) {
          console.log(chalk.yellow(`  NEW: ${t}`));
        }
        for (const t of check.removedTools) {
          console.log(chalk.red(`  REMOVED: ${t}`));
        }
        console.log('');
        if (check.mismatches.length > 0) process.exit(1);
        return;
      }

      if (options.json) {
        const json = reportMCPJson(result, options.output);
        if (!options.output) {
          console.log(json);
        } else {
          console.log(`MCP scan written to: ${options.output}`);
        }
      } else {
        reportMCPTerminal(result);
        if (options.output) {
          reportMCPJson(result, options.output);
        }
      }

      // Upload to platform
      const { shouldUpload } = await import('../../platform/upload.js');
      const uploadDecision = await shouldUpload(options.upload);
      if (uploadDecision.upload) {
        try {
          if (uploadDecision.isAuto) {
            console.log('\n  Auto-uploading (authenticated)...');
          }
          const { uploadResults, collectProjectMeta, collectMachineMeta, detectCIMeta } = await import('../../platform/upload.js');
          const response = await uploadResults({
            type: 'mcp',
            project: resolvedPath ? collectProjectMeta(resolvedPath) : undefined,
            machine: collectMachineMeta(),
            ci: detectCIMeta(),
            result,
          });
          if (response) {
            console.log(`\n  Uploaded to: ${response.url}`);
          }
        } catch (err) {
          console.error(`  Upload failed: ${err instanceof Error ? err.message : err}`);
        }
      }
    } catch (error) {
      spinner.stop();
      console.error('MCP scan failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    } finally {
      cleanup?.();
    }
  });

// Subcommand: scan specific path
const scanSubcommand = new Command('scan')
  .description('Scan a specific MCP server source file or config')
  .argument('<path>', 'Path to MCP server source or config file')
  .option('--json', 'Output as JSON')
  .option('-o, --output <file>', 'Write output to file')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((targetPath: string, options: {
    json?: boolean;
    output?: string;
    banner?: boolean;
  }) => {
    const resolvedPath = path.resolve(targetPath);

    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: Path does not exist: ${resolvedPath}`);
      process.exit(1);
    }

    const spinner = createSpinner('Scanning MCP server...');
    spinner.start();

    try {
      const ext = path.extname(resolvedPath);
      const isSource = ['.py', '.ts', '.js', '.mjs'].includes(ext);
      const result = isSource
        ? scanMCPServer(resolvedPath)
        : scanMCPConfigFile(resolvedPath);

      spinner.stop();

      if (options.json) {
        const json = reportMCPJson(result, options.output);
        if (!options.output) {
          console.log(json);
        } else {
          console.log(`MCP scan written to: ${options.output}`);
        }
      } else {
        reportMCPTerminal(result);
        if (options.output) {
          reportMCPJson(result, options.output);
        }
      }
    } catch (error) {
      spinner.stop();
      console.error('MCP scan failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Subcommand: list servers
const listSubcommand = new Command('list')
  .description('List all detected MCP servers on this machine')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: {
    json?: boolean;
    banner?: boolean;
  }) => {
    const result = listMCPServers();

    if (options.json) {
      console.log(reportMCPJson(result));
    } else {
      reportMCPTerminal(result);
    }
  });

// Subcommand: verify npm package
const verifySubcommand = new Command('verify')
  .description('Verify an MCP server npm package for security signals')
  .argument('<package>', 'npm package name (e.g. @modelcontextprotocol/server-filesystem)')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (packageName: string, options: {
    json?: boolean;
    banner?: boolean;
  }) => {
    const spinner = createSpinner(`Verifying ${packageName}...`);
    spinner.start();

    try {
      const result = await verifyNpmPackage(packageName);
      spinner.stop();

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        reportMCPVerifyTerminal(result);
      }

      if (result.overallRisk === 'critical' || result.overallRisk === 'high') {
        process.exit(1);
      }
    } catch (error) {
      spinner.stop();
      console.error('Verification failed:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

mcpCommand.addCommand(scanSubcommand);
mcpCommand.addCommand(listSubcommand);
mcpCommand.addCommand(verifySubcommand);
