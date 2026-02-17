import * as os from 'node:os';
import * as path from 'node:path';
import chalk from 'chalk';
import { Command } from 'commander';
import { loadDaemonConfig } from '../../daemon/config.js';
import { readPid } from '../../daemon/process.js';
import { getMachineId } from '../../platform/machine-id.js';
import { isAuthenticated } from '../../platform/auth.js';
import { collectProjectMeta, collectMachineMeta, shouldUpload, uploadResults } from '../../platform/upload.js';
import { scanAllMCPConfigs, listMCPServers } from '../../mcp/analyzer.js';
import { runScan, runDiscovery, runGraphBuild } from '../../pipeline.js';
import { buildInventory } from '../../inventory/builder.js';
import { createSpinner, gradeColor, printScoreBar } from '../ui.js';
import type { EndpointScanResult, EndpointInventoryResult, EndpointStatusResult } from '../../types/endpoint.js';

export const endpointCommand = new Command('endpoint')
  .description('Assess the entire developer endpoint (machine-wide scanning)');

// ─── Helpers ────────────────────────────────────────────────────────────────

function resolveWatchPaths(pathsFlag?: string): string[] {
  if (pathsFlag) {
    return pathsFlag.split(',').map(p => path.resolve(p.trim()));
  }
  const config = loadDaemonConfig();
  return config.watchPaths.map(p => path.resolve(p));
}

// ─── g0 endpoint scan ───────────────────────────────────────────────────────

const scanSubcommand = new Command('scan')
  .description('Scan all watched projects and MCP configs')
  .option('--paths <paths>', 'Comma-separated project paths (overrides daemon watch paths)')
  .option('--json', 'Output as JSON')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-upload', 'Disable upload')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: {
    paths?: string;
    json?: boolean;
    upload?: boolean;
    banner?: boolean;
  }) => {
    const startTime = Date.now();
    const watchPaths = resolveWatchPaths(options.paths);
    const machineId = getMachineId();
    const hostname = os.hostname();

    if (!options.json) {
      console.log(chalk.bold('\n  Endpoint Scan'));
      console.log(chalk.dim('  ' + '─'.repeat(60)));
      console.log(chalk.dim(`  Machine: ${hostname} (${machineId.slice(0, 8)}...)`));
    }

    // MCP scan
    const mcpSpinner = !options.json ? createSpinner('Scanning MCP configurations...').start() : null;
    let mcp: ReturnType<typeof scanAllMCPConfigs>;
    try {
      mcp = scanAllMCPConfigs();
      mcpSpinner?.succeed(`MCP: ${mcp.summary.totalServers} servers, ${mcp.summary.totalFindings} findings`);
    } catch (err) {
      mcpSpinner?.fail('MCP scan failed');
      mcp = { clients: [], servers: [], tools: [], findings: [], summary: { totalClients: 0, totalServers: 0, totalTools: 0, totalFindings: 0, findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, overallStatus: 'ok' as const } };
    }

    // Project scans
    const projects: EndpointScanResult['projects'] = [];

    if (watchPaths.length === 0 && !options.json) {
      console.log(chalk.yellow('\n  No watch paths configured. Use --paths or configure daemon watch paths.'));
      console.log(chalk.dim('  Run: g0 daemon start --watch /path/to/project1,/path/to/project2\n'));
    }

    for (const projectPath of watchPaths) {
      const name = path.basename(projectPath);
      const spinner = !options.json ? createSpinner(`Scanning ${name}...`).start() : null;

      try {
        const result = await runScan({ targetPath: projectPath });
        projects.push({ path: projectPath, name, result });
        spinner?.succeed(`${name}: score ${result.score.overall} (${result.score.grade}), ${result.findings.length} findings`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        projects.push({ path: projectPath, name, error: errorMsg });
        spinner?.fail(`${name}: ${errorMsg}`);
      }
    }

    // Build summary
    const scannedProjects = projects.filter(p => p.result);
    const failedProjects = projects.filter(p => p.error);
    const allFindings = scannedProjects.reduce((sum, p) => sum + (p.result?.findings.length ?? 0), 0);
    const totalMcpFindings = mcp.summary.totalFindings;

    const scores = scannedProjects.map(p => p.result!.score.overall);
    const averageScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;

    let worstProject: EndpointScanResult['summary']['worstProject'];
    if (scores.length > 0) {
      const minScore = Math.min(...scores);
      const worst = scannedProjects.find(p => p.result!.score.overall === minScore)!;
      worstProject = { name: worst.name, path: worst.path, score: minScore };
    }

    const findingsBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const p of scannedProjects) {
      for (const f of p.result!.findings) {
        findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] ?? 0) + 1;
      }
    }

    const duration = Date.now() - startTime;

    const endpointResult: EndpointScanResult = {
      machineId,
      hostname,
      timestamp: new Date().toISOString(),
      mcp,
      projects,
      summary: {
        totalFindings: allFindings + totalMcpFindings,
        totalProjects: watchPaths.length,
        scannedProjects: scannedProjects.length,
        failedProjects: failedProjects.length,
        averageScore,
        worstProject,
        findingsBySeverity,
      },
      duration,
    };

    if (options.json) {
      console.log(JSON.stringify(endpointResult, null, 2));
      return;
    }

    // Terminal summary
    console.log(chalk.bold('\n  Endpoint Summary'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    console.log(`  Projects scanned:  ${scannedProjects.length}/${watchPaths.length}`);
    if (failedProjects.length > 0) {
      console.log(chalk.red(`  Failed:            ${failedProjects.length}`));
    }
    console.log(`  Average score:     ${printScoreBar(averageScore)}`);
    if (worstProject) {
      console.log(`  Worst project:     ${worstProject.name} (${worstProject.score})`);
    }
    console.log(`  Total findings:    ${allFindings} project + ${totalMcpFindings} MCP`);
    console.log(`  ${chalk.bgRed.white.bold(' CRIT ')} ${findingsBySeverity.critical}  ${chalk.red.bold(' HIGH ')} ${findingsBySeverity.high}  ${chalk.yellow(' MED  ')} ${findingsBySeverity.medium}  ${chalk.blue(' LOW  ')} ${findingsBySeverity.low}`);
    console.log(chalk.dim(`  Duration: ${(duration / 1000).toFixed(1)}s\n`));

    // Upload per-project results
    const { upload } = await shouldUpload(options.upload);
    if (upload) {
      const machine = collectMachineMeta();
      for (const p of scannedProjects) {
        const project = collectProjectMeta(p.path);
        await uploadResults({ type: 'scan', project, machine, result: p.result! });
      }
      if (mcp.findings.length > 0) {
        await uploadResults({ type: 'mcp', machine, result: mcp });
      }
      console.log(chalk.dim('  Results uploaded to Guard0 platform.\n'));
    }
  });

// ─── g0 endpoint inventory ──────────────────────────────────────────────────

const inventorySubcommand = new Command('inventory')
  .description('Machine-wide AI bill of materials across all projects')
  .option('--paths <paths>', 'Comma-separated project paths (overrides daemon watch paths)')
  .option('--json', 'Output as JSON')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--no-upload', 'Disable upload')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: {
    paths?: string;
    json?: boolean;
    upload?: boolean;
    banner?: boolean;
  }) => {
    const startTime = Date.now();
    const watchPaths = resolveWatchPaths(options.paths);
    const machineId = getMachineId();
    const hostname = os.hostname();

    if (!options.json) {
      console.log(chalk.bold('\n  Endpoint Inventory'));
      console.log(chalk.dim('  ' + '─'.repeat(60)));
      console.log(chalk.dim(`  Machine: ${hostname} (${machineId.slice(0, 8)}...)`));
    }

    // MCP servers
    const mcpSpinner = !options.json ? createSpinner('Listing MCP servers...').start() : null;
    let mcp: ReturnType<typeof listMCPServers>;
    try {
      mcp = listMCPServers();
      mcpSpinner?.succeed(`MCP: ${mcp.summary.totalServers} servers`);
    } catch {
      mcpSpinner?.fail('MCP listing failed');
      mcp = { clients: [], servers: [], tools: [], findings: [], summary: { totalClients: 0, totalServers: 0, totalTools: 0, totalFindings: 0, findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, overallStatus: 'ok' as const } };
    }

    // Per-project inventory
    const projects: EndpointInventoryResult['projects'] = [];

    if (watchPaths.length === 0 && !options.json) {
      console.log(chalk.yellow('\n  No watch paths configured. Use --paths or configure daemon watch paths.'));
      console.log(chalk.dim('  Run: g0 daemon start --watch /path/to/project1,/path/to/project2\n'));
    }

    for (const projectPath of watchPaths) {
      const name = path.basename(projectPath);
      const spinner = !options.json ? createSpinner(`Inventorying ${name}...`).start() : null;

      try {
        const discovery = await runDiscovery(projectPath);
        const graph = runGraphBuild(projectPath, discovery);
        const result = buildInventory(graph, discovery);
        projects.push({ path: projectPath, name, result });
        spinner?.succeed(`${name}: ${result.summary.totalModels} models, ${result.summary.totalTools} tools, ${result.summary.totalAgents} agents`);
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        projects.push({ path: projectPath, name, error: errorMsg });
        spinner?.fail(`${name}: ${errorMsg}`);
      }
    }

    // Aggregate unique counts
    const scannedProjects = projects.filter(p => p.result);
    const failedProjects = projects.filter(p => p.error);

    const allModels = new Set<string>();
    const allFrameworks = new Set<string>();
    const allTools = new Set<string>();
    const allAgents = new Set<string>();
    for (const p of scannedProjects) {
      for (const m of p.result!.models) allModels.add(m.name);
      for (const f of p.result!.frameworks) allFrameworks.add(f.name);
      for (const t of p.result!.tools) allTools.add(t.name);
      for (const a of p.result!.agents) allAgents.add(a.name);
    }

    const duration = Date.now() - startTime;

    const endpointResult: EndpointInventoryResult = {
      machineId,
      hostname,
      timestamp: new Date().toISOString(),
      mcp,
      projects,
      summary: {
        totalProjects: watchPaths.length,
        scannedProjects: scannedProjects.length,
        failedProjects: failedProjects.length,
        uniqueModels: allModels.size,
        uniqueFrameworks: allFrameworks.size,
        uniqueTools: allTools.size,
        uniqueAgents: allAgents.size,
        totalMCPServers: mcp.summary.totalServers,
      },
      duration,
    };

    if (options.json) {
      console.log(JSON.stringify(endpointResult, null, 2));
      return;
    }

    // Terminal summary
    console.log(chalk.bold('\n  Endpoint AI-BOM Summary'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    console.log(`  Projects scanned:  ${scannedProjects.length}/${watchPaths.length}`);
    if (failedProjects.length > 0) {
      console.log(chalk.red(`  Failed:            ${failedProjects.length}`));
    }
    console.log(`  Unique models:     ${allModels.size}`);
    console.log(`  Unique frameworks: ${allFrameworks.size}`);
    console.log(`  Unique tools:      ${allTools.size}`);
    console.log(`  Unique agents:     ${allAgents.size}`);
    console.log(`  MCP servers:       ${mcp.summary.totalServers}`);

    if (allModels.size > 0) {
      console.log(chalk.bold('\n  Models'));
      for (const m of allModels) console.log(`    ${chalk.cyan('●')} ${m}`);
    }
    if (allFrameworks.size > 0) {
      console.log(chalk.bold('\n  Frameworks'));
      for (const f of allFrameworks) console.log(`    ${chalk.cyan('●')} ${f}`);
    }

    console.log(chalk.dim(`\n  Duration: ${(duration / 1000).toFixed(1)}s\n`));

    // Upload per-project results
    const { upload } = await shouldUpload(options.upload);
    if (upload) {
      const machine = collectMachineMeta();
      for (const p of scannedProjects) {
        const project = collectProjectMeta(p.path);
        await uploadResults({ type: 'inventory', project, machine, result: p.result! });
      }
      console.log(chalk.dim('  Results uploaded to Guard0 platform.\n'));
    }
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
endpointCommand.addCommand(inventorySubcommand);
endpointCommand.addCommand(statusSubcommand);
