import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { runScan } from '../../pipeline.js';
import { buildInventory } from '../../inventory/builder.js';
import { runDiscovery, runGraphBuild } from '../../pipeline.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { maybeShowCta } from '../../platform/cta.js';
import {
  buildSnapshot,
  writeSnapshot,
  computeFleetSummary,
  computeDrift,
  listAssetIds,
  latestSnapshot,
  fleetDir,
} from '../../platform/fleet.js';

function gradeColor(grade: string): (s: string) => string {
  if (grade === 'A') return chalk.green.bold;
  if (grade === 'B') return chalk.green;
  if (grade === 'C') return chalk.yellow;
  if (grade === 'D') return chalk.hex('#ff8800');
  return chalk.red.bold;
}

export const fleetCommand = new Command('fleet')
  .description('Fleet control plane — track your whole agent estate across repos and machines');

// ── g0 fleet scan <paths...> ────────────────────────────────────────────────
fleetCommand
  .command('scan')
  .description('Scan one or more projects and record them into the fleet')
  .argument('<paths...>', 'Project paths to scan and record')
  .option('--owner <owner>', 'Owning team or person for these assets')
  .option('--fleet-dir <dir>', 'Fleet store directory (default: ~/.g0/fleet)')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .action(async (paths: string[], options: { owner?: string; fleetDir?: string; config?: string }) => {
    const dir = fleetDir(options.fleetDir);
    let recorded = 0;

    for (const p of paths) {
      const resolvedPath = path.resolve(p);
      if (!fs.existsSync(resolvedPath)) {
        console.error(chalk.red(`  Skipping (not found): ${resolvedPath}`));
        continue;
      }

      const spinner = createSpinner(`Scanning ${path.basename(resolvedPath)}...`);
      spinner.start();
      try {
        const config = loadConfig(resolvedPath, options.config) ?? undefined;
        const result = await runScan({ targetPath: resolvedPath, config });
        const discovery = await runDiscovery(resolvedPath, config?.exclude_paths ?? []);
        const graph = runGraphBuild(resolvedPath, discovery);
        const inventory = buildInventory(graph, discovery);

        const owner = options.owner ?? (config as { owner?: string } | undefined)?.owner;
        const snapshot = buildSnapshot({
          targetPath: resolvedPath,
          name: path.basename(resolvedPath),
          owner,
          score: result.score,
          findings: result.findings,
          inventory,
          timestamp: new Date().toISOString(),
        });
        writeSnapshot(snapshot, dir);
        spinner.stop();
        const gc = gradeColor(snapshot.grade);
        console.log(`  ${gc(snapshot.grade.padEnd(2))} ${snapshot.name}  ${chalk.dim(`(${snapshot.findings.total} findings, ${snapshot.inventory.agents} agents)`)}`);
        recorded++;
      } catch (err) {
        spinner.stop();
        console.error(chalk.red(`  Failed: ${resolvedPath} — ${err instanceof Error ? err.message : err}`));
      }
    }

    console.log(chalk.dim(`\n  Recorded ${recorded} asset snapshot(s) → ${dir}\n`));
  });

// ── g0 fleet status ─────────────────────────────────────────────────────────
fleetCommand
  .command('status')
  .description('Estate roll-up across all tracked assets')
  .option('--fleet-dir <dir>', 'Fleet store directory (default: ~/.g0/fleet)')
  .option('--json', 'Output as JSON')
  .action((options: { fleetDir?: string; json?: boolean }) => {
    const dir = fleetDir(options.fleetDir);
    const summary = computeFleetSummary(dir);

    if (options.json) {
      console.log(JSON.stringify(summary, null, 2));
      return;
    }

    if (summary.assetCount === 0) {
      console.log(chalk.dim('\n  No assets tracked yet. Record some with: g0 fleet scan <path...>\n'));
      return;
    }

    console.log(chalk.bold('\n  Fleet Status'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    console.log(`  Assets: ${summary.assetCount}   Agents: ${summary.totals.agents}   Tools: ${summary.totals.tools}   Models: ${summary.totals.models}   MCP: ${summary.totals.mcpServers}`);
    console.log(`  Findings: ${summary.totals.findings}   ${chalk.red(`Critical: ${summary.totals.criticals}`)}   ${chalk.hex('#ff8800')(`High: ${summary.totals.highs}`)}`);

    const ecos = Object.entries(summary.ecosystems).sort((a, b) => b[1] - a[1]);
    if (ecos.length > 0) {
      console.log(chalk.dim('\n  Ecosystems: ') + ecos.map(([e, n]) => `${e} (${n})`).join(', '));
    }

    const owners = Object.entries(summary.owners).sort((a, b) => b[1] - a[1]);
    if (owners.length > 0) {
      console.log(chalk.dim('  Owners:     ') + owners.map(([o, n]) => `${o} (${n})`).join(', '));
    }

    console.log(chalk.bold('\n  Assets (worst first)'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const a of summary.assets) {
      const gc = gradeColor(a.grade);
      const owner = a.owner ? chalk.dim(` · ${a.owner}`) : '';
      const crit = a.criticals > 0 ? chalk.red(` ${a.criticals} crit`) : '';
      console.log(`  ${gc(a.grade.padEnd(2))} ${a.name.padEnd(28)} ${chalk.dim(`${a.totalFindings} findings`)}${crit}${owner}`);
    }
    console.log('');

    if (summary.totals.criticals > 0) {
      maybeShowCta('drift-detected', { detail: `${summary.totals.criticals} critical(s) across fleet` });
    }
  });

// ── g0 fleet list ───────────────────────────────────────────────────────────
fleetCommand
  .command('list')
  .description('List tracked assets with last-seen and snapshot count')
  .option('--fleet-dir <dir>', 'Fleet store directory (default: ~/.g0/fleet)')
  .action((options: { fleetDir?: string }) => {
    const dir = fleetDir(options.fleetDir);
    const ids = listAssetIds(dir);
    if (ids.length === 0) {
      console.log(chalk.dim('\n  No assets tracked yet.\n'));
      return;
    }
    console.log(chalk.bold('\n  Tracked Assets'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const id of ids) {
      const latest = latestSnapshot(id, dir);
      if (!latest) continue;
      console.log(`  ${chalk.cyan(latest.name)}  ${chalk.dim(latest.assetId)}`);
      console.log(chalk.dim(`    grade ${latest.grade} · last seen ${latest.timestamp}${latest.owner ? ` · ${latest.owner}` : ''}`));
    }
    console.log('');
  });

// ── g0 fleet drift [assetId] ────────────────────────────────────────────────
fleetCommand
  .command('drift')
  .description('Show change since the previous snapshot for each asset')
  .argument('[assetId]', 'Limit to a single asset id')
  .option('--fleet-dir <dir>', 'Fleet store directory (default: ~/.g0/fleet)')
  .option('--json', 'Output as JSON')
  .action((assetId: string | undefined, options: { fleetDir?: string; json?: boolean }) => {
    const dir = fleetDir(options.fleetDir);
    const ids = assetId ? [assetId] : listAssetIds(dir);
    const drifts = ids.map(id => computeDrift(id, dir)).filter((d): d is NonNullable<typeof d> => d !== null);

    if (options.json) {
      console.log(JSON.stringify(drifts, null, 2));
      return;
    }

    if (drifts.length === 0) {
      console.log(chalk.dim('\n  No drift data. Record at least two snapshots per asset.\n'));
      return;
    }

    console.log(chalk.bold('\n  Fleet Drift'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const d of drifts) {
      if (!d.from) {
        console.log(`  ${chalk.cyan(d.name)} ${chalk.dim('— baseline only, no prior snapshot')}`);
        continue;
      }
      const scoreStr = d.scoreDelta === 0
        ? chalk.dim('±0')
        : d.scoreDelta > 0 ? chalk.green(`+${d.scoreDelta}`) : chalk.red(`${d.scoreDelta}`);
      const gradeStr = d.gradeFrom !== d.gradeTo ? `${d.gradeFrom}→${d.gradeTo}` : d.gradeTo;
      console.log(`  ${chalk.cyan(d.name)}  score ${scoreStr} (${gradeStr})`);
      const parts: string[] = [];
      if (d.newFindings) parts.push(chalk.red(`+${d.newFindings} new findings`));
      if (d.resolvedFindings) parts.push(chalk.green(`-${d.resolvedFindings} resolved`));
      const inv = d.inventoryDelta;
      for (const [k, v] of Object.entries(inv)) {
        if (v !== 0) parts.push(`${v > 0 ? '+' : ''}${v} ${k}`);
      }
      if (parts.length > 0) console.log(chalk.dim('    ') + parts.join(chalk.dim(', ')));
    }
    console.log('');

    if (drifts.some(d => d.newFindings > 0)) {
      maybeShowCta('drift-detected', { detail: 'new findings since last snapshot' });
    }
  });
