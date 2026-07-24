import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Command } from 'commander';
import { scanEndpoint } from '../../endpoint/scanner.js';
import { buildSnapshot, defaultSnapshotPath, writeSnapshotAtomic, type MachineSnapshot } from '../../sentinel/snapshot.js';
import { buildToolExposures, toolCategory } from '../../sentinel/exposure.js';
import { scanBrowserExtensions } from '../../sentinel/browser-extensions.js';
import { evaluatePolicy, loadPolicy } from '../../sentinel/governance.js';
import { postSnapshot, startCollector } from '../../sentinel/collector.js';
import { renderOrgReportHtml, summarizeOrg } from '../../sentinel/report.js';
import { getVersion } from '../branding.js';

export const sentinelCommand = new Command('sentinel')
  .description('Fleet sentinel — unattended AI-footprint snapshot for MDM deployment');

sentinelCommand
  .command('scan')
  .description('Run one collection pass and write a machine snapshot')
  .option('--out <path>', 'Snapshot output path (default: platform well-known path)')
  .option('--post <url>', 'Also POST the snapshot to a collector URL')
  .option('--policy <file>', 'Apply a governance policy (guard0.policy.yaml) and record verdicts')
  .option('--no-pii', 'Skip the per-tool PII-exposure scan (inventory only)')
  .action(async (options: { out?: string; post?: string; policy?: string; pii?: boolean }) => {
    const out = options.out ?? defaultSnapshotPath(os.platform());
    try {
      const result = await scanEndpoint({});
      // PII exposure is scanned for INSTALLED tools only (no point scanning absent tools).
      const installed = result.tools.filter((t) => t.installed);
      const exposures =
        options.pii === false
          ? []
          : buildToolExposures(
              installed.map((t) => ({ name: t.name, mcpServerCount: t.mcpServerCount, servers: t.servers })),
              os.homedir(),
            );
      const governance = options.policy
        ? evaluatePolicy(
            loadPolicy(options.policy),
            installed.map((t) => ({ name: t.name, category: toolCategory(t.name) })),
          )
        : undefined;
      const aiExtensions = scanBrowserExtensions(os.homedir()).filter((e) => e.isAI);
      const snap = buildSnapshot(
        { tools: result.tools, score: result.score.total },
        {
          hostname: os.hostname(),
          platform: os.platform(),
          arch: os.arch(),
          sentinelVersion: getVersion(),
          generatedAtMs: Date.now(),
        },
        exposures,
        governance,
        aiExtensions,
      );
      writeSnapshotAtomic(out, snap);
      if (options.post) await postSnapshot(options.post, snap);
      const running = snap.tools.filter((t) => t.running).length;
      const piiTotal = Object.values(snap.piiSummary).reduce((a, b) => a + b, 0);
      const gov = governance ? (governance.compliant ? ', compliant' : ', NON-COMPLIANT') : '';
      const ext = aiExtensions.length ? `, ${aiExtensions.length} AI browser ext` : '';
      // Compact summary line — captured by MDM script-output reporting (spec §8).
      console.log(
        `g0 sentinel: ${snap.tools.length} AI tools (${running} running)${ext}, ${piiTotal} PII items across ${exposures.length} tools, score ${snap.endpointScore ?? 'n/a'}${gov} -> ${out}`,
      );
    } catch (err) {
      // Unattended context (MDM script/scheduled task): emit a single clean line,
      // never a stack trace, and exit non-zero so the MDM can flag the machine.
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`g0 sentinel: failed to write snapshot to ${out}: ${msg}`);
      process.exitCode = 1;
    }
  });

sentinelCommand
  .command('collect')
  .description('Run a thin HTTP collector that receives snapshots (POST /) and writes them to a directory')
  .requiredOption('--dir <dir>', 'Directory to write received snapshots into')
  .option('--port <port>', 'Port to listen on', '8787')
  .option('--host <host>', 'Bind address', '127.0.0.1')
  .action((options: { dir: string; port: string; host: string }) => {
    const port = parseInt(options.port, 10);
    const server = startCollector({ dir: options.dir, port, host: options.host });
    server.on('listening', () => {
      console.log(`g0 sentinel collector listening on http://${options.host}:${port} -> ${options.dir}`);
      console.log(`  sentinels POST snapshots to  http://${options.host}:${port}/   ·   health: /health`);
    });
    server.on('error', (err) => {
      console.error(`g0 sentinel collector: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    });
  });

sentinelCommand
  .command('report')
  .description('Roll up collected snapshots (a directory) into one org-wide HTML report')
  .requiredOption('--dir <dir>', 'Directory of collected snapshot JSON files')
  .option('--out <file>', 'HTML output path', 'g0-sentinel-report.html')
  .action((options: { dir: string; out: string }) => {
    try {
      const files = fs.readdirSync(options.dir).filter((f) => f.endsWith('.json'));
      const snapshots: MachineSnapshot[] = [];
      for (const f of files) {
        try {
          snapshots.push(JSON.parse(fs.readFileSync(path.join(options.dir, f), 'utf-8')));
        } catch {
          console.error(`  skipping unreadable snapshot: ${f}`);
        }
      }
      const summary = summarizeOrg(snapshots);
      fs.writeFileSync(options.out, renderOrgReportHtml(snapshots));
      console.log(
        `g0 sentinel report: ${summary.machines} machines, ${summary.totalTools} tools, ${summary.totalPii} PII items, ${summary.nonCompliant} non-compliant -> ${options.out}`,
      );
    } catch (err) {
      console.error(`g0 sentinel report: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
    }
  });
