import * as os from 'node:os';
import { Command } from 'commander';
import { scanEndpoint } from '../../endpoint/scanner.js';
import { buildSnapshot, defaultSnapshotPath, writeSnapshotAtomic } from '../../sentinel/snapshot.js';
import { getVersion } from '../branding.js';

export const sentinelCommand = new Command('sentinel')
  .description('Fleet sentinel — unattended AI-footprint snapshot for MDM deployment');

sentinelCommand
  .command('scan')
  .description('Run one collection pass and write a machine snapshot')
  .option('--out <path>', 'Snapshot output path (default: platform well-known path)')
  .action(async (options: { out?: string }) => {
    const out = options.out ?? defaultSnapshotPath(os.platform());
    try {
      const result = await scanEndpoint({});
      const snap = buildSnapshot(
        { tools: result.tools, score: result.score.total },
        {
          hostname: os.hostname(),
          platform: os.platform(),
          arch: os.arch(),
          sentinelVersion: getVersion(),
          generatedAtMs: Date.now(),
        },
      );
      writeSnapshotAtomic(out, snap);
      const running = snap.tools.filter((t) => t.running).length;
      // Compact summary line — captured by MDM script-output reporting (spec §8).
      console.log(
        `g0 sentinel: ${snap.tools.length} AI tools (${running} running), score ${snap.endpointScore ?? 'n/a'} -> ${out}`,
      );
    } catch (err) {
      // Unattended context (MDM script/scheduled task): emit a single clean line,
      // never a stack trace, and exit non-zero so the MDM can flag the machine.
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`g0 sentinel: failed to write snapshot to ${out}: ${msg}`);
      process.exitCode = 1;
    }
  });
