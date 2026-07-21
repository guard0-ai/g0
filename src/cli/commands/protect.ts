import chalk from 'chalk';
import { Command } from 'commander';
import {
  protectApply, protectOff, protectPlan, protectStatus, resolveSurfaces,
} from '../../protect/orchestrator.js';
import {
  reportProtectApply, reportProtectPlan, reportProtectStatus, reportProtectUndo,
} from '../../reporters/protect-terminal.js';

interface ProtectCliOptions { apply?: boolean; surfaces?: string; json?: boolean; }
interface OffCliOptions { force?: boolean; surfaces?: string; json?: boolean; }

/** Build a fresh `protect` command tree. Commander instances retain parse state, so tests construct one per parse; the CLI registers the shared `protectCommand` below. */
export function buildProtectCommand(): Command {
  const protect = new Command('protect')
    .description('Install g0 guardrails across this machine (dry-run by default; --apply to commit)')
    .option('--apply', 'execute the plan (default: dry-run preview only)')
    .option('--surfaces <list>', 'comma-separated surfaces (available: mcp; default: all)')
    .option('--json', 'machine-readable output')
    .action(async (options: ProtectCliOptions) => {
      let adapters;
      try {
        adapters = resolveSurfaces(options.surfaces);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (options.json) console.log(JSON.stringify({ error: message }));
        else console.error(chalk.red(message));
        process.exitCode = 1;
        return;
      }
      if (!options.apply) {
        const plans = await protectPlan({}, adapters);
        if (options.json) console.log(JSON.stringify({ mode: 'plan', plans }, null, 2));
        else reportProtectPlan(plans);
        return;
      }
      const { results, manifestPath } = await protectApply({}, adapters);
      if (options.json) console.log(JSON.stringify({ mode: 'apply', results, manifestPath }, null, 2));
      else reportProtectApply(results, manifestPath);
      if (results.some((r) => r.errors.length > 0)) process.exitCode = 1;
    });

  protect.addCommand(
    new Command('status')
      .description('Show what g0 protect currently guards')
      .option('--json', 'machine-readable output')
      .action(async (_options: { json?: boolean }, command: Command) => {
        // --json is declared on the parent too; read the merged value so the
        // flag works on either side of `status` (same pattern as proxy.ts).
        const options = command.optsWithGlobals<{ json?: boolean }>();
        const statuses = await protectStatus({});
        if (options.json) console.log(JSON.stringify({ statuses }, null, 2));
        else reportProtectStatus(statuses);
      }),
  );

  protect.addCommand(
    new Command('off')
      .description('Undo protect changes from the most recent apply (restores backups)')
      .option('--force', 'restore even over configs edited since the backup')
      .option('--surfaces <list>', 'comma-separated surfaces (default: all)')
      .option('--json', 'machine-readable output')
      .action(async (_options: OffCliOptions, command: Command) => {
        // --json/--surfaces are declared on the parent too; read merged values.
        const options = command.optsWithGlobals<OffCliOptions>();
        let adapters;
        try {
          adapters = resolveSurfaces(options.surfaces);
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          if (options.json) console.log(JSON.stringify({ error: message }));
          else console.error(chalk.red(message));
          process.exitCode = 1;
          return;
        }
        const { results, manifestPath } = await protectOff({}, { force: options.force }, adapters);
        if (options.json) console.log(JSON.stringify({ results, manifestPath }, null, 2));
        else reportProtectUndo(results, manifestPath);
        if (results.some((r) => r.errors.length > 0)) process.exitCode = 1;
      }),
  );

  return protect;
}

export const protectCommand = buildProtectCommand();
