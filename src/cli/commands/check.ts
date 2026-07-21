import { Command } from 'commander';
import { runCheck } from '../../check/runner.js';
import { reportCheckTerminal } from '../../reporters/check-terminal.js';
import { maybeShowCta } from '../../platform/cta.js';
import { createSpinner } from '../ui.js';

interface CheckCliOptions {
  json?: boolean;
  endpoint: boolean;
}

export const checkCommand = new Command('check')
  .description('One-command background check: endpoint estate + installed skills vs known-malicious DB')
  .argument('[path]', 'project root to include in the skill audit (default: cwd)')
  .option('--json', 'output machine-readable JSON')
  .option('--no-endpoint', 'skip the endpoint (machine) scan, audit skills only')
  .action(async (pathArg: string | undefined, options: CheckCliOptions) => {
    const spinner = !options.json ? createSpinner('Running background check...').start() : null;

    const result = await runCheck({
      rootPath: pathArg ?? process.cwd(),
      endpoint: options.endpoint,
    });

    spinner?.stop();

    if (result.verdict.capped) {
      process.exitCode = 1;
    }

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }

    reportCheckTerminal(result);

    if (result.verdict.capped) {
      maybeShowCta('check-malicious', { detail: result.verdict.headline });
    }
  });
