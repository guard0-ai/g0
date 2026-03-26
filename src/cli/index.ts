import { Command } from 'commander';
import { basename } from 'node:path';
import { printBanner, getVersion } from './branding.js';
import { scanCommand } from './commands/scan.js';
import { initCommand } from './commands/init.js';
import { gateCommand } from './commands/gate.js';
import { inventoryCommand } from './commands/inventory.js';
import { flowsCommand } from './commands/flows.js';
import { mcpCommand } from './commands/mcp.js';
import { testCommand } from './commands/test.js';
import { authCommand } from './commands/auth.js';
import { daemonCommand } from './commands/daemon.js';
import { endpointCommand } from './commands/endpoint.js';
import { detectCommand } from './commands/detect.js';

/** Detect whether CLI was invoked as `guard0` or `g0`. */
function cliName(): string {
  const invoked = basename(process.argv[1] ?? '');
  return invoked.startsWith('guard0') ? 'guard0' : 'g0';
}

export function createCli(): Command {
  const program = new Command();

  program
    .name(cliName())
    .description('Open-source security assessment for AI agents')
    .version(getVersion())
    .hook('preAction', (thisCommand, actionCommand) => {
      const opts = actionCommand.opts();
      // Suppress banner for machine-readable outputs
      if (opts.json || opts.sarif || opts.quiet || opts.banner === false) return;
      if (opts.markdown) return;
      printBanner();
    });

  program.addCommand(scanCommand);
  program.addCommand(initCommand);
  program.addCommand(gateCommand);
  program.addCommand(inventoryCommand);
  program.addCommand(flowsCommand);
  program.addCommand(mcpCommand);
  program.addCommand(testCommand);
  program.addCommand(authCommand);
  program.addCommand(daemonCommand);
  program.addCommand(endpointCommand);
  program.addCommand(detectCommand);

  return program;
}
