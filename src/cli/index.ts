import { Command } from 'commander';
import { printBanner, getVersion } from './branding.js';
import { scanCommand } from './commands/scan.js';
import { initCommand } from './commands/init.js';
import { gateCommand } from './commands/gate.js';
import { inventoryCommand } from './commands/inventory.js';
import { flowsCommand } from './commands/flows.js';
import { mcpCommand } from './commands/mcp.js';
import { testCommand } from './commands/test.js';
import { loginCommand } from './commands/login.js';
import { logoutCommand } from './commands/logout.js';
import { whoamiCommand } from './commands/whoami.js';
import { daemonCommand } from './commands/daemon.js';
import { endpointCommand } from './commands/endpoint.js';
import { detectCommand } from './commands/detect.js';
import { attestCommand } from './commands/attest.js';
import { fleetCommand } from './commands/fleet.js';
import { proxyCommand } from './commands/proxy.js';
import { configCommand } from './commands/config.js';

export function createCli(): Command {
  const program = new Command();

  program
    .name('g0')
    .description('Background check for AI agents')
    .version(getVersion())
    .hook('preAction', (thisCommand, actionCommand) => {
      // optsWithGlobals(), not opts(): several subcommands (e.g. `endpoint
      // scan`, `endpoint status`, `endpoint quarantine`) either declare the
      // same option names (`--json`, `--no-banner`) as their parent command
      // or read a machine-readable flag declared only on the parent, and
      // Commander's parser can attach the value to either command depending
      // on where it lands while walking to the action command.
      // `actionCommand.opts()` only sees values Commander attributed to that
      // exact command, so it can miss a `--json` that landed on the parent —
      // printing the banner ahead of what should be pure machine-readable
      // JSON. optsWithGlobals() merges the action command's own options with
      // every ancestor's, so the check is correct regardless of which command
      // in the chain captured the flag (and is a superset of opts(), so
      // commands that declare the flag directly are unaffected).
      const opts = actionCommand.optsWithGlobals();
      // Suppress banner for machine-readable outputs
      if (opts.json || opts.quiet || opts.banner === false) return;
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
  program.addCommand(loginCommand);
  program.addCommand(logoutCommand);
  program.addCommand(whoamiCommand);
  program.addCommand(daemonCommand);
  program.addCommand(endpointCommand);
  program.addCommand(detectCommand);
  program.addCommand(attestCommand);
  program.addCommand(fleetCommand);
  program.addCommand(proxyCommand);
  program.addCommand(configCommand);

  return program;
}
