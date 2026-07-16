import { createCli } from '../src/cli/index.js';
import { runProxyFromArgvOverride } from '../src/cli/commands/proxy.js';

// `g0 proxy -- <cmd> [args...]` must always stream through the run path,
// never commander's subcommand dispatch (which can mistake a wrapped
// command name like `install` for the `g0 proxy install` subcommand — see
// `detectProxyRunOverride`'s doc comment). Check for that pattern in the
// raw argv before handing off to commander at all.
const handled = await runProxyFromArgvOverride(process.argv.slice(2));
if (!handled) {
  const cli = createCli();
  cli.parse();
}
