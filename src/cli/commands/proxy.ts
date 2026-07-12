import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import chalk from 'chalk';
import { Command } from 'commander';

import { runProxy } from '../../proxy/proxy-core.js';
import { installProxy, uninstallProxy, listInstalls } from '../../proxy/installer.js';
import type { InstallResult, UninstallResult, InstallManifestEntry } from '../../proxy/installer.js';
import { summarizeAudit, readAudit } from '../../proxy/audit-log.js';
import type { AuditRecord } from '../../types/proxy.js';

const PROXY_DIR = path.join(os.homedir(), '.g0', 'proxy');
const ONE_DAY_MS = 24 * 60 * 60 * 1000;

// ─────────────────────────────────────────────────────────────────────────
// Run path (`g0 proxy -- <command> [args...]`)
//
// STDOUT PURITY: this is a live stdio JSON-RPC MITM — stdout is reserved
// exclusively for the traffic `runProxy` forwards between the client and
// the wrapped server (see src/proxy/proxy-core.ts's own header comment).
// The `--quiet` option below has no `--no-quiet` counterpart (like `mcp
// serve`'s), so it always defaults to `true` on this command and cannot be
// turned off — the program-level `preAction` hook in `src/cli/index.ts`
// reads `actionCommand.opts().quiet` and skips `printBanner()` whenever
// it's true. Nothing in the action below may write to stdout before
// handing off to `runProxy`: no chalk, no console.log — diagnostics only
// ever go to console.error (stderr).
// ─────────────────────────────────────────────────────────────────────────

export interface RunTarget {
  serverName: string;
  command: string;
  args: string[];
}

/**
 * Split the parsed `[command...]` positional (everything after `--`, or
 * everything after the recognized options if `--` was omitted) into a
 * `RunTarget`. Factored out of the action so the splitting logic — the
 * part most likely to have an off-by-one bug — is unit-testable without
 * going through commander at all. Returns `undefined` when no command was
 * given (the caller should print usage and exit non-zero).
 */
export function resolveRunTarget(command: string[], options: { server?: string }): RunTarget | undefined {
  if (!Array.isArray(command) || command.length === 0) return undefined;
  const [cmd, ...args] = command;
  const serverName = options.server && options.server.length > 0 ? options.server : path.basename(cmd);
  return { serverName, command: cmd, args };
}

const runAction = async (command: string[], options: { server?: string; policyDir?: string }): Promise<void> => {
  const target = resolveRunTarget(command, options);
  if (!target) {
    console.error('Usage: g0 proxy [--server <name>] [--policy-dir <path>] -- <command> [args...]');
    process.exit(1);
    return;
  }

  const code = await runProxy({
    serverName: target.serverName,
    command: target.command,
    args: target.args,
    policyDir: options.policyDir,
  });
  process.exit(code);
};

// ─────────────────────────────────────────────────────────────────────────
// install / uninstall
// ─────────────────────────────────────────────────────────────────────────

function printInstallSummary(result: InstallResult): void {
  console.log(chalk.bold(`\n  g0 proxy install${result.dryRun ? ' (dry run)' : ''}`));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  if (result.wrapped.length === 0) {
    console.log(chalk.dim('  No servers to wrap.'));
  } else {
    const clients = new Set(result.wrapped.map((w) => w.client));
    console.log(`  Wrapped ${chalk.green(String(result.wrapped.length))} server(s) across ${clients.size} client(s):`);
    for (const w of result.wrapped) {
      console.log(`    ${chalk.cyan('●')} ${w.client}: ${w.serverName}`);
    }
  }

  if (result.skippedAlreadyWrapped.length > 0) {
    console.log(`\n  Already wrapped (skipped): ${result.skippedAlreadyWrapped.length}`);
    for (const s of result.skippedAlreadyWrapped) console.log(`    ${chalk.dim('●')} ${s}`);
  }

  if (result.unproxyable.length > 0) {
    console.log(chalk.yellow(`\n  Unproxyable (remote/url-only, left untouched): ${result.unproxyable.length}`));
    for (const s of result.unproxyable) console.log(`    ${chalk.yellow('●')} ${s}`);
  }

  if (!result.dryRun && result.backups.length > 0) {
    console.log(`\n  Backups written: ${result.backups.length}`);
  }

  if (result.errors.length > 0) {
    console.log(chalk.red(`\n  Errors: ${result.errors.length}`));
    for (const e of result.errors) console.log(chalk.red(`    ${e.client} (${e.configPath}): ${e.message}`));
  }

  if (!result.dryRun && result.wrapped.length > 0) {
    console.log(chalk.bold('\n  Restart your IDE/agent client(s) for the change to take effect.\n'));
  } else {
    console.log('');
  }
}

function printUninstallSummary(result: UninstallResult): void {
  console.log(chalk.bold('\n  g0 proxy uninstall'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  if (result.restored.length === 0) {
    console.log(chalk.dim('  Nothing to restore — no g0-wrapped servers found.'));
  } else {
    console.log(`  Restored ${chalk.green(String(result.restored.length))} server(s):`);
    for (const r of result.restored) {
      console.log(`    ${chalk.cyan('●')} ${r.client}: ${r.serverName}`);
    }
  }

  if (result.backups.length > 0) {
    console.log(`\n  Backups written: ${result.backups.length}`);
  }

  if (result.errors.length > 0) {
    console.log(chalk.red(`\n  Errors: ${result.errors.length}`));
    for (const e of result.errors) console.log(chalk.red(`    ${e.client} (${e.configPath}): ${e.message}`));
  }

  if (result.restored.length > 0) {
    console.log(chalk.bold('\n  Restart your IDE/agent client(s) for the change to take effect.\n'));
  } else {
    console.log('');
  }
}

const installSubcommand = new Command('install')
  .description('Rewrite IDE/agent MCP configs to route stdio servers through g0 proxy')
  .option('--client <name>', 'Only install for this client')
  .option('--server <name>', 'Only install for this server')
  .option('--dry-run', 'Show what would change without writing anything')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: { client?: string; server?: string; dryRun?: boolean; json?: boolean }) => {
    const result = await installProxy({
      clients: options.client ? [options.client] : undefined,
      servers: options.server ? [options.server] : undefined,
      dryRun: options.dryRun,
    });

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    printInstallSummary(result);
  });

const uninstallSubcommand = new Command('uninstall')
  .description('Restore IDE/agent MCP configs to their pre-proxy state')
  .option('--client <name>', 'Only uninstall for this client')
  .option('--server <name>', 'Only uninstall for this server')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async (options: { client?: string; server?: string; json?: boolean }) => {
    const result = await uninstallProxy({
      clients: options.client ? [options.client] : undefined,
      servers: options.server ? [options.server] : undefined,
    });

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
      return;
    }
    printUninstallSummary(result);
  });

// ─────────────────────────────────────────────────────────────────────────
// status
// ─────────────────────────────────────────────────────────────────────────

const statusSubcommand = new Command('status')
  .description('Show installed g0 proxy wraps and recent proxy activity')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: { json?: boolean }) => {
    const installs: InstallManifestEntry[] = listInstalls();
    const summary = summarizeAudit({ sinceMs: ONE_DAY_MS });

    if (options.json) {
      console.log(JSON.stringify({ installs, activity: summary }, null, 2));
      return;
    }

    console.log(chalk.bold('\n  g0 proxy status'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));

    if (installs.length === 0) {
      console.log(chalk.dim('  No servers installed. Run `g0 proxy install` to get started.'));
    } else {
      console.log(`  Installed: ${installs.length} server(s)`);
      for (const i of installs) {
        console.log(`    ${chalk.cyan('●')} ${i.client}: ${i.serverName}`);
      }
    }

    console.log(chalk.bold('\n  Activity (last 24h)'));
    console.log(`  Proxied servers: ${summary.proxiedServers.length}`);
    console.log(
      `  Calls: ${summary.totalCalls}   ${chalk.red(`Denied: ${summary.denied}`)}   ${chalk.yellow(`Alerted: ${summary.alerted}`)}   ${chalk.magenta(`Redacted: ${summary.redacted}`)}`,
    );
    console.log('');
  });

// ─────────────────────────────────────────────────────────────────────────
// logs
// ─────────────────────────────────────────────────────────────────────────

function actionColor(action: AuditRecord['action']): (s: string) => string {
  if (action === 'deny') return chalk.red;
  if (action === 'alert') return chalk.yellow;
  if (action === 'redact') return chalk.magenta;
  return chalk.dim;
}

const logsSubcommand = new Command('logs')
  .description('Show recent g0 proxy audit records')
  .option('--server <name>', 'Only show logs for this server')
  .option('--tail <n>', 'Number of records to show', '50')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: { server?: string; tail: string; json?: boolean }) => {
    const limit = Number.parseInt(options.tail, 10);
    const records = readAudit({ serverName: options.server, limit: Number.isFinite(limit) && limit > 0 ? limit : 50 });

    if (options.json) {
      console.log(JSON.stringify(records, null, 2));
      return;
    }

    console.log(chalk.bold(`\n  g0 proxy logs${options.server ? ` (${options.server})` : ''}`));
    console.log(chalk.dim('  ' + '─'.repeat(76)));

    if (records.length === 0) {
      console.log(chalk.dim('  No audit records found.'));
    } else {
      for (const r of records) {
        const color = actionColor(r.action);
        const label = r.toolName ?? r.kind;
        console.log(
          `  ${chalk.dim(r.ts)}  ${r.serverName.padEnd(16)}  ${label.padEnd(20)}  ${color((r.action ?? '-').padEnd(6))}  ${chalk.dim(r.ruleId ?? '')}`,
        );
      }
    }
    console.log('');
  });

// ─────────────────────────────────────────────────────────────────────────
// policy init
// ─────────────────────────────────────────────────────────────────────────

export const DEFAULT_POLICY_YAML = `# g0 proxy policy
#
# mode: observe (the safe default) never blocks anything: every rule's
# action is downgraded to "alert" (logged, not enforced), so it's safe to
# turn the proxy on and see what WOULD have happened before switching to
# "alert" mode (deny -> alert only, everything else honored) or "enforce"
# mode (rules run exactly as written).
version: 1
mode: observe
onError: open

limits:
  maxScanBytes: 1048576

response:
  redactSecrets: false
  injection: alert

rules: []
# Uncomment (and move out from under the empty "rules: []" above) to try
# these once you're ready to move past observe mode:
#
# - id: block-destructive-commands
#   direction: request
#   tools: ["execute_command", "run_*", "*shell*", "bash"]
#   argsRegex: '(rm\\s+-rf\\s+/|mkfs|dd\\s+if=)'
#   action: deny
#   message: "Blocked by g0 policy: destructive command"
#
# - id: redact-response-secrets
#   direction: response
#   action: alert
#   message: "Potential secret found in a tool response"
#
# (or just set response.redactSecrets: true above to redact secret findings
# in every tool response, globally, without a dedicated rule.)
`;

export interface WriteDefaultPolicyResult {
  ok: boolean;
  path: string;
  message?: string;
}

/**
 * Write `DEFAULT_POLICY_YAML` to `targetPath`, refusing to clobber an
 * existing file unless `force` is set. Factored out of the action so the
 * overwrite-guard logic is unit-testable without going through commander.
 */
export function writeDefaultPolicyFile(targetPath: string, opts: { force?: boolean } = {}): WriteDefaultPolicyResult {
  if (fs.existsSync(targetPath) && !opts.force) {
    return { ok: false, path: targetPath, message: `Policy file already exists: ${targetPath} (use --force to overwrite)` };
  }

  try {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(targetPath, DEFAULT_POLICY_YAML, { mode: 0o600 });
    return { ok: true, path: targetPath };
  } catch (err) {
    return { ok: false, path: targetPath, message: err instanceof Error ? err.message : String(err) };
  }
}

const policyInitSubcommand = new Command('init')
  .description('Write a default (observe-mode) g0 proxy policy file')
  .option('--server <name>', 'Write a per-server override instead of the global policy')
  .option('--force', 'Overwrite an existing policy file')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((options: { server?: string; force?: boolean; json?: boolean }) => {
    const target = options.server
      ? path.join(PROXY_DIR, 'policies', `${options.server}.yaml`)
      : path.join(PROXY_DIR, 'policy.yaml');

    const result = writeDefaultPolicyFile(target, { force: options.force });

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
      if (!result.ok) process.exitCode = 1;
      return;
    }

    if (!result.ok) {
      console.error(chalk.red(`  ${result.message}`));
      process.exitCode = 1;
      return;
    }
    console.log(chalk.green(`\n  Wrote default policy to ${result.path}\n`));
  });

const policyCommand = new Command('policy').description('Manage g0 proxy policy files');
policyCommand.addCommand(policyInitSubcommand);

// ─────────────────────────────────────────────────────────────────────────
// proxyCommand
// ─────────────────────────────────────────────────────────────────────────

export const proxyCommand = new Command('proxy')
  .description('Run and manage the g0 MCP proxy — a policy-enforcing man-in-the-middle for MCP servers')
  .option('--server <name>', "Logical server name for policy/audit (defaults to the wrapped command's basename)")
  .option('--policy-dir <path>', 'Policy + audit directory (default: ~/.g0/proxy)')
  .option('--quiet', 'Suppress the g0 banner (always on — stdout is reserved for the proxied JSON-RPC stream)', true)
  .argument('[command...]', 'The MCP server command to wrap, e.g. `g0 proxy -- npx -y server-x`')
  .allowUnknownOption()
  .action(runAction);

proxyCommand.addCommand(installSubcommand);
proxyCommand.addCommand(uninstallSubcommand);
proxyCommand.addCommand(statusSubcommand);
proxyCommand.addCommand(logsSubcommand);
proxyCommand.addCommand(policyCommand);
