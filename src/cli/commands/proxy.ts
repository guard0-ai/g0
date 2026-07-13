import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import chalk from 'chalk';
import { Command } from 'commander';

import { runProxy } from '../../proxy/proxy-core.js';
import { installProxy, uninstallProxy, listInstalls } from '../../proxy/installer.js';
import type { InstallResult, UninstallResult, InstallManifestEntry } from '../../proxy/installer.js';
import { summarizeAudit, readAudit } from '../../proxy/audit-log.js';
import { buildAndWriteEdmIndex, fingerprintsDir } from '../../proxy/edm.js';
import type { EdmMode } from '../../proxy/edm.js';
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

/**
 * Wait for `stream` (in production, `process.stdout`) to fully flush any
 * buffered writes before the caller hard-exits.
 *
 * `runProxy` resolves inside the child's `'close'` handler right after
 * calling `stdout.end()` — WITHOUT waiting for that `.end()` to actually
 * drain (its `'finish'` event). When `process.stdout` is a pipe (every real
 * IDE run), `process.exit()` does NOT flush pending writes: a large final
 * response still sitting in Node's internal write buffer gets truncated
 * mid-stream, corrupting JSON-RPC framing for the client. Waiting for
 * `'finish'` here (at the CLI boundary, not inside `runProxy` itself —
 * `runProxy`'s resolve timing is relied on by its injectable-stream
 * contract/tests) closes that gap without touching `runProxy`.
 *
 * A short unref'd safety-valve timeout guards against ever hanging the CLI
 * forever on a stuck/half-closed pipe.
 */
function waitForStdoutFlush(stream: NodeJS.WriteStream = process.stdout): Promise<void> {
  if (stream.writableFinished) return Promise.resolve();
  return new Promise<void>((resolve) => {
    let settled = false;
    const timer = setTimeout(() => finish(), 3000);
    timer.unref?.();
    function finish(): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve();
    }
    stream.once('finish', finish);
  });
}

export const runAction = async (
  command: string[],
  options: { server?: string; policyDir?: string },
): Promise<void> => {
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
    // --policy-dir is documented as "Policy + audit directory", so it must
    // redirect BOTH the policy lookup and the audit log; otherwise audit
    // silently lands in ~/.g0/proxy regardless of the flag.
    policyDir: options.policyDir,
    auditDir: options.policyDir,
  });
  // See waitForStdoutFlush's doc comment: without this, a large final
  // response can be truncated by process.exit() below.
  await waitForStdoutFlush();
  process.exit(code);
};

/**
 * Detect a `g0 proxy -- <command> [args...]` invocation directly from raw
 * CLI argv, bypassing commander's subcommand dispatch entirely when it's
 * present.
 *
 * Why this exists: commander's option/operand parser (`Command.parseOptions`)
 * strips a literal `--` separator without leaving any trace that it was
 * there — `g0 proxy -- install foo` and `g0 proxy install foo` both parse
 * down to the same `operands = ['install', 'foo']`. Commander then matches
 * `operands[0]` ('install') against the registered `install` subcommand
 * name and dispatches there, even though the user's `--` explicitly marked
 * `install` as the *wrapped command* to run, not a subcommand. That's a
 * stdout-purity bug: `g0 proxy` is a live stdio JSON-RPC MITM (see the
 * header comment below) and the `install` subcommand prints a human-
 * readable summary straight to stdout, corrupting the JSON-RPC stream an
 * IDE expects to read from this process.
 *
 * This function scans the raw argv (e.g. `process.argv.slice(2)`) for a
 * leading `proxy` token followed later by a bare `--`, and if found,
 * extracts the run-path command + the two options the run path understands
 * (`--server`, `--policy-dir`) itself — so the caller can invoke the run
 * path directly and skip commander (and its subcommand-name matching) for
 * this invocation entirely. Returns `undefined` when the pattern isn't
 * present, in which case the ordinary commander parse handles everything
 * else, including real subcommand invocations like `g0 proxy install`
 * (no `--`).
 */
export function detectProxyRunOverride(
  argv: string[],
): { command: string[]; options: { server?: string; policyDir?: string } } | undefined {
  if (argv[0] !== 'proxy') return undefined;
  const rest = argv.slice(1);
  const dashIdx = rest.indexOf('--');
  if (dashIdx === -1) return undefined;

  const before = rest.slice(0, dashIdx);
  const command = rest.slice(dashIdx + 1);
  const options: { server?: string; policyDir?: string } = {};
  for (let i = 0; i < before.length; i++) {
    if (before[i] === '--server') options.server = before[++i];
    else if (before[i] === '--policy-dir') options.policyDir = before[++i];
  }
  return { command, options };
}

/**
 * Run `detectProxyRunOverride` against raw argv and, if it matches, invoke
 * the run path directly (bypassing commander) and return `true`. Returns
 * `false` when the pattern doesn't match, so the caller falls through to
 * the normal `createCli().parse()` path. `runAction` always calls
 * `process.exit()`, so this function never returns when it handles the
 * invocation.
 */
export async function runProxyFromArgvOverride(argv: string[]): Promise<boolean> {
  const override = detectProxyRunOverride(argv);
  if (!override) return false;
  await runAction(override.command, override.options);
  return true;
}

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
      `  Calls: ${summary.totalCalls}   ${chalk.red(`Denied: ${summary.denied}`)}   ${chalk.yellow.bold(`Coached: ${summary.coached}`)}   ${chalk.yellow(`Alerted: ${summary.alerted}`)}   ${chalk.magenta(`Redacted: ${summary.redacted}`)}`,
    );
    console.log('');
  });

// ─────────────────────────────────────────────────────────────────────────
// logs
// ─────────────────────────────────────────────────────────────────────────

function actionColor(action: AuditRecord['action']): (s: string) => string {
  if (action === 'deny') return chalk.red;
  // `coach` is a louder warning than a plain `alert` (a would-be `deny`
  // downgraded by alert mode — see adjustAction in policy.ts): give it a
  // visually distinct, bolder color rather than silently falling through to
  // alert's plain yellow.
  if (action === 'coach') return chalk.yellow.bold;
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
// fingerprint (Exact-Data-Match corpus fingerprinting)
// ─────────────────────────────────────────────────────────────────────────

/**
 * Derive the index name from `--name` or the corpus file's basename (with
 * its extension stripped, e.g. `secrets.txt` -> `secrets`). Factored out
 * of the action so it's unit-testable without touching the filesystem —
 * mirrors `resolveRunTarget`'s split above.
 */
export function resolveFingerprintName(file: string, name?: string): string {
  if (name && name.length > 0) return name;
  const base = path.basename(file);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(0, dot) : base;
}

const fingerprintSubcommand = new Command('fingerprint')
  .description(
    'Fingerprint a corpus of secrets/sensitive lines for exact-data-match (EDM) detection — ' +
      'stores ONLY salted hashes + a bloom filter, never the corpus plaintext',
  )
  .argument('<file>', 'Path to a corpus file: one secret, DB value, or confidential doc line per line')
  .option('--name <name>', "Index name (defaults to the corpus file's basename)")
  .option(
    '--mode <mode>',
    'Tokenization mode: "line" (whole-value match — secrets, DB dumps) or "shingle" (word n-gram match — prose/doc fragments)',
    'line',
  )
  .option('--shingle-size <n>', 'Word-shingle size for --mode shingle', '5')
  .option('--policy-dir <path>', 'Policy + audit directory (default: ~/.g0/proxy)')
  .option('--json', 'Output as JSON')
  .option('--no-banner', 'Suppress the g0 banner')
  .action((file: string, options: { name?: string; mode?: string; shingleSize?: string; json?: boolean }, command: Command) => {
    const mode: EdmMode = options.mode === 'shingle' ? 'shingle' : 'line';
    const shingleSizeParsed = Number.parseInt(options.shingleSize ?? '5', 10);
    const shingleSize = Number.isFinite(shingleSizeParsed) && shingleSizeParsed > 0 ? shingleSizeParsed : 5;
    const name = resolveFingerprintName(file, options.name);
    // --policy-dir is declared on the top-level `proxyCommand` too, so read
    // the merged value via optsWithGlobals() — it works whether the flag
    // lands on this subcommand (`g0 proxy fingerprint f --policy-dir X`) or
    // on the parent (`g0 proxy --policy-dir X fingerprint f`). The load side
    // (loadEdmIndexes) already honors the policy dir; this fixes the write side.
    const policyDir = command.optsWithGlobals<{ policyDir?: string }>().policyDir;
    const outDir = fingerprintsDir(policyDir ?? PROXY_DIR);

    try {
      const result = buildAndWriteEdmIndex(file, outDir, { name, mode, shingleSize });

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
        return;
      }

      console.log(chalk.bold('\n  g0 proxy fingerprint'));
      console.log(chalk.dim('  ' + '─'.repeat(60)));
      console.log(`  Corpus: ${file}`);
      console.log(`  Mode: ${result.mode}${result.mode === 'shingle' ? ` (shingle size ${shingleSize})` : ''}`);
      console.log(`  Corpus lines read: ${result.entryCount}`);
      console.log(`  Entries fingerprinted: ${chalk.green(String(result.tokenCount))}`);
      console.log(`  Index written: ${chalk.cyan(result.filePath)}`);
      console.log(chalk.dim('\n  Only salted hashes + a bloom filter were written — the corpus contents were never persisted.\n'));
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (options.json) {
        console.log(JSON.stringify({ ok: false, message }));
      } else {
        console.error(chalk.red(`  Failed to fingerprint "${file}": ${message}`));
      }
      process.exitCode = 1;
    }
  });

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
proxyCommand.addCommand(fingerprintSubcommand);
