import { Command } from 'commander';
import { createSpinner } from '../ui.js';

export const detectCommand = new Command('detect')
  .description('Detect MDM enrollment, running AI agents, and host security posture')
  .option('--json', 'Output as JSON')
  .option('-q, --quiet', 'Suppress terminal output')
  .option('--upload', 'Upload results to Guard0 platform')
  .option('--section <name>', 'Run only a specific section (mdm|agents|host)')
  .action(async (options: { json?: boolean; quiet?: boolean; upload?: boolean; section?: string }) => {
    const spinner = options.quiet ? null : createSpinner('Detecting environment...');
    spinner?.start();

    try {
      const { detectMDM, getMDMSummary } = await import('../../endpoint/mdm-detect.js');
      const { detectRunningAgents, getAgentSummary } = await import('../../daemon/agent-watchers/index.js');
      const { auditHostHardening } = await import('../../endpoint/host-hardening.js');

      const runMdm = !options.section || options.section === 'mdm';
      const runAgents = !options.section || options.section === 'agents';
      const runHost = !options.section || options.section === 'host';

      const [mdm, agents, host] = await Promise.all([
        runMdm ? detectMDM() : null,
        runAgents ? detectRunningAgents() : null,
        runHost ? auditHostHardening() : null,
      ]);

      spinner?.stop();

      // JSON output
      if (options.json) {
        const output: Record<string, unknown> = {};
        if (mdm) output.mdm = mdm;
        if (agents) output.agents = agents;
        if (host) output.host = host;
        console.log(JSON.stringify(output, null, 2));

        // Upload if requested
        if (options.upload) {
          await uploadDetectResults(output, options.quiet);
        }
        return;
      }

      const chalk = (await import('chalk')).default;

      console.log('');
      console.log(chalk.bold('  g0 detect'));
      console.log(chalk.dim('  ' + '\u2500'.repeat(74)));

      // ── MDM Section ──────────────────────────────────────────────────────
      if (mdm) {
        console.log('');
        console.log(chalk.bold.underline('  MDM Status'));
        console.log('');

        if (mdm.managed) {
          const providerLabel = mdm.provider === 'unknown' ? 'Unknown Provider' : mdm.provider;
          console.log(`  ${chalk.yellow('\u26a0')}  Enrolled: ${chalk.cyan(providerLabel!)}`);
          console.log(`     Enrollment: ${chalk.dim(mdm.enrollmentStatus)}`);
        } else {
          console.log(`  ${chalk.green('\u2713')}  Not enrolled — host appears unmanaged`);
        }

        // Show evidence details for detected items
        const found = mdm.details.filter(d => d.found);
        if (found.length > 0) {
          console.log('');
          console.log(`  ${chalk.dim('Evidence:')}`);
          for (const detail of found) {
            const evidence = detail.evidence
              ? chalk.dim(` \u2014 ${detail.evidence.slice(0, 80)}`)
              : '';
            console.log(`    ${chalk.dim('\u2022')} ${detail.check}${evidence}`);
          }
        }

        const notFound = mdm.details.filter(d => !d.found);
        if (notFound.length > 0 && found.length === 0) {
          console.log(`  ${chalk.dim(`${notFound.length} checks ran, none matched`)}`);
        }
      }

      // ── Running AI Agents ────────────────────────────────────────────────
      if (agents) {
        console.log('');
        console.log(chalk.bold.underline('  Running AI Agents'));
        console.log('');

        const running = agents.agents.filter(a => a.status === 'running');
        const stopped = agents.agents.filter(a => a.status === 'stopped');
        const mcpServers = agents.agents.filter(a => a.type === 'mcp-server');
        const nonMcp = agents.agents.filter(a => a.type !== 'mcp-server');

        if (nonMcp.length === 0 && mcpServers.length === 0) {
          console.log(`  ${chalk.dim('No AI agents detected on')} ${chalk.cyan(agents.hostname)}`);
        } else {
          // Active agents
          for (const agent of running) {
            if (agent.type === 'mcp-server') continue;
            const pid = agent.pid ? chalk.dim(` (PID ${agent.pid})`) : '';
            const pathStr = agent.path ? chalk.dim(` \u2014 ${agent.path}`) : '';
            console.log(`  ${chalk.green('\u25cf')}  ${chalk.bold(agent.name)}${pid}${pathStr}`);
            if (agent.metadata?.claudeMdPath) {
              console.log(`     ${chalk.dim('CLAUDE.md:')} ${agent.metadata.claudeMdPath}`);
            }
          }

          // Stopped/installed agents
          for (const agent of stopped) {
            if (agent.type === 'mcp-server') continue;
            const pathStr = agent.path ? chalk.dim(` \u2014 ${agent.path}`) : '';
            console.log(`  ${chalk.dim('\u25cb')}  ${agent.name} ${chalk.dim('(installed, not running)')}${pathStr}`);
          }

          // MCP servers
          if (mcpServers.length > 0) {
            console.log('');
            console.log(`  ${chalk.dim('MCP Servers')} ${chalk.dim(`(${mcpServers.length} configured)`)}`);
            for (const server of mcpServers) {
              const configFile = server.metadata?.configFile
                ? chalk.dim(` \u2014 ${server.metadata.configFile as string}`)
                : '';
              console.log(`    ${chalk.dim('\u2022')} ${chalk.cyan(server.name)}${configFile}`);
            }
          }
        }

        console.log('');
        console.log(`  ${chalk.dim(`Host: ${agents.hostname}  |  Scanned: ${agents.timestamp}`)}`);
      }

      // ── Host Hardening ───────────────────────────────────────────────────
      if (host) {
        console.log('');
        console.log(chalk.bold.underline(`  Host Hardening (${host.platform})`));
        console.log('');

        const { passed, failed, errors, total } = host.summary;
        const scoreColor = failed === 0 ? chalk.green : failed <= 2 ? chalk.yellow : chalk.red;
        console.log(`  ${scoreColor(`${passed}/${total} checks passed`)}  ${failed > 0 ? chalk.red(`${failed} failed`) : ''}  ${errors > 0 ? chalk.dim(`${errors} errors`) : ''}`);
        console.log('');

        // Show all checks grouped by status
        const failedChecks = host.checks.filter(c => c.status === 'fail');
        const passedChecks = host.checks.filter(c => c.status === 'pass');
        const errorChecks = host.checks.filter(c => c.status === 'error');

        if (failedChecks.length > 0) {
          for (const check of failedChecks) {
            const sev = check.severity === 'critical' ? chalk.red(`[${check.severity}]`) :
                        check.severity === 'high' ? chalk.yellow(`[${check.severity}]`) :
                        chalk.dim(`[${check.severity}]`);
            console.log(`  ${chalk.red('\u2717')}  ${check.id} ${check.name} ${sev}`);
            if (check.detail) {
              console.log(`     ${chalk.dim(check.detail)}`);
            }
          }
          console.log('');
        }

        for (const check of passedChecks) {
          console.log(`  ${chalk.green('\u2713')}  ${check.id} ${check.name}`);
        }

        if (errorChecks.length > 0) {
          console.log('');
          for (const check of errorChecks) {
            console.log(`  ${chalk.dim('\u2013')}  ${check.id} ${check.name} ${chalk.dim(check.detail ?? 'error')}`);
          }
        }
      }

      console.log('');

      // ── Upload ───────────────────────────────────────────────────────────
      if (options.upload) {
        const output: Record<string, unknown> = {};
        if (mdm) output.mdm = mdm;
        if (agents) output.agents = agents;
        if (host) output.host = host;
        await uploadDetectResults(output, options.quiet);
      }
    } catch (err) {
      spinner?.stop();
      const message = err instanceof Error ? err.message : String(err);
      console.error(`Detection failed: ${message}`);
      if (message.includes('EACCES') || message.includes('permission')) {
        console.error('Hint: Some host checks require elevated privileges. Try running with sudo.');
      }
      process.exit(1);
    }
  });

async function uploadDetectResults(data: Record<string, unknown>, quiet?: boolean): Promise<void> {
  try {
    const { shouldUpload, uploadResults, collectMachineMeta, detectCIMeta } = await import('../../platform/upload.js');
    const uploadDecision = await shouldUpload(true);
    if (!uploadDecision.upload) {
      if (!quiet) {
        console.error('  Upload skipped: not authenticated. Run `g0 auth login` first.');
      }
      return;
    }
    const response = await uploadResults({
      type: 'host-hardening' as const,
      machine: collectMachineMeta(),
      result: data as unknown as import('../../endpoint/host-hardening.js').HostHardeningResult,
    });
    if (response && !quiet) {
      console.log(`\n  Uploaded to: ${response.url}`);
    }
  } catch (err) {
    if (!quiet) {
      console.error(`  Upload failed: ${err instanceof Error ? err.message : err}`);
    }
  }
}
