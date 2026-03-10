import { Command } from 'commander';
import { createSpinner } from '../ui.js';

export const detectCommand = new Command('detect')
  .description('Detect MDM enrollment, running AI agents, and host security posture')
  .option('--json', 'Output as JSON')
  .option('-q, --quiet', 'Suppress terminal output')
  .option('--upload', 'Upload results to Guard0 platform')
  .action(async (options: { json?: boolean; quiet?: boolean; upload?: boolean }) => {
    const spinner = options.quiet ? null : createSpinner('Detecting environment...');
    spinner?.start();

    try {
      const { detectMDM, getMDMSummary } = await import('../../endpoint/mdm-detect.js');
      const { detectRunningAgents, getAgentSummary } = await import('../../daemon/agent-watchers/index.js');
      const { auditHostHardening } = await import('../../endpoint/host-hardening.js');

      const [mdm, agents, host] = await Promise.all([
        detectMDM(),
        detectRunningAgents(),
        auditHostHardening(),
      ]);

      spinner?.stop();

      if (options.json) {
        console.log(JSON.stringify({ mdm, agents, host }, null, 2));
        return;
      }

      const chalk = (await import('chalk')).default;

      // MDM Section
      console.log('');
      console.log(chalk.bold('  MDM Detection'));
      console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
      const mdmIcon = mdm.managed ? chalk.yellow('\u26a0') : chalk.green('\u2713');
      console.log(`  ${mdmIcon} ${getMDMSummary(mdm)}`);
      if (mdm.managed && mdm.provider) {
        console.log(`    Provider: ${chalk.cyan(mdm.provider)}`);
      }
      for (const detail of mdm.details.filter(d => d.found)) {
        console.log(`    ${chalk.dim(detail.check)}: ${detail.evidence ?? 'detected'}`);
      }

      // Running Agents
      console.log('');
      console.log(chalk.bold('  Running AI Agents'));
      console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
      console.log(`  ${getAgentSummary(agents)}`);
      for (const agent of agents.agents.filter(a => a.status === 'running')) {
        console.log(`    ${chalk.cyan(agent.type)}: ${agent.name}${agent.pid ? ` (PID ${agent.pid})` : ''}`);
      }
      if (agents.agents.filter(a => a.status === 'running').length === 0) {
        console.log(`    ${chalk.dim('No active AI agents detected')}`);
      }

      // Host Hardening Summary
      console.log('');
      console.log(chalk.bold(`  Host Hardening (${host.platform})`));
      console.log(chalk.dim('  ' + '\u2500'.repeat(74)));
      const passed = host.checks.filter(c => c.status === 'pass').length;
      const failed = host.checks.filter(c => c.status === 'fail').length;
      console.log(`  ${chalk.green(`${passed} passed`)}  ${chalk.red(`${failed} failed`)}`);
      for (const check of host.checks.filter(c => c.status === 'fail')) {
        console.log(`    ${chalk.red('\u2717')} ${check.id}: ${check.name}`);
      }
      console.log('');
    } catch (err) {
      spinner?.stop();
      console.error(`Detection failed: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
  });
