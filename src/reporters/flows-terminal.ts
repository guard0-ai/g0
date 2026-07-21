import chalk from 'chalk';
import type { FlowAnalysisResult, ToxicFlowSeverity } from '../types/flow.js';

export function reportFlowsTerminal(result: FlowAnalysisResult): void {
  console.log(chalk.bold('\n  Agent Flow Analysis'));
  console.log(chalk.dim('  ' + '═'.repeat(60)));

  // Flow graph summary
  console.log(chalk.bold.cyan('\n  Flow Graph'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`  Nodes: ${result.summary.totalNodes}  Edges: ${result.summary.totalEdges}  Paths: ${result.summary.totalPaths}`);

  // Status badge
  const statusBadge = result.summary.riskLevel === 'critical'
    ? chalk.bgRed.black.bold(' CRITICAL ')
    : result.summary.riskLevel === 'warning'
      ? chalk.bgYellow.black.bold(' WARNING ')
      : chalk.bgGreen.white.bold(' SAFE ');
  console.log(`  Status: ${statusBadge}`);

  // Flow tree visualization
  if (result.paths.length > 0) {
    console.log(chalk.bold.cyan('\n  Flow Paths'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));

    // Show top 20 paths by risk score
    const topPaths = [...result.paths]
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 20);

    for (const path of topPaths) {
      const risk = path.riskScore;
      const badge = risk >= 60 ? chalk.red(`[${risk}]`) :
        risk >= 30 ? chalk.yellow(`[${risk}]`) :
          chalk.green(`[${risk}]`);
      console.log(`  ${badge} ${chalk.dim(path.description)}`);
    }

    if (result.paths.length > 20) {
      console.log(chalk.dim(`  ... and ${result.paths.length - 20} more paths`));
    }
  }

  // Toxic flows
  if (result.toxicFlows.length > 0) {
    console.log(chalk.bold.red('\n  Toxic Flows'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));

    for (const toxic of result.toxicFlows) {
      const badge = toxicBadge(toxic.severity);
      console.log(`\n  ${badge} ${chalk.bold(toxic.title)}`);
      console.log(`    ${toxic.description}`);
      console.log(`    ${chalk.dim('Path:')} ${toxic.path.join(' -> ')}`);
      console.log(`    ${chalk.dim('Risk Score:')} ${toxic.riskScore}`);
    }
  } else {
    console.log(chalk.green.bold('\n  No toxic flows detected.'));
  }

  // Summary
  console.log(chalk.bold('\n  Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`  Total paths: ${result.summary.totalPaths}  Toxic flows: ${result.summary.toxicFlowCount}  Max risk: ${result.summary.maxRiskScore}`);
  console.log('');
}

function toxicBadge(severity: ToxicFlowSeverity): string {
  switch (severity) {
    case 'critical': return chalk.bgRed.black.bold(' CRIT ');
    case 'high': return chalk.red.bold(' HIGH ');
    case 'medium': return chalk.yellow(' MED  ');
  }
}
