import chalk from 'chalk';
import type { ScanResult, AIAnalysisResult } from '../types/score.js';
import {
  printFinding,
  printDomainScores,
  printOverallScore,
  printSummary,
} from '../cli/ui.js';

export interface TerminalOptions {
  showBanner?: boolean;
}

export function reportTerminal(result: ScanResult, options?: TerminalOptions): void {
  const { findings, score, graph, duration, aiAnalysis } = result;

  // Header
  console.log(chalk.bold('\n  Scan Results'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  console.log(`  ${chalk.dim('Path:')} ${graph.rootPath}`);
  console.log(`  ${chalk.dim('Framework:')} ${graph.primaryFramework}${graph.secondaryFrameworks.length > 0 ? ` (+${graph.secondaryFrameworks.join(', ')})` : ''}`);
  console.log(`  ${chalk.dim('Files scanned:')} ${graph.files.all.length}`);
  console.log(`  ${chalk.dim('Agents:')} ${graph.agents.length}  ${chalk.dim('Tools:')} ${graph.tools.length}  ${chalk.dim('Prompts:')} ${graph.prompts.length}`);
  console.log(`  ${chalk.dim('Duration:')} ${(duration / 1000).toFixed(1)}s`);
  if (aiAnalysis) {
    console.log(`  ${chalk.dim('AI Analysis:')} ${aiAnalysis.provider} (${(aiAnalysis.duration / 1000).toFixed(1)}s)`);
  }

  // Findings by severity
  if (findings.length > 0) {
    console.log(chalk.bold('\n  Findings'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));

    const sorted = [...findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    });

    for (let i = 0; i < sorted.length; i++) {
      printFinding(sorted[i], i);

      // Show AI enrichment inline if available
      if (aiAnalysis) {
        const enrichment = aiAnalysis.enrichments.get(sorted[i].id);
        if (enrichment) {
          if (enrichment.falsePositive) {
            console.log(chalk.yellow(`    AI: Likely false positive — ${enrichment.falsePositiveReason}`));
          }
          if (enrichment.explanation) {
            console.log(chalk.magenta(`    AI: ${enrichment.explanation}`));
          }
        }
      }
    }
  } else {
    console.log(chalk.green.bold('\n  No security findings detected!'));
  }

  // AI complex findings
  if (aiAnalysis && aiAnalysis.complexFindings.length > 0) {
    console.log(chalk.bold('\n  AI-Detected Patterns'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const cf of aiAnalysis.complexFindings) {
      const sevLabel = cf.severity.toUpperCase().padEnd(8);
      console.log(`\n  ${chalk.magenta(` ${sevLabel} `)} ${chalk.bold(cf.title)}`);
      console.log(`    ${cf.description}`);
    }
  }

  // Summary
  printSummary(findings);

  // Domain scores
  printDomainScores(score.domains);

  // Overall score
  printOverallScore(score);
  console.log('');
}
