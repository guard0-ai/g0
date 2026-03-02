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
  showUploadNudge?: boolean;
  hiddenLowConfidence?: number;
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
    if (aiAnalysis.excludedCount && aiAnalysis.excludedCount > 0) {
      console.log(chalk.dim(`    ${aiAnalysis.excludedCount} finding(s) excluded as false positives`));
    }
  }

  // Security Metadata (from enrichment layer)
  const hasEnrichment = graph.apiEndpoints.length > 0 || graph.databaseAccesses.length > 0 ||
    graph.authFlows.length > 0 || graph.permissionChecks.length > 0 ||
    graph.piiReferences.length > 0 || graph.messageQueues.length > 0 ||
    graph.rateLimits.length > 0 || graph.callGraph.length > 0 || graph.permissions.length > 0;
  if (hasEnrichment) {
    console.log(chalk.bold.cyan('\n  Security Metadata'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    const items: string[] = [];
    if (graph.apiEndpoints.length > 0) {
      const ext = graph.apiEndpoints.filter(e => e.isExternal).length;
      items.push(`API Endpoints: ${graph.apiEndpoints.length} (${ext} external)`);
    }
    if (graph.databaseAccesses.length > 0) {
      const unparam = graph.databaseAccesses.filter(d => d.type === 'sql' && !d.hasParameterizedQuery).length;
      let db = `DB Accesses: ${graph.databaseAccesses.length}`;
      if (unparam > 0) db += chalk.red(` (${unparam} unparameterized)`);
      items.push(db);
    }
    if (graph.authFlows.length > 0) items.push(`Auth Flows: ${graph.authFlows.length}`);
    if (graph.permissionChecks.length > 0) items.push(`Permission Checks: ${graph.permissionChecks.length}`);
    if (graph.permissions.length > 0) items.push(`Prompt Permissions: ${graph.permissions.length}`);
    if (graph.piiReferences.length > 0) {
      const unmasked = graph.piiReferences.filter(p => !p.hasMasking).length;
      let pii = `PII References: ${graph.piiReferences.length}`;
      if (unmasked > 0) pii += chalk.yellow(` (${unmasked} unmasked)`);
      items.push(pii);
    }
    if (graph.messageQueues.length > 0) items.push(`Message Queues: ${graph.messageQueues.length}`);
    if (graph.rateLimits.length > 0) items.push(`Rate Limits: ${graph.rateLimits.length}`);
    if (graph.callGraph.length > 0) items.push(`Call Graph Edges: ${graph.callGraph.length}`);
    for (const item of items) {
      console.log(`  ${item}`);
    }
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

  // Suppressed count
  if (result.suppressedCount && result.suppressedCount > 0) {
    console.log(chalk.dim(`\n  + ${result.suppressedCount} utility-code findings suppressed (use --show-all)`));
  }

  // Hidden low-confidence count
  if (options?.hiddenLowConfidence && options.hiddenLowConfidence > 0) {
    console.log(chalk.dim(`  + ${options.hiddenLowConfidence} low-confidence findings hidden (use --min-confidence low)`));
  }

  // Summary
  printSummary(findings);

  // Domain scores
  printDomainScores(score.domains);

  // Overall score
  printOverallScore(score);

  // Upload nudge (shown when not authenticated and --upload not used)
  if (options?.showUploadNudge) {
    console.log(chalk.dim('\n  See your agent architecture \u2192 g0 scan . --upload (free at guard0.ai)'));
  }

  // Split scores (security vs hardening)
  if (score.securityScore !== undefined && score.hardeningScore !== undefined) {
    console.log(chalk.dim(`\n  Security: ${score.securityScore}/100  |  Hardening: ${score.hardeningScore}/100`));
  }

  console.log('');
}
