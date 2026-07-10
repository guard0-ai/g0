import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { runScan } from '../../pipeline.js';
import { reportJson } from '../../reporters/json.js';
import { reportSarif } from '../../reporters/sarif.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';
import { maybeShowCta } from '../../platform/cta.js';
import {
  buildBaseline,
  writeBaseline,
  loadBaseline,
  diffAgainstBaseline,
} from '../../ci/baseline.js';
import { evaluateGate } from '../../ci/thresholds.js';
import type { Finding } from '../../types/finding.js';
import { G0_VERSION } from '../../utils/version.js';

export const gateCommand = new Command('gate')
  .description('CI/CD gate — exits with code 1 if scan fails thresholds')
  .argument('[path]', 'Path to the agent project', '.')
  .option('--min-score <score>', 'Minimum overall score (0-100)', '70')
  .option('--min-grade <grade>', 'Minimum grade (A, B, C, D)')
  .option('--no-critical', 'Fail if any critical findings')
  .option('--no-high', 'Fail if any high or critical findings')
  .option('--baseline <file>', 'Regression mode: only fail on findings new vs this baseline')
  .option('--write-baseline <file>', 'Snapshot current findings to a baseline file and exit')
  .option('-o, --output <file>', 'Write JSON report to file')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .option('--sarif [file]', 'Also output SARIF report')
  .action(async (targetPath: string, options: {
    minScore?: string;
    minGrade?: string;
    critical?: boolean;
    high?: boolean;
    baseline?: string;
    writeBaseline?: string;
    output?: string;
    config?: string;
    sarif?: string | boolean;
  }) => {
    const resolvedPath = path.resolve(targetPath);

    if (!fs.existsSync(resolvedPath)) {
      console.error(`Error: Path does not exist: ${resolvedPath}`);
      process.exit(1);
    }

    // Load config
    let config;
    try {
      config = loadConfig(resolvedPath, options.config) ?? undefined;
    } catch (err) {
      console.error(`Config error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }

    // Config values as defaults, CLI flags override
    const minScore = parseInt(options.minScore ?? String(config?.min_score ?? 70));
    const minGrade = options.minGrade ?? config?.min_grade;

    const spinner = createSpinner('Running security gate...');
    spinner.start();

    try {
      const result = await runScan({ targetPath: resolvedPath, config });
      spinner.stop();

      if (options.output) {
        reportJson(result, options.output);
      }

      if (options.sarif) {
        const sarifPath = typeof options.sarif === 'string'
          ? options.sarif
          : undefined;
        reportSarif(result, sarifPath);
      }

      // Snapshot mode: write a baseline of current findings and exit.
      if (options.writeBaseline) {
        const baseline = buildBaseline(result.findings, G0_VERSION, new Date().toISOString());
        writeBaseline(options.writeBaseline, baseline);
        console.log(chalk.cyan.bold('\n  BASELINE WRITTEN'));
        console.log(`  ${baseline.fingerprints.length} unique finding(s) recorded → ${options.writeBaseline}`);
        console.log(chalk.dim('  Future runs with --baseline will fail only on NEW findings.\n'));
        process.exit(0);
      }

      // Regression mode: evaluate only findings new relative to the baseline.
      let evalFindings: Finding[] = result.findings;
      let baselineNote = '';
      if (options.baseline) {
        const baseline = loadBaseline(options.baseline);
        if (!baseline) {
          console.error(chalk.red(`  Baseline not found or unreadable: ${options.baseline}`));
          console.error(chalk.dim('  Create one with:  g0 gate --write-baseline ' + options.baseline));
          process.exit(2);
        }
        const diff = diffAgainstBaseline(result.findings, baseline);
        evalFindings = diff.newFindings;
        baselineNote = `Baseline mode: ${diff.knownCount} known finding(s) ignored, ${diff.newFindings.length} new evaluated`;
      }

      // Absolute posture gates (score/grade) apply to the whole project, so they
      // are skipped in regression mode where pre-existing debt is intentionally
      // tolerated. Finding-count gates apply to the evaluated set (new-only in
      // baseline mode, all findings otherwise).
      const inBaselineMode = Boolean(options.baseline);

      const { passed, failures } = evaluateGate({
        result,
        evalFindings,
        minScore,
        minGrade,
        failCritical: options.critical === false,
        failHigh: options.high === false,
        failOn: config?.fail_on,
        inBaselineMode,
      });

      if (baselineNote) {
        console.log(chalk.dim(`\n  ${baselineNote}`));
      }

      if (!passed) {
        console.log(chalk.red.bold('\n  GATE FAILED'));
        for (const failure of failures) {
          console.log(chalk.red(`  - ${failure}`));
        }
        console.log(`\n  Score: ${result.score.overall}/100 (${result.score.grade})`);
        console.log(`  Findings: ${result.findings.length}\n`);
        // Suppressed on CI/non-TTY by maybeShowCta itself — only fires when a
        // developer runs `gate` locally in a terminal.
        maybeShowCta('gate-failed', { detail: 'gate failed', configCta: config?.cta });
        process.exit(1);
      } else {
        console.log(chalk.green.bold('\n  GATE PASSED'));
        console.log(`  Score: ${result.score.overall}/100 (${result.score.grade})`);
        console.log(`  Findings: ${result.findings.length}\n`);
        process.exit(0);
      }
    } catch (error) {
      spinner.stop();
      console.error('Gate check failed:', error instanceof Error ? error.message : error);
      process.exit(2);
    }
  });
