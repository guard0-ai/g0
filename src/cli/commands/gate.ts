import * as path from 'node:path';
import * as fs from 'node:fs';
import { Command } from 'commander';
import chalk from 'chalk';
import { runScan } from '../../pipeline.js';
import { reportJson } from '../../reporters/json.js';
import { reportSarif } from '../../reporters/sarif.js';
import { loadConfig } from '../../config/loader.js';
import { createSpinner } from '../ui.js';

export const gateCommand = new Command('gate')
  .description('CI/CD gate — exits with code 1 if scan fails thresholds')
  .argument('[path]', 'Path to the agent project', '.')
  .option('--min-score <score>', 'Minimum overall score (0-100)', '70')
  .option('--min-grade <grade>', 'Minimum grade (A, B, C, D)')
  .option('--no-critical', 'Fail if any critical findings')
  .option('--no-high', 'Fail if any high or critical findings')
  .option('-o, --output <file>', 'Write JSON report to file')
  .option('--config <file>', 'Path to config file (default: .g0.yaml)')
  .option('--sarif [file]', 'Also output SARIF report')
  .option('--upload', 'Upload results to Guard0 platform')
  .action(async (targetPath: string, options: {
    minScore?: string;
    minGrade?: string;
    critical?: boolean;
    high?: boolean;
    output?: string;
    config?: string;
    sarif?: string | boolean;
    upload?: boolean;
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

      const failures: string[] = [];

      // Check minimum score
      if (result.score.overall < minScore) {
        failures.push(`Score ${result.score.overall} is below minimum ${minScore}`);
      }

      // Check minimum grade
      if (minGrade) {
        const gradeOrder: Record<string, number> = { A: 5, B: 4, C: 3, D: 2, F: 1 };
        const requiredLevel = gradeOrder[minGrade.toUpperCase()] ?? 3;
        const actualLevel = gradeOrder[result.score.grade] ?? 1;
        if (actualLevel < requiredLevel) {
          failures.push(`Grade ${result.score.grade} is below minimum ${minGrade.toUpperCase()}`);
        }
      }

      // Check critical findings
      if (options.critical === false) {
        const criticalCount = result.findings.filter(f => f.severity === 'critical').length;
        if (criticalCount > 0) {
          failures.push(`${criticalCount} critical finding(s) detected`);
        }
      }

      // Check high findings
      if (options.high === false) {
        const highCount = result.findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
        if (highCount > 0) {
          failures.push(`${highCount} high/critical finding(s) detected`);
        }
      }

      // Check fail_on from config
      if (config?.fail_on) {
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const threshold = severityOrder[config.fail_on] ?? 0;
        const violating = result.findings.filter(f => (severityOrder[f.severity] ?? 4) <= threshold);
        if (violating.length > 0) {
          failures.push(`${violating.length} finding(s) at or above ${config.fail_on} severity`);
        }
      }

      if (failures.length > 0) {
        console.log(chalk.red.bold('\n  GATE FAILED'));
        for (const failure of failures) {
          console.log(chalk.red(`  - ${failure}`));
        }
        console.log(`\n  Score: ${result.score.overall}/100 (${result.score.grade})`);
        console.log(`  Findings: ${result.findings.length}\n`);
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
