import chalk from 'chalk';
import type { SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult } from '../protect/types.js';

export function reportProtectPlan(plans: SurfacePlan[]): void {
  for (const plan of plans) {
    console.log(chalk.bold(`\n[${plan.surface}]`));
    if (plan.steps.length === 0) {
      console.log(chalk.dim('  nothing to change — already protected, or nothing discovered'));
    }
    for (const step of plan.steps) {
      console.log(`  ${chalk.green('+')} ${step.description}`);
      for (const file of step.files) console.log(chalk.dim(`      ${file}`));
    }
    if (plan.advisories.length > 0) {
      console.log(chalk.bold('  advisories (report-only):'));
      for (const advisory of plan.advisories) {
        console.log(`  ${chalk.yellow('!')} [${advisory.severity}] ${advisory.description}`);
      }
    }
  }
  console.log(chalk.dim('\nDry-run only. Re-run with --apply to make these changes; `g0 protect off` restores them.'));
}

export function reportProtectApply(results: SurfaceApplyResult[], manifestPath: string): void {
  for (const result of results) {
    console.log(chalk.bold(`\n[${result.surface}]`));
    for (const id of result.applied) console.log(`  ${chalk.green('✓')} ${id}`);
    for (const skip of result.skipped) console.log(chalk.dim(`  - skipped: ${skip.reason}`));
    for (const error of result.errors) console.log(`  ${chalk.red('✗')} ${error}`);
  }
  console.log(chalk.dim(`\nSession manifest: ${manifestPath}`));
  console.log(chalk.dim('Undo everything with: g0 protect off'));
}

export function reportProtectStatus(statuses: SurfaceStatus[]): void {
  for (const status of statuses) {
    // Black-on-color badges — same legibility rule as the 2.1.0 badge fix.
    const badge = status.protected ? chalk.black.bgGreen(' PROTECTED ') : chalk.black.bgYellow(' OFF ');
    console.log(`\n${badge} ${chalk.bold(`[${status.surface}]`)} ${status.summary}`);
    for (const line of status.detail) console.log(chalk.dim(`  ${line}`));
  }
}

export function reportProtectUndo(results: SurfaceUndoResult[], manifestPath: string | null): void {
  for (const result of results) {
    console.log(chalk.bold(`\n[${result.surface}]`));
    for (const id of result.restored) console.log(`  ${chalk.green('✓')} restored: ${id}`);
    for (const skip of result.skipped) console.log(chalk.dim(`  - skipped: ${skip.reason}`));
    for (const error of result.errors) console.log(`  ${chalk.red('✗')} ${error}`);
  }
  if (manifestPath) console.log(chalk.dim(`\nFrom manifest: ${manifestPath}`));
}
