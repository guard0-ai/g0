import chalk from 'chalk';
import { getG0Version } from '../utils/version.js';

// Delegate to the single source of truth (utils/version.ts) so the compiled
// binary's version override applies here too, and the package.json read isn't
// duplicated.
function loadVersion(): string {
  return getG0Version();
}

export function printBanner(): void {
  const logo = chalk.bold.cyan(`
   ██████╗  ██████╗
  ██╔════╝ ██╔═████╗
  ██║  ███╗██║██╔██║
  ██║   ██║████╔╝██║
  ╚██████╔╝╚██████╔╝
   ╚═════╝  ╚═════╝
`);
  const tagline = chalk.dim('  Background Check for AI Agents');
  const version = chalk.dim(`  v${loadVersion()} by Guard0`);
  console.log(logo + tagline + '\n' + version + '\n');
}

export function getVersion(): string {
  return loadVersion();
}
