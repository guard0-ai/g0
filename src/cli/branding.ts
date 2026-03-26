import chalk from 'chalk';
import { createRequire } from 'node:module';

let _version: string | undefined;

function loadVersion(): string {
  if (_version) return _version;
  try {
    const require = createRequire(import.meta.url);
    const pkg = require('../../package.json');
    _version = pkg.version ?? '0.1.0';
  } catch {
    _version = '0.1.0';
  }
  return _version!;
}

export function printBanner(): void {
  const logo = chalk.bold.cyan(`
   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ██████╗
  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔═████╗
  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║██╔██║
  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║████╔╝██║
  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝╚██████╔╝
   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝
`);
  const tagline = chalk.dim('  The Control Layer for AI Agents');
  const version = chalk.dim(`  v${loadVersion()} — guard0.ai`);
  console.log(logo + tagline + '\n' + version + '\n');
}

export function getVersion(): string {
  return loadVersion();
}
