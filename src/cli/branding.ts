import chalk from 'chalk';

const VERSION = '1.0.0';

export function printBanner(): void {
  const logo = chalk.bold.cyan(`
   ██████╗  ██████╗
  ██╔════╝ ██╔═████╗
  ██║  ███╗██║██╔██║
  ██║   ██║████╔╝██║
  ╚██████╔╝╚██████╔╝
   ╚═════╝  ╚═════╝
`);
  const tagline = chalk.dim('  AI Agent Security Scanner');
  const version = chalk.dim(`  v${VERSION}`);
  console.log(logo + tagline + '\n' + version + '\n');
}

export function getVersion(): string {
  return VERSION;
}
