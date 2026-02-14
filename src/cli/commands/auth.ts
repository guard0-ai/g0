import chalk from 'chalk';
import { Command } from 'commander';
import {
  loadTokens,
  clearTokens,
  saveTokens,
  resolveToken,
  isAuthenticated,
  startDeviceFlow,
  pollForToken,
  getAuthFilePath,
} from '../../platform/auth.js';
import { createSpinner } from '../ui.js';

export const authCommand = new Command('auth')
  .description('Authenticate with the Guard0 platform');

// ─── g0 auth login ───────────────────────────────────────────────────────────

const loginCommand = new Command('login')
  .description('Authenticate with Guard0 platform via browser')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(async () => {
    if (process.env.G0_API_TOKEN) {
      console.log(chalk.yellow('  G0_API_TOKEN is set. Unset it to use interactive login.'));
      return;
    }

    // Check if already authenticated
    const existing = loadTokens();
    if (existing && existing.expiresAt > Date.now()) {
      console.log(chalk.green(`  Already authenticated${existing.email ? ` as ${existing.email}` : ''}.`));
      console.log(chalk.dim('  Run `g0 auth logout` first to re-authenticate.'));
      return;
    }

    console.log(chalk.bold('\n  Guard0 Authentication\n'));

    const spinner = createSpinner('Starting device authorization...');
    spinner.start();

    try {
      const deviceCode = await startDeviceFlow();
      spinner.stop();

      console.log(chalk.bold('  Open this URL in your browser:\n'));
      console.log(chalk.cyan(`    ${deviceCode.verificationUri}\n`));
      console.log(`  Enter code: ${chalk.bold.yellow(deviceCode.userCode)}\n`);

      // Try to open browser automatically
      try {
        const { exec } = await import('node:child_process');
        const cmd = process.platform === 'darwin' ? 'open'
          : process.platform === 'win32' ? 'start'
          : 'xdg-open';
        exec(`${cmd} ${deviceCode.verificationUri}`);
      } catch {
        // Non-fatal: user can open manually
      }

      const pollSpinner = createSpinner('Waiting for authorization...');
      pollSpinner.start();

      const tokens = await pollForToken(
        deviceCode.deviceCode,
        deviceCode.interval,
        deviceCode.expiresIn,
      );

      saveTokens(tokens);
      pollSpinner.stop();

      console.log(chalk.green(`\n  Authenticated successfully${tokens.email ? ` as ${chalk.bold(tokens.email)}` : ''}!`));
      console.log(chalk.dim(`  Token stored in ${getAuthFilePath()}\n`));
    } catch (err) {
      spinner.stop();
      console.error(chalk.red(`  Login failed: ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
  });

// ─── g0 auth logout ──────────────────────────────────────────────────────────

const logoutCommand = new Command('logout')
  .description('Remove stored authentication tokens')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(() => {
    clearTokens();
    console.log(chalk.green('  Logged out. Token cleared.'));

    if (process.env.G0_API_TOKEN) {
      console.log(chalk.yellow('  Note: G0_API_TOKEN env var is still set.'));
    }
  });

// ─── g0 auth status ──────────────────────────────────────────────────────────

const statusCommand = new Command('status')
  .description('Show current authentication status')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(() => {
    console.log(chalk.bold('\n  Auth Status\n'));

    // Check env var
    if (process.env.G0_API_TOKEN) {
      const prefix = process.env.G0_API_TOKEN.substring(0, 8);
      console.log(chalk.green('  Authenticated via G0_API_TOKEN'));
      console.log(chalk.dim(`  Key prefix: ${prefix}...`));
      console.log('');
      return;
    }

    // Check stored tokens
    const tokens = loadTokens();
    if (!tokens) {
      console.log(chalk.yellow('  Not authenticated.'));
      console.log(chalk.dim('  Run `g0 auth login` to authenticate.\n'));
      return;
    }

    const expired = tokens.expiresAt < Date.now();
    if (expired) {
      console.log(chalk.yellow('  Token expired.'));
      console.log(chalk.dim('  Run `g0 auth login` to re-authenticate.\n'));
      return;
    }

    console.log(chalk.green('  Authenticated'));
    if (tokens.email) console.log(`  Email:   ${tokens.email}`);
    if (tokens.userId) console.log(`  User ID: ${chalk.dim(tokens.userId)}`);
    if (tokens.orgId) console.log(`  Org ID:  ${chalk.dim(tokens.orgId)}`);
    const expiresIn = Math.round((tokens.expiresAt - Date.now()) / 1000 / 60);
    console.log(`  Expires: ${chalk.dim(`in ${expiresIn} minutes`)}`);
    console.log('');
  });

// ─── g0 auth token ───────────────────────────────────────────────────────────

const tokenCommand = new Command('token')
  .description('Print the current access token (for piping to other tools)')
  .option('--no-banner', 'Suppress the g0 banner')
  .action(() => {
    const token = resolveToken();
    if (!token) {
      console.error('Not authenticated');
      process.exit(1);
    }
    // Print raw token to stdout for piping
    process.stdout.write(token);
  });

authCommand.addCommand(loginCommand);
authCommand.addCommand(logoutCommand);
authCommand.addCommand(statusCommand);
authCommand.addCommand(tokenCommand);
