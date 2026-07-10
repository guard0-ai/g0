// `g0 login` — OAuth device flow (default) or API key (--api-key) authentication
// against the guard0.ai platform.
//
// The network/poll orchestration lives in the exported `runDeviceLogin` /
// `runApiKeyLogin` helpers, which take an injectable `deps` bag so tests can
// drive the whole flow with fakes — zero real timers, zero real network. The
// commander `.action` below is a thin wrapper that supplies the real deps
// (dynamically imported platform modules, a real sleep, Date.now, etc).
import { execFile } from 'node:child_process';
import { Command } from 'commander';
import chalk from 'chalk';
import { createSpinner } from '../ui.js';
import { DeviceFlowError } from '../../platform/client.js';
import type { DeviceCodeResponse, TokenResponse, MeResponse } from '../../platform/client.js';
import type { StoredAuth } from '../../platform/auth.js';
import type { Entitlements } from '../../platform/entitlements.js';

export interface LoginResult {
  ok: boolean;
  email?: string;
  plan?: string;
  features?: string[];
  error?: string;
}

// ─── Device flow ─────────────────────────────────────────────────────────────

export interface DeviceLoginDeps {
  startDeviceFlow: () => Promise<DeviceCodeResponse>;
  pollDeviceToken: (deviceCode: string) => Promise<TokenResponse>;
  saveTokens: (tokens: StoredAuth, dir?: string) => void;
  refreshEntitlements: (dir?: string) => Promise<Entitlements | null>;
  openBrowser: (url: string) => void | Promise<void>;
  /** Whether to attempt opening a browser at all — decided by the caller (TTY/CI/--no-browser). */
  shouldOpenBrowser: boolean;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
  log: (msg: string) => void;
  dir?: string;
}

/**
 * Runs the OAuth device-authorization flow end to end: starts the flow,
 * (maybe) opens a browser, then polls until the user approves, the code
 * expires, or the overall deadline (`expires_in`) is hit.
 */
export async function runDeviceLogin(deps: DeviceLoginDeps): Promise<LoginResult> {
  let device: DeviceCodeResponse;
  try {
    device = await deps.startDeviceFlow();
  } catch (err) {
    return { ok: false, error: `Failed to start device login: ${errorMessage(err)}` };
  }

  const { device_code, user_code, verification_uri, verification_uri_complete, expires_in } = device;
  let interval = device.interval && device.interval > 0 ? device.interval : 5;

  deps.log(`Enter code ${user_code} at ${verification_uri}`);
  deps.log(`Or open: ${verification_uri_complete}`);

  if (deps.shouldOpenBrowser) {
    try {
      await deps.openBrowser(verification_uri_complete);
    } catch {
      // Never fatal — the user can still open the URL manually.
    }
  }

  const deadline = deps.now() + expires_in * 1000;

  for (;;) {
    if (deps.now() >= deadline) {
      return { ok: false, error: 'Login timed out waiting for approval. Run `g0 login` again.' };
    }

    try {
      const token = await deps.pollDeviceToken(device_code);
      const storedAuth: StoredAuth = {
        tokenType: 'oauth',
        accessToken: token.access_token,
        refreshToken: token.refresh_token,
        expiresAt: deps.now() + token.expires_in * 1000,
        email: token.email,
        userId: token.user_id,
        orgId: token.org_id,
      };
      deps.saveTokens(storedAuth, deps.dir);
      const entitlements = await deps.refreshEntitlements(deps.dir);
      return {
        ok: true,
        email: token.email,
        plan: entitlements?.plan,
        features: entitlements?.features,
      };
    } catch (err) {
      if (err instanceof DeviceFlowError) {
        const handled = handleDeviceFlowError(err);
        if (handled.result) return handled.result;
        if (handled.error === 'slow_down') {
          interval += 5;
        }
        deps.log('Waiting for approval...');
        await deps.sleep(interval * 1000);
        continue;
      }
      return { ok: false, error: errorMessage(err) };
    }
  }
}

function handleDeviceFlowError(err: DeviceFlowError): { result?: LoginResult; error: string } {
  switch (err.error) {
    case 'authorization_pending':
      return { error: err.error };
    case 'slow_down':
      return { error: err.error };
    case 'expired_token':
      return { result: { ok: false, error: 'Code expired. Run `g0 login` again.' }, error: err.error };
    case 'access_denied':
      return { result: { ok: false, error: 'Access denied.' }, error: err.error };
    default:
      return { result: { ok: false, error: `Device flow error: ${err.error}` }, error: err.error };
  }
}

// ─── API key flow ────────────────────────────────────────────────────────────

export interface ApiKeyLoginDeps {
  apiKey: string;
  fetchMe: (token: string) => Promise<MeResponse>;
  saveTokens: (tokens: StoredAuth, dir?: string) => void;
  refreshEntitlements: (dir?: string) => Promise<Entitlements | null>;
  dir?: string;
}

export async function runApiKeyLogin(deps: ApiKeyLoginDeps): Promise<LoginResult> {
  let me: MeResponse;
  try {
    me = await deps.fetchMe(deps.apiKey);
  } catch (err) {
    return { ok: false, error: `Invalid API key: ${errorMessage(err)}` };
  }

  const storedAuth: StoredAuth = {
    tokenType: 'api-key',
    accessToken: deps.apiKey,
    expiresAt: 0,
    email: me.email,
    userId: me.user_id,
    orgId: me.org_id,
  };
  deps.saveTokens(storedAuth, deps.dir);
  const entitlements = await deps.refreshEntitlements(deps.dir);
  return {
    ok: true,
    email: me.email,
    plan: entitlements?.plan ?? me.plan,
    features: entitlements?.features,
  };
}

// ─── Browser helper ──────────────────────────────────────────────────────────

/** Best-effort browser open. Never throws — swallows ENOENT/no-DISPLAY/etc. */
export function openBrowser(url: string): void {
  try {
    if (process.platform === 'darwin') {
      execFile('open', [url], () => {});
    } else if (process.platform === 'win32') {
      execFile('cmd', ['/c', 'start', '""', url], () => {});
    } else {
      execFile('xdg-open', [url], () => {});
    }
  } catch {
    // Non-fatal — the user can open the URL manually.
  }
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function printLoginResult(result: LoginResult, json: boolean): void {
  if (json) {
    console.log(
      JSON.stringify(
        result.ok
          ? { ok: true, email: result.email, plan: result.plan }
          : { ok: false, error: result.error }
      )
    );
    return;
  }

  if (!result.ok) {
    console.error(chalk.red(`  Login failed: ${result.error}`));
    return;
  }

  const planSuffix = result.plan ? chalk.dim(` (${result.plan} plan)`) : '';
  console.log(chalk.green(`  Signed in as ${chalk.bold(result.email ?? 'unknown')}${planSuffix}`));
  if (result.features && result.features.length > 0) {
    console.log(chalk.dim(`  Unlocked features: ${result.features.join(', ')}`));
  }
}

// ─── Command ─────────────────────────────────────────────────────────────────

export const loginCommand = new Command('login')
  .description('Sign in to the guard0.ai platform')
  .option('--api-key <key>', 'Authenticate with an API key instead of the browser flow')
  .option('--no-browser', 'Do not attempt to open a browser automatically')
  .option('--json', 'Output as JSON')
  .action(async (options: { apiKey?: string; browser: boolean; json?: boolean }) => {
    const { saveTokens } = await import('../../platform/auth.js');
    const { refreshEntitlements } = await import('../../platform/entitlements.js');
    const json = !!options.json;

    if (options.apiKey) {
      const spinner = json ? null : createSpinner('Validating API key...');
      spinner?.start();
      const { fetchMe } = await import('../../platform/client.js');
      const result = await runApiKeyLogin({
        apiKey: options.apiKey,
        fetchMe,
        saveTokens,
        refreshEntitlements,
      });
      spinner?.stop();
      printLoginResult(result, json);
      if (!result.ok) process.exitCode = 1;
      return;
    }

    const { startDeviceFlow, pollDeviceToken } = await import('../../platform/client.js');
    const spinner = json ? null : createSpinner('Starting device login...');
    spinner?.start();

    const shouldOpenBrowser = options.browser !== false && !process.env.CI && !!process.stdout.isTTY;

    const log = (msg: string) => {
      if (json) return;
      if (spinner) {
        spinner.text = msg;
        if (!spinner.isSpinning) spinner.start();
      } else {
        console.log(`  ${msg}`);
      }
    };

    const result = await runDeviceLogin({
      startDeviceFlow,
      pollDeviceToken,
      saveTokens,
      refreshEntitlements,
      openBrowser,
      shouldOpenBrowser,
      sleep: (ms: number) => new Promise(resolve => setTimeout(resolve, ms)),
      now: () => Date.now(),
      log,
    });

    spinner?.stop();
    printLoginResult(result, json);
    if (!result.ok) process.exitCode = 1;
  });
