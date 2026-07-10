// `g0 whoami` — offline-first login status. Default path reads cached disk
// state only (no network). `--verify` additionally confirms the session is
// live against the platform. Orchestration lives in `runWhoami(deps)` for
// unit testing; the commander `.action` wires real deps.
import { Command } from 'commander';
import chalk from 'chalk';
import type { AuthState, StoredAuth } from '../../platform/auth.js';
import type { Entitlements } from '../../platform/entitlements.js';
import type { MeResponse } from '../../platform/client.js';

export interface WhoamiDeps {
  getAuthState: (dir?: string) => AuthState;
  loadTokens: (dir?: string) => StoredAuth | null;
  getEntitlementsCached: (dir?: string) => Entitlements | null;
  getValidAccessToken: (dir?: string) => Promise<string | null>;
  fetchMe: (token: string) => Promise<MeResponse>;
  refreshEntitlements: (dir?: string) => Promise<Entitlements | null>;
  verify?: boolean;
  dir?: string;
}

export interface WhoamiResult {
  loggedIn: boolean;
  email?: string;
  org?: string;
  plan?: string;
  source?: AuthState['source'];
  verified?: boolean;
  verifyError?: string;
}

export async function runWhoami(deps: WhoamiDeps): Promise<WhoamiResult> {
  const state = deps.getAuthState(deps.dir);
  if (!state.loggedIn) {
    return { loggedIn: false };
  }

  const stored = deps.loadTokens(deps.dir);
  const cached = deps.getEntitlementsCached(deps.dir);

  const result: WhoamiResult = {
    loggedIn: true,
    email: state.email ?? stored?.email,
    org: stored?.orgId,
    plan: cached?.plan ?? 'unknown',
    source: state.source,
  };

  if (!deps.verify) {
    return result;
  }

  try {
    const token = await deps.getValidAccessToken(deps.dir);
    if (!token) {
      result.verified = false;
      result.verifyError = 'No valid access token available.';
      return result;
    }

    const me = await deps.fetchMe(token);
    result.verified = true;
    result.email = me.email;
    result.org = me.org_id;
    result.plan = me.plan;

    const refreshed = await deps.refreshEntitlements(deps.dir);
    if (refreshed) result.plan = refreshed.plan;
  } catch (err) {
    result.verified = false;
    result.verifyError = err instanceof Error ? err.message : String(err);
  }

  return result;
}

export const whoamiCommand = new Command('whoami')
  .description('Show the current guard0.ai login status')
  .option('--json', 'Output as JSON')
  .option('-q, --quiet', 'Suppress terminal output')
  .option('--verify', 'Verify the session against the platform (requires network)')
  .action(async (options: { json?: boolean; quiet?: boolean; verify?: boolean }) => {
    const { getAuthState, loadTokens, getValidAccessToken } = await import('../../platform/auth.js');
    const { getEntitlementsCached, refreshEntitlements } = await import('../../platform/entitlements.js');
    const { fetchMe } = await import('../../platform/client.js');

    const result = await runWhoami({
      getAuthState,
      loadTokens,
      getEntitlementsCached,
      getValidAccessToken,
      fetchMe,
      refreshEntitlements,
      verify: options.verify,
    });

    if (options.quiet) {
      if (!result.loggedIn) process.exitCode = 1;
      return;
    }

    if (options.json) {
      console.log(JSON.stringify(result));
      if (!result.loggedIn) process.exitCode = 1;
      return;
    }

    if (!result.loggedIn) {
      console.log(chalk.yellow('  Not logged in. Run `g0 login`.'));
      process.exitCode = 1;
      return;
    }

    console.log(chalk.bold(`  Signed in as ${result.email ?? 'unknown'}`));
    if (result.org) console.log(`  Org:    ${chalk.dim(result.org)}`);
    console.log(`  Plan:   ${result.plan ?? 'unknown'}`);
    console.log(`  Source: ${chalk.dim(result.source ?? 'unknown')}`);

    if (options.verify) {
      if (result.verified) {
        console.log(chalk.green('  Session verified.'));
      } else {
        console.log(
          chalk.yellow(`  Warning: could not verify session${result.verifyError ? ` (${result.verifyError})` : ''}.`)
        );
      }
    }
  });
