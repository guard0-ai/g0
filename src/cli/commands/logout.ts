// `g0 logout` — best-effort server-side revoke, then clear local auth +
// entitlements state. The orchestration lives in `runLogout(deps)` so it can
// be unit-tested with fakes; the commander `.action` just wires real deps.
import { Command } from 'commander';
import chalk from 'chalk';
import type { AuthState, StoredAuth } from '../../platform/auth.js';

export interface LogoutDeps {
  getAuthState: (dir?: string) => AuthState;
  loadTokens: (dir?: string) => StoredAuth | null;
  revokeToken: (refreshToken: string, accessToken: string) => Promise<void>;
  clearTokens: (dir?: string) => void;
  clearEntitlements: (dir?: string) => void;
  dir?: string;
}

export interface LogoutResult {
  ok: true;
  /** False when the caller was already logged out (no-op). */
  loggedOut: boolean;
}

export async function runLogout(deps: LogoutDeps): Promise<LogoutResult> {
  const state = deps.getAuthState(deps.dir);
  if (!state.loggedIn) {
    return { ok: true, loggedOut: false };
  }

  const stored = deps.loadTokens(deps.dir);
  if (stored?.refreshToken) {
    try {
      await deps.revokeToken(stored.refreshToken, stored.accessToken);
    } catch {
      // Best-effort — revocation failing must never block a local logout.
    }
  }

  deps.clearTokens(deps.dir);
  deps.clearEntitlements(deps.dir);
  return { ok: true, loggedOut: true };
}

export const logoutCommand = new Command('logout')
  .description('Sign out of the guard0.ai platform')
  .option('--json', 'Output as JSON')
  .action(async (options: { json?: boolean }) => {
    const { getAuthState, loadTokens, clearTokens } = await import('../../platform/auth.js');
    const { clearEntitlements } = await import('../../platform/entitlements.js');
    const { revokeToken } = await import('../../platform/client.js');

    const result = await runLogout({
      getAuthState,
      loadTokens,
      revokeToken,
      clearTokens,
      clearEntitlements,
    });

    if (options.json) {
      console.log(JSON.stringify(result));
      return;
    }

    console.log(result.loggedOut ? chalk.green('  Logged out.') : chalk.dim('  Not logged in.'));
  });
