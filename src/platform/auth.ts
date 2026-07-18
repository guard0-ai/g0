// Offline-first auth token storage for the guard0.ai platform.
//
// Hard rule: nothing in this module may block a scan. `getAuthState` is a
// synchronous, disk-only read that never throws. Only `getValidAccessToken`
// touches the network, and only when a refresh is actually needed — on any
// network failure it falls back to the stale token rather than blocking or
// throwing, since the server is the final authority (a stale token just gets
// a 401 if truly dead).
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { AuthTokens } from './types.js';
import { refreshTokens, InvalidGrantError } from './client.js';
import { withLock } from '../utils/file-lock.js';

const G0_DIR = path.join(os.homedir(), '.g0');

/** How long before expiry we still consider a token usable without refreshing. */
const REFRESH_SKEW_MS = 60_000;

export type TokenType = 'oauth' | 'api-key';

export interface StoredAuth extends AuthTokens {
  tokenType: TokenType;
}

export function authFilePath(dir: string = G0_DIR): string {
  return path.join(dir, 'auth.json');
}

function entitlementsFilePathLocal(dir: string): string {
  return path.join(dir, 'entitlements.json');
}

/** Sync read. Returns null on missing file, corrupt JSON, or any other error. */
export function loadTokens(dir: string = G0_DIR): StoredAuth | null {
  try {
    const raw = fs.readFileSync(authFilePath(dir), 'utf-8');
    const parsed = JSON.parse(raw) as StoredAuth;
    if (!parsed || typeof parsed.accessToken !== 'string') return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Sync write. Creates ~/.g0 (0700) if needed and writes auth.json (0600). */
export function saveTokens(tokens: StoredAuth, dir: string = G0_DIR): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(authFilePath(dir), JSON.stringify(tokens, null, 2), { mode: 0o600 });
}

/** Removes both auth.json and entitlements.json. Never throws. */
export function clearTokens(dir: string = G0_DIR): void {
  for (const p of [authFilePath(dir), entitlementsFilePathLocal(dir)]) {
    try {
      fs.unlinkSync(p);
    } catch {
      // Already gone, or never existed — fine.
    }
  }
}

export interface AuthState {
  loggedIn: boolean;
  email?: string;
  source: 'api-key-env' | 'api-key' | 'oauth' | 'none';
}

/**
 * Synchronous, disk-only, never throws. Safe to call from any scan path.
 * Precedence: G0_API_KEY env var wins over any stored file.
 */
export function getAuthState(dir: string = G0_DIR): AuthState {
  if (process.env.G0_API_KEY) {
    return { loggedIn: true, source: 'api-key-env' };
  }

  const stored = loadTokens(dir);
  if (!stored) {
    return { loggedIn: false, source: 'none' };
  }

  return {
    loggedIn: true,
    email: stored.email,
    source: stored.tokenType === 'api-key' ? 'api-key' : 'oauth',
  };
}

/**
 * The only async function in this module. Resolves a usable access token,
 * refreshing an oauth token when it's near expiry. Falls back to the stale
 * token on network failure so a flaky connection never blocks a command —
 * the server will simply 401 if the token is truly dead.
 */
export async function getValidAccessToken(dir: string = G0_DIR): Promise<string | null> {
  if (process.env.G0_API_KEY) {
    return process.env.G0_API_KEY;
  }

  const stored = loadTokens(dir);
  if (!stored) return null;

  if (stored.tokenType === 'api-key') {
    return stored.accessToken;
  }

  // oauth
  if (stored.expiresAt - Date.now() > REFRESH_SKEW_MS) {
    return stored.accessToken;
  }

  if (!stored.refreshToken) {
    // No way to refresh — return the (soon-to-be) stale token and let the
    // server 401 rather than force a login here.
    return stored.accessToken;
  }

  return withLock(authFilePath(dir), async () => {
    // Re-read inside the lock in case another process already refreshed.
    const fresh = loadTokens(dir) ?? stored;
    if (fresh.expiresAt - Date.now() > REFRESH_SKEW_MS) {
      return fresh.accessToken;
    }
    if (!fresh.refreshToken) {
      return fresh.accessToken;
    }

    try {
      const result = await refreshTokens(fresh.refreshToken);
      const updated: StoredAuth = {
        tokenType: 'oauth',
        accessToken: result.access_token,
        refreshToken: result.refresh_token ?? fresh.refreshToken,
        expiresAt: Date.now() + result.expires_in * 1000,
        email: result.email ?? fresh.email,
        userId: result.user_id ?? fresh.userId,
        orgId: result.org_id ?? fresh.orgId,
      };
      saveTokens(updated, dir);
      return updated.accessToken;
    } catch (err) {
      if (err instanceof InvalidGrantError) {
        clearTokens(dir);
        return null;
      }
      // Network or server error — offline grace: return the stale token.
      return fresh.accessToken;
    }
  });
}
