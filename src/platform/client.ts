// Thin typed fetch wrapper for the guard0.ai platform API.
//
// This module performs the actual network I/O for auth and entitlements.
// Nothing in here is called from scan paths directly — callers in auth.ts /
// entitlements.ts decide when a network round-trip is appropriate (login,
// explicit refresh). Every request uses a bounded timeout so a slow/unreachable
// platform can never hang a command.
import { G0_VERSION } from '../utils/version.js';
import { DEFAULT_PLATFORM_CONFIG } from './types.js';

const REQUEST_TIMEOUT_MS = 10_000;
const REVOKE_TIMEOUT_MS = 2_000;

/**
 * Resolve the platform base URL. `DEFAULT_PLATFORM_CONFIG.baseUrl` in types.ts
 * is a placeholder (`cloud.guard0.ai`) kept for backward compatibility with
 * other modules — the live platform is `app.guard0.ai`. Resolution order:
 * `G0_PLATFORM_URL` env override, else the live default.
 */
export function platformBaseUrl(): string {
  return process.env.G0_PLATFORM_URL ?? 'https://app.guard0.ai';
}

function apiUrl(path: string): string {
  return `${platformBaseUrl()}/${DEFAULT_PLATFORM_CONFIG.apiVersion}${path}`;
}

function defaultHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    'User-Agent': `g0-security/${G0_VERSION}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

// ─── Tagged errors ───────────────────────────────────────────────────────────

/** Thrown by pollDeviceToken on a 400 response with an OAuth device-flow error code. */
export class DeviceFlowError extends Error {
  readonly code = 'device_flow_error' as const;
  readonly error: 'authorization_pending' | 'slow_down' | 'expired_token' | 'access_denied' | string;

  constructor(error: string) {
    super(`Device flow error: ${error}`);
    this.name = 'DeviceFlowError';
    this.error = error;
  }
}

/** Thrown by refreshTokens when the refresh token is no longer valid. */
export class InvalidGrantError extends Error {
  readonly code = 'invalid_grant' as const;

  constructor(message = 'Refresh token is invalid or expired') {
    super(message);
    this.name = 'InvalidGrantError';
  }
}

// ─── Response types ──────────────────────────────────────────────────────────

export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  email?: string;
  user_id?: string;
  org_id?: string;
}

export interface MeResponse {
  email: string;
  user_id: string;
  org_id?: string;
  plan: string;
}

export interface EntitlementsResponse {
  plan: 'free' | 'pro' | 'enterprise';
  features: string[];
  feed_token?: string;
}

// ─── Requests ────────────────────────────────────────────────────────────────

export async function startDeviceFlow(): Promise<DeviceCodeResponse> {
  const resp = await fetch(apiUrl('/auth/device/code'), {
    method: 'POST',
    headers: defaultHeaders(),
    body: JSON.stringify({ client_id: 'g0-cli', scope: 'cli' }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!resp.ok) {
    throw new Error(`Failed to start device flow: HTTP ${resp.status}`);
  }
  return (await resp.json()) as DeviceCodeResponse;
}

export async function pollDeviceToken(deviceCode: string): Promise<TokenResponse> {
  const resp = await fetch(apiUrl('/auth/device/token'), {
    method: 'POST',
    headers: defaultHeaders(),
    body: JSON.stringify({
      client_id: 'g0-cli',
      device_code: deviceCode,
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  if (resp.status === 400) {
    const body = await safeJson<{ error?: string }>(resp);
    throw new DeviceFlowError(body?.error ?? 'unknown_error');
  }
  if (!resp.ok) {
    throw new Error(`Device token poll failed: HTTP ${resp.status}`);
  }
  return (await resp.json()) as TokenResponse;
}

export async function refreshTokens(refreshToken: string): Promise<TokenResponse> {
  const resp = await fetch(apiUrl('/auth/token/refresh'), {
    method: 'POST',
    headers: defaultHeaders(),
    body: JSON.stringify({ refresh_token: refreshToken }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });

  if (resp.status === 400 || resp.status === 401) {
    const body = await safeJson<{ error?: string }>(resp);
    if (body?.error === 'invalid_grant') {
      throw new InvalidGrantError();
    }
    throw new Error(`Token refresh failed: HTTP ${resp.status}`);
  }
  if (!resp.ok) {
    throw new Error(`Token refresh failed: HTTP ${resp.status}`);
  }
  return (await resp.json()) as TokenResponse;
}

/** Best-effort token revocation. Never throws — a failed revoke just leaves a dead token server-side. */
export async function revokeToken(refreshToken: string, accessToken: string): Promise<void> {
  try {
    await fetch(apiUrl('/auth/revoke'), {
      method: 'POST',
      headers: defaultHeaders({ Authorization: `Bearer ${accessToken}` }),
      body: JSON.stringify({ refresh_token: refreshToken }),
      signal: AbortSignal.timeout(REVOKE_TIMEOUT_MS),
    });
  } catch {
    // Swallow — best-effort only.
  }
}

export async function fetchMe(token: string): Promise<MeResponse> {
  const resp = await fetch(apiUrl('/me'), {
    method: 'GET',
    headers: defaultHeaders({ Authorization: `Bearer ${token}` }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!resp.ok) {
    throw new Error(`Failed to fetch profile: HTTP ${resp.status}`);
  }
  return (await resp.json()) as MeResponse;
}

export async function fetchEntitlements(token: string): Promise<EntitlementsResponse> {
  const resp = await fetch(apiUrl('/me/entitlements'), {
    method: 'GET',
    headers: defaultHeaders({ Authorization: `Bearer ${token}` }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (!resp.ok) {
    throw new Error(`Failed to fetch entitlements: HTTP ${resp.status}`);
  }
  return (await resp.json()) as EntitlementsResponse;
}

async function safeJson<T>(resp: Response): Promise<T | null> {
  try {
    return (await resp.json()) as T;
  } catch {
    return null;
  }
}
