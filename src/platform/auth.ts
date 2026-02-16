import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import type { AuthTokens, DeviceCodeResponse, TokenResponse } from './types.js';

const G0_DIR = path.join(os.homedir(), '.g0');
const AUTH_PATH = path.join(G0_DIR, 'auth.json');

// ─── Token Storage ───────────────────────────────────────────────────────────

export function loadTokens(): AuthTokens | null {
  try {
    const raw = fs.readFileSync(AUTH_PATH, 'utf-8');
    const tokens = JSON.parse(raw) as AuthTokens;
    return tokens;
  } catch {
    return null;
  }
}

export function saveTokens(tokens: AuthTokens): void {
  fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(AUTH_PATH, JSON.stringify(tokens, null, 2) + '\n', { mode: 0o600 });
}

export function clearTokens(): void {
  try {
    fs.unlinkSync(AUTH_PATH);
  } catch {
    // Already gone
  }
}

export function getAuthFilePath(): string {
  return AUTH_PATH;
}

// ─── Token Resolution ────────────────────────────────────────────────────────

/**
 * Resolves an auth token, checking in order:
 * 1. G0_API_TOKEN env var (for CI/CD)
 * 2. Stored tokens from ~/.g0/auth.json
 */
export function resolveToken(): string | null {
  // CI/CD: env var takes priority
  const envToken = process.env.G0_API_TOKEN;
  if (envToken) return envToken;

  // Interactive: stored tokens
  const tokens = loadTokens();
  if (!tokens) return null;

  // Check expiry (with 60s buffer)
  if (tokens.expiresAt && Date.now() > tokens.expiresAt - 60_000) {
    return null; // Expired
  }

  return tokens.accessToken;
}

/**
 * Check if user is authenticated.
 */
export function isAuthenticated(): boolean {
  return resolveToken() !== null;
}

/**
 * Ensure the user is authenticated, triggering inline device flow if needed.
 * Used by --upload to provide frictionless first-time auth.
 * Returns true if authenticated, false if user declined or flow failed.
 */
export async function ensureAuthenticated(): Promise<boolean> {
  // Already authenticated
  if (resolveToken()) return true;

  // CI environment — don't prompt interactively
  if (process.env.CI) return false;

  // Check if stdin is a TTY (interactive terminal)
  if (!process.stdin.isTTY) return false;

  console.log('\n  Not authenticated. Sign up in 10 seconds:');

  try {
    const deviceCode = await startDeviceFlow();

    console.log(`\n  Open this URL in your browser:`);
    console.log(`    ${deviceCode.verificationUri}\n`);
    console.log(`  Enter code: ${deviceCode.userCode}\n`);

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

    console.log('  Waiting for authorization...');

    const tokens = await pollForToken(
      deviceCode.deviceCode,
      deviceCode.interval,
      deviceCode.expiresIn,
    );

    saveTokens(tokens);

    console.log(`  Authenticated${tokens.email ? ` as ${tokens.email}` : ''}!\n`);
    return true;
  } catch (err) {
    console.error(`  Auth failed: ${err instanceof Error ? err.message : err}`);
    return false;
  }
}

// ─── Device Authorization Flow ───────────────────────────────────────────────

const DEFAULT_AUTH_URL = 'https://app.guard0.ai';

function getAuthBaseUrl(): string {
  return process.env.G0_AUTH_URL ?? DEFAULT_AUTH_URL;
}

/**
 * Start the device authorization flow.
 * Returns a device code + user code for the CLI to display.
 */
export async function startDeviceFlow(): Promise<DeviceCodeResponse> {
  const baseUrl = getAuthBaseUrl();
  const response = await fetch(`${baseUrl}/api/v1/auth/device`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: 'g0-cli',
      scope: 'upload read',
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Device flow initiation failed (${response.status}): ${body}`);
  }

  return response.json() as Promise<DeviceCodeResponse>;
}

/**
 * Poll for token after user authorizes in browser.
 * Implements exponential backoff on slow_down responses.
 */
export async function pollForToken(
  deviceCode: string,
  interval: number,
  expiresIn: number,
): Promise<AuthTokens> {
  const baseUrl = getAuthBaseUrl();
  const deadline = Date.now() + expiresIn * 1000;
  let pollInterval = interval * 1000;

  while (Date.now() < deadline) {
    await sleep(pollInterval);

    const response = await fetch(`${baseUrl}/api/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code: deviceCode,
        client_id: 'g0-cli',
      }),
    });

    if (response.ok) {
      const data = await response.json() as TokenResponse;
      const tokens: AuthTokens = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt: Date.now() + data.expires_in * 1000,
      };

      // Fetch user info
      try {
        const userInfo = await fetchUserInfo(data.access_token, baseUrl);
        tokens.email = userInfo.email;
        tokens.userId = userInfo.userId;
        tokens.orgId = userInfo.orgId;
      } catch {
        // Non-fatal: tokens still valid without user info
      }

      return tokens;
    }

    const body = await response.json() as { error: string };

    if (body.error === 'authorization_pending') {
      continue;
    }
    if (body.error === 'slow_down') {
      pollInterval += 5000;
      continue;
    }
    if (body.error === 'expired_token') {
      throw new Error('Device code expired. Please try again.');
    }
    if (body.error === 'access_denied') {
      throw new Error('Authorization denied by user.');
    }

    throw new Error(`Token polling failed: ${body.error}`);
  }

  throw new Error('Device code expired. Please try again.');
}

async function fetchUserInfo(
  accessToken: string,
  baseUrl: string,
): Promise<{ email?: string; userId?: string; orgId?: string }> {
  const response = await fetch(`${baseUrl}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) return {};
  return response.json() as Promise<{ email?: string; userId?: string; orgId?: string }>;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
