import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import * as http from 'node:http';
import type { AuthTokens } from './types.js';
import { withLock } from '../utils/file-lock.js';
import { readEncryptedJson, writeEncryptedJson } from '../utils/encryption.js';

const G0_DIR = path.join(os.homedir(), '.g0');
const AUTH_PATH = path.join(G0_DIR, 'auth.json');

// ─── Token Storage ───────────────────────────────────────────────────────────

export function loadTokens(): AuthTokens | null {
  try {
    return readEncryptedJson<AuthTokens>(AUTH_PATH);
  } catch {
    return null;
  }
}

export async function saveTokens(tokens: AuthTokens): Promise<void> {
  await withLock(AUTH_PATH, () => {
    writeEncryptedJson(AUTH_PATH, tokens);
  });
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

  // API keys (g0_ prefix) don't expire
  if (tokens.accessToken.startsWith('g0_')) {
    return tokens.accessToken;
  }

  // Check expiry (with 60s buffer) for non-API-key tokens
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

// ─── Localhost Callback Auth Flow ────────────────────────────────────────────

const DEFAULT_AUTH_URL = 'https://cloud.guard0.ai';

function getAuthBaseUrl(): string {
  return process.env.G0_AUTH_URL ?? DEFAULT_AUTH_URL;
}

interface CallbackResult {
  token: string;
  userId?: string;
  orgId?: string;
  email?: string;
}

const SUCCESS_HTML = `<!DOCTYPE html>
<html><head><title>Guard0 CLI</title>
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0a0a0a;color:#e5e5e5}
.card{text-align:center;padding:2rem;border:1px solid #333;border-radius:12px;max-width:400px}
h1{color:#22c55e;margin-bottom:0.5rem}p{color:#a3a3a3}</style></head>
<body><div class="card"><h1>Authenticated!</h1><p>You can close this tab and return to the terminal.</p></div></body></html>`;

const ERROR_HTML = `<!DOCTYPE html>
<html><head><title>Guard0 CLI</title>
<style>body{font-family:system-ui,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;background:#0a0a0a;color:#e5e5e5}
.card{text-align:center;padding:2rem;border:1px solid #333;border-radius:12px;max-width:400px}
h1{color:#ef4444;margin-bottom:0.5rem}p{color:#a3a3a3}</style></head>
<body><div class="card"><h1>Authentication Failed</h1><p>State mismatch. Please try again with <code>g0 auth login</code>.</p></div></body></html>`;

/**
 * Start a localhost HTTP server and wait for the auth callback from the platform.
 * Returns the auth URL to open in the browser and a promise that resolves with the callback result.
 */
export async function startCallbackAuth(): Promise<{
  authUrl: string;
  port: number;
  result: Promise<CallbackResult>;
  cleanup: () => void;
}> {
  const baseUrl = getAuthBaseUrl();
  const state = crypto.randomBytes(16).toString('hex'); // 32 hex chars

  let resolveResult: (value: CallbackResult) => void;
  let rejectResult: (reason: Error) => void;
  const result = new Promise<CallbackResult>((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', `http://127.0.0.1`);

    if (url.pathname !== '/callback') {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }

    const callbackState = url.searchParams.get('state');
    const token = url.searchParams.get('token');

    if (callbackState !== state) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end(ERROR_HTML);
      rejectResult(new Error('State mismatch — possible CSRF attack. Please try again.'));
      return;
    }

    if (!token) {
      res.writeHead(400, { 'Content-Type': 'text/html' });
      res.end(ERROR_HTML);
      rejectResult(new Error('No token received from platform.'));
      return;
    }

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(SUCCESS_HTML);

    resolveResult({
      token,
      userId: url.searchParams.get('user_id') ?? undefined,
      orgId: url.searchParams.get('org_id') ?? undefined,
      email: url.searchParams.get('email') ?? undefined,
    });
  });

  // Bind to localhost only, wait for server to be ready
  const port = await new Promise<number>((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve(typeof addr === 'object' && addr ? addr.port : 0);
    });
  });

  // 2-minute timeout
  const timeout = setTimeout(() => {
    server.close();
    rejectResult(new Error('Authentication timed out (2 minutes). Please try again.'));
  }, 120_000);

  const cleanup = () => {
    clearTimeout(timeout);
    server.close();
  };

  // Auto-cleanup when result resolves or rejects
  result.then(() => cleanup, () => cleanup);

  const authUrl = `${baseUrl}/cli-auth?callback_port=${port}&state=${state}`;

  return { authUrl, port, result, cleanup };
}

/**
 * Ensure the user is authenticated, triggering inline localhost callback flow if needed.
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

  console.log('\n  Not authenticated. Opening browser to sign in...');

  try {
    const { authUrl, result } = await startCallbackAuth();

    console.log(`\n  If the browser doesn't open, visit:`);
    console.log(`    ${authUrl}\n`);

    // Try to open browser automatically
    try {
      const { exec } = await import('node:child_process');
      const cmd = process.platform === 'darwin' ? 'open'
        : process.platform === 'win32' ? 'start'
        : 'xdg-open';
      exec(`${cmd} "${authUrl}"`);
    } catch {
      // Non-fatal: user can open manually
    }

    console.log('  Waiting for authorization...');

    const callbackResult = await result;

    const tokens: AuthTokens = {
      accessToken: callbackResult.token,
      expiresAt: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000, // API keys don't expire; use 10 years
      email: callbackResult.email,
      userId: callbackResult.userId,
      orgId: callbackResult.orgId,
    };

    await saveTokens(tokens);

    console.log(`  Authenticated${tokens.email ? ` as ${tokens.email}` : ''}!\n`);
    return true;
  } catch (err) {
    console.error(`  Auth failed: ${err instanceof Error ? err.message : err}`);
    return false;
  }
}
