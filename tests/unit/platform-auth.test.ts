import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

function fakeResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

describe('platform auth', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-auth-test-'));
    delete process.env.G0_API_KEY;
    delete process.env.G0_PLATFORM_URL;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.unstubAllGlobals();
    delete process.env.G0_API_KEY;
    delete process.env.G0_PLATFORM_URL;
  });

  describe('authFilePath', () => {
    it('joins dir with auth.json', async () => {
      const { authFilePath } = await import('../../src/platform/auth.js');
      expect(authFilePath(tmpDir)).toBe(path.join(tmpDir, 'auth.json'));
    });
  });

  describe('saveTokens / loadTokens', () => {
    it('round-trips stored tokens', async () => {
      const { saveTokens, loadTokens } = await import('../../src/platform/auth.js');
      const tokens = {
        tokenType: 'oauth' as const,
        accessToken: 'at1',
        refreshToken: 'rt1',
        expiresAt: Date.now() + 3600_000,
        email: 'a@b.com',
        userId: 'u1',
        orgId: 'o1',
      };
      saveTokens(tokens, tmpDir);
      expect(loadTokens(tmpDir)).toEqual(tokens);
    });

    it('writes auth.json with 0600 file mode and 0700 dir mode', async () => {
      const { saveTokens, authFilePath } = await import('../../src/platform/auth.js');
      const nestedDir = path.join(tmpDir, 'nested', '.g0');
      saveTokens({ tokenType: 'api-key', accessToken: 'key1', expiresAt: 0 }, nestedDir);

      const fileMode = fs.statSync(authFilePath(nestedDir)).mode & 0o777;
      expect(fileMode).toBe(0o600);

      const dirMode = fs.statSync(nestedDir).mode & 0o777;
      expect(dirMode).toBe(0o700);
    });

    it('returns null for a missing file', async () => {
      const { loadTokens } = await import('../../src/platform/auth.js');
      expect(loadTokens(tmpDir)).toBeNull();
    });

    it('returns null for a corrupt file rather than throwing', async () => {
      const { authFilePath, loadTokens } = await import('../../src/platform/auth.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(authFilePath(tmpDir), '{ not valid json', { mode: 0o600 });
      expect(() => loadTokens(tmpDir)).not.toThrow();
      expect(loadTokens(tmpDir)).toBeNull();
    });
  });

  describe('clearTokens', () => {
    it('removes both auth.json and entitlements.json', async () => {
      const { saveTokens, authFilePath, clearTokens } = await import('../../src/platform/auth.js');
      const { entitlementsFilePath } = await import('../../src/platform/entitlements.js');

      saveTokens({ tokenType: 'api-key', accessToken: 'key1', expiresAt: 0 }, tmpDir);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify({ plan: 'pro', features: [], fetchedAt: new Date().toISOString() }), { mode: 0o600 });

      expect(fs.existsSync(authFilePath(tmpDir))).toBe(true);
      expect(fs.existsSync(entitlementsFilePath(tmpDir))).toBe(true);

      clearTokens(tmpDir);

      expect(fs.existsSync(authFilePath(tmpDir))).toBe(false);
      expect(fs.existsSync(entitlementsFilePath(tmpDir))).toBe(false);
    });

    it('does not throw when files do not exist', async () => {
      const { clearTokens } = await import('../../src/platform/auth.js');
      expect(() => clearTokens(tmpDir)).not.toThrow();
    });
  });

  describe('getAuthState', () => {
    it('returns loggedIn:false, source:none with no file and no env', async () => {
      const { getAuthState } = await import('../../src/platform/auth.js');
      expect(getAuthState(tmpDir)).toEqual({ loggedIn: false, source: 'none' });
    });

    it('prefers G0_API_KEY env over a stored file', async () => {
      const { saveTokens, getAuthState } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'at1', expiresAt: Date.now() + 3600_000, email: 'file@b.com' }, tmpDir);

      process.env.G0_API_KEY = 'env-key';
      expect(getAuthState(tmpDir)).toEqual({ loggedIn: true, source: 'api-key-env' });
    });

    it('reports source oauth for a stored oauth token', async () => {
      const { saveTokens, getAuthState } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'at1', expiresAt: Date.now() + 3600_000, email: 'a@b.com' }, tmpDir);
      expect(getAuthState(tmpDir)).toEqual({ loggedIn: true, email: 'a@b.com', source: 'oauth' });
    });

    it('reports source api-key for a stored api-key token', async () => {
      const { saveTokens, getAuthState } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'api-key', accessToken: 'key1', expiresAt: 0 }, tmpDir);
      expect(getAuthState(tmpDir)).toEqual({ loggedIn: true, email: undefined, source: 'api-key' });
    });

    it('never throws even with a corrupt file', async () => {
      const { authFilePath, getAuthState } = await import('../../src/platform/auth.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(authFilePath(tmpDir), 'not json', { mode: 0o600 });
      expect(() => getAuthState(tmpDir)).not.toThrow();
      expect(getAuthState(tmpDir).loggedIn).toBe(false);
    });
  });

  describe('getValidAccessToken', () => {
    it('returns the env key when G0_API_KEY is set, ignoring any file', async () => {
      const { getValidAccessToken, saveTokens } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'file-token', expiresAt: Date.now() + 3600_000 }, tmpDir);
      process.env.G0_API_KEY = 'env-key';
      await expect(getValidAccessToken(tmpDir)).resolves.toBe('env-key');
    });

    it('returns null when no token is stored', async () => {
      const { getValidAccessToken } = await import('../../src/platform/auth.js');
      await expect(getValidAccessToken(tmpDir)).resolves.toBeNull();
    });

    it('returns the api-key token directly without refresh', async () => {
      const { getValidAccessToken, saveTokens } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'api-key', accessToken: 'key1', expiresAt: 0 }, tmpDir);
      await expect(getValidAccessToken(tmpDir)).resolves.toBe('key1');
    });

    it('returns the stored oauth token when not near expiry', async () => {
      const { getValidAccessToken, saveTokens } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'at1', refreshToken: 'rt1', expiresAt: Date.now() + 3600_000 }, tmpDir);
      await expect(getValidAccessToken(tmpDir)).resolves.toBe('at1');
    });

    it('refreshes and persists when within 60s of expiry', async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce(fakeResponse(200, {
        access_token: 'at2',
        refresh_token: 'rt2',
        expires_in: 3600,
        email: 'a@b.com',
      }));
      vi.stubGlobal('fetch', fetchMock);

      const { getValidAccessToken, saveTokens, loadTokens } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'at1', refreshToken: 'rt1', expiresAt: Date.now() + 10_000 }, tmpDir);

      const token = await getValidAccessToken(tmpDir);
      expect(token).toBe('at2');
      expect(fetchMock).toHaveBeenCalledTimes(1);

      const persisted = loadTokens(tmpDir);
      expect(persisted?.accessToken).toBe('at2');
      expect(persisted?.refreshToken).toBe('rt2');
      expect(persisted?.tokenType).toBe('oauth');
    });

    it('returns the stale token when refresh fails due to a network error', async () => {
      const fetchMock = vi.fn().mockRejectedValueOnce(new Error('network down'));
      vi.stubGlobal('fetch', fetchMock);

      const { getValidAccessToken, saveTokens, loadTokens } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'stale-token', refreshToken: 'rt1', expiresAt: Date.now() + 10_000 }, tmpDir);

      const token = await getValidAccessToken(tmpDir);
      expect(token).toBe('stale-token');
      // File is untouched on network failure.
      expect(loadTokens(tmpDir)?.accessToken).toBe('stale-token');
    });

    it('clears tokens and returns null on invalid_grant', async () => {
      const fetchMock = vi.fn().mockResolvedValueOnce(fakeResponse(400, { error: 'invalid_grant' }));
      vi.stubGlobal('fetch', fetchMock);

      const { getValidAccessToken, saveTokens, loadTokens, authFilePath } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'dead-token', refreshToken: 'dead-refresh', expiresAt: Date.now() + 10_000 }, tmpDir);

      const token = await getValidAccessToken(tmpDir);
      expect(token).toBeNull();
      expect(loadTokens(tmpDir)).toBeNull();
      expect(fs.existsSync(authFilePath(tmpDir))).toBe(false);
    });

    it('returns the stale token when there is no refresh token to use', async () => {
      const { getValidAccessToken, saveTokens } = await import('../../src/platform/auth.js');
      saveTokens({ tokenType: 'oauth', accessToken: 'no-refresh-token', expiresAt: Date.now() + 10_000 }, tmpDir);
      await expect(getValidAccessToken(tmpDir)).resolves.toBe('no-refresh-token');
    });
  });
});
