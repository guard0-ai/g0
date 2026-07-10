import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceFlowError } from '../../src/platform/client.js';
import { runDeviceLogin, runApiKeyLogin, type DeviceLoginDeps, type ApiKeyLoginDeps } from '../../src/cli/commands/login.js';
import { runLogout, type LogoutDeps } from '../../src/cli/commands/logout.js';
import { runWhoami, type WhoamiDeps } from '../../src/cli/commands/whoami.js';

const DEVICE_RESPONSE = {
  device_code: 'dc1',
  user_code: 'ABCD-1234',
  verification_uri: 'https://app.guard0.ai/device',
  verification_uri_complete: 'https://app.guard0.ai/device?code=ABCD-1234',
  expires_in: 900,
  interval: 5,
};

function baseDeviceDeps(overrides: Partial<DeviceLoginDeps> = {}): DeviceLoginDeps {
  let clock = 1_000_000;
  return {
    startDeviceFlow: vi.fn().mockResolvedValue(DEVICE_RESPONSE),
    pollDeviceToken: vi.fn(),
    saveTokens: vi.fn(),
    refreshEntitlements: vi.fn().mockResolvedValue({ plan: 'pro', features: ['fleet'], fetchedAt: new Date().toISOString() }),
    openBrowser: vi.fn(),
    shouldOpenBrowser: true,
    sleep: vi.fn().mockResolvedValue(undefined),
    now: vi.fn(() => clock),
    log: vi.fn(),
    dir: '/fake/dir',
    ...overrides,
  };
}

describe('runDeviceLogin', () => {
  it('polls through authorization_pending twice then succeeds, saving tokens and refreshing entitlements', async () => {
    const pollDeviceToken = vi.fn()
      .mockRejectedValueOnce(new DeviceFlowError('authorization_pending'))
      .mockRejectedValueOnce(new DeviceFlowError('authorization_pending'))
      .mockResolvedValueOnce({
        access_token: 'at1',
        refresh_token: 'rt1',
        expires_in: 3600,
        email: 'a@b.com',
        user_id: 'u1',
        org_id: 'o1',
      });

    let clock = 1_000_000;
    const now = vi.fn(() => clock);
    const sleep = vi.fn().mockImplementation(async () => {
      clock += 5000;
    });

    const deps = baseDeviceDeps({ pollDeviceToken, now, sleep });
    const result = await runDeviceLogin(deps);

    expect(result.ok).toBe(true);
    expect(result.email).toBe('a@b.com');
    expect(result.plan).toBe('pro');
    expect(pollDeviceToken).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);

    expect(deps.saveTokens).toHaveBeenCalledTimes(1);
    const [savedTokens, savedDir] = (deps.saveTokens as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(savedTokens).toEqual({
      tokenType: 'oauth',
      accessToken: 'at1',
      refreshToken: 'rt1',
      expiresAt: clock + 3600 * 1000,
      email: 'a@b.com',
      userId: 'u1',
      orgId: 'o1',
    });
    expect(savedDir).toBe('/fake/dir');
    expect(deps.refreshEntitlements).toHaveBeenCalledWith('/fake/dir');
  });

  it('increases the sleep interval on slow_down', async () => {
    const pollDeviceToken = vi.fn()
      .mockRejectedValueOnce(new DeviceFlowError('slow_down'))
      .mockResolvedValueOnce({ access_token: 'at1', expires_in: 3600 });

    const sleep = vi.fn().mockResolvedValue(undefined);
    const deps = baseDeviceDeps({ pollDeviceToken, sleep });

    const result = await runDeviceLogin(deps);

    expect(result.ok).toBe(true);
    // First sleep call should reflect interval bumped from 5 -> 10 seconds.
    expect(sleep).toHaveBeenCalledWith(10_000);
  });

  it('stops with a failure and does not save tokens on expired_token', async () => {
    const pollDeviceToken = vi.fn().mockRejectedValueOnce(new DeviceFlowError('expired_token'));
    const deps = baseDeviceDeps({ pollDeviceToken });

    const result = await runDeviceLogin(deps);

    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/expired/i);
    expect(deps.saveTokens).not.toHaveBeenCalled();
  });

  it('stops with a failure and does not save tokens on access_denied', async () => {
    const pollDeviceToken = vi.fn().mockRejectedValueOnce(new DeviceFlowError('access_denied'));
    const deps = baseDeviceDeps({ pollDeviceToken });

    const result = await runDeviceLogin(deps);

    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/denied/i);
    expect(deps.saveTokens).not.toHaveBeenCalled();
  });

  it('times out when the overall deadline is exceeded', async () => {
    let clock = 1_000_000;
    const now = vi.fn(() => clock);
    const pollDeviceToken = vi.fn().mockImplementation(async () => {
      // Every poll attempt "consumes" more time than the code allows for.
      clock += 1_000_000;
      throw new DeviceFlowError('authorization_pending');
    });
    const sleep = vi.fn().mockResolvedValue(undefined);

    const deps = baseDeviceDeps({ pollDeviceToken, now, sleep });
    const result = await runDeviceLogin(deps);

    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/timed out/i);
    expect(deps.saveTokens).not.toHaveBeenCalled();
  });

  it('fails cleanly when startDeviceFlow itself throws', async () => {
    const deps = baseDeviceDeps({ startDeviceFlow: vi.fn().mockRejectedValue(new Error('network down')) });
    const result = await runDeviceLogin(deps);
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/network down/);
    expect(deps.pollDeviceToken).not.toHaveBeenCalled();
  });

  it('attempts to open the browser when shouldOpenBrowser is true', async () => {
    const pollDeviceToken = vi.fn().mockResolvedValueOnce({ access_token: 'at1', expires_in: 3600 });
    const deps = baseDeviceDeps({ pollDeviceToken, shouldOpenBrowser: true });

    await runDeviceLogin(deps);

    expect(deps.openBrowser).toHaveBeenCalledWith(DEVICE_RESPONSE.verification_uri_complete);
  });

  it('does not open the browser when shouldOpenBrowser is false (e.g. --no-browser/CI/non-TTY)', async () => {
    const pollDeviceToken = vi.fn().mockResolvedValueOnce({ access_token: 'at1', expires_in: 3600 });
    const deps = baseDeviceDeps({ pollDeviceToken, shouldOpenBrowser: false });

    await runDeviceLogin(deps);

    expect(deps.openBrowser).not.toHaveBeenCalled();
  });

  it('never fails the login when openBrowser itself throws', async () => {
    const pollDeviceToken = vi.fn().mockResolvedValueOnce({ access_token: 'at1', expires_in: 3600 });
    const openBrowser = vi.fn().mockImplementation(() => {
      throw new Error('no display');
    });
    const deps = baseDeviceDeps({ pollDeviceToken, shouldOpenBrowser: true, openBrowser });

    const result = await runDeviceLogin(deps);
    expect(result.ok).toBe(true);
  });
});

describe('runApiKeyLogin', () => {
  function baseApiKeyDeps(overrides: Partial<ApiKeyLoginDeps> = {}): ApiKeyLoginDeps {
    return {
      apiKey: 'g0_testkey',
      fetchMe: vi.fn().mockResolvedValue({ email: 'a@b.com', user_id: 'u1', org_id: 'o1', plan: 'pro' }),
      saveTokens: vi.fn(),
      refreshEntitlements: vi.fn().mockResolvedValue({ plan: 'pro', features: ['fleet'], fetchedAt: new Date().toISOString() }),
      dir: '/fake/dir',
      ...overrides,
    };
  }

  it('saves an api-key StoredAuth with expiresAt 0 on fetchMe success', async () => {
    const deps = baseApiKeyDeps();
    const result = await runApiKeyLogin(deps);

    expect(result.ok).toBe(true);
    expect(result.email).toBe('a@b.com');
    expect(result.plan).toBe('pro');
    expect(deps.saveTokens).toHaveBeenCalledWith(
      {
        tokenType: 'api-key',
        accessToken: 'g0_testkey',
        expiresAt: 0,
        email: 'a@b.com',
        userId: 'u1',
        orgId: 'o1',
      },
      '/fake/dir'
    );
  });

  it('does not save tokens and returns failure when fetchMe rejects', async () => {
    const deps = baseApiKeyDeps({ fetchMe: vi.fn().mockRejectedValue(new Error('HTTP 401')) });
    const result = await runApiKeyLogin(deps);

    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/401/);
    expect(deps.saveTokens).not.toHaveBeenCalled();
    expect(deps.refreshEntitlements).not.toHaveBeenCalled();
  });
});

describe('runLogout', () => {
  function baseLogoutDeps(overrides: Partial<LogoutDeps> = {}): LogoutDeps {
    return {
      getAuthState: vi.fn().mockReturnValue({ loggedIn: true, email: 'a@b.com', source: 'oauth' }),
      loadTokens: vi.fn().mockReturnValue({ tokenType: 'oauth', accessToken: 'at1', refreshToken: 'rt1', expiresAt: Date.now() + 1000 }),
      revokeToken: vi.fn().mockResolvedValue(undefined),
      clearTokens: vi.fn(),
      clearEntitlements: vi.fn(),
      dir: '/fake/dir',
      ...overrides,
    };
  }

  it('is a no-op when already logged out', async () => {
    const deps = baseLogoutDeps({ getAuthState: vi.fn().mockReturnValue({ loggedIn: false, source: 'none' }) });
    const result = await runLogout(deps);

    expect(result.loggedOut).toBe(false);
    expect(deps.revokeToken).not.toHaveBeenCalled();
    expect(deps.clearTokens).not.toHaveBeenCalled();
    expect(deps.clearEntitlements).not.toHaveBeenCalled();
  });

  it('revokes and clears local state when logged in', async () => {
    const deps = baseLogoutDeps();
    const result = await runLogout(deps);

    expect(result.loggedOut).toBe(true);
    expect(deps.revokeToken).toHaveBeenCalledWith('rt1', 'at1');
    expect(deps.clearTokens).toHaveBeenCalledWith('/fake/dir');
    expect(deps.clearEntitlements).toHaveBeenCalledWith('/fake/dir');
  });

  it('still clears local state even when revokeToken throws', async () => {
    const deps = baseLogoutDeps({ revokeToken: vi.fn().mockRejectedValue(new Error('network down')) });
    const result = await runLogout(deps);

    expect(result.loggedOut).toBe(true);
    expect(deps.clearTokens).toHaveBeenCalledTimes(1);
    expect(deps.clearEntitlements).toHaveBeenCalledTimes(1);
  });

  it('skips revoke when there is no refresh token (e.g. api-key session) but still clears', async () => {
    const deps = baseLogoutDeps({
      loadTokens: vi.fn().mockReturnValue({ tokenType: 'api-key', accessToken: 'key1', expiresAt: 0 }),
    });
    const result = await runLogout(deps);

    expect(result.loggedOut).toBe(true);
    expect(deps.revokeToken).not.toHaveBeenCalled();
    expect(deps.clearTokens).toHaveBeenCalledTimes(1);
  });
});

describe('runWhoami', () => {
  function baseWhoamiDeps(overrides: Partial<WhoamiDeps> = {}): WhoamiDeps {
    return {
      getAuthState: vi.fn().mockReturnValue({ loggedIn: true, email: 'a@b.com', source: 'oauth' }),
      loadTokens: vi.fn().mockReturnValue({ tokenType: 'oauth', accessToken: 'at1', expiresAt: Date.now() + 1000, orgId: 'o1' }),
      getEntitlementsCached: vi.fn().mockReturnValue({ plan: 'pro', features: [], fetchedAt: new Date().toISOString() }),
      getValidAccessToken: vi.fn().mockResolvedValue('at1'),
      fetchMe: vi.fn().mockResolvedValue({ email: 'a@b.com', user_id: 'u1', org_id: 'o1', plan: 'pro' }),
      refreshEntitlements: vi.fn().mockResolvedValue({ plan: 'pro', features: ['fleet'], fetchedAt: new Date().toISOString() }),
      dir: '/fake/dir',
      ...overrides,
    };
  }

  it('reports loggedIn:false with no network calls when logged out', async () => {
    const deps = baseWhoamiDeps({ getAuthState: vi.fn().mockReturnValue({ loggedIn: false, source: 'none' }) });
    const result = await runWhoami(deps);

    expect(result).toEqual({ loggedIn: false });
    expect(deps.getValidAccessToken).not.toHaveBeenCalled();
    expect(deps.fetchMe).not.toHaveBeenCalled();
  });

  it('reports cached info offline (no verify)', async () => {
    const deps = baseWhoamiDeps();
    const result = await runWhoami(deps);

    expect(result.loggedIn).toBe(true);
    expect(result.email).toBe('a@b.com');
    expect(result.org).toBe('o1');
    expect(result.plan).toBe('pro');
    expect(result.source).toBe('oauth');
    expect(result.verified).toBeUndefined();
    expect(deps.getValidAccessToken).not.toHaveBeenCalled();
    expect(deps.fetchMe).not.toHaveBeenCalled();
  });

  it('defaults plan to unknown when there is no cached entitlements', async () => {
    const deps = baseWhoamiDeps({ getEntitlementsCached: vi.fn().mockReturnValue(null) });
    const result = await runWhoami(deps);
    expect(result.plan).toBe('unknown');
  });

  it('verifies against the platform and reflects fresh data on --verify success', async () => {
    const deps = baseWhoamiDeps({ verify: true });
    const result = await runWhoami(deps);

    expect(result.verified).toBe(true);
    expect(result.email).toBe('a@b.com');
    expect(result.plan).toBe('pro');
    expect(deps.fetchMe).toHaveBeenCalledWith('at1');
    expect(deps.refreshEntitlements).toHaveBeenCalledWith('/fake/dir');
  });

  it('still shows cached info with a warning when --verify fails, without flipping loggedIn', async () => {
    const deps = baseWhoamiDeps({ verify: true, fetchMe: vi.fn().mockRejectedValue(new Error('HTTP 401')) });
    const result = await runWhoami(deps);

    expect(result.loggedIn).toBe(true);
    expect(result.verified).toBe(false);
    expect(result.verifyError).toMatch(/401/);
    // Cached fields remain populated even though verification failed.
    expect(result.email).toBe('a@b.com');
    expect(result.plan).toBe('pro');
  });

  it('reports verified:false when there is no valid access token to verify with', async () => {
    const deps = baseWhoamiDeps({ verify: true, getValidAccessToken: vi.fn().mockResolvedValue(null) });
    const result = await runWhoami(deps);

    expect(result.verified).toBe(false);
    expect(result.verifyError).toMatch(/no valid access token/i);
    expect(deps.fetchMe).not.toHaveBeenCalled();
  });
});
