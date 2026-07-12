import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

function fakeResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response;
}

describe('platform client', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    delete process.env.G0_PLATFORM_URL;
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.G0_PLATFORM_URL;
  });

  describe('platformBaseUrl', () => {
    it('defaults to the live platform', async () => {
      const { platformBaseUrl } = await import('../../src/platform/client.js');
      expect(platformBaseUrl()).toBe('https://app.guard0.ai');
    });

    it('respects G0_PLATFORM_URL override', async () => {
      process.env.G0_PLATFORM_URL = 'https://staging.guard0.ai';
      const { platformBaseUrl } = await import('../../src/platform/client.js');
      expect(platformBaseUrl()).toBe('https://staging.guard0.ai');
    });
  });

  describe('startDeviceFlow', () => {
    it('POSTs to /v1/auth/device/code with client_id and scope', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(200, {
        device_code: 'dc1',
        user_code: 'ABCD-1234',
        verification_uri: 'https://app.guard0.ai/device',
        verification_uri_complete: 'https://app.guard0.ai/device?code=ABCD-1234',
        expires_in: 900,
        interval: 5,
      }));

      const { startDeviceFlow } = await import('../../src/platform/client.js');
      const result = await startDeviceFlow();

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://app.guard0.ai/v1/auth/device/code');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ client_id: 'g0-cli', scope: 'cli' });
      expect(init.headers['User-Agent']).toMatch(/^g0-security\//);
      expect(init.signal).toBeInstanceOf(AbortSignal);
      expect(result.user_code).toBe('ABCD-1234');
    });
  });

  describe('pollDeviceToken', () => {
    it('POSTs to /v1/auth/device/token with the device code', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(200, {
        access_token: 'at1',
        refresh_token: 'rt1',
        expires_in: 3600,
        email: 'a@b.com',
        user_id: 'u1',
        org_id: 'o1',
      }));

      const { pollDeviceToken } = await import('../../src/platform/client.js');
      const result = await pollDeviceToken('dc1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://app.guard0.ai/v1/auth/device/token');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({
        client_id: 'g0-cli',
        device_code: 'dc1',
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      });
      expect(result.access_token).toBe('at1');
    });

    it('throws DeviceFlowError carrying the error code on 400', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(400, { error: 'authorization_pending' }));

      const { pollDeviceToken, DeviceFlowError } = await import('../../src/platform/client.js');
      await expect(pollDeviceToken('dc1')).rejects.toSatisfy((err: unknown) => {
        expect(err).toBeInstanceOf(DeviceFlowError);
        expect((err as InstanceType<typeof DeviceFlowError>).error).toBe('authorization_pending');
        expect((err as InstanceType<typeof DeviceFlowError>).code).toBe('device_flow_error');
        return true;
      });
    });

    it('surfaces each device flow error variant', async () => {
      const { pollDeviceToken, DeviceFlowError } = await import('../../src/platform/client.js');
      for (const code of ['slow_down', 'expired_token', 'access_denied']) {
        fetchMock.mockResolvedValueOnce(fakeResponse(400, { error: code }));
        await expect(pollDeviceToken('dc1')).rejects.toThrow(DeviceFlowError);
      }
    });
  });

  describe('refreshTokens', () => {
    it('POSTs to /v1/auth/token/refresh with the refresh token', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(200, {
        access_token: 'at2',
        refresh_token: 'rt2',
        expires_in: 3600,
      }));

      const { refreshTokens } = await import('../../src/platform/client.js');
      const result = await refreshTokens('rt1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://app.guard0.ai/v1/auth/token/refresh');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ refresh_token: 'rt1' });
      expect(result.access_token).toBe('at2');
    });

    it('throws InvalidGrantError on invalid_grant', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(400, { error: 'invalid_grant' }));

      const { refreshTokens, InvalidGrantError } = await import('../../src/platform/client.js');
      await expect(refreshTokens('dead-token')).rejects.toBeInstanceOf(InvalidGrantError);
    });

    it('throws InvalidGrantError on a 401 invalid_grant', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(401, { error: 'invalid_grant' }));

      const { refreshTokens, InvalidGrantError } = await import('../../src/platform/client.js');
      await expect(refreshTokens('dead-token')).rejects.toBeInstanceOf(InvalidGrantError);
    });

    it('throws a plain error for other 400s', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(400, { error: 'invalid_request' }));

      const { refreshTokens, InvalidGrantError } = await import('../../src/platform/client.js');
      await expect(refreshTokens('rt1')).rejects.not.toBeInstanceOf(InvalidGrantError);
    });
  });

  describe('revokeToken', () => {
    it('POSTs to /v1/auth/revoke with bearer auth and swallows errors', async () => {
      fetchMock.mockRejectedValueOnce(new Error('network down'));

      const { revokeToken } = await import('../../src/platform/client.js');
      await expect(revokeToken('rt1', 'at1')).resolves.toBeUndefined();

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://app.guard0.ai/v1/auth/revoke');
      expect(init.headers.Authorization).toBe('Bearer at1');
      expect(JSON.parse(init.body)).toEqual({ refresh_token: 'rt1' });
    });
  });

  describe('fetchMe', () => {
    it('GETs /v1/me with bearer auth', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(200, {
        email: 'a@b.com',
        user_id: 'u1',
        org_id: 'o1',
        plan: 'pro',
      }));

      const { fetchMe } = await import('../../src/platform/client.js');
      const result = await fetchMe('at1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://app.guard0.ai/v1/me');
      expect(init.method).toBe('GET');
      expect(init.headers.Authorization).toBe('Bearer at1');
      expect(result.plan).toBe('pro');
    });
  });

  describe('fetchEntitlements', () => {
    it('GETs /v1/me/entitlements with bearer auth', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(200, {
        plan: 'pro',
        features: ['fleet', 'attestation'],
        feed_token: 'ft1',
      }));

      const { fetchEntitlements } = await import('../../src/platform/client.js');
      const result = await fetchEntitlements('at1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('https://app.guard0.ai/v1/me/entitlements');
      expect(init.headers.Authorization).toBe('Bearer at1');
      expect(result.features).toEqual(['fleet', 'attestation']);
    });

    it('throws on non-ok response', async () => {
      fetchMock.mockResolvedValueOnce(fakeResponse(500, {}));
      const { fetchEntitlements } = await import('../../src/platform/client.js');
      await expect(fetchEntitlements('at1')).rejects.toThrow();
    });
  });
});
