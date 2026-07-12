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

describe('entitlements', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-entitlements-test-'));
    delete process.env.G0_API_KEY;
    delete process.env.G0_PLATFORM_URL;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    vi.unstubAllGlobals();
    delete process.env.G0_API_KEY;
    delete process.env.G0_PLATFORM_URL;
  });

  describe('entitlementsFilePath', () => {
    it('joins dir with entitlements.json', async () => {
      const { entitlementsFilePath } = await import('../../src/platform/entitlements.js');
      expect(entitlementsFilePath(tmpDir)).toBe(path.join(tmpDir, 'entitlements.json'));
    });
  });

  describe('getEntitlementsCached', () => {
    it('returns null when no cache exists, without throwing', async () => {
      const { getEntitlementsCached } = await import('../../src/platform/entitlements.js');
      expect(() => getEntitlementsCached(tmpDir)).not.toThrow();
      expect(getEntitlementsCached(tmpDir)).toBeNull();
    });

    it('reads a previously written cache', async () => {
      const { entitlementsFilePath, getEntitlementsCached } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      const entitlements = { plan: 'pro', features: ['fleet'], fetchedAt: new Date().toISOString() };
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify(entitlements), { mode: 0o600 });
      expect(getEntitlementsCached(tmpDir)).toEqual(entitlements);
    });

    it('returns null for a corrupt cache file', async () => {
      const { entitlementsFilePath, getEntitlementsCached } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(entitlementsFilePath(tmpDir), 'not json', { mode: 0o600 });
      expect(getEntitlementsCached(tmpDir)).toBeNull();
    });

    it('does not enforce TTL on read', async () => {
      const { entitlementsFilePath, getEntitlementsCached } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      const stale = {
        plan: 'pro',
        features: ['fleet'],
        fetchedAt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(),
      };
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify(stale), { mode: 0o600 });
      expect(getEntitlementsCached(tmpDir)).toEqual(stale);
    });
  });

  describe('refreshEntitlements', () => {
    it('returns null with no stored auth', async () => {
      const { refreshEntitlements } = await import('../../src/platform/entitlements.js');
      await expect(refreshEntitlements(tmpDir)).resolves.toBeNull();
    });

    it('fetches, saves (0600), and returns entitlements when authenticated', async () => {
      process.env.G0_API_KEY = 'env-key';
      const fetchMock = vi.fn().mockResolvedValueOnce(fakeResponse(200, {
        plan: 'pro',
        features: ['fleet', 'attestation'],
        feed_token: 'ft1',
      }));
      vi.stubGlobal('fetch', fetchMock);

      const { refreshEntitlements, entitlementsFilePath, getEntitlementsCached } = await import('../../src/platform/entitlements.js');
      const result = await refreshEntitlements(tmpDir);

      expect(result?.plan).toBe('pro');
      expect(result?.features).toEqual(['fleet', 'attestation']);
      expect(result?.feedToken).toBe('ft1');
      expect(typeof result?.fetchedAt).toBe('string');

      const fileMode = fs.statSync(entitlementsFilePath(tmpDir)).mode & 0o777;
      expect(fileMode).toBe(0o600);
      expect(getEntitlementsCached(tmpDir)).toEqual(result);
    });

    it('returns the existing stale cache on a network failure, never throwing', async () => {
      process.env.G0_API_KEY = 'env-key';
      const { entitlementsFilePath } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      const stale = { plan: 'free', features: ['scan'], fetchedAt: new Date(0).toISOString() };
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify(stale), { mode: 0o600 });

      const fetchMock = vi.fn().mockRejectedValueOnce(new Error('network down'));
      vi.stubGlobal('fetch', fetchMock);

      const { refreshEntitlements } = await import('../../src/platform/entitlements.js');
      await expect(refreshEntitlements(tmpDir)).resolves.toEqual(stale);
    });

    it('returns null on network failure with no existing cache', async () => {
      process.env.G0_API_KEY = 'env-key';
      const fetchMock = vi.fn().mockRejectedValueOnce(new Error('network down'));
      vi.stubGlobal('fetch', fetchMock);

      const { refreshEntitlements } = await import('../../src/platform/entitlements.js');
      await expect(refreshEntitlements(tmpDir)).resolves.toBeNull();
    });
  });

  describe('clearEntitlements', () => {
    it('removes the cache file', async () => {
      const { entitlementsFilePath, clearEntitlements } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify({ plan: 'pro', features: [], fetchedAt: new Date().toISOString() }), { mode: 0o600 });
      clearEntitlements(tmpDir);
      expect(fs.existsSync(entitlementsFilePath(tmpDir))).toBe(false);
    });

    it('does not throw when the file does not exist', async () => {
      const { clearEntitlements } = await import('../../src/platform/entitlements.js');
      expect(() => clearEntitlements(tmpDir)).not.toThrow();
    });
  });

  describe('hasFeature', () => {
    it('returns true when the feature is present in the cache', async () => {
      const { entitlementsFilePath } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify({ plan: 'pro', features: ['fleet'], fetchedAt: new Date().toISOString() }), { mode: 0o600 });

      const { hasFeature } = await import('../../src/platform/entitlements.js');
      expect(hasFeature('fleet', tmpDir)).toBe(true);
      expect(hasFeature('attestation', tmpDir)).toBe(false);
    });

    it('returns false with no cache, never throwing', async () => {
      const { hasFeature } = await import('../../src/platform/entitlements.js');
      expect(() => hasFeature('fleet', tmpDir)).not.toThrow();
      expect(hasFeature('fleet', tmpDir)).toBe(false);
    });
  });

  describe('isEntitlementsStale', () => {
    it('is true when there is no cache', async () => {
      const { isEntitlementsStale } = await import('../../src/platform/entitlements.js');
      expect(isEntitlementsStale(tmpDir)).toBe(true);
    });

    it('is false for a fresh cache', async () => {
      const { entitlementsFilePath } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify({ plan: 'pro', features: [], fetchedAt: new Date().toISOString() }), { mode: 0o600 });

      const { isEntitlementsStale } = await import('../../src/platform/entitlements.js');
      expect(isEntitlementsStale(tmpDir)).toBe(false);
    });

    it('is true for a cache older than the TTL', async () => {
      const { entitlementsFilePath, ENTITLEMENTS_TTL_MS } = await import('../../src/platform/entitlements.js');
      fs.mkdirSync(tmpDir, { recursive: true });
      const old = new Date(Date.now() - ENTITLEMENTS_TTL_MS - 1000).toISOString();
      fs.writeFileSync(entitlementsFilePath(tmpDir), JSON.stringify({ plan: 'pro', features: [], fetchedAt: old }), { mode: 0o600 });

      const { isEntitlementsStale } = await import('../../src/platform/entitlements.js');
      expect(isEntitlementsStale(tmpDir)).toBe(true);
    });
  });
});
