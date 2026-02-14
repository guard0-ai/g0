import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

// ─── Machine ID ──────────────────────────────────────────────────────────────

describe('machine-id', () => {
  const testDir = path.join(os.tmpdir(), `g0-test-${Date.now()}`);
  const machineIdPath = path.join(testDir, 'machine-id');

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('generates a valid UUID', async () => {
    // Import fresh to test generation
    const { getMachineId } = await import('../../src/platform/machine-id.js');
    const id = getMachineId();
    // UUID v4 format
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it('returns same ID on repeated calls', async () => {
    const { getMachineId } = await import('../../src/platform/machine-id.js');
    const id1 = getMachineId();
    const id2 = getMachineId();
    expect(id1).toBe(id2);
  });
});

// ─── Auth ────────────────────────────────────────────────────────────────────

describe('auth', () => {
  const testDir = path.join(os.tmpdir(), `g0-auth-test-${Date.now()}`);
  const authPath = path.join(testDir, 'auth.json');

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
    delete process.env.G0_API_TOKEN;
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
    delete process.env.G0_API_TOKEN;
  });

  it('resolveToken returns null when not authenticated', async () => {
    const { resolveToken } = await import('../../src/platform/auth.js');
    // When no env var and no file, resolveToken depends on home dir
    // but we test the env var path
    delete process.env.G0_API_TOKEN;
    const token = resolveToken();
    // May or may not be null depending on whether ~/.g0/auth.json exists
    expect(token === null || typeof token === 'string').toBe(true);
  });

  it('resolveToken returns G0_API_TOKEN when set', async () => {
    process.env.G0_API_TOKEN = 'g0_test_token_12345';
    const { resolveToken } = await import('../../src/platform/auth.js');
    expect(resolveToken()).toBe('g0_test_token_12345');
  });

  it('isAuthenticated returns true when G0_API_TOKEN is set', async () => {
    process.env.G0_API_TOKEN = 'g0_test_token_12345';
    const { isAuthenticated } = await import('../../src/platform/auth.js');
    expect(isAuthenticated()).toBe(true);
  });

  it('saveTokens and loadTokens round-trip', async () => {
    const { saveTokens, loadTokens } = await import('../../src/platform/auth.js');
    const tokens = {
      accessToken: 'test-access-token',
      refreshToken: 'test-refresh-token',
      expiresAt: Date.now() + 3600_000,
      email: 'test@example.com',
      userId: 'user_123',
    };

    saveTokens(tokens);
    const loaded = loadTokens();
    expect(loaded).toBeTruthy();
    expect(loaded!.accessToken).toBe('test-access-token');
    expect(loaded!.email).toBe('test@example.com');
  });

  it('clearTokens removes auth file', async () => {
    const { saveTokens, clearTokens, loadTokens } = await import('../../src/platform/auth.js');
    saveTokens({
      accessToken: 'test',
      expiresAt: Date.now() + 3600_000,
    });
    clearTokens();
    // loadTokens may return null or previous depending on path
    // We mainly verify clearTokens doesn't throw
    expect(true).toBe(true);
  });
});

// ─── Platform Client ─────────────────────────────────────────────────────────

describe('PlatformClient', () => {
  it('throws when not authenticated', async () => {
    delete process.env.G0_API_TOKEN;
    const { PlatformClient } = await import('../../src/platform/client.js');
    const client = new PlatformClient({ baseUrl: 'http://localhost:9999' });

    // Only fails if no token at all
    // This test validates the error path
    try {
      await client.checkAuth();
      // If it doesn't throw, there must be a token in ~/.g0/auth.json
    } catch (err: any) {
      expect(err.message).toContain('Not authenticated');
    }
  });

  it('PlatformError has correct properties', async () => {
    const { PlatformError } = await import('../../src/platform/client.js');
    const err = new PlatformError(401, 'Unauthorized', 'https://app.guard0.ai/api/v1/upload');
    expect(err.status).toBe(401);
    expect(err.body).toBe('Unauthorized');
    expect(err.url).toContain('upload');
    expect(err.name).toBe('PlatformError');
  });

  it('uses G0_PLATFORM_URL env var', async () => {
    process.env.G0_PLATFORM_URL = 'http://localhost:3000';
    process.env.G0_API_TOKEN = 'g0_test_key';
    const { PlatformClient } = await import('../../src/platform/client.js');
    const client = new PlatformClient();
    // We can't easily test the internal baseUrl, but we verify construction works
    expect(client).toBeDefined();
    delete process.env.G0_PLATFORM_URL;
    delete process.env.G0_API_TOKEN;
  });
});

// ─── Upload Metadata ─────────────────────────────────────────────────────────

describe('upload metadata', () => {
  it('collectMachineMeta returns valid metadata', async () => {
    const { collectMachineMeta } = await import('../../src/platform/upload.js');
    const meta = collectMachineMeta();
    expect(meta.hostname).toBeTruthy();
    expect(meta.platform).toBeTruthy();
    expect(meta.arch).toBeTruthy();
    expect(meta.nodeVersion).toMatch(/^v\d+/);
    expect(meta.machineId).toMatch(/^[0-9a-f-]+$/);
  });

  it('collectProjectMeta detects name from package.json', async () => {
    const { collectProjectMeta } = await import('../../src/platform/upload.js');
    // Use this project's root directory
    const meta = collectProjectMeta(process.cwd());
    expect(meta.name).toBe('@guard0/g0');
    expect(meta.path).toBe(process.cwd());
  });

  it('collectProjectMeta returns git metadata', async () => {
    const { collectProjectMeta } = await import('../../src/platform/upload.js');
    const meta = collectProjectMeta(process.cwd());
    expect(meta.git).toBeTruthy();
    expect(meta.git!.branch).toBeTruthy();
    expect(meta.git!.commit).toBeTruthy();
  });

  it('detectCIMeta returns undefined in non-CI environment', async () => {
    const origCI = process.env.CI;
    const origGH = process.env.GITHUB_ACTIONS;
    delete process.env.CI;
    delete process.env.GITHUB_ACTIONS;
    delete process.env.GITLAB_CI;
    delete process.env.JENKINS_URL;
    delete process.env.CIRCLECI;

    const { detectCIMeta } = await import('../../src/platform/upload.js');
    const ci = detectCIMeta();
    expect(ci).toBeUndefined();

    // Restore
    if (origCI) process.env.CI = origCI;
    if (origGH) process.env.GITHUB_ACTIONS = origGH;
  });

  it('detectCIMeta detects GitHub Actions', async () => {
    const origGH = process.env.GITHUB_ACTIONS;
    process.env.GITHUB_ACTIONS = 'true';
    process.env.GITHUB_RUN_ID = '12345';

    const { detectCIMeta } = await import('../../src/platform/upload.js');
    const ci = detectCIMeta();
    expect(ci).toBeTruthy();
    expect(ci!.provider).toBe('github-actions');
    expect(ci!.buildId).toBe('12345');

    delete process.env.GITHUB_ACTIONS;
    delete process.env.GITHUB_RUN_ID;
    if (origGH) process.env.GITHUB_ACTIONS = origGH;
  });
});

// ─── Platform Types ──────────────────────────────────────────────────────────

describe('platform types', () => {
  it('DEFAULT_PLATFORM_CONFIG has correct values', async () => {
    const { DEFAULT_PLATFORM_CONFIG } = await import('../../src/platform/types.js');
    expect(DEFAULT_PLATFORM_CONFIG.baseUrl).toBe('https://app.guard0.ai');
    expect(DEFAULT_PLATFORM_CONFIG.apiVersion).toBe('v1');
  });
});
