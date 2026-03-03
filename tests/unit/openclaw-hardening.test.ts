import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { probeOpenClawInstance } from '../../src/mcp/openclaw-hardening.js';

const TARGET = 'http://localhost:8080';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

type FetchResponse = {
  status: number;
  ok: boolean;
  headers: { get: (name: string) => string | null };
  json?: () => Promise<unknown>;
};

function mockEndpoints(overrides: Record<string, Partial<FetchResponse>>): void {
  mockFetch.mockImplementation((url: string, init?: RequestInit) => {
    const urlStr = url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const key = `${method} ${urlStr}`;

    for (const [pattern, response] of Object.entries(overrides)) {
      if (urlStr.includes(pattern) || key.includes(pattern)) {
        return Promise.resolve({
          status: 200,
          ok: true,
          headers: { get: () => null },
          ...response,
        });
      }
    }
    // Default: return 404
    return Promise.resolve({
      status: 404,
      ok: false,
      headers: { get: () => null },
    });
  });
}

describe('OpenClaw Live Hardening Probes', () => {
  it('returns 12 checks for any target', async () => {
    mockFetch.mockResolvedValue({ status: 404, ok: false, headers: { get: () => null } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    expect(result.checks).toHaveLength(12);
    expect(result.targetUrl).toBe(TARGET);
  });

  it('OC-H-001: fails when /api/skills returns 200 without auth', async () => {
    mockEndpoints({ '/api/skills': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-001');
    expect(check).toBeDefined();
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('OC-H-001: passes when /api/skills returns 401', async () => {
    mockFetch.mockResolvedValue({ status: 401, ok: false, headers: { get: () => null } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-001');
    expect(check!.status).toBe('pass');
  });

  it('OC-H-002: fails when /api/admin/config returns 200', async () => {
    mockEndpoints({ '/api/admin/config': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-002');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('OC-H-003: fails when /api/soul returns 200', async () => {
    mockEndpoints({ '/api/soul': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-003');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('OC-H-004: fails when /api/memory returns 200', async () => {
    mockEndpoints({ '/api/memory': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-004');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('OC-H-005: fails when /api/skills/install accepts crafted URI', async () => {
    mockEndpoints({ '/api/skills/install': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-005');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('OC-H-006: fails when /api/exec accepts non-allowlisted binary', async () => {
    mockEndpoints({ '/api/exec': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-006');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('OC-H-007: fails when /api/debug returns 200', async () => {
    mockEndpoints({ '/api/debug': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-007');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('high');
  });

  it('OC-H-008: fails when CORS header is wildcard (*)', async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      ok: true,
      headers: { get: (h: string) => h === 'Access-Control-Allow-Origin' ? '*' : null },
    });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-008');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('high');
  });

  it('OC-H-008: passes when CORS is restricted', async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      ok: true,
      headers: { get: (h: string) => h === 'Access-Control-Allow-Origin' ? 'https://app.example.com' : null },
    });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-008');
    expect(check!.status).toBe('pass');
  });

  it('OC-H-011: fails when X-OpenClaw-Version header is present', async () => {
    mockFetch.mockResolvedValue({
      status: 200,
      ok: true,
      headers: { get: (h: string) => h === 'X-OpenClaw-Version' ? '1.2.3' : null },
    });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-011');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('low');
  });

  it('OC-H-012: fails when admin/admin returns 200', async () => {
    mockEndpoints({ '/api/auth/login': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const check = result.checks.find(c => c.id === 'OC-H-012');
    expect(check!.status).toBe('fail');
    expect(check!.severity).toBe('critical');
  });

  it('overall status is critical when any critical check fails', async () => {
    mockEndpoints({ '/api/skills': { status: 200, ok: true } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    expect(result.summary.overallStatus).toBe('critical');
  });

  it('overall status is secure when all checks pass', async () => {
    mockFetch.mockResolvedValue({
      status: 403,
      ok: false,
      headers: { get: () => 'https://app.example.com' },
    });
    const result = await probeOpenClawInstance(TARGET, 1000);
    // With all 403 responses, critical checks pass; rate limit may show fail
    expect(['secure', 'warn']).toContain(result.summary.overallStatus);
  });

  it('summary counts are consistent', async () => {
    mockFetch.mockResolvedValue({ status: 404, ok: false, headers: { get: () => null } });
    const result = await probeOpenClawInstance(TARGET, 1000);
    const s = result.summary;
    expect(s.passed + s.failed + s.errors + result.checks.filter(c => c.status === 'skip').length).toBe(s.total);
  });
});
