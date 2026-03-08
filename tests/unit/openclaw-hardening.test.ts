import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { probeOpenClawInstance } from '../../src/mcp/openclaw-hardening.js';
import type { AIProvider } from '../../src/ai/provider.js';

const TARGET = 'http://localhost:18789';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

// ── Mock helpers ──────────────────────────────────────────────────────────

/** OpenClaw-identified response: serves OpenClaw HTML + version headers */
function openClawResponse(overrides?: Record<string, unknown>) {
  return {
    status: 200,
    ok: true,
    headers: {
      get: (h: string) => {
        const lower = h.toLowerCase();
        if (lower === 'x-openclaw-version') return '2026.2.23';
        if (lower === 'server') return 'openclaw-gateway/2026.2.23';
        return null;
      },
    },
    text: async () => '<html><head><title>OpenClaw</title></head><body>OpenClaw Control UI</body></html>',
    ...overrides,
  };
}

/** Routes requests to appropriate mock responses for a vulnerable OpenClaw instance */
function mockVulnerableOpenClaw(routeOverrides?: Record<string, unknown>): void {
  mockFetch.mockImplementation((url: string, init?: RequestInit) => {
    const urlStr = url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();

    // Check route overrides first
    if (routeOverrides) {
      for (const [pattern, response] of Object.entries(routeOverrides)) {
        if (urlStr.includes(pattern)) return Promise.resolve(response);
      }
    }

    // Default OpenClaw headers
    const ocHeaders = {
      get: (h: string) => {
        const lower = h.toLowerCase();
        if (lower === 'x-openclaw-version') return '2026.2.23';
        if (lower === 'server') return 'openclaw-gateway/2026.2.23';
        if (lower === 'content-security-policy') return "default-src 'self'; connect-src 'self' ws: wss:";
        if (lower === 'access-control-allow-origin') return '*';
        if (lower === 'content-type') return 'application/json';
        return null;
      },
    };

    // /healthz (GET and OPTIONS)
    if (urlStr.includes('/healthz') && (method === 'GET' || method === 'OPTIONS')) {
      if (method === 'OPTIONS') {
        return Promise.resolve({ status: 204, ok: true, headers: ocHeaders, text: async () => '' });
      }
      return Promise.resolve({ status: 200, ok: true, headers: ocHeaders, text: async () => '{"ok":true,"status":"live"}' });
    }
    // GET /readyz
    if (urlStr.includes('/readyz')) {
      return Promise.resolve({ status: 200, ok: true, headers: ocHeaders, text: async () => '{"ok":true,"channels":{"whatsapp":"connected"}}' });
    }
    // GET / (Control UI)
    if ((urlStr.endsWith('/') || urlStr.endsWith(':18789')) && method === 'GET') {
      return Promise.resolve(openClawResponse({
        headers: {
          get: (h: string) => {
            const lower = h.toLowerCase();
            if (lower === 'x-openclaw-version') return '2026.2.23';
            if (lower === 'server') return 'openclaw-gateway/2026.2.23';
            if (lower === 'content-security-policy') return "default-src 'self'; connect-src 'self' ws: wss:";
            return null;
          },
        },
      }));
    }
    // POST /hooks/wake
    if (urlStr.includes('/hooks/wake') && method === 'POST') {
      return Promise.resolve({ status: 200, ok: true, headers: ocHeaders, text: async () => '{"ok":true,"triggered":true}' });
    }
    // POST /hooks/agent
    if (urlStr.includes('/hooks/agent') && method === 'POST') {
      return Promise.resolve({ status: 202, ok: true, headers: ocHeaders, text: async () => '{"ok":true,"sessionId":"abc"}' });
    }
    // POST /v1/chat/completions
    if (urlStr.includes('/v1/chat/completions') && method === 'POST') {
      return Promise.resolve({ status: 200, ok: true, headers: ocHeaders, text: async () => '{"choices":[{"message":{"role":"assistant","content":"OK"}}]}' });
    }
    // __openclaw__
    if (urlStr.includes('__openclaw__')) {
      return Promise.resolve({ status: 200, ok: true, headers: ocHeaders, text: async () => '<html><body>OpenClaw Canvas</body></html>' });
    }
    // Favicon
    if (urlStr.includes('/favicon.svg')) {
      return Promise.resolve({
        status: 200, ok: true,
        headers: { get: (h: string) => h.toLowerCase() === 'content-type' ? 'image/svg+xml' : null },
        text: async () => '<svg></svg>',
      });
    }

    return Promise.resolve({ status: 404, ok: false, headers: { get: () => null }, text: async () => '{"error":"Not Found"}' });
  });
}

function mockSecureOpenClaw(): void {
  mockFetch.mockImplementation((url: string, init?: RequestInit) => {
    const urlStr = url.toString();
    const method = (init?.method ?? 'GET').toUpperCase();

    const secHeaders = { get: () => null }; // No version headers

    if (urlStr.includes('/healthz') && method === 'GET') {
      return Promise.resolve({ status: 403, ok: false, headers: secHeaders, text: async () => '{"error":"Forbidden"}' });
    }
    if (urlStr.includes('/readyz')) {
      return Promise.resolve({ status: 403, ok: false, headers: secHeaders, text: async () => '{"error":"Forbidden"}' });
    }
    // Secure: Control UI requires pairing but still fingerprintable via /__openclaw__
    if (urlStr.includes('__openclaw__')) {
      return Promise.resolve({
        status: 200, ok: true,
        headers: { get: (h: string) => h.toLowerCase() === 'x-openclaw-version' ? '2026.2.23' : null },
        text: async () => '<html><body>OpenClaw Canvas (auth required)</body></html>',
      });
    }
    if ((urlStr.endsWith('/') || urlStr.endsWith(':18789')) && method === 'GET') {
      return Promise.resolve({ status: 401, ok: false, headers: secHeaders, text: async () => '{"error":"Device pairing required"}' });
    }
    if (urlStr.includes('/hooks/') && method === 'POST') {
      return Promise.resolve({ status: 401, ok: false, headers: secHeaders, text: async () => '{"error":"Bearer token required"}' });
    }
    if (urlStr.includes('/v1/chat/completions')) {
      return Promise.resolve({ status: 401, ok: false, headers: secHeaders, text: async () => '{"error":"Bearer token required"}' });
    }
    if (urlStr.includes('/favicon')) {
      return Promise.resolve({ status: 404, ok: false, headers: secHeaders, text: async () => '' });
    }
    return Promise.resolve({ status: 404, ok: false, headers: secHeaders, text: async () => '' });
  });
}

describe('OpenClaw Hardening Probes', () => {

  // ── Fingerprint ─────────────────────────────────────────────────────────

  describe('Fingerprint', () => {
    it('confirms OpenClaw via version header', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.fingerprint.confidence).toBe('confirmed');
      expect(result.fingerprint.version).toBe('2026.2.23');
      expect(result.fingerprint.signals.length).toBeGreaterThan(0);
    });

    it('returns unknown for non-OpenClaw target', async () => {
      mockFetch.mockImplementation((url: string) => {
        const u = url.toString();
        // Non-OpenClaw: /__openclaw__/ returns 404 (path doesn't exist)
        if (u.includes('__openclaw__')) {
          return Promise.resolve({ status: 404, ok: false, headers: { get: () => null }, text: async () => '' });
        }
        return Promise.resolve({
          status: 200, ok: true,
          headers: { get: () => null },
          text: async () => '<html><body>My Blog</body></html>',
        });
      });
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.fingerprint.confidence).toBe('unknown');
    });

    it('skips all 18 checks when fingerprint is unknown', async () => {
      mockFetch.mockImplementation((url: string) => {
        const u = url.toString();
        if (u.includes('__openclaw__')) {
          return Promise.resolve({ status: 404, ok: false, headers: { get: () => null }, text: async () => '' });
        }
        return Promise.resolve({
          status: 200, ok: true,
          headers: { get: () => null },
          text: async () => '<html><body>My Blog</body></html>',
        });
      });
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks).toHaveLength(18);
      expect(result.checks.every(c => c.status === 'skip')).toBe(true);
    });

    it('skips all when target is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'));
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.fingerprint.confidence).toBe('unknown');
      expect(result.checks.every(c => c.status === 'skip')).toBe(true);
    });
  });

  // ── AI Integration ────────────────────────────────────────────────────

  describe('AI verification', () => {
    it('AI can upgrade unknown → likely', async () => {
      // Target returns ambiguous responses — must return 404 for __openclaw__ to stay unknown
      mockFetch.mockImplementation((url: string) => {
        const u = url.toString();
        if (u.includes('__openclaw__')) {
          return Promise.resolve({ status: 404, ok: false, headers: { get: () => null }, text: async () => '' });
        }
        return Promise.resolve({
          status: 200, ok: true,
          headers: { get: () => null },
          text: async () => '<html><body>Gateway UI</body></html>',
        });
      });

      const mockProvider: AIProvider = {
        name: 'test',
        model: 'test-model',
        analyze: vi.fn().mockResolvedValue(JSON.stringify({
          isOpenClaw: true,
          confidence: 'high',
          version: '2026.3.0',
          reasoning: 'HTML structure matches OpenClaw SPA',
          securityIssues: [
            { title: 'Missing CSP', severity: 'high', detail: 'No CSP header on Control UI' },
          ],
        })),
      };

      const result = await probeOpenClawInstance(TARGET, 1000, { aiProvider: mockProvider });
      expect(result.fingerprint.confidence).toBe('likely');
      expect(result.fingerprint.signals.some(s => s.includes('AI verification'))).toBe(true);
      expect(result.aiAnalysis?.provider).toBe('test');
      expect(result.aiAnalysis?.insights).toHaveLength(1);
      // Checks should run (not all skip)
      expect(result.checks.some(c => c.status !== 'skip')).toBe(true);
    });

    it('AI does not upgrade when it says not OpenClaw', async () => {
      mockFetch.mockImplementation((url: string) => {
        const u = url.toString();
        if (u.includes('__openclaw__')) {
          return Promise.resolve({ status: 404, ok: false, headers: { get: () => null }, text: async () => '' });
        }
        return Promise.resolve({
          status: 200, ok: true,
          headers: { get: () => null },
          text: async () => '<html><body>Other App</body></html>',
        });
      });

      const mockProvider: AIProvider = {
        name: 'test',
        model: 'test-model',
        analyze: vi.fn().mockResolvedValue(JSON.stringify({
          isOpenClaw: false,
          confidence: 'high',
          version: null,
          reasoning: 'Not OpenClaw',
          securityIssues: [],
        })),
      };

      const result = await probeOpenClawInstance(TARGET, 1000, { aiProvider: mockProvider });
      expect(result.fingerprint.confidence).toBe('unknown');
      expect(result.checks.every(c => c.status === 'skip')).toBe(true);
    });
  });

  // ── Vulnerable OpenClaw checks ────────────────────────────────────────

  describe('Vulnerable OpenClaw', () => {
    it('returns 18 checks for confirmed OpenClaw', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks).toHaveLength(18);
      expect(result.fingerprint.confidence).toBe('confirmed');
    });

    it('OC-H-001: fails when /healthz returns 200', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-001')!.status).toBe('fail');
    });

    it('OC-H-003: fails when Control UI serves HTML', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-003')!.status).toBe('fail');
    });

    it('OC-H-004: fails when /hooks/wake accepts unauthenticated POST', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-004')!.status).toBe('fail');
    });

    it('OC-H-005: fails when /hooks/agent accepts unauthenticated POST', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-005')!.status).toBe('fail');
    });

    it('OC-H-006: fails when /v1/chat/completions returns 200', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-006')!.status).toBe('fail');
    });

    it('OC-H-008: fails for wildcard CORS', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-008')!.status).toBe('fail');
    });

    it('OC-H-011: fails when version headers present', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-011')!.status).toBe('fail');
    });

    it('OC-H-013: skips when webhooks do not require auth', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-013')!.status).toBe('skip');
    });

    it('OC-H-014: fails when CSP allows ws:', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-014')!.status).toBe('fail');
    });

    it('OC-H-017: fails when favicon has image content-type', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-017')!.status).toBe('fail');
    });

    it('overall status is critical', async () => {
      mockVulnerableOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.summary.overallStatus).toBe('critical');
    });
  });

  // ── Secure OpenClaw checks ────────────────────────────────────────────

  describe('Secure OpenClaw', () => {
    it('OC-H-001: passes when /healthz returns 403', async () => {
      mockSecureOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-001')!.status).toBe('pass');
    });

    it('OC-H-003: passes when Control UI requires auth', async () => {
      mockSecureOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-003')!.status).toBe('pass');
    });

    it('OC-H-004: passes when webhooks require auth', async () => {
      mockSecureOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-004')!.status).toBe('pass');
    });

    it('OC-H-011: passes when version headers hidden', async () => {
      mockSecureOpenClaw();
      const result = await probeOpenClawInstance(TARGET, 1000);
      expect(result.checks.find(c => c.id === 'OC-H-011')!.status).toBe('pass');
    });
  });

  // ── Summary ────────────────────────────────────────────────────────────

  it('summary counts are consistent', async () => {
    mockVulnerableOpenClaw();
    const result = await probeOpenClawInstance(TARGET, 1000);
    const s = result.summary;
    const skipped = result.checks.filter(c => c.status === 'skip').length;
    expect(s.passed + s.failed + s.errors + skipped).toBe(s.total);
  });
});
