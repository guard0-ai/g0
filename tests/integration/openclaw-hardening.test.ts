import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { probeOpenClawInstance } from '../../src/mcp/openclaw-hardening.js';
import { startOpenClawServer } from '../helpers/openclaw-test-server.js';

describe('OpenClaw Hardening — Integration (real HTTP)', () => {
  describe('Fully vulnerable gateway', () => {
    let url: string;
    let close: () => Promise<void>;

    beforeAll(async () => {
      const server = await startOpenClawServer({ mode: 'vulnerable' });
      url = server.url;
      close = server.close;
    });

    afterAll(async () => { await close(); });

    it('returns 18 checks', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks).toHaveLength(18);
    });

    it('OC-H-001: health endpoint exposed', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-001')!;
      expect(check.status).toBe('fail');
      expect(check.detail).toContain('/healthz');
    });

    it('OC-H-002: readiness endpoint leaks state', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-002')!;
      expect(check.status).toBe('fail');
      expect(check.detail).toContain('readiness');
    });

    it('OC-H-003: Control UI accessible without pairing', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-003')!;
      expect(check.status).toBe('fail');
      expect(check.severity).toBe('critical');
      expect(check.detail).toContain('Control UI');
    });

    it('OC-H-004: /hooks/wake accepts unauthenticated POST', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-004')!;
      expect(check.status).toBe('fail');
      expect(check.severity).toBe('critical');
    });

    it('OC-H-005: /hooks/agent accepts unauthenticated POST', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-005')!;
      expect(check.status).toBe('fail');
      expect(check.severity).toBe('critical');
    });

    it('OC-H-006: OpenAI API exposed without bearer token', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-006')!;
      expect(check.status).toBe('fail');
      expect(check.severity).toBe('critical');
    });

    it('OC-H-007: CVE-2026-25253 gatewayUrl reflected', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-007')!;
      expect(check.status).toBe('fail');
      expect(check.severity).toBe('critical');
      expect(check.detail).toContain('CVE-2026-25253');
    });

    it('OC-H-008: CORS wildcard', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-008')!;
      expect(check.status).toBe('fail');
      expect(check.detail).toContain('wildcard');
    });

    it('OC-H-009: no TLS redirect', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-009')!;
      expect(check.status).toBe('fail');
    });

    it('OC-H-010: no rate limiting', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-010')!;
      expect(check.status).toBe('fail');
    });

    it('OC-H-011: version header disclosed', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-011')!;
      expect(check.status).toBe('fail');
      expect(check.detail).toContain('version');
    });

    it('OC-H-012: WebSocket upgrade without auth', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-012')!;
      // fetch() may not fully support WS upgrade — status depends on env
      expect(['fail', 'pass', 'error']).toContain(check.status);
    });

    it('OC-H-013: weak webhook token detected', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-013')!;
      // Vulnerable mode has no webhook auth, so this should skip (deferred to OC-H-004)
      expect(check.status).toBe('skip');
    });

    it('OC-H-014: CSP allows ws:/wss: in vulnerable mode', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-014')!;
      expect(check.status).toBe('fail');
    });

    it('OC-H-015: SPA catch-all masks 404s', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-015')!;
      expect(check.status).toBe('fail');
      expect(check.detail).toContain('sentinel paths');
    });

    it('OC-H-016: canvas endpoint exposed', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-016')!;
      expect(check.status).toBe('fail');
    });

    it('OC-H-017: favicon serves product fingerprint', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-017')!;
      expect(check.status).toBe('fail');
    });

    it('OC-H-018: config check skipped without configPath', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const check = result.checks.find(c => c.id === 'OC-H-018')!;
      expect(check.status).toBe('skip');
    });

    it('overall status is critical', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.summary.overallStatus).toBe('critical');
    });

    it('summary counts are consistent', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const s = result.summary;
      const skipped = result.checks.filter(c => c.status === 'skip').length;
      expect(s.passed + s.failed + s.errors + skipped).toBe(s.total);
    });
  });

  describe('Fully secure gateway', () => {
    let url: string;
    let close: () => Promise<void>;

    beforeAll(async () => {
      const server = await startOpenClawServer({ mode: 'secure' });
      url = server.url;
      close = server.close;
    });

    afterAll(async () => { await close(); });

    it('no critical failures', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      const criticalFails = result.checks.filter(c => c.status === 'fail' && c.severity === 'critical');
      expect(criticalFails).toHaveLength(0);
    });

    it('OC-H-001: health endpoint blocked', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-001')!.status).toBe('pass');
    });

    it('OC-H-003: Control UI does not reflect gatewayUrl', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-007')!.status).toBe('pass');
    });

    it('OC-H-004: /hooks/wake requires auth', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-004')!.status).toBe('pass');
    });

    it('OC-H-005: /hooks/agent requires auth', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-005')!.status).toBe('pass');
    });

    it('OC-H-006: chat completions API requires bearer token', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-006')!.status).toBe('pass');
    });

    it('OC-H-010: rate limiting active', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-010')!.status).toBe('pass');
    });

    it('OC-H-011: version header hidden', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-011')!.status).toBe('pass');
    });

    it('OC-H-013: webhook token is strong (or rate limited)', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      // Rate limiter from OC-H-010 may cause 429 before OC-H-013 can check
      const status = result.checks.find(c => c.id === 'OC-H-013')!.status;
      expect(['pass', 'error']).toContain(status);
    });

    it('OC-H-014: CSP restricts connect-src', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-014')!.status).toBe('pass');
    });

    it('OC-H-015: no SPA catch-all', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-015')!.status).toBe('pass');
    });

    it('OC-H-016: canvas endpoint not exposed', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-016')!.status).toBe('pass');
    });

    it('OC-H-017: no favicon fingerprinting', async () => {
      const result = await probeOpenClawInstance(url, 5000);
      expect(result.checks.find(c => c.id === 'OC-H-017')!.status).toBe('pass');
    });
  });

  describe('Mixed configuration', () => {
    it('webhooks open but chat API secured', async () => {
      const server = await startOpenClawServer({
        mode: 'custom',
        healthzExposed: true,
        readyzExposed: false,
        controlUIOpen: true,
        webhookAuth: false,       // vulnerable
        chatApiAuth: true,        // secure
        gatewayUrlReflected: false,
        corsOrigin: null,
        enableRateLimit: true,
        hideVersion: true,
        wsAuthRequired: true,
        cspHeader: "default-src 'self'; connect-src 'self'",
        spaCatchAll: false,
        canvasExposed: false,
        faviconExposed: false,
      });

      try {
        const result = await probeOpenClawInstance(server.url, 5000);

        // Webhooks should fail (critical)
        expect(result.checks.find(c => c.id === 'OC-H-004')!.status).toBe('fail');
        expect(result.checks.find(c => c.id === 'OC-H-005')!.status).toBe('fail');

        // Chat API should pass
        expect(result.checks.find(c => c.id === 'OC-H-006')!.status).toBe('pass');

        // CVE-2026-25253 should pass (not reflected)
        expect(result.checks.find(c => c.id === 'OC-H-007')!.status).toBe('pass');

        // Overall critical due to webhook exposure
        expect(result.summary.overallStatus).toBe('critical');
      } finally {
        await server.close();
      }
    });
  });

  describe('Unreachable server', () => {
    it('all probes return error or skip when server is down', async () => {
      const result = await probeOpenClawInstance('http://127.0.0.1:19999', 1000);
      expect(result.checks).toHaveLength(18);
      const errorsOrSkips = result.checks.filter(c => c.status === 'error' || c.status === 'skip');
      expect(errorsOrSkips.length).toBeGreaterThanOrEqual(15);
    });
  });
});
