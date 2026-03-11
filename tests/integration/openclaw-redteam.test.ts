/**
 * Red Team Tests against a REAL OpenClaw gateway.
 *
 * These tests perform independent security discovery — they do NOT rely on
 * the hardening probe IDs or existing detection logic. They test what an
 * attacker would actually try against a misconfigured OpenClaw instance.
 *
 * Prerequisites:
 *   OPENCLAW_CONFIG_PATH=~/.openclaw-dev/openclaw-vuln.json \
 *   openclaw gateway --port 18789 --allow-unconfigured --force
 */
import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';

const BASE = 'http://127.0.0.1:18789';
const TIMEOUT = 5000;

async function get(path: string, headers?: Record<string, string>): Promise<{ status: number; body: string; headers: Headers }> {
  const res = await fetch(`${BASE}${path}`, {
    signal: AbortSignal.timeout(TIMEOUT),
    headers,
  });
  const body = await res.text();
  return { status: res.status, body, headers: res.headers };
}

async function post(path: string, data: unknown, headers?: Record<string, string>): Promise<{ status: number; body: string; headers: Headers }> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const body = await res.text();
  return { status: res.status, body, headers: res.headers };
}

async function isUp(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/`, { signal: AbortSignal.timeout(2000) });
    return res.status === 200;
  } catch {
    return false;
  }
}

describe('Red Team: OpenClaw Gateway Discovery', () => {
  let gatewayUp = false;

  beforeAll(async () => {
    gatewayUp = await isUp();
    if (!gatewayUp) console.log('⚠ Gateway not running — skipping red team tests');
  });

  // ─── DISCOVERY ──────────────────────────────────────────────────────────

  describe('Surface discovery', () => {
    it('SPA catch-all returns 200 for arbitrary paths (information leak)', async () => {
      if (!gatewayUp) return;
      const paths = ['/.env', '/admin', '/debug', '/config', '/status', '/metrics'];
      const results: string[] = [];
      for (const p of paths) {
        const { status, body } = await get(p);
        if (status === 200 && body.includes('<html')) {
          results.push(p);
        }
      }
      console.log(`  SPA catch-all serves HTML for: ${results.join(', ')}`);
      expect(results.length).toBeGreaterThan(0);
    });

    it('security headers present on responses', async () => {
      if (!gatewayUp) return;
      const { headers } = await get('/');
      const findings: string[] = [];

      if (!headers.get('x-content-type-options')) findings.push('missing X-Content-Type-Options');
      if (!headers.get('x-frame-options')) findings.push('missing X-Frame-Options');
      if (!headers.get('content-security-policy')) findings.push('missing CSP');
      if (!headers.get('referrer-policy')) findings.push('missing Referrer-Policy');
      if (headers.get('server')) findings.push(`Server header exposed: ${headers.get('server')}`);
      if (headers.get('x-powered-by')) findings.push(`X-Powered-By exposed: ${headers.get('x-powered-by')}`);

      console.log(`  Security headers: ${findings.length === 0 ? 'all present' : findings.join(', ')}`);
    });

    it('canvas endpoint is publicly accessible', async () => {
      if (!gatewayUp) return;
      const { status, body } = await get('/__openclaw__/canvas/');
      console.log(`  Canvas endpoint: ${status} (${body.length} bytes)`);
      if (status === 200) {
        expect(body.toLowerCase()).toContain('canvas');
      }
    });
  });

  // ─── AUTHENTICATION BYPASS ──────────────────────────────────────────────

  describe('Authentication bypass', () => {
    it('Control UI served without any authentication', async () => {
      if (!gatewayUp) return;
      const { status, body } = await get('/');
      expect(status).toBe(200);
      expect(body.toLowerCase()).toContain('openclaw');
      console.log('  CRITICAL: Control UI accessible without auth');
    });

    it('healthz/readyz expose operational info without auth', async () => {
      if (!gatewayUp) return;
      const healthz = await get('/healthz');
      const readyz = await get('/readyz');
      console.log(`  /healthz: ${healthz.status} | /readyz: ${readyz.status}`);
      expect(healthz.status).toBe(200);
      expect(readyz.status).toBe(200);
    });

    it('webhooks require auth even with auth=none gateway', async () => {
      if (!gatewayUp) return;
      const unauthStatus = (await post('/hooks/wake', { text: 'probe' })).status;
      console.log(`  /hooks/wake without token: ${unauthStatus}`);

      if (unauthStatus === 404) {
        console.log('  Webhooks not configured — skipping auth check');
        return;
      }

      // If webhooks exist, they MUST require auth (not return 200 without token)
      expect(unauthStatus).toBe(401);

      const authStatus = (await post(
        '/hooks/wake',
        { text: 'probe' },
        { 'Authorization': 'Bearer insecure-test-token-12345' },
      )).status;
      console.log(`  /hooks/wake with token: ${authStatus}`);
      expect(authStatus).toBe(200);
    });

    it('/v1/chat/completions attack surface', async () => {
      if (!gatewayUp) return;
      const { status, body } = await post('/v1/chat/completions', {
        model: 'default',
        messages: [{ role: 'user', content: 'say OK' }],
      });
      console.log(`  /v1/chat/completions: ${status} — ${body.slice(0, 100)}`);

      if (status === 404) {
        console.log('  LLM proxy not enabled — reduced attack surface');
      } else if (status === 200) {
        console.log('  CRITICAL: LLM proxy accepts unauthenticated requests');
      } else {
        console.log(`  LLM proxy responds with ${status} — verify auth is required`);
      }
      // Test passes regardless — we're documenting the attack surface
    });
  });

  // ─── CVE TESTING ────────────────────────────────────────────────────────

  describe('CVE-2026-25253: gatewayUrl reflection', () => {
    it('gatewayUrl parameter not reflected in HTML (patched)', async () => {
      if (!gatewayUp) return;
      // Use a unique nonce to check for reflection without triggering URL sanitization rules
      const nonce = `g0probe_${Date.now()}`;
      const { body } = await get(`/?gatewayUrl=ws://${nonce}:18789`);
      const reflected = body.includes(nonce);
      console.log(`  gatewayUrl reflected: ${reflected ? 'YES (VULNERABLE)' : 'NO (patched)'}`);
      expect(reflected).toBe(false);
    });

    it('alternate injection vectors for gatewayUrl', async () => {
      if (!gatewayUp) return;
      // Use a unique nonce per vector to detect reflection
      const nonce = `g0probe_${Date.now()}`;
      const vectors = [
        `/?gatewayUrl=ws%3A%2F%2F${nonce}`,
        `/?gateway_url=ws://${nonce}`,
        `/?wsUrl=ws://${nonce}`,
        `/?host=${nonce}`,
        `/#gatewayUrl=ws://${nonce}`,
      ];
      const reflected: string[] = [];
      for (const v of vectors) {
        const { body } = await get(v);
        if (body.includes(nonce)) {
          reflected.push(v);
        }
      }
      console.log(`  Alternate vectors reflected: ${reflected.length === 0 ? 'none' : reflected.join(', ')}`);
      expect(reflected).toHaveLength(0);
    });
  });

  // ─── RATE LIMITING & DOS ────────────────────────────────────────────────

  describe('Rate limiting', () => {
    it('no rate limiting on gateway endpoints', async () => {
      if (!gatewayUp) return;
      const count = 30;
      let got429 = false;
      for (let i = 0; i < count; i++) {
        const { status } = await get('/healthz');
        if (status === 429) { got429 = true; break; }
      }
      console.log(`  ${count} rapid requests: ${got429 ? 'rate limited (429)' : 'no rate limiting'}`);
    });
  });

  // ─── INFORMATION DISCLOSURE ─────────────────────────────────────────────

  describe('Information disclosure', () => {
    it('CSP connect-src allows ws: and wss: from any origin', async () => {
      if (!gatewayUp) return;
      const { headers } = await get('/');
      const csp = headers.get('content-security-policy') ?? '';
      const allowsWs = csp.includes("connect-src 'self' ws: wss:");
      console.log(`  CSP allows ws:/wss:: ${allowsWs}`);
      if (allowsWs) {
        console.log('  FINDING: CSP connect-src allows ws: and wss: from any origin');
        console.log('  This means any page loaded in the Control UI can establish WebSocket connections');
      }
    });

    it('no version information leaked in headers', async () => {
      if (!gatewayUp) return;
      const { headers } = await get('/');
      const version = headers.get('x-openclaw-version')
        ?? headers.get('server')
        ?? headers.get('x-powered-by');
      console.log(`  Version headers: ${version ?? 'none found'}`);
    });

    it('favicon exposes product identity', async () => {
      if (!gatewayUp) return;
      const { status } = await get('/favicon.svg');
      console.log(`  /favicon.svg: ${status} (product fingerprint via favicon)`);
      expect(status).toBe(200);
    });
  });

  // ─── WEBSOCKET ──────────────────────────────────────────────────────────

  describe('WebSocket attack surface', () => {
    it('WebSocket upgrade attempt (auth=none)', async () => {
      if (!gatewayUp) return;
      try {
        const res = await fetch(`${BASE}/`, {
          headers: {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
          },
          signal: AbortSignal.timeout(3000),
        });
        console.log(`  WS upgrade response: ${res.status}`);
        if (res.status === 101) {
          console.log('  CRITICAL: WebSocket upgrade accepted without auth — full gateway RPC access');
        }
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (msg.includes('upgrade')) {
          console.log('  WebSocket upgrade initiated (fetch API limitation prevents completion)');
        } else {
          console.log(`  WebSocket probe: ${msg}`);
        }
      }
    });
  });

  // ─── CONFIG FILE SECURITY ──────────────────────────────────────────────

  describe('Local config security', () => {
    it('config file permissions should be 600', async () => {
      if (!gatewayUp) return;
      const configPath = `${process.env.HOME}/.openclaw-dev/openclaw-vuln.json`;
      try {
        const stat = fs.statSync(configPath);
        const mode = (stat.mode & 0o777).toString(8);
        console.log(`  Config file permissions: ${mode} (should be 600)`);
        if (mode !== '600') {
          console.log(`  FINDING: Config file has ${mode} permissions — may expose webhook token`);
        }
      } catch {
        console.log('  Could not check config permissions');
      }
    });

    it('webhook token in config file is guessable', async () => {
      if (!gatewayUp) return;
      const weakTokens = [
        'test', 'password', 'admin', 'token', 'secret',
        'insecure-test-token-12345', 'openclaw', '12345',
      ];
      let found: string | null = null;
      for (const token of weakTokens) {
        const { status } = await post(
          '/hooks/wake',
          { text: 'brute-force-probe' },
          { 'Authorization': `Bearer ${token}` },
        );
        if (status === 200) {
          found = token;
          break;
        }
      }
      if (found) {
        console.log(`  CRITICAL: Webhook token guessed: "${found}"`);
      } else {
        console.log('  Webhook token not in common wordlist');
      }
    });
  });

  // ─── RUN OUR PROBES & COMPARE ──────────────────────────────────────────

  describe('Automated probe comparison', () => {
    it('run g0 hardening probes against live gateway', async () => {
      if (!gatewayUp) return;
      const { probeOpenClawInstance } = await import('../../src/mcp/openclaw-hardening.js');
      const result = await probeOpenClawInstance(BASE, 8000);

      console.log('\n  === g0 Automated Probe Results ===');
      for (const c of result.checks) {
        const icon = c.status === 'fail' ? '✗' : c.status === 'pass' ? '✓' : c.status === 'skip' ? '○' : '?';
        console.log(`  ${icon} ${c.id} [${c.severity}] ${c.status}: ${c.detail}`);
      }
      console.log(`\n  Overall: ${result.summary.overallStatus}`);
      console.log(`  Passed: ${result.summary.passed}, Failed: ${result.summary.failed}, Errors: ${result.summary.errors}`);

      expect(result.checks).toHaveLength(18);
      expect(result.summary.failed).toBeGreaterThan(0);
    });
  });
});
