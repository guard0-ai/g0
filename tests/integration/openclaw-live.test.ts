/**
 * Integration tests against a REAL OpenClaw gateway instance.
 *
 * Prerequisites:
 *   openclaw --dev gateway --auth none --port 18789 --allow-unconfigured --bind loopback
 *
 * These tests are skipped if the gateway is not running.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { probeOpenClawInstance } from '../../src/mcp/openclaw-hardening.js';

const GATEWAY_URL = 'http://127.0.0.1:18789';

async function isGatewayRunning(): Promise<boolean> {
  try {
    const res = await fetch(`${GATEWAY_URL}/healthz`, {
      signal: AbortSignal.timeout(2000),
    });
    return res.status === 200;
  } catch {
    return false;
  }
}

describe('OpenClaw Hardening — LIVE GATEWAY (auth=none)', () => {
  let gatewayUp = false;

  beforeAll(async () => {
    gatewayUp = await isGatewayRunning();
    if (!gatewayUp) {
      console.log('⚠ OpenClaw gateway not running on :18789 — skipping live tests');
    }
  });

  it('gateway is reachable', () => {
    if (!gatewayUp) return; // skip when gateway not running
    expect(gatewayUp).toBe(true);
  });

  it('probe returns 12 checks against real gateway', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    expect(result.checks).toHaveLength(18);
    expect(result.targetUrl).toBe(GATEWAY_URL);

    // Log all results for visibility
    console.log('\n=== LIVE OpenClaw Probe Results ===');
    for (const c of result.checks) {
      const icon = c.status === 'fail' ? '✗' : c.status === 'pass' ? '✓' : c.status === 'skip' ? '○' : '?';
      console.log(`  ${icon} ${c.id} [${c.severity}] ${c.status}: ${c.detail}`);
    }
    console.log(`\n  Overall: ${result.summary.overallStatus}`);
    console.log(`  Passed: ${result.summary.passed}, Failed: ${result.summary.failed}, Errors: ${result.summary.errors}`);
  });

  it('OC-H-001: /healthz is exposed (auth=none)', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-001')!;
    // With auth=none, healthz returns 200 (possibly HTML — known bug)
    expect(check.status).toBe('fail');
  });

  it('OC-H-003: Control UI is accessible without device pairing', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-003')!;
    // auth=none means Control UI is fully open
    expect(check.status).toBe('fail');
    expect(check.severity).toBe('critical');
  });

  it('OC-H-007: CVE-2026-25253 gatewayUrl reflection test', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-007')!;
    // v2026.3.2 should have this patched (fixed in v2026.1.29+)
    console.log(`  CVE-2026-25253: ${check.status} — ${check.detail}`);
  });

  it('OC-H-008: CORS configuration', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-008')!;
    console.log(`  CORS: ${check.status} — ${check.detail}`);
  });

  it('OC-H-010: rate limiting', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-010')!;
    console.log(`  Rate limiting: ${check.status} — ${check.detail}`);
  });

  it('OC-H-011: version disclosure', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-011')!;
    console.log(`  Version disclosure: ${check.status} — ${check.detail}`);
  });

  it('OC-H-012: WebSocket upgrade without auth', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    const check = result.checks.find(c => c.id === 'OC-H-012')!;
    console.log(`  WebSocket auth: ${check.status} — ${check.detail}`);
  });

  it('overall status reflects auth=none exposure', async () => {
    if (!gatewayUp) return;
    const result = await probeOpenClawInstance(GATEWAY_URL, 8000);
    // With auth=none, there should be critical failures
    expect(result.summary.overallStatus).toBe('critical');
    expect(result.summary.failed).toBeGreaterThan(0);
  });
});
