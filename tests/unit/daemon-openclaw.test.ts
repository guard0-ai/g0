import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ── OpenClaw Drift Detection ──────────────────────────────────────────────

describe('openclaw-drift', () => {
  let tmpDir: string;
  let originalHome: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-drift-'));
    originalHome = process.env.HOME!;
    // Redirect .g0 dir to temp for isolated tests
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    process.env.HOME = originalHome;
  });

  describe('detectOpenClawDrift', () => {
    it('reports all failures as new on first run (no previous audit)', async () => {
      const { detectOpenClawDrift } = await import('../../src/daemon/openclaw-drift.js');

      const result = {
        checks: [
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'fail' as const, detail: '19 creds shared' },
          { id: 'OC-H-025', name: 'Container root', severity: 'high' as const, status: 'pass' as const, detail: 'OK' },
        ],
        summary: { total: 2, passed: 1, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      };

      // Clear any saved audit from prior test runs
      const g0Dir = path.join(os.homedir(), '.g0');
      const auditPath = path.join(g0Dir, 'last-openclaw-audit.json');
      try { fs.unlinkSync(auditPath); } catch { /* ok */ }

      const drift = detectOpenClawDrift(result);
      expect(drift.currentStatus).toBe('critical');
      expect(drift.previousStatus).toBeNull();

      const newFailures = drift.events.filter(e => e.type === 'new-failure');
      expect(newFailures.length).toBeGreaterThanOrEqual(1);
      expect(newFailures[0].checkId).toBe('OC-H-020');
    });

    it('detects regression when previously passing check fails', async () => {
      const { detectOpenClawDrift, saveLastAudit } = await import('../../src/daemon/openclaw-drift.js');

      // Save a "clean" previous audit
      saveLastAudit({
        checks: [
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'pass' as const, detail: 'No duplicates' },
          { id: 'OC-H-025', name: 'Container root', severity: 'high' as const, status: 'pass' as const, detail: 'OK' },
        ],
        summary: { total: 2, passed: 2, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const },
      });

      // Now run with a failure
      const drift = detectOpenClawDrift({
        checks: [
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'fail' as const, detail: '5 creds shared' },
          { id: 'OC-H-025', name: 'Container root', severity: 'high' as const, status: 'pass' as const, detail: 'OK' },
        ],
        summary: { total: 2, passed: 1, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      });

      const regressions = drift.events.filter(e => e.type === 'regression');
      expect(regressions).toHaveLength(1);
      expect(regressions[0].checkId).toBe('OC-H-020');
      expect(regressions[0].title).toContain('REGRESSION');
    });

    it('detects resolved checks', async () => {
      const { detectOpenClawDrift, saveLastAudit } = await import('../../src/daemon/openclaw-drift.js');

      saveLastAudit({
        checks: [
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'fail' as const, detail: 'Shared creds' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      });

      const drift = detectOpenClawDrift({
        checks: [
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'pass' as const, detail: 'No duplicates' },
        ],
        summary: { total: 1, passed: 1, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const },
      });

      const resolved = drift.events.filter(e => e.type === 'resolved');
      expect(resolved).toHaveLength(1);
      expect(resolved[0].checkId).toBe('OC-H-020');
    });

    it('detects overall status change', async () => {
      const { detectOpenClawDrift, saveLastAudit } = await import('../../src/daemon/openclaw-drift.js');

      saveLastAudit({
        checks: [],
        summary: { total: 0, passed: 0, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const },
      });

      const drift = detectOpenClawDrift({
        checks: [
          { id: 'OC-H-021', name: 'Docker socket', severity: 'critical' as const, status: 'fail' as const, detail: 'Mounted' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      });

      const statusChange = drift.events.find(e => e.type === 'status-change');
      expect(statusChange).toBeDefined();
      expect(statusChange!.title).toContain('SECURE');
      expect(statusChange!.title).toContain('CRITICAL');
      expect(statusChange!.severity).toBe('critical');
    });
  });

  describe('saveLastAudit / loadLastAudit', () => {
    it('round-trips audit data', async () => {
      const { saveLastAudit, loadLastAudit } = await import('../../src/daemon/openclaw-drift.js');

      saveLastAudit({
        checks: [
          { id: 'OC-H-020', name: 'Test', severity: 'high' as const, status: 'pass' as const, detail: 'OK' },
        ],
        summary: { total: 1, passed: 1, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const },
      });

      const loaded = loadLastAudit();
      expect(loaded).not.toBeNull();
      expect(loaded!.checks).toHaveLength(1);
      expect(loaded!.summary.overallStatus).toBe('secure');
      expect(loaded!.timestamp).toBeTruthy();
    });
  });
});

// ── Webhook Alerter ───────────────────────────────────────────────────────

describe('alerter', () => {
  describe('sendWebhookAlert', () => {
    it('returns sent:false when no webhookUrl', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      const result = await sendWebhookAlert(
        { webhookUrl: undefined },
        [],
        [],
        'secure',
      );

      expect(result.sent).toBe(false);
      expect(result.error).toContain('No webhookUrl');
    });

    it('returns sent:false when no findings meet severity threshold', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      const result = await sendWebhookAlert(
        { webhookUrl: 'https://example.com/hook', minSeverity: 'critical' },
        [
          { id: 'OC-H-026', name: 'Log rotation', severity: 'medium' as const, status: 'fail' as const, detail: 'No rotation' },
        ],
        [],
        'secure',
      );

      expect(result.sent).toBe(false);
    });

    it('sends webhook when critical findings exist', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      // Mock fetch
      const mockFetch = vi.fn().mockResolvedValue({ status: 200 });
      vi.stubGlobal('fetch', mockFetch);

      const result = await sendWebhookAlert(
        { webhookUrl: 'https://hooks.slack.com/test', format: 'slack' },
        [
          { id: 'OC-H-020', name: 'Secret duplication', severity: 'critical' as const, status: 'fail' as const, detail: 'Shared creds' },
        ],
        [],
        'critical',
      );

      expect(result.sent).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(mockFetch).toHaveBeenCalledOnce();

      // Verify Slack format
      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe('https://hooks.slack.com/test');
      const body = JSON.parse(options.body);
      expect(body.attachments).toBeDefined();
      expect(body.attachments[0].color).toBe('#dc2626'); // Red for critical

      vi.unstubAllGlobals();
    });

    it('sends generic JSON format by default', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      const mockFetch = vi.fn().mockResolvedValue({ status: 200 });
      vi.stubGlobal('fetch', mockFetch);

      await sendWebhookAlert(
        { webhookUrl: 'https://example.com/hook' },
        [
          { id: 'OC-H-021', name: 'Docker socket', severity: 'critical' as const, status: 'fail' as const, detail: 'Mounted' },
        ],
        [],
        'critical',
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.source).toBe('g0-daemon');
      expect(body.overallStatus).toBe('critical');
      expect(body.failedChecks).toHaveLength(1);

      vi.unstubAllGlobals();
    });

    it('sends Discord format when configured', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      const mockFetch = vi.fn().mockResolvedValue({ status: 204 });
      vi.stubGlobal('fetch', mockFetch);

      await sendWebhookAlert(
        { webhookUrl: 'https://discord.com/api/webhooks/test', format: 'discord' },
        [
          { id: 'OC-H-020', name: 'Secret dup', severity: 'critical' as const, status: 'fail' as const, detail: 'Shared' },
        ],
        [],
        'critical',
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.embeds).toBeDefined();
      expect(body.embeds[0].color).toBe(0xdc2626);

      vi.unstubAllGlobals();
    });

    it('sends PagerDuty format when configured', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      const mockFetch = vi.fn().mockResolvedValue({ status: 202 });
      vi.stubGlobal('fetch', mockFetch);

      await sendWebhookAlert(
        { webhookUrl: 'https://events.pagerduty.com/v2/enqueue', format: 'pagerduty' },
        [
          { id: 'OC-H-021', name: 'Docker socket', severity: 'critical' as const, status: 'fail' as const, detail: 'Bad' },
        ],
        [],
        'critical',
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.event_action).toBe('trigger');
      expect(body.payload.severity).toBe('critical');

      vi.unstubAllGlobals();
    });

    it('returns error on network failure', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('ECONNREFUSED')));

      const result = await sendWebhookAlert(
        { webhookUrl: 'https://unreachable.example.com/hook' },
        [
          { id: 'OC-H-020', name: 'Test', severity: 'critical' as const, status: 'fail' as const, detail: 'x' },
        ],
        [],
        'critical',
      );

      expect(result.sent).toBe(false);
      expect(result.error).toContain('ECONNREFUSED');

      vi.unstubAllGlobals();
    });

    it('includes custom headers when configured', async () => {
      const { sendWebhookAlert } = await import('../../src/daemon/alerter.js');

      const mockFetch = vi.fn().mockResolvedValue({ status: 200 });
      vi.stubGlobal('fetch', mockFetch);

      await sendWebhookAlert(
        {
          webhookUrl: 'https://example.com/hook',
          headers: { 'X-Custom-Token': 'secret123' },
        },
        [
          { id: 'OC-H-020', name: 'Test', severity: 'critical' as const, status: 'fail' as const, detail: 'x' },
        ],
        [],
        'critical',
      );

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers['X-Custom-Token']).toBe('secret123');

      vi.unstubAllGlobals();
    });
  });
});

// ── Enforcement ───────────────────────────────────────────────────────────

describe('enforcement', () => {
  describe('enforceOnCritical', () => {
    it('does not action until threshold is reached', async () => {
      const { enforceOnCritical, resetCriticalCounter } = await import('../../src/daemon/enforcement.js');

      resetCriticalCounter();

      const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() } as any;

      const result = {
        checks: [
          { id: 'OC-H-021', name: 'Docker socket', severity: 'critical' as const, status: 'fail' as const, detail: 'Mounted' },
        ],
        summary: { total: 1, passed: 0, failed: 1, errors: 0, skipped: 0, overallStatus: 'critical' as const },
      };

      // First tick — below threshold (default 2)
      const first = await enforceOnCritical(result, { criticalThreshold: 2 }, mockLogger);
      expect(first.actioned).toBe(false);

      // Second tick — reaches threshold, but no stop config
      const second = await enforceOnCritical(result, { criticalThreshold: 2 }, mockLogger);
      expect(second.actioned).toBe(false); // No stop or command configured
    });

    it('resets counter when status is not critical', async () => {
      const { enforceOnCritical, resetCriticalCounter, getConsecutiveCriticalTicks } = await import('../../src/daemon/enforcement.js');

      resetCriticalCounter();
      const mockLogger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() } as any;

      // Tick with critical
      await enforceOnCritical(
        { checks: [], summary: { total: 0, passed: 0, failed: 0, errors: 0, skipped: 0, overallStatus: 'critical' as const } },
        { criticalThreshold: 3 },
        mockLogger,
      );
      expect(getConsecutiveCriticalTicks()).toBe(1);

      // Tick with secure — should reset
      await enforceOnCritical(
        { checks: [], summary: { total: 0, passed: 0, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const } },
        { criticalThreshold: 3 },
        mockLogger,
      );
      expect(getConsecutiveCriticalTicks()).toBe(0);
    });
  });
});

// ── Heartbeat Status Derivation ───────────────────────────────────────────

describe('heartbeat status', () => {
  it('platform types include openclaw fields', async () => {
    // Verify the HeartbeatPayload type accepts openclaw fields
    const payload: import('../../src/platform/types.js').HeartbeatPayload = {
      endpointId: 'test-id',
      machineId: 'machine-id',
      timestamp: new Date().toISOString(),
      status: 'degraded',
      openclawStatus: 'critical',
      openclawFailedChecks: 4,
      openclawDriftEvents: 2,
    };

    expect(payload.openclawStatus).toBe('critical');
    expect(payload.openclawFailedChecks).toBe(4);
    expect(payload.openclawDriftEvents).toBe(2);
  });

  it('UploadPayload union includes openclaw-audit type', async () => {
    // Verify the type compiles
    const payload: import('../../src/platform/types.js').UploadPayload = {
      type: 'openclaw-audit',
      machine: {
        machineId: 'test',
        hostname: 'test',
        platform: 'linux',
        arch: 'x64',
        nodeVersion: '20.0.0',
        g0Version: '1.3.0',
      },
      result: {
        checks: [],
        summary: { total: 0, passed: 0, failed: 0, errors: 0, skipped: 0, overallStatus: 'secure' as const },
      },
    };

    expect(payload.type).toBe('openclaw-audit');
  });
});
