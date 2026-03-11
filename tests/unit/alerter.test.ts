import { describe, it, expect, vi, beforeEach } from 'vitest';
import { sendWebhookAlert, sendUrgentAlert } from '../../src/daemon/alerter.js';
import type { HardeningCheck } from '../../src/mcp/openclaw-hardening.js';
import type { OpenClawDriftEvent } from '../../src/daemon/openclaw-drift.js';
import type { DaemonConfig } from '../../src/daemon/config.js';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function makeCheck(overrides: Partial<HardeningCheck> = {}): HardeningCheck {
  return {
    id: 'OC-H-001',
    name: 'Test Check',
    severity: 'high',
    status: 'fail',
    detail: 'Something failed',
    ...overrides,
  };
}

function makeDriftEvent(overrides: Partial<OpenClawDriftEvent> = {}): OpenClawDriftEvent {
  return {
    type: 'new-failure',
    severity: 'high',
    title: 'New failure detected',
    detail: 'Some detail',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

type AlertConfig = NonNullable<DaemonConfig['alerting']>;

describe('alerter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetch.mockResolvedValue({ status: 200 });
  });

  it('returns error when no webhookUrl configured', async () => {
    const config: AlertConfig = {};
    const res = await sendWebhookAlert(config, [], [], 'secure');
    expect(res.sent).toBe(false);
    expect(res.error).toContain('No webhookUrl');
  });

  it('returns not sent when no findings meet severity threshold', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'critical',
    };
    const checks = [makeCheck({ severity: 'medium' })];
    const res = await sendWebhookAlert(config, checks, [], 'secure');
    expect(res.sent).toBe(false);
    expect(res.error).toContain('No findings meet minimum severity');
  });

  it('sends generic format by default', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'high',
    };
    const checks = [makeCheck({ severity: 'critical' })];

    const res = await sendWebhookAlert(config, checks, [], 'critical');
    expect(res.sent).toBe(true);
    expect(res.statusCode).toBe(200);

    const [url, opts] = mockFetch.mock.calls[0];
    expect(url).toBe('https://hooks.example.com/test');
    const body = JSON.parse(opts.body);
    expect(body.source).toBe('g0-daemon');
    expect(body.overallStatus).toBe('critical');
    expect(body.failedChecks).toHaveLength(1);
  });

  it('sends slack format with correct structure', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.slack.com/xxx',
      format: 'slack',
      minSeverity: 'high',
    };
    const checks = [makeCheck({ severity: 'critical', id: 'OC-H-005', name: 'Gateway Auth' })];
    const drift = [makeDriftEvent()];

    const res = await sendWebhookAlert(config, checks, drift, 'critical');
    expect(res.sent).toBe(true);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.attachments).toBeDefined();
    expect(body.attachments[0].color).toBe('#dc2626');
    // header + fields + divider + check + divider + drift + context = 7
    expect(body.attachments[0].blocks.length).toBeGreaterThanOrEqual(5);
    // First block is header
    expect(body.attachments[0].blocks[0].type).toBe('header');
    expect(body.attachments[0].blocks[0].text.text).toContain('CRITICAL');
    // Second block has fields (host, time, counts)
    expect(body.attachments[0].blocks[1].fields).toHaveLength(4);
  });

  it('sends discord format with embeds', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://discord.com/api/webhooks/xxx',
      format: 'discord',
      minSeverity: 'medium',
    };
    const checks = [makeCheck({ severity: 'high' })];

    const res = await sendWebhookAlert(config, checks, [], 'warn');
    expect(res.sent).toBe(true);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.embeds).toBeDefined();
    expect(body.embeds[0].title).toContain('WARN');
    expect(body.embeds[0].color).toBe(0xf59e0b);
    expect(body.embeds[0].fields).toHaveLength(1);
  });

  it('sends pagerduty format with trigger action', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://events.pagerduty.com/v2/enqueue',
      format: 'pagerduty',
      minSeverity: 'high',
    };
    const checks = [makeCheck({ severity: 'critical' })];

    const res = await sendWebhookAlert(config, checks, [], 'critical');
    expect(res.sent).toBe(true);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.event_action).toBe('trigger');
    expect(body.payload.severity).toBe('critical');
    expect(body.payload.component).toBe('openclaw');
  });

  it('sends pagerduty resolve when secure (no findings needed)', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://events.pagerduty.com/v2/enqueue',
      format: 'pagerduty',
      minSeverity: 'high',
      routingKey: 'test-routing-key',
    };

    const res = await sendWebhookAlert(config, [], [], 'secure');
    expect(res.sent).toBe(true);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.event_action).toBe('resolve');
    expect(body.routing_key).toBe('test-routing-key');
    expect(body.payload.severity).toBe('info');
  });

  it('includes custom headers', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      headers: { Authorization: 'Bearer secret123' },
      minSeverity: 'low',
    };
    const checks = [makeCheck({ severity: 'medium' })];

    await sendWebhookAlert(config, checks, [], 'warn');

    const headers = mockFetch.mock.calls[0][1].headers;
    expect(headers['Authorization']).toBe('Bearer secret123');
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['User-Agent']).toBe('g0-daemon/1.0.0');
  });

  it('handles fetch failure gracefully after retries', async () => {
    mockFetch.mockRejectedValue(new Error('Connection refused'));

    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'low',
    };
    const checks = [makeCheck({ severity: 'high' })];

    const res = await sendWebhookAlert(config, checks, [], 'critical');
    expect(res.sent).toBe(false);
    expect(res.error).toContain('Connection refused');
    // Should have retried (1 initial + 2 retries = 3 calls)
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('filters checks by minimum severity', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'high',
    };
    const checks = [
      makeCheck({ id: 'OC-H-001', severity: 'critical' }),
      makeCheck({ id: 'OC-H-002', severity: 'high' }),
      makeCheck({ id: 'OC-H-003', severity: 'medium' }),
      makeCheck({ id: 'OC-H-004', severity: 'low' }),
    ];

    await sendWebhookAlert(config, checks, [], 'warn');

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    // Only critical and high should pass the filter
    expect(body.failedChecks).toHaveLength(2);
    expect(body.failedChecks.map((c: any) => c.id)).toEqual(['OC-H-001', 'OC-H-002']);
  });

  it('filters drift events by minimum severity', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'critical',
    };
    const drift = [
      makeDriftEvent({ severity: 'critical' }),
      makeDriftEvent({ severity: 'high' }),
    ];

    await sendWebhookAlert(config, [], drift, 'critical');

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.driftEvents).toHaveLength(1);
    expect(body.driftEvents[0].severity).toBe('critical');
  });

  it('slack format includes detail in individual check blocks', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.slack.com/xxx',
      format: 'slack',
      minSeverity: 'high',
    };
    const checks = [makeCheck({
      severity: 'critical',
      id: 'OC-H-064',
      name: 'Secrets in process args',
      detail: 'openclaw: OPENAI_API_KEY=<redacted>',
    })];

    await sendWebhookAlert(config, checks, [], 'critical');

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    // Find the check section block (after header, fields, divider)
    const checkBlocks = body.attachments[0].blocks.filter(
      (b: any) => b.type === 'section' && b.text?.text?.includes('OC-H-064')
    );
    expect(checkBlocks).toHaveLength(1);
    expect(checkBlocks[0].text.text).toContain('openclaw: OPENAI_API_KEY=<redacted>');
  });

  it('discord format includes detail in field value', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://discord.com/api/webhooks/xxx',
      format: 'discord',
      minSeverity: 'high',
    };
    const checks = [makeCheck({
      severity: 'high',
      detail: 'Agent dirs world-readable: canvas, workspace',
    })];

    await sendWebhookAlert(config, checks, [], 'warn');

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.embeds[0].fields[0].value).toContain('Agent dirs world-readable');
    expect(body.embeds[0].fields[0].inline).toBe(false);
  });

  it('slack format shows counts in fields section', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.slack.com/xxx',
      format: 'slack',
      minSeverity: 'high',
    };
    const checks = [makeCheck({ severity: 'critical' }), makeCheck({ severity: 'high', id: 'OC-H-002' })];

    await sendWebhookAlert(config, checks, [], 'critical');

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    const fields = body.attachments[0].blocks[1].fields;
    const failedField = fields.find((f: any) => f.text.includes('Failed Checks'));
    expect(failedField.text).toContain('2');
  });

  it('sends alert when status is not secure even with no checks/drift', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'critical',
    };

    // No checks or drift pass filter, but status is critical
    const res = await sendWebhookAlert(config, [], [], 'critical');
    expect(res.sent).toBe(true);
  });

  it('retries on server 500 then succeeds', async () => {
    mockFetch
      .mockResolvedValueOnce({ status: 502 })
      .mockResolvedValueOnce({ status: 200 });

    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'high',
    };
    const checks = [makeCheck({ severity: 'critical' })];

    const res = await sendWebhookAlert(config, checks, [], 'critical');
    expect(res.sent).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('sendUrgentAlert sends critical alert', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.slack.com/xxx',
      format: 'slack',
      minSeverity: 'high',
    };

    const res = await sendUrgentAlert(config, 'KILL SWITCH ACTIVATED', '5 injection events in 60s');
    expect(res.sent).toBe(true);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.attachments[0].color).toBe('#dc2626');
    // Header block
    expect(body.attachments[0].blocks[0].text.text).toContain('CRITICAL');
    // Check block should contain the title and detail
    const checkBlock = body.attachments[0].blocks.find(
      (b: any) => b.type === 'section' && b.text?.text?.includes('KILL SWITCH')
    );
    expect(checkBlock).toBeDefined();
    expect(checkBlock.text.text).toContain('5 injection events in 60s');
  });

  it('sendUrgentAlert respects minSeverity', async () => {
    const config: AlertConfig = {
      webhookUrl: 'https://hooks.example.com/test',
      minSeverity: 'critical',
    };

    const res = await sendUrgentAlert(config, 'Test', 'Detail', 'medium');
    expect(res.sent).toBe(false);
    expect(res.error).toContain('minimum severity');
  });
});
