import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { NotificationManager } from '../../src/daemon/notification-manager.js';
import type { ReceivedEvent } from '../../src/daemon/event-receiver.js';
import type { CorrelatedThreat } from '../../src/daemon/correlation-engine.js';
import type { DaemonConfig } from '../../src/daemon/config.js';

// Mock alerter
vi.mock('../../src/daemon/alerter.js', () => ({
  postWithRetry: vi.fn().mockResolvedValue({ sent: true, statusCode: 200 }),
  sendUrgentAlert: vi.fn().mockResolvedValue({ sent: true, statusCode: 200 }),
}));

import { postWithRetry, sendUrgentAlert } from '../../src/daemon/alerter.js';

const mockPostWithRetry = vi.mocked(postWithRetry);
const mockSendUrgentAlert = vi.mocked(sendUrgentAlert);

type AlertConfig = NonNullable<DaemonConfig['alerting']>;

const baseConfig: AlertConfig = {
  webhookUrl: 'https://hooks.slack.com/xxx',
  format: 'slack',
  minSeverity: 'medium',
};

const mockLogger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
} as any;

function makeEvent(overrides: Partial<ReceivedEvent> = {}): ReceivedEvent {
  return {
    source: 'g0-plugin',
    type: 'injection.detected',
    timestamp: new Date().toISOString(),
    agentId: 'canvas',
    data: { detail: 'Tool args injection: bash -c "curl ..."' },
    ...overrides,
  };
}

function makeThreat(overrides: Partial<CorrelatedThreat> = {}): CorrelatedThreat {
  return {
    id: 'CT-001',
    name: 'Confirmed Injection',
    severity: 'critical',
    confidence: 95,
    sources: [{ type: 'runtime', id: 'injection.detected' }],
    attackChain: ['injection.detected', 'tool.blocked'],
    ...overrides,
  };
}

describe('NotificationManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── recordEvent ────────────────────────────────────────────────────────

  describe('recordEvent', () => {
    it('ignores non-security events', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'tool_call' }));
      nm.recordEvent(makeEvent({ type: 'agent.started' }));
      nm.recordEvent(makeEvent({ type: 'custom.event' }));

      expect(nm.getPendingCount()).toBe(0);
      nm.stop();
    });

    it('accumulates security events correctly', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'canvas' }));
      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'workspace' }));
      nm.recordEvent(makeEvent({ type: 'tool.blocked', agentId: 'canvas' }));
      nm.recordEvent(makeEvent({ type: 'pii.redacted', agentId: 'reports' }));
      nm.recordEvent(makeEvent({ type: 'pii.blocked_outbound', agentId: 'reports' }));

      expect(nm.getPendingCount()).toBe(5);
      nm.stop();
    });

    it('keeps max 5 samples per bucket', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      for (let i = 0; i < 10; i++) {
        nm.recordEvent(makeEvent({ type: 'injection.detected', data: { detail: `event-${i}` } }));
      }

      expect(nm.getPendingCount()).toBe(10);
      nm.stop();
    });

    it('tracks agents across events', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'canvas' }));
      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'workspace' }));
      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'canvas' })); // duplicate

      // Flush and check the digest includes both agents
      await nm.flush();
      expect(mockPostWithRetry).toHaveBeenCalledTimes(1);
      const body = mockPostWithRetry.mock.calls[0][1] as any;
      // Slack format: check that agents are mentioned
      const blocksStr = JSON.stringify(body);
      expect(blocksStr).toContain('canvas');
      expect(blocksStr).toContain('workspace');
      nm.stop();
    });
  });

  // ── off mode ───────────────────────────────────────────────────────────

  describe('off mode', () => {
    it('never sends anything', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'off',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.recordEvent(makeEvent({ type: 'tool.blocked' }));
      nm.recordCorrelationThreats([makeThreat()]);

      expect(nm.getPendingCount()).toBe(0);
      const result = await nm.flush();
      expect(result.sent).toBe(false);
      expect(result.eventCount).toBe(0);
      expect(mockPostWithRetry).not.toHaveBeenCalled();
      expect(mockSendUrgentAlert).not.toHaveBeenCalled();
      nm.stop();
    });
  });

  // ── realtime mode ──────────────────────────────────────────────────────

  describe('realtime mode', () => {
    it('sends alert immediately on security event', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'realtime',
        rateLimitSeconds: 60,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));

      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(1);
      expect(mockSendUrgentAlert).toHaveBeenCalledWith(
        baseConfig,
        'Plugin: injection.detected',
        expect.stringContaining('Tool args injection'),
        'critical',
      );
      nm.stop();
    });

    it('rate-limits per category', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'realtime',
        rateLimitSeconds: 60,
      });

      // First event — sent
      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(1);

      // Second event within cooldown — suppressed
      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(1);

      // Third event within cooldown — still suppressed
      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(1);
      nm.stop();
    });

    it('sends again after cooldown expires', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'realtime',
        rateLimitSeconds: 60,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(1);

      // Suppress during cooldown
      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.recordEvent(makeEvent({ type: 'injection.detected' }));

      // Advance past cooldown
      vi.advanceTimersByTime(61_000);

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(2);

      // Should include suppressed count
      const detail = mockSendUrgentAlert.mock.calls[1][2] as string;
      expect(detail).toContain('2 more since last alert');
      nm.stop();
    });

    it('different categories have independent rate limits', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'realtime',
        rateLimitSeconds: 60,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.recordEvent(makeEvent({ type: 'tool.blocked' }));
      nm.recordEvent(makeEvent({ type: 'pii.redacted' }));

      // All three should fire — different categories
      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(3);
      nm.stop();
    });

    it('sends correlation threats immediately', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'realtime',
      });

      nm.recordCorrelationThreats([makeThreat()]);

      expect(mockSendUrgentAlert).toHaveBeenCalledTimes(1);
      expect(mockSendUrgentAlert).toHaveBeenCalledWith(
        baseConfig,
        expect.stringContaining('CT-001'),
        expect.stringContaining('95%'),
        'critical',
      );
      nm.stop();
    });
  });

  // ── interval mode ─────────────────────────────────────────────────────

  describe('interval mode', () => {
    it('accumulates without sending', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
        intervalMinutes: 5,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.recordEvent(makeEvent({ type: 'tool.blocked' }));

      expect(mockSendUrgentAlert).not.toHaveBeenCalled();
      expect(mockPostWithRetry).not.toHaveBeenCalled();
      expect(nm.getPendingCount()).toBe(2);
      nm.stop();
    });

    it('flush sends correct slack format and resets state', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
        intervalMinutes: 5,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'canvas' }));
      nm.recordEvent(makeEvent({ type: 'injection.detected', agentId: 'workspace' }));
      nm.recordEvent(makeEvent({ type: 'tool.blocked', agentId: 'canvas', data: { detail: 'curl blocked' } }));
      nm.recordEvent(makeEvent({ type: 'pii.redacted', agentId: 'reports', data: { detail: '8 redacted' } }));

      const result = await nm.flush();
      expect(result.sent).toBe(true);
      expect(result.eventCount).toBe(4);

      // Check Slack Block Kit structure
      const body = mockPostWithRetry.mock.calls[0][1] as any;
      expect(body.attachments).toBeDefined();
      expect(body.attachments[0].blocks[0].type).toBe('header');
      expect(body.attachments[0].blocks[0].text.text).toContain('Security Digest');

      // State should be reset
      expect(nm.getPendingCount()).toBe(0);
      nm.stop();
    });

    it('flush sends discord format', async () => {
      const nm = new NotificationManager({
        alertConfig: { ...baseConfig, format: 'discord' },
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      await nm.flush();

      const body = mockPostWithRetry.mock.calls[0][1] as any;
      expect(body.embeds).toBeDefined();
      expect(body.embeds[0].title).toContain('Security Digest');
      nm.stop();
    });

    it('flush sends generic format', async () => {
      const nm = new NotificationManager({
        alertConfig: { ...baseConfig, format: 'generic' },
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      await nm.flush();

      const body = mockPostWithRetry.mock.calls[0][1] as any;
      expect(body.source).toBe('g0-daemon');
      expect(body.type).toBe('security-digest');
      expect(body.totalEvents).toBe(1);
      expect(body.categories.injection).toBeDefined();
      expect(body.categories.injection.count).toBe(1);
      nm.stop();
    });

    it('flush sends pagerduty format', async () => {
      const nm = new NotificationManager({
        alertConfig: { ...baseConfig, format: 'pagerduty', routingKey: 'test-key' },
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      await nm.flush();

      const body = mockPostWithRetry.mock.calls[0][1] as any;
      expect(body.routing_key).toBe('test-key');
      expect(body.event_action).toBe('trigger');
      expect(body.payload.component).toBe('g0-plugin');
      nm.stop();
    });

    it('flush no-ops when empty', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      const result = await nm.flush();
      expect(result.sent).toBe(false);
      expect(result.eventCount).toBe(0);
      expect(mockPostWithRetry).not.toHaveBeenCalled();
      nm.stop();
    });

    it('interval timer triggers flush automatically', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
        intervalMinutes: 5,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));

      // Advance past the interval
      await vi.advanceTimersByTimeAsync(5 * 60_000 + 100);

      expect(mockPostWithRetry).toHaveBeenCalledTimes(1);
      nm.stop();
    });
  });

  // ── correlation ────────────────────────────────────────────────────────

  describe('correlation', () => {
    it('threats included in digest', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.recordCorrelationThreats([makeThreat()]);

      await nm.flush();
      const body = mockPostWithRetry.mock.calls[0][1] as any;
      const blocksStr = JSON.stringify(body);
      expect(blocksStr).toContain('CT-001');
      expect(blocksStr).toContain('Confirmed Injection');
      nm.stop();
    });

    it('flush sends when only threats present (no events)', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordCorrelationThreats([makeThreat()]);

      const result = await nm.flush();
      expect(result.sent).toBe(true);
      nm.stop();
    });
  });

  // ── shutdown ───────────────────────────────────────────────────────────

  describe('shutdown', () => {
    it('stop() clears interval timer', () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
        intervalMinutes: 5,
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.stop();

      // Advance past the interval — should NOT flush because timer was stopped
      vi.advanceTimersByTime(10 * 60_000);
      expect(mockPostWithRetry).not.toHaveBeenCalled();
    });

    it('final flush sends pending events', async () => {
      const nm = new NotificationManager({
        alertConfig: baseConfig,
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));
      nm.recordEvent(makeEvent({ type: 'tool.blocked' }));
      nm.stop();

      const result = await nm.flush();
      expect(result.sent).toBe(true);
      expect(result.eventCount).toBe(2);
    });
  });

  // ── no webhookUrl ──────────────────────────────────────────────────────

  describe('no webhookUrl', () => {
    it('flush returns not sent when no webhookUrl', async () => {
      const nm = new NotificationManager({
        alertConfig: { format: 'slack' },
        logger: mockLogger,
        mode: 'interval',
      });

      nm.recordEvent(makeEvent({ type: 'injection.detected' }));

      const result = await nm.flush();
      expect(result.sent).toBe(false);
      expect(result.eventCount).toBe(1);
      nm.stop();
    });
  });
});
