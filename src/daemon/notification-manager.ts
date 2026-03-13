import type { DaemonConfig } from './config.js';
import type { DaemonLogger } from './logger.js';
import type { ReceivedEvent } from './event-receiver.js';
import type { CorrelatedThreat } from './correlation-engine.js';
import { postWithRetry, sendUrgentAlert } from './alerter.js';
import * as os from 'node:os';

// ── Security Event Categories ────────────────────────────────────────────────

const SECURITY_EVENT_TYPES: Record<string, SecurityCategory> = {
  'injection.detected': 'injection',
  'tool.blocked': 'tool-blocked',
  'pii.redacted': 'pii',
  'pii.blocked_outbound': 'pii',
  'pii.detected': 'pii',
  'message.blocked': 'message-blocked',
  'subagent.blocked': 'subagent-blocked',
};

type SecurityCategory = 'injection' | 'tool-blocked' | 'pii' | 'message-blocked' | 'subagent-blocked' | 'correlation';

const CATEGORY_SEVERITY: Record<SecurityCategory, 'critical' | 'high' | 'medium'> = {
  'injection': 'critical',
  'tool-blocked': 'high',
  'pii': 'medium',
  'message-blocked': 'high',
  'subagent-blocked': 'high',
  'correlation': 'critical',
};

const CATEGORY_EMOJI: Record<SecurityCategory, string> = {
  'injection': ':red_circle:',
  'tool-blocked': ':large_orange_circle:',
  'pii': ':large_yellow_circle:',
  'message-blocked': ':large_orange_circle:',
  'subagent-blocked': ':large_orange_circle:',
  'correlation': ':rotating_light:',
};

// ── Event Bucket ─────────────────────────────────────────────────────────────

interface EventBucket {
  category: SecurityCategory;
  count: number;
  samples: string[];       // max 5 representative event summaries
  agents: Set<string>;
  maxSeverity: 'critical' | 'high' | 'medium';
  eventTypes: Set<string>;
}

function createBucket(category: SecurityCategory): EventBucket {
  return {
    category,
    count: 0,
    samples: [],
    agents: new Set(),
    maxSeverity: CATEGORY_SEVERITY[category],
    eventTypes: new Set(),
  };
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2 };

function higherSeverity(a: string, b: string): 'critical' | 'high' | 'medium' {
  return (SEVERITY_ORDER[a] ?? 2) <= (SEVERITY_ORDER[b] ?? 2) ? a as 'critical' | 'high' | 'medium' : b as 'critical' | 'high' | 'medium';
}

// ── NotificationManager ──────────────────────────────────────────────────────

export class NotificationManager {
  private mode: 'realtime' | 'interval' | 'off';
  private buckets: Map<SecurityCategory, EventBucket> = new Map();
  private correlationThreats: CorrelatedThreat[] = [];
  private lastFlushTimestamp: string;
  private lastAlertTimestamp: Map<SecurityCategory, number> = new Map();
  private suppressedCounts: Map<SecurityCategory, number> = new Map();
  private rateLimitMs: number;
  private intervalTimer: ReturnType<typeof setInterval> | null = null;
  private alertConfig: NonNullable<DaemonConfig['alerting']>;
  private logger: DaemonLogger;

  constructor(opts: {
    alertConfig: NonNullable<DaemonConfig['alerting']>;
    logger: DaemonLogger;
    mode: 'realtime' | 'interval' | 'off';
    intervalMinutes?: number;
    rateLimitSeconds?: number;
  }) {
    this.alertConfig = opts.alertConfig;
    this.logger = opts.logger;
    this.mode = opts.mode;
    this.rateLimitMs = (opts.rateLimitSeconds ?? 60) * 1000;
    this.lastFlushTimestamp = new Date().toISOString();

    if (this.mode === 'interval') {
      const intervalMs = (opts.intervalMinutes ?? 5) * 60_000;
      this.intervalTimer = setInterval(() => {
        this.flush().catch(err => {
          this.logger.error(`Notification flush failed: ${err instanceof Error ? err.message : err}`);
        });
      }, intervalMs);
    }
  }

  /** Called from onEvent handler for every incoming event */
  recordEvent(event: ReceivedEvent): void {
    if (this.mode === 'off') return;

    const category = SECURITY_EVENT_TYPES[event.type];
    if (!category) return; // not a security event

    // Accumulate into bucket
    let bucket = this.buckets.get(category);
    if (!bucket) {
      bucket = createBucket(category);
      this.buckets.set(category, bucket);
    }

    bucket.count++;
    bucket.eventTypes.add(event.type);
    if (event.agentId) bucket.agents.add(event.agentId);
    if (bucket.samples.length < 5) {
      bucket.samples.push(summarizeEvent(event));
    }

    // Track max severity from event data
    const eventSev = (event.data?.severity as string) ?? CATEGORY_SEVERITY[category];
    if (eventSev) {
      bucket.maxSeverity = higherSeverity(bucket.maxSeverity, eventSev);
    }

    // Realtime mode: send immediately with rate limiting
    if (this.mode === 'realtime') {
      const now = Date.now();
      const lastAlert = this.lastAlertTimestamp.get(category) ?? 0;

      if (now - lastAlert >= this.rateLimitMs) {
        const suppressed = this.suppressedCounts.get(category) ?? 0;
        this.lastAlertTimestamp.set(category, now);
        this.suppressedCounts.set(category, 0);

        const detail = suppressed > 0
          ? `${summarizeEvent(event)} (${suppressed} more since last alert)`
          : summarizeEvent(event);

        const agent = event.agentId ? ` | agent: ${event.agentId}` : '';
        sendUrgentAlert(
          this.alertConfig,
          `Plugin: ${event.type}`,
          `${detail}${agent}`,
          CATEGORY_SEVERITY[category],
        ).catch(err => {
          this.logger.error(`Realtime notification failed: ${err instanceof Error ? err.message : err}`);
        });
      } else {
        // Within cooldown — accumulate suppressed count
        this.suppressedCounts.set(category, (this.suppressedCounts.get(category) ?? 0) + 1);
      }
    }
  }

  /** Called after correlation engine runs */
  recordCorrelationThreats(threats: CorrelatedThreat[]): void {
    if (this.mode === 'off' || threats.length === 0) return;

    this.correlationThreats.push(...threats);

    // In realtime mode, correlation threats are always sent immediately
    if (this.mode === 'realtime') {
      for (const threat of threats) {
        sendUrgentAlert(
          this.alertConfig,
          `Correlated: ${threat.id} ${threat.name}`,
          `Severity: ${threat.severity}, confidence: ${threat.confidence}%, chain: ${threat.attackChain.join(' → ')}`,
          threat.severity === 'medium' ? 'medium' : threat.severity,
        ).catch(err => {
          this.logger.error(`Correlation notification failed: ${err instanceof Error ? err.message : err}`);
        });
      }
    }
  }

  /** Flush accumulated events as a digest */
  async flush(): Promise<{ sent: boolean; eventCount: number }> {
    const totalEvents = this.getPendingCount();
    if (totalEvents === 0 && this.correlationThreats.length === 0) {
      return { sent: false, eventCount: 0 };
    }

    if (!this.alertConfig.webhookUrl) {
      return { sent: false, eventCount: totalEvents };
    }

    const now = new Date().toISOString();
    const periodStart = this.lastFlushTimestamp;
    const hostname = os.hostname();
    const format = this.alertConfig.format ?? 'generic';

    let body: unknown;
    switch (format) {
      case 'slack':
        body = this.buildSlackDigest(periodStart, now, hostname, totalEvents);
        break;
      case 'discord':
        body = this.buildDiscordDigest(periodStart, now, hostname, totalEvents);
        break;
      case 'pagerduty':
        body = this.buildPagerDutyDigest(hostname, totalEvents);
        break;
      default:
        body = this.buildGenericDigest(periodStart, now, hostname, totalEvents);
    }

    const result = await postWithRetry(this.alertConfig, body);

    // Reset state after send attempt
    this.buckets.clear();
    this.correlationThreats = [];
    this.lastFlushTimestamp = now;

    if (result.sent) {
      this.logger.info(`Notification digest sent: ${totalEvents} events (status: ${result.statusCode})`);
    } else {
      this.logger.warn(`Notification digest failed: ${result.error}`);
    }

    return { sent: result.sent, eventCount: totalEvents };
  }

  /** Start the interval timer (for interval mode). Already started in constructor. */
  start(): void {
    // Timer is created in constructor for interval mode.
    // This is a no-op but available for explicit lifecycle control.
  }

  /** Stop the interval timer */
  stop(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
  }

  /** For stats/testing */
  getPendingCount(): number {
    let total = 0;
    for (const bucket of this.buckets.values()) {
      total += bucket.count;
    }
    return total;
  }

  // ── Slack Block Kit Digest ───────────────────────────────────────────────

  private buildSlackDigest(periodStart: string, periodEnd: string, hostname: string, totalEvents: number): unknown {
    const startTime = formatTime(periodStart);
    const endTime = formatTime(periodEnd);
    const categories = this.buckets.size;

    const blocks: unknown[] = [
      {
        type: 'header',
        text: { type: 'plain_text', text: ':shield: g0 Security Digest', emoji: true },
      },
      { type: 'divider' },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Period*\n${startTime}–${endTime} UTC` },
          { type: 'mrkdwn', text: `*Total*\n${totalEvents} events` },
          { type: 'mrkdwn', text: `*Host*\n\`${hostname}\`` },
          { type: 'mrkdwn', text: `*Categories*\n${categories}` },
        ],
      },
      { type: 'divider' },
    ];

    // Category sections (sorted by severity)
    const sortedBuckets = [...this.buckets.entries()].sort(
      (a, b) => (SEVERITY_ORDER[a[1].maxSeverity] ?? 2) - (SEVERITY_ORDER[b[1].maxSeverity] ?? 2),
    );

    for (const [category, bucket] of sortedBuckets) {
      const emoji = CATEGORY_EMOJI[category];
      const agents = bucket.agents.size > 0 ? ` — agents: ${[...bucket.agents].join(', ')}` : '';
      const types = [...bucket.eventTypes].join(', ');

      let text = `${emoji} *${types}* (${bucket.count})${agents}`;
      for (const sample of bucket.samples.slice(0, 3)) {
        text += `\n  > ${sample}`;
      }

      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: truncateText(text) },
      });
    }

    // Correlated threats
    if (this.correlationThreats.length > 0) {
      blocks.push({ type: 'divider' });
      let threatText = ':rotating_light: *Correlated Threats*';
      for (const threat of this.correlationThreats) {
        threatText += `\n  ${threat.id}: ${threat.name} (${threat.confidence}% confidence)`;
      }
      blocks.push({
        type: 'section',
        text: { type: 'mrkdwn', text: truncateText(threatText) },
      });
    }

    blocks.push({
      type: 'context',
      elements: [{ type: 'mrkdwn', text: `g0 daemon | \`${hostname}\` | ${endTime} UTC` }],
    });

    return { attachments: [{ color: this.digestColor(), blocks }] };
  }

  // ── Discord Digest ─────────────────────────────────────────────────────

  private buildDiscordDigest(periodStart: string, periodEnd: string, hostname: string, totalEvents: number): unknown {
    const fields = [...this.buckets.entries()].map(([category, bucket]) => ({
      name: `${[...bucket.eventTypes].join(', ')} (${bucket.count})`,
      value: bucket.samples.slice(0, 3).join('\n').slice(0, 1024) || 'No samples',
      inline: false,
    }));

    for (const threat of this.correlationThreats) {
      fields.push({
        name: `Correlated: ${threat.id}`,
        value: `${threat.name} (${threat.confidence}% confidence)`.slice(0, 1024),
        inline: false,
      });
    }

    return {
      embeds: [{
        title: `g0 Security Digest — ${totalEvents} events`,
        description: `Host: ${hostname}\nPeriod: ${formatTime(periodStart)}–${formatTime(periodEnd)} UTC`,
        color: this.digestColorHex(),
        fields,
        timestamp: periodEnd,
      }],
    };
  }

  // ── PagerDuty Digest ───────────────────────────────────────────────────

  private buildPagerDutyDigest(hostname: string, totalEvents: number): unknown {
    const maxSev = this.overallMaxSeverity();
    const severity = maxSev === 'critical' ? 'critical' : maxSev === 'high' ? 'warning' : 'info';

    return {
      routing_key: this.alertConfig.routingKey ?? '',
      event_action: 'trigger',
      payload: {
        summary: `g0 Security Digest: ${totalEvents} events across ${this.buckets.size} categories`,
        source: hostname,
        severity,
        component: 'g0-plugin',
        group: 'g0-daemon',
        custom_details: {
          categories: Object.fromEntries(
            [...this.buckets.entries()].map(([cat, b]) => [cat, { count: b.count, agents: [...b.agents] }]),
          ),
          correlatedThreats: this.correlationThreats.map(t => ({ id: t.id, name: t.name, confidence: t.confidence })),
        },
      },
    };
  }

  // ── Generic JSON Digest ────────────────────────────────────────────────

  private buildGenericDigest(periodStart: string, periodEnd: string, hostname: string, totalEvents: number): unknown {
    return {
      source: 'g0-daemon',
      type: 'security-digest',
      timestamp: periodEnd,
      hostname,
      period: { start: periodStart, end: periodEnd },
      totalEvents,
      categories: Object.fromEntries(
        [...this.buckets.entries()].map(([cat, b]) => [cat, {
          count: b.count,
          maxSeverity: b.maxSeverity,
          agents: [...b.agents],
          samples: b.samples,
          eventTypes: [...b.eventTypes],
        }]),
      ),
      correlatedThreats: this.correlationThreats.map(t => ({
        id: t.id,
        name: t.name,
        severity: t.severity,
        confidence: t.confidence,
      })),
    };
  }

  // ── Helpers ────────────────────────────────────────────────────────────

  private digestColor(): string {
    const sev = this.overallMaxSeverity();
    if (sev === 'critical') return '#dc2626';
    if (sev === 'high') return '#f59e0b';
    return '#3b82f6';
  }

  private digestColorHex(): number {
    const sev = this.overallMaxSeverity();
    if (sev === 'critical') return 0xdc2626;
    if (sev === 'high') return 0xf59e0b;
    return 0x3b82f6;
  }

  private overallMaxSeverity(): 'critical' | 'high' | 'medium' {
    let max: 'critical' | 'high' | 'medium' = 'medium';
    for (const bucket of this.buckets.values()) {
      max = higherSeverity(max, bucket.maxSeverity);
    }
    for (const threat of this.correlationThreats) {
      max = higherSeverity(max, threat.severity);
    }
    return max;
  }
}

// ── Module Helpers ─────────────────────────────────────────────────────────

function summarizeEvent(event: ReceivedEvent): string {
  const detail = (event.data?.detail as string)
    ?? (event.data?.toolName as string)
    ?? (event.data?.reason as string)
    ?? event.type;
  return detail.length > 120 ? detail.slice(0, 117) + '...' : detail;
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toISOString().slice(11, 16);
  } catch {
    return iso;
  }
}

function truncateText(text: string, max = 2900): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + '\n_... truncated_';
}
