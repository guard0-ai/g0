import type { DaemonConfig } from './config.js';
import type { OpenClawDriftEvent } from './openclaw-drift.js';
import type { HardeningCheck } from '../mcp/openclaw-hardening.js';

// ── Alert Payload ─────────────────────────────────────────────────────────

export interface AlertPayload {
  source: 'g0-daemon';
  timestamp: string;
  hostname: string;
  overallStatus: 'secure' | 'warn' | 'critical';
  failedChecks: FailedCheckSummary[];
  driftEvents: OpenClawDriftEvent[];
  summary: string;
}

interface FailedCheckSummary {
  id: string;
  name: string;
  severity: string;
  detail: string;
}

// ── Severity Filter ───────────────────────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

function meetsMinSeverity(severity: string, min: string): boolean {
  return (SEVERITY_ORDER[severity] ?? 3) <= (SEVERITY_ORDER[min] ?? 1);
}

// ── Format Builders ───────────────────────────────────────────────────────

/** Truncate text to stay within Slack Block Kit's 3000-char section limit */
function truncateSlackText(text: string, max = 2900): string {
  if (text.length <= max) return text;
  return text.slice(0, max) + '\n_... truncated_';
}

function buildSlackPayload(alert: AlertPayload): unknown {
  const emoji = alert.overallStatus === 'critical' ? ':rotating_light:' : alert.overallStatus === 'warn' ? ':warning:' : ':white_check_mark:';
  const color = alert.overallStatus === 'critical' ? '#dc2626' : alert.overallStatus === 'warn' ? '#f59e0b' : '#22c55e';

  const blocks: unknown[] = [
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `${emoji} *g0 Daemon Alert — ${alert.overallStatus.toUpperCase()}*\nHost: \`${alert.hostname}\` | ${alert.summary}`,
      },
    },
  ];

  if (alert.failedChecks.length > 0) {
    const lines = alert.failedChecks.slice(0, 10).map(
      c => `• \`${c.id}\` [${c.severity.toUpperCase()}] ${c.name}\n   ${c.detail}`,
    );
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: truncateSlackText(lines.join('\n')) },
    });
  }

  if (alert.driftEvents.length > 0) {
    const lines = alert.driftEvents.slice(0, 5).map(
      e => `• ${e.type}: ${e.title}`,
    );
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: truncateSlackText(`*Drift Events:*\n${lines.join('\n')}`) },
    });
  }

  return {
    attachments: [{ color, blocks }],
  };
}

function buildDiscordPayload(alert: AlertPayload): unknown {
  const color = alert.overallStatus === 'critical' ? 0xdc2626 : alert.overallStatus === 'warn' ? 0xf59e0b : 0x22c55e;

  const fields = alert.failedChecks.slice(0, 10).map(c => ({
    name: `${c.id} [${c.severity.toUpperCase()}]`,
    value: `${c.name}\n${c.detail}`.slice(0, 1024),
    inline: false,
  }));

  return {
    embeds: [{
      title: `g0 Daemon Alert — ${alert.overallStatus.toUpperCase()}`,
      description: `Host: ${alert.hostname}\n${alert.summary}`,
      color,
      fields,
      timestamp: alert.timestamp,
    }],
  };
}

function buildPagerDutyPayload(alert: AlertPayload, routingKey?: string): unknown {
  const severity = alert.overallStatus === 'critical' ? 'critical'
    : alert.overallStatus === 'warn' ? 'warning' : 'info';

  return {
    routing_key: routingKey ?? '',
    event_action: alert.overallStatus === 'secure' ? 'resolve' : 'trigger',
    payload: {
      summary: alert.summary,
      source: alert.hostname,
      severity,
      component: 'openclaw',
      group: 'g0-daemon',
      custom_details: {
        failedChecks: alert.failedChecks,
        driftEvents: alert.driftEvents,
      },
    },
  };
}

// ── Main Send Function ────────────────────────────────────────────────────

export async function sendWebhookAlert(
  config: NonNullable<DaemonConfig['alerting']>,
  failedChecks: HardeningCheck[],
  driftEvents: OpenClawDriftEvent[],
  overallStatus: 'secure' | 'warn' | 'critical',
): Promise<{ sent: boolean; statusCode?: number; error?: string }> {
  if (!config.webhookUrl) {
    return { sent: false, error: 'No webhookUrl configured' };
  }

  const minSev = config.minSeverity ?? 'high';

  // Filter failed checks by minimum severity
  const relevantChecks = failedChecks
    .filter(c => c.status === 'fail' && meetsMinSeverity(c.severity, minSev));

  // Filter drift events by minimum severity
  const relevantDrift = driftEvents
    .filter(e => meetsMinSeverity(e.severity, minSev));

  // Nothing to alert on — but still send "resolved" for PagerDuty
  if (relevantChecks.length === 0 && relevantDrift.length === 0 && overallStatus === 'secure') {
    if (config.format === 'pagerduty') {
      // PagerDuty needs an explicit resolve event to close the incident
    } else {
      return { sent: false, error: 'No findings meet minimum severity threshold' };
    }
  }

  const hostname = await import('node:os').then(os => os.hostname());

  const alert: AlertPayload = {
    source: 'g0-daemon',
    timestamp: new Date().toISOString(),
    hostname,
    overallStatus,
    failedChecks: relevantChecks.map(c => ({
      id: c.id,
      name: c.name,
      severity: c.severity,
      detail: c.detail,
    })),
    driftEvents: relevantDrift,
    summary: `${relevantChecks.length} failed checks, ${relevantDrift.length} drift events — status: ${overallStatus}`,
  };

  const format = config.format ?? 'generic';
  let body: unknown;

  switch (format) {
    case 'slack':
      body = buildSlackPayload(alert);
      break;
    case 'discord':
      body = buildDiscordPayload(alert);
      break;
    case 'pagerduty':
      body = buildPagerDutyPayload(alert, config.routingKey);
      break;
    default:
      body = alert;
  }

  return postWithRetry(config, body);
}

/**
 * Send an urgent alert for critical one-off events (kill switch, cost breaker,
 * behavioral anomalies). These bypass the OpenClaw audit structure and
 * send a simpler payload with a title + detail.
 */
export async function sendUrgentAlert(
  config: NonNullable<DaemonConfig['alerting']>,
  title: string,
  detail: string,
  severity: 'critical' | 'high' | 'medium' = 'critical',
): Promise<{ sent: boolean; statusCode?: number; error?: string }> {
  if (!config.webhookUrl) {
    return { sent: false, error: 'No webhookUrl configured' };
  }

  const minSev = config.minSeverity ?? 'high';
  if (!meetsMinSeverity(severity, minSev)) {
    return { sent: false, error: 'Does not meet minimum severity threshold' };
  }

  const hostname = await import('node:os').then(os => os.hostname());
  const alert: AlertPayload = {
    source: 'g0-daemon',
    timestamp: new Date().toISOString(),
    hostname,
    overallStatus: severity === 'critical' ? 'critical' : 'warn',
    failedChecks: [{
      id: 'URGENT',
      name: title,
      severity,
      detail,
    }],
    driftEvents: [],
    summary: title,
  };

  const format = config.format ?? 'generic';
  let body: unknown;

  switch (format) {
    case 'slack':
      body = buildSlackPayload(alert);
      break;
    case 'discord':
      body = buildDiscordPayload(alert);
      break;
    case 'pagerduty':
      body = buildPagerDutyPayload(alert, config.routingKey);
      break;
    default:
      body = alert;
  }

  return postWithRetry(config, body);
}

// ── HTTP Post with Retry ─────────────────────────────────────────────────

async function postWithRetry(
  config: NonNullable<DaemonConfig['alerting']>,
  body: unknown,
  maxRetries = 2,
): Promise<{ sent: boolean; statusCode?: number; error?: string }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'g0-daemon/1.0.0',
    ...config.headers,
  };

  const payload = JSON.stringify(body);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(config.webhookUrl!, {
        method: 'POST',
        headers,
        body: payload,
        signal: AbortSignal.timeout(10_000),
      });

      if (response.status >= 500 && attempt < maxRetries) {
        // Server error — retry after backoff
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }

      return { sent: true, statusCode: response.status };
    } catch (err) {
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      return { sent: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  return { sent: false, error: 'Max retries exceeded' };
}
