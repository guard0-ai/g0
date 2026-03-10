import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const G0_DIR = path.join(os.homedir(), '.g0');
const KILLSWITCH_PATH = path.join(G0_DIR, '.killswitch');

export interface KillSwitchState {
  active: boolean;
  reason: string;
  activatedBy?: string;
  timestamp: string;
}

/**
 * Activate the kill switch — blocks all tool execution via the OpenClaw plugin
 */
export function activateKillSwitch(reason: string, activatedBy?: string): KillSwitchState {
  const state: KillSwitchState = {
    active: true,
    reason,
    activatedBy,
    timestamp: new Date().toISOString(),
  };

  fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
  fs.writeFileSync(KILLSWITCH_PATH, JSON.stringify(state, null, 2), { mode: 0o600 });

  return state;
}

/**
 * Deactivate the kill switch
 */
export function deactivateKillSwitch(): void {
  try {
    if (fs.existsSync(KILLSWITCH_PATH)) {
      fs.unlinkSync(KILLSWITCH_PATH);
    }
  } catch {
    // Non-fatal
  }
}

/**
 * Check if the kill switch is currently active
 */
export function isKillSwitchActive(switchPath?: string): KillSwitchState {
  const filePath = switchPath ?? KILLSWITCH_PATH;
  try {
    if (!fs.existsSync(filePath)) {
      return { active: false, reason: '', timestamp: '' };
    }
    const raw = fs.readFileSync(filePath, 'utf-8');
    const state = JSON.parse(raw) as KillSwitchState;
    return state;
  } catch {
    return { active: false, reason: '', timestamp: '' };
  }
}

/**
 * Auto-activate kill switch based on event patterns.
 * Called by the daemon when processing security events.
 */
export interface KillSwitchAutoRule {
  /** Event type to watch for */
  eventType: string;
  /** Max events in window before triggering */
  threshold: number;
  /** Window in seconds */
  windowSeconds: number;
}

const DEFAULT_AUTO_RULES: KillSwitchAutoRule[] = [
  { eventType: 'injection.detected', threshold: 5, windowSeconds: 60 },
  { eventType: 'tool.blocked', threshold: 10, windowSeconds: 60 },
  { eventType: 'pii.redacted', threshold: 20, windowSeconds: 300 },
];

export interface KillSwitchMonitor {
  /** Record an event and check if auto-activation should trigger */
  recordEvent(eventType: string, timestamp?: string): KillSwitchState | null;
  /** Get current event counts per type */
  getEventCounts(): Record<string, number>;
  /** Reset all counters */
  reset(): void;
}

export function createKillSwitchMonitor(
  rules?: KillSwitchAutoRule[],
  switchPath?: string,
): KillSwitchMonitor {
  const activeRules = rules ?? DEFAULT_AUTO_RULES;
  const eventLog: Array<{ type: string; timestamp: number }> = [];

  return {
    recordEvent(eventType: string, timestamp?: string): KillSwitchState | null {
      const now = timestamp ? new Date(timestamp).getTime() : Date.now();
      eventLog.push({ type: eventType, timestamp: now });

      // Check each rule
      for (const rule of activeRules) {
        if (rule.eventType !== eventType) continue;

        const windowStart = now - rule.windowSeconds * 1000;
        const count = eventLog.filter(
          e => e.type === rule.eventType && e.timestamp >= windowStart,
        ).length;

        if (count >= rule.threshold) {
          const reason = `Auto-activated: ${count} ${rule.eventType} events in ${rule.windowSeconds}s (threshold: ${rule.threshold})`;

          // Write the kill switch file
          const state: KillSwitchState = {
            active: true,
            reason,
            activatedBy: 'auto-monitor',
            timestamp: new Date(now).toISOString(),
          };

          const filePath = switchPath ?? KILLSWITCH_PATH;
          try {
            fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
            fs.writeFileSync(filePath, JSON.stringify(state, null, 2), { mode: 0o600 });
          } catch {
            // Non-fatal
          }

          return state;
        }
      }

      // Prune old events (keep last 5 minutes)
      const cutoff = now - 5 * 60 * 1000;
      while (eventLog.length > 0 && eventLog[0].timestamp < cutoff) {
        eventLog.shift();
      }

      return null;
    },

    getEventCounts(): Record<string, number> {
      const counts: Record<string, number> = {};
      const now = Date.now();
      for (const rule of activeRules) {
        const windowStart = now - rule.windowSeconds * 1000;
        counts[rule.eventType] = eventLog.filter(
          e => e.type === rule.eventType && e.timestamp >= windowStart,
        ).length;
      }
      return counts;
    },

    reset(): void {
      eventLog.length = 0;
    },
  };
}
