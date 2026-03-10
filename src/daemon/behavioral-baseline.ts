import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const G0_DIR = path.join(os.homedir(), '.g0');
const BASELINE_PATH = path.join(G0_DIR, 'behavioral-baseline.json');

// ── Types ──────────────────────────────────────────────────────────────────

export interface ToolStats {
  count: number;
  avgPerHour: number;
  stddev: number;
  lastSeen: string;
}

export interface BehavioralBaseline {
  toolFrequency: Record<string, ToolStats>;
  learningMode: boolean;
  learningStarted: string;
  learningEndedAt?: string;
  totalEvents: number;
  hoursObserved: number;
}

export interface BehavioralAnomaly {
  type: 'unusual-tool-frequency' | 'new-tool-first-seen' | 'tool-burst';
  toolName: string;
  expected: number;
  actual: number;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface AnomalyCheckResult {
  anomalies: BehavioralAnomaly[];
  baseline: BehavioralBaseline;
}

// ── Baseline Manager ──────────────────────────────────────────────────────

const LEARNING_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours
const STDDEV_THRESHOLD = 3; // 3 standard deviations
const BURST_WINDOW_MS = 60 * 1000; // 1 minute
const BURST_THRESHOLD = 10; // >10 calls to same tool in 1 minute

export interface BaselineManagerOptions {
  baselinePath?: string;
  learningDurationMs?: number;
  stddevThreshold?: number;
  burstThreshold?: number;
  burstWindowMs?: number;
}

export class BaselineManager {
  private baseline: BehavioralBaseline;
  private baselinePath: string;
  private learningDurationMs: number;
  private stddevThreshold: number;
  private burstThreshold: number;
  private burstWindowMs: number;
  private recentEvents: Array<{ toolName: string; timestamp: number }> = [];

  constructor(opts?: BaselineManagerOptions) {
    this.baselinePath = opts?.baselinePath ?? BASELINE_PATH;
    this.learningDurationMs = opts?.learningDurationMs ?? LEARNING_DURATION_MS;
    this.stddevThreshold = opts?.stddevThreshold ?? STDDEV_THRESHOLD;
    this.burstThreshold = opts?.burstThreshold ?? BURST_THRESHOLD;
    this.burstWindowMs = opts?.burstWindowMs ?? BURST_WINDOW_MS;

    // Load or create baseline
    this.baseline = this.loadBaseline() ?? this.createBaseline();
  }

  /**
   * Record a tool call event and check for anomalies.
   * During learning mode: updates baseline stats only.
   * After learning: returns detected anomalies.
   */
  recordToolCall(toolName: string, timestamp?: string): BehavioralAnomaly[] {
    const now = timestamp ? new Date(timestamp).getTime() : Date.now();
    const nowISO = new Date(now).toISOString();
    const anomalies: BehavioralAnomaly[] = [];

    this.baseline.totalEvents++;
    this.recentEvents.push({ toolName, timestamp: now });

    // Prune old recent events (keep last 5 minutes)
    const cutoff = now - 5 * 60 * 1000;
    this.recentEvents = this.recentEvents.filter(e => e.timestamp >= cutoff);

    // Check if learning period is over
    const learningStart = new Date(this.baseline.learningStarted).getTime();
    if (this.baseline.learningMode && (now - learningStart) >= this.learningDurationMs) {
      this.baseline.learningMode = false;
      this.baseline.learningEndedAt = nowISO;
      this.baseline.hoursObserved = (now - learningStart) / (60 * 60 * 1000);

      // Compute final stats
      this.finalizeStats();
    }

    if (this.baseline.learningMode) {
      // Learning mode — just track
      if (!this.baseline.toolFrequency[toolName]) {
        this.baseline.toolFrequency[toolName] = {
          count: 0,
          avgPerHour: 0,
          stddev: 0,
          lastSeen: nowISO,
        };
      }
      this.baseline.toolFrequency[toolName].count++;
      this.baseline.toolFrequency[toolName].lastSeen = nowISO;
    } else {
      // Detection mode
      const stats = this.baseline.toolFrequency[toolName];

      // New tool never seen in baseline
      if (!stats) {
        anomalies.push({
          type: 'new-tool-first-seen',
          toolName,
          expected: 0,
          actual: 1,
          timestamp: nowISO,
          severity: 'high',
        });
        // Start tracking the new tool
        this.baseline.toolFrequency[toolName] = {
          count: 1,
          avgPerHour: 0,
          stddev: 0,
          lastSeen: nowISO,
        };
      } else {
        stats.count++;
        stats.lastSeen = nowISO;

        // Calculate current hourly rate (based on recent window)
        const recentCount = this.recentEvents.filter(e => e.toolName === toolName).length;
        const windowMinutes = Math.max(1, (now - Math.min(...this.recentEvents.map(e => e.timestamp))) / 60000);
        const currentRate = (recentCount / windowMinutes) * 60; // extrapolate to per-hour

        // Check for unusual frequency (>3 stddev above average)
        if (stats.stddev > 0 && stats.avgPerHour > 0) {
          const deviations = (currentRate - stats.avgPerHour) / stats.stddev;
          if (deviations > this.stddevThreshold) {
            anomalies.push({
              type: 'unusual-tool-frequency',
              toolName,
              expected: Math.round(stats.avgPerHour * 100) / 100,
              actual: Math.round(currentRate * 100) / 100,
              timestamp: nowISO,
              severity: deviations > 5 ? 'critical' : 'high',
            });
          }
        }
      }

      // Check for burst (many calls to same tool in short window)
      const burstStart = now - this.burstWindowMs;
      const burstCount = this.recentEvents.filter(
        e => e.toolName === toolName && e.timestamp >= burstStart,
      ).length;

      if (burstCount >= this.burstThreshold) {
        anomalies.push({
          type: 'tool-burst',
          toolName,
          expected: this.burstThreshold - 1,
          actual: burstCount,
          timestamp: nowISO,
          severity: 'critical',
        });
      }
    }

    // Periodically save
    if (this.baseline.totalEvents % 100 === 0) {
      this.save();
    }

    return anomalies;
  }

  /**
   * Get the current baseline state
   */
  getBaseline(): BehavioralBaseline {
    return { ...this.baseline };
  }

  /**
   * Force save the baseline to disk
   */
  save(): void {
    try {
      const dir = path.dirname(this.baselinePath);
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(this.baselinePath, JSON.stringify(this.baseline, null, 2), { mode: 0o600 });
    } catch {
      // Non-fatal
    }
  }

  /**
   * Reset the baseline and start learning again
   */
  reset(): void {
    this.baseline = this.createBaseline();
    this.recentEvents = [];
    this.save();
  }

  // ── Internal ──────────────────────────────────────────────────────────

  private createBaseline(): BehavioralBaseline {
    return {
      toolFrequency: {},
      learningMode: true,
      learningStarted: new Date().toISOString(),
      totalEvents: 0,
      hoursObserved: 0,
    };
  }

  private loadBaseline(): BehavioralBaseline | null {
    try {
      if (!fs.existsSync(this.baselinePath)) return null;
      const raw = fs.readFileSync(this.baselinePath, 'utf-8');
      return JSON.parse(raw) as BehavioralBaseline;
    } catch {
      return null;
    }
  }

  private finalizeStats(): void {
    const hours = Math.max(1, this.baseline.hoursObserved);

    for (const [, stats] of Object.entries(this.baseline.toolFrequency)) {
      stats.avgPerHour = stats.count / hours;
      // Simple stddev approximation: assume Poisson-like distribution
      // stddev ≈ sqrt(avgPerHour) for event counts
      stats.stddev = Math.sqrt(stats.avgPerHour);
    }
  }
}
