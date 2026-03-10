import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

const G0_DIR = path.join(os.homedir(), '.g0');
const CONFIG_PATH = path.join(G0_DIR, 'daemon.json');

export interface DaemonConfig {
  /** Tick interval in minutes (default: 30) */
  intervalMinutes: number;
  /** Paths to watch for inventory changes */
  watchPaths: string[];
  /** Path to daemon log file */
  logFile: string;
  /** Path to PID file */
  pidFile: string;
  /** Upload results to platform (requires auth) */
  upload: boolean;
  /** Enable MCP config scanning */
  mcpScan: boolean;
  /** Enable MCP pin checking */
  mcpPinCheck: boolean;
  /** Enable inventory diffing */
  inventoryDiff: boolean;
  /** Enable network port scanning */
  networkScan: boolean;
  /** Enable artifact (credential + data store) scanning */
  artifactScan: boolean;
  /** Enable drift detection between scans */
  driftDetection: boolean;
  /** OpenClaw deployment audit configuration */
  openclaw?: {
    /** Enable OpenClaw deployment auditing */
    enabled: boolean;
    /** Path to OpenClaw agent data directory */
    agentDataPath: string;
    /** Gateway URL for hardening probes */
    gatewayUrl?: string;
    /** Egress allowlist for network monitoring */
    egressAllowlist?: string[];
    /** Path to docker-compose.yml */
    composePath?: string;
    /** Path to Docker daemon.json */
    dockerDaemonConfigPath?: string;
    /** Fast egress scan interval in seconds (default: 60). Set 0 to disable. */
    egressIntervalSeconds?: number;
  };
  /** Webhook alerting configuration */
  alerting?: {
    /** Webhook URL to POST alerts to (Slack, PagerDuty, Discord, generic) */
    webhookUrl?: string;
    /** Minimum severity to trigger webhook alerts (default: high) */
    minSeverity?: 'critical' | 'high' | 'medium' | 'low';
    /** Only alert on status changes / new failures (default: true) */
    onChangeOnly?: boolean;
    /** Custom headers for webhook requests */
    headers?: Record<string, string>;
    /** Webhook format: slack, pagerduty, discord, or generic JSON (default: generic) */
    format?: 'slack' | 'pagerduty' | 'discord' | 'generic';
  };
  /** Enforcement actions on critical findings */
  enforcement?: {
    /** Stop containers when critical Docker findings detected */
    stopContainersOnCritical?: boolean;
    /** Container name patterns to never stop (safety valve) */
    protectedContainers?: string[];
    /** Run custom shell command on critical findings (receives JSON on stdin) */
    onCriticalCommand?: string;
    /** Number of consecutive critical ticks before enforcement triggers (default: 2) */
    criticalThreshold?: number;
    /** Generate and apply iptables egress rules from allowlist (default: false) */
    applyEgressRules?: boolean;
    /** Generate and install auditd rules for agent monitoring (default: false) */
    applyAuditdRules?: boolean;
  };
  /** Kill switch configuration */
  killSwitch?: {
    /** Enable auto-activation based on event patterns (default: true) */
    autoEnabled?: boolean;
    /** Custom auto-activation rules */
    rules?: Array<{
      eventType: string;
      threshold: number;
      windowSeconds: number;
    }>;
  };
  /** Cost monitoring configuration */
  costMonitor?: {
    /** Enable cost monitoring (default: false) */
    enabled?: boolean;
    /** Hourly spend limit in USD */
    hourlyLimitUsd?: number;
    /** Daily spend limit in USD */
    dailyLimitUsd?: number;
    /** Monthly spend limit in USD */
    monthlyLimitUsd?: number;
    /** Auto-activate kill switch when cost limit exceeded (default: true) */
    circuitBreakerEnabled?: boolean;
    /** Path to events directory for cost calculation */
    eventsDir?: string;
  };
  /** Event receiver configuration (HTTP webhook endpoint for plugins/Falco/Tetragon) */
  eventReceiver?: {
    /** Enable the event receiver HTTP server (default: false) */
    enabled: boolean;
    /** Port to listen on (default: 6040) */
    port?: number;
    /** Bind address (default: 127.0.0.1) */
    bind?: string;
    /** Shared secret for authenticating incoming events */
    authToken?: string;
    /** Path to JSONL log file for event persistence (default: ~/.g0/events.jsonl) */
    logFile?: string;
  };
  /** Fleet management configuration */
  fleet?: {
    /** Enable fleet registration and reporting (default: false) */
    enabled?: boolean;
    /** Fleet group/team name for aggregate scoring */
    group?: string;
    /** Custom tags for this machine */
    tags?: string[];
    /** Report agent watcher results (detected AI agents) */
    reportAgents?: boolean;
    /** Report host hardening results */
    reportHostHardening?: boolean;
  };
}

export const DEFAULT_DAEMON_CONFIG: DaemonConfig = {
  intervalMinutes: 30,
  watchPaths: [],
  logFile: path.join(G0_DIR, 'daemon.log'),
  pidFile: path.join(G0_DIR, 'daemon.pid'),
  upload: true,
  mcpScan: true,
  mcpPinCheck: true,
  inventoryDiff: true,
  networkScan: true,
  artifactScan: true,
  driftDetection: true,
};

export function loadDaemonConfig(): DaemonConfig {
  const config = { ...DEFAULT_DAEMON_CONFIG };

  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    const parsed = JSON.parse(raw);
    Object.assign(config, parsed);
  } catch {
    // Use defaults
  }

  return config;
}

export function saveDaemonConfig(config: Partial<DaemonConfig>): void {
  fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
  const existing = loadDaemonConfig();
  const merged = { ...existing, ...config };
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(merged, null, 2) + '\n', { mode: 0o600 });
}

export function getG0Dir(): string {
  return G0_DIR;
}
