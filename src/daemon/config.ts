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
