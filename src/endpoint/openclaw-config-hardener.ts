import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';

// Note: execSync is used for Tailscale detection (`tailscale status`) and
// network interface enumeration (`ip addr` / `ifconfig`). All command strings
// are hardcoded constants — no user input is interpolated into shell commands.

// ── Types ────────────────────────────────────────────────────────────────────

export type RecommendationSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ConfigRecommendation {
  /** JSON path (e.g. "gateway.auth.mode") */
  path: string;
  /** Current value (null if missing) */
  current: unknown;
  /** Recommended value */
  recommended: unknown;
  severity: RecommendationSeverity;
  /** Security category (NET, CRED, DOCK, DATA, O11Y) */
  finding?: string;
  reason: string;
}

export interface HardenedConfigResult {
  /** Path to the openclaw.json that was analyzed */
  sourceFile: string | null;
  /** The parsed original config */
  original: Record<string, unknown>;
  /** The hardened config (original + applied recommendations) */
  hardened: Record<string, unknown>;
  /** All recommendations */
  recommendations: ConfigRecommendation[];
  /** Detected environment signals */
  environment: {
    tailscaleDetected: boolean;
    tailscaleIp?: string;
    dockerDetected: boolean;
    platform: string;
  };
}

// ── Config discovery ─────────────────────────────────────────────────────────

const STANDARD_PATHS = [
  '/opt/openclaw/openclaw.json',
  '/etc/openclaw/openclaw.json',
  'openclaw.json',
  'config/openclaw.json',
];

/**
 * Find openclaw.json from standard paths or agentDataPath.
 */
export function findOpenClawConfig(agentDataPath?: string): string | null {
  const candidates = [...STANDARD_PATHS];
  if (agentDataPath) {
    candidates.unshift(
      path.join(agentDataPath, '..', 'openclaw.json'),
      path.join(agentDataPath, '..', 'config', 'openclaw.json'),
    );
  }
  for (const p of candidates) {
    const resolved = path.resolve(p);
    try {
      if (fs.statSync(resolved).isFile()) return resolved;
    } catch {
      // not found
    }
  }
  return null;
}

/**
 * Read and parse openclaw.json. Returns empty object if not found.
 */
export function readOpenClawConfig(filePath: string | null): Record<string, unknown> {
  if (!filePath) return {};
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  } catch {
    return {};
  }
}

// ── Environment detection ────────────────────────────────────────────────────

interface EnvDetection {
  tailscaleDetected: boolean;
  tailscaleIp?: string;
  dockerDetected: boolean;
  platform: string;
}

function detectEnvironment(): EnvDetection {
  const env: EnvDetection = {
    tailscaleDetected: false,
    dockerDetected: false,
    platform: process.platform,
  };

  // Tailscale detection
  try {
    const status = execSync('tailscale status --json 2>/dev/null', {
      timeout: 5000,
      encoding: 'utf-8',
    });
    const parsed = JSON.parse(status);
    if (parsed.Self?.TailscaleIPs?.length) {
      env.tailscaleDetected = true;
      env.tailscaleIp = parsed.Self.TailscaleIPs[0];
    }
  } catch {
    // Tailscale not installed or not running — check for tailscale0 interface
    try {
      const ifOutput = execSync(
        process.platform === 'darwin'
          ? 'ifconfig 2>/dev/null'
          : 'ip addr 2>/dev/null',
        { timeout: 3000, encoding: 'utf-8' },
      );
      if (/tailscale0|100\.6[4-9]\.|100\.[7-9]\d\.|100\.1[0-2]\d\./.test(ifOutput)) {
        env.tailscaleDetected = true;
      }
    } catch {
      // no network tools
    }
  }

  // Docker detection
  try {
    execSync('docker info 2>/dev/null', { timeout: 5000 });
    env.dockerDetected = true;
  } catch {
    // Docker not available
  }

  return env;
}

// ── Deep get/set helpers ─────────────────────────────────────────────────────

function deepGet(obj: Record<string, unknown>, dotPath: string): unknown {
  const keys = dotPath.split('.');
  let current: unknown = obj;
  for (const key of keys) {
    if (current == null || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function deepSet(obj: Record<string, unknown>, dotPath: string, value: unknown): void {
  const keys = dotPath.split('.');
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
    if (current[key] == null || typeof current[key] !== 'object') {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }
  const lastKey = keys[keys.length - 1];
  if (lastKey === '__proto__' || lastKey === 'constructor' || lastKey === 'prototype') return;
  current[lastKey] = value;
}

function deepClone<T>(obj: T): T {
  return JSON.parse(JSON.stringify(obj));
}

// ── Hardening rules ──────────────────────────────────────────────────────────

interface HardeningRule {
  path: string;
  severity: RecommendationSeverity;
  finding?: string;
  reason: string;
  check: (current: unknown, env: EnvDetection) => unknown | null;
}

const HARDENING_RULES: HardeningRule[] = [
  // ── Gateway binding ──
  {
    path: 'gateway.bind',
    severity: 'critical',
    finding: 'NET',
    reason: 'Bind gateway to loopback or Tailscale interface only — prevents exposure to untrusted networks',
    check(current, env) {
      if (env.tailscaleDetected) {
        if (current === 'tailnet' || current === 'loopback') return null;
        return 'tailnet';
      }
      if (current === 'loopback') return null;
      return 'loopback';
    },
  },
  {
    path: 'gateway.port',
    severity: 'medium',
    reason: 'Use non-default port to reduce attack surface from automated scanners',
    check(current) {
      if (current && current !== 18789) return null;
      return 18789; // default is fine if explicitly set
    },
  },

  // ── Authentication ──
  {
    path: 'gateway.auth.mode',
    severity: 'critical',
    finding: 'CRED',
    reason: 'Require token-based authentication — "password" and "none" are insecure',
    check(current) {
      if (current === 'token' || current === 'device-pairing') return null;
      return 'token';
    },
  },
  {
    path: 'gateway.auth.token',
    severity: 'high',
    finding: 'CRED',
    reason: 'Set a strong auth token (min 32 chars). Use environment variable $OPENCLAW_AUTH_TOKEN',
    check(current) {
      if (typeof current === 'string' && current.length >= 32) return null;
      if (current === '$OPENCLAW_AUTH_TOKEN' || current === '${OPENCLAW_AUTH_TOKEN}') return null;
      return '${OPENCLAW_AUTH_TOKEN}';
    },
  },

  // ── Sandbox ──
  {
    path: 'agents.defaults.sandbox.mode',
    severity: 'critical',
    finding: 'DATA',
    reason: 'Enable sandboxing for all agents — prevents cross-agent data access',
    check(current) {
      if (current === 'all') return null;
      return 'all';
    },
  },
  {
    path: 'agents.defaults.sandbox.docker.network',
    severity: 'high',
    finding: 'DOCK',
    reason: 'Use isolated Docker networks per agent instead of shared bridge',
    check(current) {
      if (current === 'isolated' || current === 'none') return null;
      return 'isolated';
    },
  },

  // ── Tool execution ──
  {
    path: 'tools.exec.safeBins',
    severity: 'critical',
    reason: 'Enable safe binary allowlist — prevents CVE-2026-28363 GNU abbreviation bypass',
    check(current) {
      if (current === true || current === undefined) return null; // default is true
      if (current === false) return true;
      return null;
    },
  },
  {
    path: 'tools.exec.host',
    severity: 'critical',
    finding: 'EXEC',
    reason: 'Route tool execution through sandbox, not gateway host — prevents direct host access',
    check(current) {
      if (current === 'sandbox') return null;
      return 'sandbox';
    },
  },
  {
    path: 'tools.elevated.enabled',
    severity: 'high',
    finding: 'EXEC',
    reason: 'Disable elevated tool execution — prevents privilege escalation',
    check(current) {
      if (current === false || current === undefined) return null;
      return false;
    },
  },
  {
    path: 'tools.fs.workspaceOnly',
    severity: 'high',
    finding: 'DATA',
    reason: 'Restrict filesystem access to agent workspace only — prevents reading sensitive host files',
    check(current) {
      if (current === true) return null;
      return true;
    },
  },

  // ── Logging / Observability ──
  {
    path: 'logging.level',
    severity: 'medium',
    finding: 'O11Y',
    reason: 'Set verbose logging for full audit trail of agent actions',
    check(current) {
      if (current === 'verbose' || current === 'debug') return null;
      return 'verbose';
    },
  },
  {
    path: 'logging.redactSensitive',
    severity: 'medium',
    finding: 'O11Y',
    reason: 'Enable sensitive log redaction at tools level — prevents credential leakage in logs',
    check(current) {
      if (current === 'tools' || current === true) return null;
      return 'tools';
    },
  },

  // ── Gateway control UI ──
  {
    path: 'gateway.controlUi.enabled',
    severity: 'high',
    finding: 'NET',
    reason: 'Disable web control UI in production — reduces attack surface',
    check(current) {
      if (current === false || current === undefined) return null;
      return false;
    },
  },

  // ── Network discovery ──
  {
    path: 'discovery.mdns.mode',
    severity: 'medium',
    finding: 'NET',
    reason: 'Disable mDNS broadcasting — prevents network discovery of gateway',
    check(current) {
      if (current === 'off') return null;
      return 'off';
    },
  },

  // ── Session isolation ──
  {
    path: 'session.dmScope',
    severity: 'medium',
    finding: 'ISOL',
    reason: 'Isolate sessions per channel and peer — prevents cross-session data leakage',
    check(current) {
      if (current === 'per-channel-peer') return null;
      return 'per-channel-peer';
    },
  },

  // ── Trusted proxies ──
  {
    path: 'gateway.trustedProxies',
    severity: 'high',
    finding: 'NET',
    reason: 'Configure trusted proxies when gateway is not loopback — prevents auth bypass via header spoofing',
    check(current, env) {
      // Not needed when binding to loopback
      // We can't easily check gateway.bind from here, so always recommend if not set
      if (Array.isArray(current) && current.length > 0) return null;
      return [];
    },
  },

  // ── Require mention ──
  {
    path: 'requireMention',
    severity: 'medium',
    finding: 'NET',
    reason: 'Require @mention in group channels — prevents responding to arbitrary messages',
    check(current) {
      if (current === true) return null;
      return true;
    },
  },

  // ── Plugins ──
  {
    path: 'plugins.allow',
    severity: 'high',
    reason: 'Restrict plugins to an explicit allowlist instead of allowing all',
    check(current) {
      if (Array.isArray(current) && current.length > 0) return null;
      return []; // empty = none allowed (user should populate)
    },
  },

  // ── Registry ──
  {
    path: 'registry',
    severity: 'high',
    reason: 'Use only the official ClawHub registry to prevent supply chain attacks',
    check(current) {
      if (!current || current === 'https://clawhub.ai' || current === 'https://registry.clawhub.ai') return null;
      return 'https://clawhub.ai';
    },
  },

];

// ── Main hardener ────────────────────────────────────────────────────────────

export interface HardenOptions {
  /** Path to openclaw.json (auto-discovered if not provided) */
  configPath?: string;
  /** Agent data path for config discovery */
  agentDataPath?: string;
  /** Skip environment detection (for testing) */
  skipEnvDetection?: boolean;
  /** Override environment (for testing) */
  envOverride?: Partial<EnvDetection>;
}

/**
 * Analyze an openclaw.json and produce hardening recommendations + a hardened config.
 */
export function hardenOpenClawConfig(options: HardenOptions = {}): HardenedConfigResult {
  const configPath = options.configPath ?? findOpenClawConfig(options.agentDataPath);
  const original = readOpenClawConfig(configPath);
  const hardened = deepClone(original);

  const env: EnvDetection = options.skipEnvDetection
    ? { tailscaleDetected: false, dockerDetected: false, platform: process.platform, ...options.envOverride }
    : { ...detectEnvironment(), ...options.envOverride };

  const recommendations: ConfigRecommendation[] = [];

  for (const rule of HARDENING_RULES) {
    const current = deepGet(original, rule.path);
    const recommended = rule.check(current, env);

    if (recommended !== null) {
      recommendations.push({
        path: rule.path,
        current: current ?? null,
        recommended,
        severity: rule.severity,
        finding: rule.finding,
        reason: rule.reason,
      });
      deepSet(hardened, rule.path, recommended);
    }
  }

  // Sort by severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  recommendations.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return {
    sourceFile: configPath,
    original,
    hardened,
    recommendations,
    environment: env,
  };
}

/**
 * Write the hardened config to disk (creates backup of original).
 */
export function writeHardenedConfig(result: HardenedConfigResult, outputPath?: string): string {
  const target = outputPath ?? result.sourceFile ?? 'openclaw.json';
  const resolved = path.resolve(target);

  // Back up original if it exists
  if (fs.existsSync(resolved)) {
    const backupPath = resolved + '.backup.' + Date.now();
    fs.copyFileSync(resolved, backupPath);
  }

  fs.writeFileSync(resolved, JSON.stringify(result.hardened, null, 2) + '\n', 'utf-8');
  return resolved;
}

/**
 * Format recommendations as human-readable text (for terminal output).
 */
export function formatRecommendations(result: HardenedConfigResult): string {
  const lines: string[] = [];

  if (result.recommendations.length === 0) {
    lines.push('  No hardening recommendations — config looks good!');
    return lines.join('\n');
  }

  lines.push(`  ${result.recommendations.length} recommendations found`);
  if (result.environment.tailscaleDetected) {
    lines.push(`  Tailscale detected (${result.environment.tailscaleIp ?? 'active'})`);
  }
  lines.push('');

  for (const rec of result.recommendations) {
    const sev = rec.severity.toUpperCase().padEnd(8);
    const finding = rec.finding ? `[${rec.finding}] ` : '';
    lines.push(`  ${sev}  ${finding}${rec.path}`);
    if (rec.current !== null && rec.current !== undefined) {
      lines.push(`           Current:     ${JSON.stringify(rec.current)}`);
    } else {
      lines.push(`           Current:     (not set)`);
    }
    lines.push(`           Recommended: ${JSON.stringify(rec.recommended)}`);
    lines.push(`           ${rec.reason}`);
    lines.push('');
  }

  return lines.join('\n');
}
