import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { HardeningCheck, HardeningSeverity } from './openclaw-hardening.js';
import {
  scanAgentConfigs,
  type AgentConfigScanResult,
} from '../endpoint/agent-config-scanner.js';
import {
  scanEgress,
  type EgressScanResult,
} from '../endpoint/egress-monitor.js';
import {
  scanSessionTranscripts,
  getForensicsSummary,
  type SessionForensicsResult,
} from '../endpoint/session-forensics.js';

// Note: execSync is used intentionally here for host-level system probes
// (iptables, docker, pgrep, systemctl, crontab). All command strings are
// hardcoded constants — no user input is interpolated into shell commands.

// ── Deployment Audit Options & Result ─────────────────────────────────────

export interface DeploymentAuditOptions {
  /** Path to OpenClaw agent data (e.g. /data/.openclaw/agents) */
  agentDataPath?: string;
  /** Path to docker-compose.yml or docker-compose.yaml */
  composePath?: string;
  /** Path to /etc/docker/daemon.json */
  dockerDaemonConfigPath?: string;
  /** Egress allowlist for network monitoring */
  egressAllowlist?: string[];
  /** Skip Docker checks if Docker is not available */
  skipDocker?: boolean;
}

export interface DeploymentAuditResult {
  checks: HardeningCheck[];
  agentConfigResult?: import('../endpoint/agent-config-scanner.js').AgentConfigScanResult;
  egressResult?: import('../endpoint/egress-monitor.js').EgressScanResult;
  forensicsResults?: SessionForensicsResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    errors: number;
    skipped: number;
    overallStatus: 'secure' | 'warn' | 'critical';
  };
}

// ── Helper functions ──────────────────────────────────────────────────────

function runCommand(cmd: string): string | null {
  try {
    return execSync(cmd, {
      encoding: 'utf-8',
      timeout: 15_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

function dockerAvailable(): boolean {
  const result = runCommand('docker info --format "{{.ServerVersion}}" 2>/dev/null');
  return result !== null && result.length > 0;
}

function parseDockerInspect(output: string): unknown {
  try {
    return JSON.parse(output);
  } catch {
    return null;
  }
}

function findComposeFile(searchPath?: string): string | null {
  const candidates = [
    searchPath,
    'docker-compose.yml',
    'docker-compose.yaml',
    '/opt/openclaw/docker-compose.yml',
    '/opt/openclaw/docker-compose.yaml',
    path.join(os.homedir(), 'docker-compose.yml'),
    path.join(os.homedir(), 'docker-compose.yaml'),
  ].filter(Boolean) as string[];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function findCIConfigs(searchPath?: string): string[] {
  const base = searchPath ?? process.cwd();
  const configs: string[] = [];

  // GitHub Actions
  const ghDir = path.join(base, '.github', 'workflows');
  if (fs.existsSync(ghDir)) {
    try {
      const files = fs.readdirSync(ghDir);
      for (const f of files) {
        if (f.endsWith('.yml') || f.endsWith('.yaml')) {
          configs.push(path.join(ghDir, f));
        }
      }
    } catch { /* skip */ }
  }

  // GitLab CI
  const gitlabCI = path.join(base, '.gitlab-ci.yml');
  if (fs.existsSync(gitlabCI)) configs.push(gitlabCI);

  // Jenkinsfile
  const jenkinsfile = path.join(base, 'Jenkinsfile');
  if (fs.existsSync(jenkinsfile)) configs.push(jenkinsfile);

  // Dockerfile (for multi-stage build scanning)
  const dockerfile = path.join(base, 'Dockerfile');
  if (fs.existsSync(dockerfile)) configs.push(dockerfile);

  return configs;
}

function isMacOS(): boolean {
  return os.platform() === 'darwin';
}

function isLinux(): boolean {
  return os.platform() === 'linux';
}

// ── Individual Probe Implementations ──────────────────────────────────────

/**
 * OC-H-019: Egress filtering (iptables DOCKER-USER chain)
 */
function probeEgressFiltering(): HardeningCheck {
  const id = 'OC-H-019';
  const name = 'Egress filtering (iptables DOCKER-USER chain)';
  const severity: HardeningSeverity = 'critical';

  if (isMacOS()) {
    return { id, name, severity, status: 'skip', detail: 'macOS — iptables not available; use pf or application-level egress control' };
  }

  if (!isLinux()) {
    return { id, name, severity, status: 'skip', detail: `Unsupported platform: ${os.platform()} — iptables check skipped` };
  }

  const output = runCommand('iptables -L DOCKER-USER -n 2>/dev/null');

  if (output === null) {
    // Could be permission denied or iptables not installed
    const whichIptables = runCommand('which iptables 2>/dev/null');
    if (!whichIptables) {
      return { id, name, severity, status: 'error', detail: 'iptables not installed — cannot verify egress filtering' };
    }
    return { id, name, severity, status: 'error', detail: 'Permission denied — run as root or with CAP_NET_ADMIN to check iptables' };
  }

  // Parse the chain output
  const lines = output.split('\n').filter(l => l.trim().length > 0);
  // First two lines are headers: "Chain DOCKER-USER ..." and "target prot opt source destination"
  const ruleLines = lines.slice(2);

  // Check if chain only has RETURN (no real filtering)
  const hasFilterRules = ruleLines.some(line => {
    const target = line.trim().split(/\s+/)[0];
    return target === 'DROP' || target === 'REJECT' || target === 'LOG';
  });

  const onlyReturn = ruleLines.every(line => {
    const target = line.trim().split(/\s+/)[0];
    return target === 'RETURN' || target === '';
  });

  if (ruleLines.length === 0 || onlyReturn) {
    return {
      id, name, severity, status: 'fail',
      detail: `DOCKER-USER chain has ${ruleLines.length === 0 ? 'no rules' : 'only RETURN rule'} — containers have unrestricted egress`,
    };
  }

  if (hasFilterRules) {
    const dropCount = ruleLines.filter(l => l.trim().startsWith('DROP') || l.trim().startsWith('REJECT')).length;
    return {
      id, name, severity, status: 'pass',
      detail: `DOCKER-USER chain has ${dropCount} DROP/REJECT rule${dropCount !== 1 ? 's' : ''} — egress filtering active`,
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: `DOCKER-USER chain has ${ruleLines.length} rules but no DROP/REJECT — filtering may be incomplete`,
  };
}

/**
 * OC-H-020: Secret duplication across agents
 */
async function probeSecretDuplication(agentDataPath?: string): Promise<HardeningCheck> {
  const id = 'OC-H-020';
  const name = 'Secret duplication across agents';
  const severity: HardeningSeverity = 'critical';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided — skipped' };
  }

  if (!fs.existsSync(agentDataPath)) {
    return { id, name, severity, status: 'error', detail: `Agent data path does not exist: ${agentDataPath}` };
  }

  try {
    const result = await scanAgentConfigs({ agentDataPath });

    if (result.duplicateGroups.length === 0) {
      return {
        id, name, severity, status: 'pass',
        detail: `No duplicated secrets across ${result.agentsScanned} agents (${result.totalCredentials} total credentials)`,
      };
    }

    // Format detail with worst offenders
    const worst = result.duplicateGroups
      .sort((a, b) => b.agents.length - a.agents.length)
      .slice(0, 3);
    const details = worst.map(d => {
      const agentList = d.agents.length > 5
        ? `${d.agents.slice(0, 5).join(', ')}, ...`
        : d.agents.join(', ');
      return `${d.key} duplicated in ${d.agents.length} agents: ${agentList}`;
    });

    return {
      id, name, severity, status: 'fail',
      detail: details.join('; '),
    };
  } catch (err) {
    return { id, name, severity, status: 'error', detail: `Failed to scan agent configs: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/**
 * OC-H-021: Docker socket mounted
 */
function probeDockerSocket(skipDocker: boolean, composePath?: string): HardeningCheck {
  const id = 'OC-H-021';
  const name = 'Docker socket mounted in container';
  const severity: HardeningSeverity = 'critical';

  if (skipDocker || !dockerAvailable()) {
    // Try compose file as fallback
    const composeFile = composePath ?? findComposeFile();
    if (composeFile) {
      try {
        const content = fs.readFileSync(composeFile, 'utf-8');
        const hasSocket = /\/var\/run\/docker\.sock/.test(content);
        const hasPrivileged = /privileged\s*:\s*true/i.test(content);

        if (hasSocket || hasPrivileged) {
          const issues: string[] = [];
          if (hasSocket) issues.push('docker.sock volume mount');
          if (hasPrivileged) issues.push('privileged: true');
          return {
            id, name, severity, status: 'fail',
            detail: `Compose file (${composeFile}): ${issues.join(', ')} — container escape risk`,
          };
        }
        return {
          id, name, severity, status: 'pass',
          detail: `Compose file (${composeFile}): no socket mount or privileged mode`,
        };
      } catch {
        return { id, name, severity, status: 'error', detail: `Cannot read compose file: ${composeFile}` };
      }
    }

    return {
      id, name, severity, status: 'skip',
      detail: skipDocker ? 'Docker checks skipped by configuration' : 'Docker not available — skipped',
    };
  }

  // Check running containers
  const containerIds = runCommand('docker ps -q 2>/dev/null');
  if (!containerIds || containerIds.trim().length === 0) {
    return { id, name, severity, status: 'pass', detail: 'No running containers — docker socket mount not applicable' };
  }

  const ids = containerIds.split('\n').filter(i => i.trim().length > 0);
  const socketContainers: string[] = [];
  const privilegedContainers: string[] = [];

  for (const cid of ids) {
    const shortId = cid.slice(0, 12);

    // Check binds
    const bindsOutput = runCommand(`docker inspect --format '{{json .HostConfig.Binds}}' ${cid} 2>/dev/null`);
    if (bindsOutput) {
      const binds = parseDockerInspect(bindsOutput);
      if (Array.isArray(binds) && binds.some((b: string) => b.includes('/var/run/docker.sock'))) {
        const nameOutput = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`);
        socketContainers.push(nameOutput?.replace(/^\//, '') ?? shortId);
      }
    }

    // Also check Mounts for bind propagation
    const mountsOutput = runCommand(`docker inspect --format '{{json .Mounts}}' ${cid} 2>/dev/null`);
    if (mountsOutput) {
      const mounts = parseDockerInspect(mountsOutput);
      if (Array.isArray(mounts) && mounts.some((m: Record<string, string>) =>
        m.Source === '/var/run/docker.sock' || m.Destination === '/var/run/docker.sock'
      )) {
        const nameOutput = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`);
        const containerName = nameOutput?.replace(/^\//, '') ?? shortId;
        if (!socketContainers.includes(containerName)) {
          socketContainers.push(containerName);
        }
      }
    }

    // Check privileged
    const privOutput = runCommand(`docker inspect --format '{{.HostConfig.Privileged}}' ${cid} 2>/dev/null`);
    if (privOutput === 'true') {
      const nameOutput = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`);
      privilegedContainers.push(nameOutput?.replace(/^\//, '') ?? shortId);
    }
  }

  if (socketContainers.length === 0 && privilegedContainers.length === 0) {
    return {
      id, name, severity, status: 'pass',
      detail: `Checked ${ids.length} containers — no docker socket mounts or privileged mode`,
    };
  }

  const issues: string[] = [];
  if (socketContainers.length > 0) {
    issues.push(`docker.sock mounted in: ${socketContainers.join(', ')}`);
  }
  if (privilegedContainers.length > 0) {
    issues.push(`privileged mode: ${privilegedContainers.join(', ')}`);
  }

  return {
    id, name, severity, status: 'fail',
    detail: `${issues.join('; ')} — container escape and host takeover risk`,
  };
}

/**
 * OC-H-022: Cross-agent filesystem readable
 */
function probeCrossAgentFilesystem(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-022';
  const name = 'Cross-agent filesystem readable';
  const severity: HardeningSeverity = 'high';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided — skipped' };
  }

  if (!fs.existsSync(agentDataPath)) {
    return { id, name, severity, status: 'error', detail: `Agent data path does not exist: ${agentDataPath}` };
  }

  try {
    const entries = fs.readdirSync(agentDataPath, { withFileTypes: true });
    const agentDirs = entries.filter(e => e.isDirectory());

    if (agentDirs.length === 0) {
      return { id, name, severity, status: 'pass', detail: 'No agent directories found' };
    }

    const worldReadable: string[] = [];
    const groupReadable: string[] = [];

    for (const dir of agentDirs) {
      const dirPath = path.join(agentDataPath, dir.name);
      try {
        const stat = fs.statSync(dirPath);
        const mode = stat.mode & 0o777;

        // Check world-readable (o+r)
        if (mode & 0o004) {
          worldReadable.push(dir.name);
        }
        // Check group-readable without proper group isolation (g+r with same group)
        else if (mode & 0o040) {
          groupReadable.push(dir.name);
        }
      } catch { /* skip unreadable dirs */ }
    }

    if (worldReadable.length === 0 && groupReadable.length === 0) {
      return {
        id, name, severity, status: 'pass',
        detail: `${agentDirs.length} agent directories have restricted permissions — cross-agent reads prevented`,
      };
    }

    const issues: string[] = [];
    if (worldReadable.length > 0) {
      const list = worldReadable.length > 5
        ? `${worldReadable.slice(0, 5).join(', ')}, ... (${worldReadable.length} total)`
        : worldReadable.join(', ');
      issues.push(`world-readable: ${list}`);
    }
    if (groupReadable.length > 0) {
      const list = groupReadable.length > 5
        ? `${groupReadable.slice(0, 5).join(', ')}, ... (${groupReadable.length} total)`
        : groupReadable.join(', ');
      issues.push(`group-readable (verify group isolation): ${list}`);
    }

    return {
      id, name, severity, status: 'fail',
      detail: `Agent dirs ${issues.join('; ')} — cross-agent data exposure risk`,
    };
  } catch (err) {
    return { id, name, severity, status: 'error', detail: `Failed to check agent directories: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/**
 * OC-H-023: No audit logging
 */
function probeAuditLogging(): HardeningCheck {
  const id = 'OC-H-023';
  const name = 'No audit logging';
  const severity: HardeningSeverity = 'high';

  if (isMacOS()) {
    // macOS uses praudit/openbsm
    const prauditRunning = runCommand('pgrep -x prauditd 2>/dev/null');
    const auditdRunning = runCommand('pgrep -x auditd 2>/dev/null');
    const logForwarder = runCommand("pgrep -f '(fluentd|fluent-bit|vector|filebeat|promtail|loki|osquery)' 2>/dev/null");

    if (auditdRunning || prauditRunning || logForwarder) {
      const services: string[] = [];
      if (auditdRunning || prauditRunning) services.push('auditd');
      if (logForwarder) services.push('log forwarder');
      return {
        id, name, severity, status: 'pass',
        detail: `Audit services detected: ${services.join(', ')}`,
      };
    }
    return {
      id, name, severity, status: 'fail',
      detail: 'No audit daemon or log forwarder detected — agent actions may not be recorded',
    };
  }

  if (!isLinux()) {
    return { id, name, severity, status: 'skip', detail: `Unsupported platform: ${os.platform()}` };
  }

  // Check auditd
  const auditdActive = runCommand('systemctl is-active auditd 2>/dev/null');
  const auditdPid = runCommand('pgrep -x auditd 2>/dev/null');
  const hasAuditd = auditdActive === 'active' || (auditdPid !== null && auditdPid.length > 0);

  // Check log forwarders
  const forwarderPattern = '(fluentd|fluent-bit|vector|filebeat|promtail|loki|osquery)';
  const forwarderPid = runCommand(`pgrep -f '${forwarderPattern}' 2>/dev/null`);
  const hasForwarder = forwarderPid !== null && forwarderPid.length > 0;

  if (hasAuditd || hasForwarder) {
    const services: string[] = [];
    if (hasAuditd) services.push('auditd');
    if (hasForwarder) services.push('log forwarder');
    return {
      id, name, severity, status: 'pass',
      detail: `Audit services detected: ${services.join(', ')}`,
    };
  }

  // Check if auditd is installed but not running
  const auditdInstalled = runCommand('which auditd 2>/dev/null');
  if (auditdInstalled) {
    return {
      id, name, severity, status: 'fail',
      detail: 'auditd installed but not running, no log forwarder detected — enable auditd or deploy a log collector',
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: 'No audit daemon or log forwarder detected — agent actions may not be recorded',
  };
}

/**
 * OC-H-031: Per-agent tool call logging
 * Checks if OpenClaw is configured to emit structured logs of tool invocations.
 * Looks for: gateway log config, tool-calls.log, structured JSON logs, hooks config.
 */
function probeToolCallLogging(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-031';
  const name = 'Per-agent tool call logging';
  const severity: HardeningSeverity = 'high';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided' };
  }

  const signals: string[] = [];

  // 1. Check openclaw.json for logging config
  const configCandidates = [
    path.join(agentDataPath, '..', 'openclaw.json'),
    path.join(agentDataPath, '..', 'config', 'openclaw.json'),
    '/opt/openclaw/openclaw.json',
    '/etc/openclaw/openclaw.json',
  ];

  for (const configPath of configCandidates) {
    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      const parsed = JSON.parse(content);
      // Check for logging configuration
      if (parsed.logging?.toolCalls === true || parsed.logging?.level === 'debug' || parsed.logging?.level === 'verbose') {
        signals.push(`openclaw.json logging enabled (${configPath})`);
      }
      if (parsed.hooks?.onToolCall || parsed.hooks?.afterToolCall) {
        signals.push(`Tool call hooks configured in ${configPath}`);
      }
      if (parsed.auditLog === true || parsed.audit?.enabled === true) {
        signals.push(`Audit log enabled in ${configPath}`);
      }
    } catch { /* not found or unparseable */ }
  }

  // 2. Check for structured tool-call log files in agent dirs
  if (fs.existsSync(agentDataPath)) {
    try {
      const agentDirs = fs.readdirSync(agentDataPath, { withFileTypes: true })
        .filter(e => e.isDirectory());

      let agentsWithToolLogs = 0;
      const toolLogPatterns = [
        'tool-calls.log', 'tool_calls.log', 'audit.log', 'agent-audit.log',
        'tool-calls.jsonl', 'tool_calls.jsonl', 'audit.jsonl',
      ];

      for (const dir of agentDirs) {
        const agentPath = path.join(agentDataPath, dir.name);
        const logsDir = path.join(agentPath, 'logs');
        const searchDirs = [agentPath, logsDir];

        for (const searchDir of searchDirs) {
          try {
            const files = fs.readdirSync(searchDir);
            const hasToolLog = files.some(f =>
              toolLogPatterns.some(p => f.toLowerCase() === p) ||
              f.match(/tool[_-]?call/i) ||
              f.match(/audit.*\.(?:log|jsonl)$/i)
            );
            if (hasToolLog) {
              agentsWithToolLogs++;
              break;
            }
          } catch { /* dir doesn't exist */ }
        }
      }

      if (agentsWithToolLogs > 0) {
        signals.push(`${agentsWithToolLogs}/${agentDirs.length} agents have tool call log files`);
      }
    } catch { /* can't read agent dirs */ }
  }

  // 3. Check for gateway-level access logs
  const gatewayLogPaths = [
    '/var/log/openclaw/access.log',
    '/var/log/openclaw/tool-calls.log',
    '/opt/openclaw/logs/access.log',
    path.join(agentDataPath, '..', 'logs', 'access.log'),
    path.join(agentDataPath, '..', 'logs', 'tool-calls.log'),
  ];

  for (const logPath of gatewayLogPaths) {
    try {
      const stat = fs.statSync(logPath);
      if (stat.size > 0) {
        signals.push(`Gateway log exists: ${logPath} (${(stat.size / 1024).toFixed(0)}KB)`);
      }
    } catch { /* not found */ }
  }

  if (signals.length > 0) {
    return {
      id, name, severity, status: 'pass',
      detail: signals.join('; '),
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: 'No tool call logging detected — agent tool invocations (which tools called, with what arguments) are not being recorded. ' +
      'Configure openclaw.json logging.toolCalls:true or deploy a gateway access log.',
  };
}

/**
 * OC-H-032: Per-agent file access auditing
 * Checks if file read/write operations in agent workspaces are being tracked.
 * Looks for: auditd rules on agent paths, inotifywait, fanotify.
 */
function probeFileAccessAuditing(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-032';
  const name = 'Per-agent file access auditing';
  const severity: HardeningSeverity = 'medium';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided' };
  }

  if (isMacOS()) {
    return { id, name, severity, status: 'skip', detail: 'File access auditing check requires Linux' };
  }

  if (!isLinux()) {
    return { id, name, severity, status: 'skip', detail: `Unsupported platform: ${os.platform()}` };
  }

  const signals: string[] = [];

  // 1. Check auditd rules specifically watching agent data paths
  const auditRules = runCommand('auditctl -l 2>/dev/null');
  if (auditRules) {
    // Normalize the agent path for matching
    const normalizedPath = agentDataPath.replace(/\/+$/, '');
    const parentPath = path.dirname(normalizedPath);

    const lines = auditRules.split('\n');
    const agentWatches = lines.filter(line =>
      line.includes(normalizedPath) ||
      line.includes(parentPath) ||
      line.includes('/data/.openclaw') ||
      line.includes('/data/workspace')
    );

    if (agentWatches.length > 0) {
      signals.push(`${agentWatches.length} auditd rules watching agent paths`);
    }
  }

  // 2. Check for inotifywait/fanotify watchers
  const inotifyPid = runCommand("pgrep -f 'inotifywait|inotify-hookable|fanotify' 2>/dev/null");
  if (inotifyPid) {
    signals.push('inotify/fanotify file watcher running');
  }

  // 3. Check for osquery file integrity monitoring
  const osqueryFim = runCommand("cat /etc/osquery/osquery.conf 2>/dev/null | grep -c file_paths");
  if (osqueryFim && parseInt(osqueryFim, 10) > 0) {
    signals.push('osquery file integrity monitoring configured');
  }

  if (signals.length > 0) {
    return {
      id, name, severity, status: 'pass',
      detail: signals.join('; '),
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: 'No file access auditing on agent data paths — file reads/writes by agents are not tracked. ' +
      'Add auditd watches: auditctl -w ' + agentDataPath + ' -p rwa -k openclaw-agent-files',
  };
}

/**
 * OC-H-033: Per-agent network connection logging
 * Checks if outbound network connections from agent containers are logged.
 * Looks for: Docker network logging, iptables LOG rules, conntrack logging.
 */
function probeNetworkConnectionLogging(): HardeningCheck {
  const id = 'OC-H-033';
  const name = 'Per-agent network connection logging';
  const severity: HardeningSeverity = 'high';

  if (isMacOS()) {
    return { id, name, severity, status: 'skip', detail: 'Network connection logging check requires Linux' };
  }

  if (!isLinux()) {
    return { id, name, severity, status: 'skip', detail: `Unsupported platform: ${os.platform()}` };
  }

  const signals: string[] = [];

  // 1. Check iptables LOG rules in DOCKER-USER or FORWARD chains
  const iptablesRules = runCommand('iptables -L -n 2>/dev/null');
  if (iptablesRules) {
    const logRules = iptablesRules.split('\n').filter(line => line.includes('LOG'));
    if (logRules.length > 0) {
      signals.push(`${logRules.length} iptables LOG rules for connection tracking`);
    }
  }

  // 2. Check for conntrack logging
  const conntrackPid = runCommand('pgrep -x conntrackd 2>/dev/null');
  if (conntrackPid) {
    signals.push('conntrackd running (connection tracking daemon)');
  }

  // 3. Check for nflog/ulog kernel modules
  const nflog = runCommand('lsmod 2>/dev/null | grep -c nfnetlink_log');
  if (nflog && parseInt(nflog, 10) > 0) {
    signals.push('nfnetlink_log kernel module loaded');
  }

  // 4. Check auditd for network syscall rules
  const auditRules = runCommand('auditctl -l 2>/dev/null');
  if (auditRules) {
    const networkRules = auditRules.split('\n').filter(line =>
      line.includes('connect') || line.includes('sendto') || line.includes('sendmsg')
    );
    if (networkRules.length > 0) {
      signals.push(`${networkRules.length} auditd rules for network syscalls`);
    }
  }

  // 5. Check for Cilium/Calico/network policy with logging
  const ciliumPid = runCommand('pgrep -x cilium-agent 2>/dev/null');
  if (ciliumPid) {
    signals.push('Cilium agent running (network policy + logging)');
  }
  const calicoPid = runCommand('pgrep -x calico-node 2>/dev/null');
  if (calicoPid) {
    signals.push('Calico running (network policy + logging)');
  }

  if (signals.length > 0) {
    return {
      id, name, severity, status: 'pass',
      detail: signals.join('; '),
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: 'No network connection logging — outbound connections from agent containers are not recorded. ' +
      'Add iptables LOG: iptables -I DOCKER-USER -j LOG --log-prefix "g0-egress: " --log-level 4, or deploy conntrackd/Cilium.',
  };
}

/**
 * OC-H-024: No backup mechanism
 */
function probeBackupMechanism(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-024';
  const name = 'No backup mechanism';
  const severity: HardeningSeverity = 'high';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided — skipped' };
  }

  if (!fs.existsSync(agentDataPath)) {
    return { id, name, severity, status: 'error', detail: `Agent data path does not exist: ${agentDataPath}` };
  }

  const signals: string[] = [];

  // Check for .git directory (versioned data)
  const gitDir = path.join(agentDataPath, '.git');
  if (fs.existsSync(gitDir)) {
    // Check how recent the last commit is
    const lastCommit = runCommand(`git -C "${agentDataPath}" log -1 --format=%cr 2>/dev/null`);
    signals.push(lastCommit ? `git history (last commit: ${lastCommit})` : 'git repository present');
  }

  // Check parent dirs for .git too
  const parentGit = path.join(path.dirname(agentDataPath), '.git');
  if (fs.existsSync(parentGit) && !fs.existsSync(gitDir)) {
    signals.push('parent directory has git repository');
  }

  // Check for backup cron
  const cronOutput = runCommand('crontab -l 2>/dev/null');
  if (cronOutput) {
    const backupPattern = /\b(backup|rsync|restic|borg|rclone|git\s+commit|git\s+push|duplicity|rdiff-backup)\b/i;
    if (backupPattern.test(cronOutput)) {
      signals.push('backup cron job detected');
    }
  }

  // Check systemd timers (Linux)
  if (isLinux()) {
    const timers = runCommand('systemctl list-timers --no-legend 2>/dev/null');
    if (timers) {
      const backupTimer = /\b(backup|restic|borg|rsync|duplicity)\b/i;
      if (backupTimer.test(timers)) {
        signals.push('backup systemd timer detected');
      }
    }
  }

  // Check for common backup tool configs
  const backupConfigs = [
    path.join(os.homedir(), '.config', 'restic'),
    path.join(os.homedir(), '.config', 'borg'),
    '/etc/restic',
    '/etc/borgmatic',
  ];
  for (const cfg of backupConfigs) {
    if (fs.existsSync(cfg)) {
      signals.push(`backup config found: ${path.basename(cfg)}`);
      break;
    }
  }

  if (signals.length > 0) {
    return {
      id, name, severity, status: 'pass',
      detail: `Backup mechanisms detected: ${signals.join('; ')}`,
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: 'No git history, backup cron, or backup tool config found — agent data is not backed up',
  };
}

/**
 * OC-H-025: Container runs as UID 0
 */
function probeContainerRootUser(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-025';
  const name = 'Container runs as UID 0';
  const severity: HardeningSeverity = 'high';

  if (skipDocker || !dockerAvailable()) {
    return {
      id, name, severity, status: 'skip',
      detail: skipDocker ? 'Docker checks skipped by configuration' : 'Docker not available — skipped',
    };
  }

  const containerIds = runCommand('docker ps -q 2>/dev/null');
  if (!containerIds || containerIds.trim().length === 0) {
    return { id, name, severity, status: 'pass', detail: 'No running containers' };
  }

  const ids = containerIds.split('\n').filter(i => i.trim().length > 0);
  const rootContainers: string[] = [];

  for (const cid of ids) {
    const userOutput = runCommand(`docker inspect --format '{{.Config.User}}' ${cid} 2>/dev/null`);
    const nameOutput = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`);
    const containerName = nameOutput?.replace(/^\//, '') ?? cid.slice(0, 12);

    // Empty user means root by default
    if (userOutput === null || userOutput === '' || userOutput === 'root' || userOutput === '0' || userOutput === '0:0') {
      rootContainers.push(containerName);
    }
  }

  if (rootContainers.length === 0) {
    return {
      id, name, severity, status: 'pass',
      detail: `${ids.length} containers run as non-root users`,
    };
  }

  const list = rootContainers.length > 5
    ? `${rootContainers.slice(0, 5).join(', ')}, ... (${rootContainers.length} total)`
    : rootContainers.join(', ');

  return {
    id, name, severity, status: 'fail',
    detail: `${rootContainers.length}/${ids.length} containers run as root: ${list} — use USER directive in Dockerfile`,
  };
}

/**
 * OC-H-026: Docker log rotation missing
 */
function probeDockerLogRotation(skipDocker: boolean, daemonConfigPath?: string): HardeningCheck {
  const id = 'OC-H-026';
  const name = 'Docker log rotation missing';
  const severity: HardeningSeverity = 'medium';

  if (skipDocker) {
    return { id, name, severity, status: 'skip', detail: 'Docker checks skipped by configuration' };
  }

  const configPath = daemonConfigPath ?? '/etc/docker/daemon.json';
  let hasFileConfig = false;
  let configDetail = '';

  // Check daemon.json
  if (fs.existsSync(configPath)) {
    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      const config = JSON.parse(content) as Record<string, unknown>;
      const logOpts = config['log-opts'] as Record<string, string> | undefined;
      const logDriver = config['log-driver'] as string | undefined;
      const maxSize = logOpts?.['max-size'];
      const maxFile = logOpts?.['max-file'];

      if (maxSize) {
        hasFileConfig = true;
        configDetail = `daemon.json: log-driver=${logDriver ?? 'json-file'}, max-size=${maxSize}`;
        if (maxFile) configDetail += `, max-file=${maxFile}`;
      } else if (logDriver && logDriver !== 'json-file' && logDriver !== 'local') {
        // External log driver (syslog, fluentd, etc.) handles rotation
        hasFileConfig = true;
        configDetail = `daemon.json: log-driver=${logDriver} (external driver handles rotation)`;
      }
    } catch {
      configDetail = `Cannot parse ${configPath}`;
    }
  }

  if (hasFileConfig) {
    return { id, name, severity, status: 'pass', detail: configDetail };
  }

  // Check via docker info as fallback
  if (dockerAvailable()) {
    const driverOutput = runCommand("docker info --format '{{.LoggingDriver}}' 2>/dev/null");
    if (driverOutput && driverOutput !== 'json-file' && driverOutput !== 'local') {
      return {
        id, name, severity, status: 'pass',
        detail: `Docker logging driver: ${driverOutput} (external driver handles rotation)`,
      };
    }

    // json-file without rotation config
    return {
      id, name, severity, status: 'fail',
      detail: `Docker logging driver: ${driverOutput ?? 'json-file'}, no log rotation configured in ${configPath} — disk exhaustion risk`,
    };
  }

  // Docker not available, no config file
  if (!fs.existsSync(configPath)) {
    return { id, name, severity, status: 'skip', detail: `${configPath} not found and Docker not available — skipped` };
  }

  return { id, name, severity, status: 'fail', detail: `${configPath} exists but no log rotation configured` };
}

/**
 * OC-H-027: Shared container network
 */
function probeSharedNetwork(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-027';
  const name = 'Shared container network';
  const severity: HardeningSeverity = 'medium';

  if (skipDocker || !dockerAvailable()) {
    return {
      id, name, severity, status: 'skip',
      detail: skipDocker ? 'Docker checks skipped by configuration' : 'Docker not available — skipped',
    };
  }

  const bridgeOutput = runCommand("docker network inspect bridge --format '{{json .Containers}}' 2>/dev/null");
  if (bridgeOutput === null) {
    return { id, name, severity, status: 'error', detail: 'Cannot inspect bridge network — permission denied or network not found' };
  }

  const containers = parseDockerInspect(bridgeOutput);
  if (!containers || typeof containers !== 'object') {
    return { id, name, severity, status: 'error', detail: 'Cannot parse bridge network container list' };
  }

  const containerEntries = Object.entries(containers as Record<string, Record<string, string>>);
  if (containerEntries.length <= 1) {
    return {
      id, name, severity, status: 'pass',
      detail: containerEntries.length === 0
        ? 'No containers on default bridge network'
        : '1 container on default bridge network — no cross-container risk',
    };
  }

  const names = containerEntries.map(([, info]) => info.Name || 'unknown').slice(0, 8);
  const nameList = containerEntries.length > 8
    ? `${names.join(', ')}, ... (${containerEntries.length} total)`
    : names.join(', ');

  return {
    id, name, severity, status: 'fail',
    detail: `${containerEntries.length} containers on default bridge network: ${nameList} — use isolated networks per service`,
  };
}

/**
 * OC-H-028: Session files unencrypted
 */
function probeSessionEncryption(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-028';
  const name = 'Session files unencrypted';
  const severity: HardeningSeverity = 'medium';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided — skipped' };
  }

  if (!fs.existsSync(agentDataPath)) {
    return { id, name, severity, status: 'error', detail: `Agent data path does not exist: ${agentDataPath}` };
  }

  try {
    const entries = fs.readdirSync(agentDataPath, { withFileTypes: true });
    const agentDirs = entries.filter(e => e.isDirectory());

    let totalFiles = 0;
    let totalBytes = 0;
    let agentsWithSessions = 0;
    let encryptedFiles = 0;

    for (const dir of agentDirs) {
      const sessionsDir = path.join(agentDataPath, dir.name, 'sessions');
      if (!fs.existsSync(sessionsDir)) continue;

      try {
        const sessionFiles = fs.readdirSync(sessionsDir);
        const jsonlFiles = sessionFiles.filter(f => f.endsWith('.jsonl') || f.endsWith('.json'));
        const encFiles = sessionFiles.filter(f => f.endsWith('.enc') || f.endsWith('.gpg') || f.endsWith('.age'));

        if (jsonlFiles.length > 0) {
          agentsWithSessions++;
          for (const sf of jsonlFiles) {
            try {
              const stat = fs.statSync(path.join(sessionsDir, sf));
              totalFiles++;
              totalBytes += stat.size;
            } catch { /* skip */ }
          }
        }

        encryptedFiles += encFiles.length;
      } catch { /* skip unreadable dirs */ }
    }

    if (totalFiles === 0 && encryptedFiles === 0) {
      return {
        id, name, severity, status: 'pass',
        detail: `No session files found across ${agentDirs.length} agents`,
      };
    }

    if (totalFiles === 0 && encryptedFiles > 0) {
      return {
        id, name, severity, status: 'pass',
        detail: `${encryptedFiles} encrypted session files found — plaintext sessions absent`,
      };
    }

    const sizeMB = (totalBytes / (1024 * 1024)).toFixed(1);

    return {
      id, name, severity, status: 'fail',
      detail: `${sizeMB}MB across ${agentsWithSessions} agents, ${totalFiles} session files, no encryption — conversation history exposed at rest`,
    };
  } catch (err) {
    return { id, name, severity, status: 'error', detail: `Failed to scan sessions: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/**
 * OC-H-029: No image scanning in CI
 */
function probeImageScanning(): HardeningCheck {
  const id = 'OC-H-029';
  const name = 'No image scanning in CI';
  const severity: HardeningSeverity = 'low';

  const ciConfigs = findCIConfigs();

  if (ciConfigs.length === 0) {
    return { id, name, severity, status: 'skip', detail: 'No CI config files found — skipped' };
  }

  const scannerPattern = /\b(trivy|grype|snyk|aqua|prisma[- ]?cloud|docker\s+scout|anchore|clair|lacework|wiz)\b/i;
  const configsWithScanners: string[] = [];
  const configsWithoutScanners: string[] = [];

  for (const configFile of ciConfigs) {
    try {
      const content = fs.readFileSync(configFile, 'utf-8');
      const basename = path.basename(configFile);
      if (scannerPattern.test(content)) {
        configsWithScanners.push(basename);
      } else {
        configsWithoutScanners.push(basename);
      }
    } catch { /* skip unreadable */ }
  }

  if (configsWithScanners.length > 0) {
    return {
      id, name, severity, status: 'pass',
      detail: `Image scanning found in: ${configsWithScanners.join(', ')}`,
    };
  }

  return {
    id, name, severity, status: 'fail',
    detail: `${ciConfigs.length} CI config(s) found (${configsWithoutScanners.join(', ')}) but no image scanner (trivy, grype, snyk, etc.) referenced`,
  };
}

/**
 * OC-H-030: Overprivileged env injection
 */
async function probeOverprivilegedEnv(agentDataPath?: string): Promise<HardeningCheck> {
  const id = 'OC-H-030';
  const name = 'Overprivileged env injection';
  const severity: HardeningSeverity = 'high';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided — skipped' };
  }

  if (!fs.existsSync(agentDataPath)) {
    return { id, name, severity, status: 'error', detail: `Agent data path does not exist: ${agentDataPath}` };
  }

  try {
    const result = await scanAgentConfigs({ agentDataPath });

    if (result.overprivileged.length === 0) {
      return {
        id, name, severity, status: 'pass',
        detail: `No overprivileged credential injection detected across ${result.agentsScanned} agents`,
      };
    }

    // Aggregate by credential prefix
    const prefixCounts = new Map<string, number>();
    for (const op of result.overprivileged) {
      const prefix = op.credential.replace(/_.*$/, '') + '_*';
      prefixCounts.set(prefix, (prefixCounts.get(prefix) ?? 0) + 1);
    }

    // Format detail
    const details = [...prefixCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([prefix, count]) => {
        const needed = result.agentsScanned - count;
        return `${prefix} in ${result.agentsScanned} agents, only ${needed} have relevant skill`;
      });

    return {
      id, name, severity, status: 'fail',
      detail: details.join('; '),
    };
  } catch (err) {
    return { id, name, severity, status: 'error', detail: `Failed to scan agent configs: ${err instanceof Error ? err.message : String(err)}` };
  }
}

// ── Backup Encryption / Retention ─────────────────────────────────────────

function probeBackupEncryption(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-034';
  const name = 'Backup encryption and retention';
  const severity: HardeningSeverity = 'high';

  const issues: string[] = [];
  let hasBackupTool = false;

  // Check restic
  const resticConfig = runCommand('restic cat config 2>/dev/null');
  if (resticConfig !== null) {
    hasBackupTool = true;
    // restic encrypts by default; config output containing "repository" confirms it
    if (!resticConfig.includes('repository')) {
      issues.push('restic repository may lack encryption');
    }
  }

  // Check borg
  const borgInfo = runCommand('borg info 2>/dev/null');
  if (borgInfo !== null) {
    hasBackupTool = true;
    if (!/Encrypted:\s*Yes/i.test(borgInfo) && !/encryption\s+mode/i.test(borgInfo)) {
      issues.push('borg repository does not appear encrypted');
    }
  }

  // If no backup tool detected, skip — OC-H-024 covers backup presence
  if (!hasBackupTool) {
    return { id, name, severity, status: 'skip', detail: 'No backup tool (restic/borg) detected — see OC-H-024 for backup presence' };
  }

  // Check for encryption key material availability
  const homeDir = os.homedir();
  const hasGnupg = fs.existsSync(path.join(homeDir, '.gnupg'));
  const hasAgeKey = runCommand('which age 2>/dev/null') !== null;
  if (!hasGnupg && !hasAgeKey) {
    issues.push('no GPG or age encryption keys found for backup encryption');
  }

  // Check git signed commits on agent data
  if (agentDataPath && fs.existsSync(agentDataPath)) {
    const gpgSign = runCommand(`git -C ${agentDataPath} config commit.gpgSign 2>/dev/null`);
    if (gpgSign !== 'true') {
      issues.push('agent data git repo does not enforce signed commits');
    }
  }

  // Check retention policy in crontab
  const crontab = runCommand('crontab -l 2>/dev/null');
  if (crontab !== null) {
    if (!crontab.includes('--keep-daily') && !crontab.includes('--prune')) {
      issues.push('no backup retention/prune policy found in crontab');
    }
  } else {
    issues.push('no crontab found for backup scheduling/retention');
  }

  if (issues.length === 0) {
    return { id, name, severity, status: 'pass', detail: 'Backup encryption and retention policy verified' };
  }

  return { id, name, severity, status: 'fail', detail: issues.join('; ') };
}

// ── Kernel Reboot Pending ─────────────────────────────────────────────────

function probeKernelRebootPending(): HardeningCheck {
  const id = 'OC-H-035';
  const name = 'Kernel reboot pending';
  const severity: HardeningSeverity = 'medium';

  if (isLinux()) {
    // Debian/Ubuntu: /var/run/reboot-required
    if (fs.existsSync('/var/run/reboot-required')) {
      return { id, name, severity, status: 'fail', detail: 'Reboot required (/var/run/reboot-required exists)' };
    }

    // RHEL/CentOS: needs-restarting
    const needsRestarting = runCommand('needs-restarting -r 2>/dev/null');
    if (needsRestarting === null) {
      // Exit code 1 means reboot needed — runCommand returns null on non-zero exit
      // But also returns null if command doesn't exist, so check if command exists first
      const hasNeedsRestarting = runCommand('which needs-restarting 2>/dev/null');
      if (hasNeedsRestarting !== null) {
        return { id, name, severity, status: 'fail', detail: 'Kernel reboot needed (needs-restarting reports pending reboot)' };
      }
    }

    // needrestart
    const needrestart = runCommand('needrestart -b 2>/dev/null');
    if (needrestart !== null && needrestart.includes('NEEDRESTART-KSTA: 3')) {
      return { id, name, severity, status: 'fail', detail: 'Kernel reboot needed (needrestart reports KSTA=3)' };
    }

    // Compare running kernel vs latest installed
    const runningKernel = runCommand('uname -r 2>/dev/null');
    const latestKernel = runCommand('ls -v /boot/vmlinuz-* 2>/dev/null | tail -1');
    if (runningKernel && latestKernel) {
      const latestVersion = latestKernel.replace(/^.*vmlinuz-/, '');
      if (latestVersion !== runningKernel) {
        return { id, name, severity, status: 'fail', detail: `Running kernel ${runningKernel} differs from latest installed ${latestVersion}` };
      }
    }

    return { id, name, severity, status: 'pass', detail: 'No kernel reboot pending' };
  }

  if (isMacOS()) {
    const updates = runCommand('softwareupdate -l 2>/dev/null');
    if (updates !== null && updates.includes('restart')) {
      return { id, name, severity, status: 'fail', detail: 'macOS software updates pending that require restart' };
    }
    return { id, name, severity, status: 'pass', detail: 'No pending macOS updates requiring restart' };
  }

  return { id, name, severity, status: 'skip', detail: 'Kernel reboot check not supported on this platform' };
}

// ── Tailscale Account Type ────────────────────────────────────────────────

function probeTailscaleAccount(): HardeningCheck {
  const id = 'OC-H-036';
  const name = 'Tailscale account type and ACL';
  const severity: HardeningSeverity = 'medium';

  const statusJson = runCommand('tailscale status --json 2>/dev/null');
  if (statusJson === null) {
    return { id, name, severity, status: 'skip', detail: 'Tailscale not installed or not running' };
  }

  try {
    const status = JSON.parse(statusJson);
    const issues: string[] = [];

    // Check tailnet name — email-based = personal, domain = org
    const tailnetName = status?.CurrentTailnet?.Name;
    if (typeof tailnetName === 'string') {
      if (tailnetName.includes('@')) {
        issues.push(`personal Tailscale account detected (${tailnetName}) — use organization tailnet`);
      }
    }

    // Check MagicDNS suffix
    const magicDNS = status?.MagicDNSSuffix;
    if (typeof magicDNS === 'string' && !magicDNS.endsWith('.ts.net')) {
      issues.push('MagicDNS suffix does not end with .ts.net');
    }

    // Count peers (device count)
    const peers = status?.Peer;
    if (peers && typeof peers === 'object') {
      const peerCount = Object.keys(peers).length;
      if (peerCount > 50) {
        issues.push(`high device count (${peerCount} peers) — review tailnet membership`);
      }
    }

    // Check for ACL indicators
    // Tailscale status --json doesn't directly expose ACLs, but we can check
    // if the tailnet has non-default settings via the control URL or admin panel
    const controlURL = status?.ControlURL;
    if (typeof controlURL === 'string' && controlURL.includes('login.tailscale.com')) {
      // Default control plane — check if ACLs are likely default
      const selfNodeKey = status?.Self?.PublicKey;
      if (selfNodeKey && peers && typeof peers === 'object') {
        // If all peers can reach all ports, ACLs may be default (allow-all)
        const peerCount = Object.keys(peers).length;
        if (peerCount > 5) {
          issues.push('large tailnet with default control plane — verify ACLs are not allow-all');
        }
      }
    }

    if (issues.length === 0) {
      return { id, name, severity, status: 'pass', detail: 'Tailscale configuration appears properly scoped' };
    }

    return { id, name, severity, status: 'fail', detail: issues.join('; ') };
  } catch {
    return { id, name, severity, status: 'error', detail: 'Failed to parse tailscale status JSON' };
  }
}

// ── Container Deep Audit ──────────────────────────────────────────────────

function probeCapDrop(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-056';
  const name = 'Container cap_drop ALL';
  const severity: HardeningSeverity = 'high';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const inspect = runCommand(`docker inspect --format '{{json .HostConfig.CapDrop}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    if (!inspect || inspect === 'null' || inspect === '[]') {
      issues.push(name_);
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'All containers drop capabilities' };
  return { id, name, severity, status: 'fail', detail: `${issues.length} container(s) without cap_drop: ${issues.slice(0, 3).join(', ')}` };
}

function probeNoNewPrivileges(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-057';
  const name = 'Container no-new-privileges';
  const severity: HardeningSeverity = 'high';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const inspect = runCommand(`docker inspect --format '{{.HostConfig.SecurityOpt}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    if (!inspect || !inspect.includes('no-new-privileges')) {
      issues.push(name_);
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'All containers have no-new-privileges' };
  return { id, name, severity, status: 'fail', detail: `${issues.length} container(s) without no-new-privileges: ${issues.slice(0, 3).join(', ')}` };
}

function probeReadOnlyRootfs(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-058';
  const name = 'Read-only root filesystem';
  const severity: HardeningSeverity = 'medium';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const inspect = runCommand(`docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    if (inspect !== 'true') {
      issues.push(name_);
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'All containers have read-only root filesystem' };
  return { id, name, severity, status: 'fail', detail: `${issues.length} container(s) with writable root filesystem: ${issues.slice(0, 3).join(', ')}` };
}

function probeResourceLimits(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-059';
  const name = 'Container memory/CPU limits';
  const severity: HardeningSeverity = 'medium';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const memory = runCommand(`docker inspect --format '{{.HostConfig.Memory}}' ${cid} 2>/dev/null`);
    const cpus = runCommand(`docker inspect --format '{{.HostConfig.NanoCpus}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    if ((!memory || memory === '0') && (!cpus || cpus === '0')) {
      issues.push(name_);
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'All containers have resource limits' };
  return { id, name, severity, status: 'fail', detail: `${issues.length} container(s) without memory/CPU limits: ${issues.slice(0, 3).join(', ')}` };
}

function probeNetworkMode(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-060';
  const name = 'Container not using host network';
  const severity: HardeningSeverity = 'high';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const networkMode = runCommand(`docker inspect --format '{{.HostConfig.NetworkMode}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    if (networkMode === 'host') {
      issues.push(name_);
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'No containers using host network mode' };
  return { id, name, severity, status: 'fail', detail: `${issues.length} container(s) using host network: ${issues.slice(0, 3).join(', ')}` };
}

function probeBonjourDisabled(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-061';
  const name = 'OPENCLAW_DISABLE_BONJOUR set';
  const severity: HardeningSeverity = 'medium';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const env = runCommand(`docker inspect --format '{{json .Config.Env}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    // Only check OpenClaw containers
    const image = runCommand(`docker inspect --format '{{.Config.Image}}' ${cid} 2>/dev/null`) ?? '';
    if (image.toLowerCase().includes('openclaw') || image.toLowerCase().includes('claw')) {
      if (!env || !env.includes('OPENCLAW_DISABLE_BONJOUR')) {
        issues.push(name_);
      }
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'All OpenClaw containers have OPENCLAW_DISABLE_BONJOUR set (or no OpenClaw containers found)' };
  return { id, name, severity, status: 'fail', detail: `${issues.length} OpenClaw container(s) without OPENCLAW_DISABLE_BONJOUR: ${issues.slice(0, 3).join(', ')}` };
}

function probeSensitiveVolumes(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-062';
  const name = 'No sensitive volume mounts';
  const severity: HardeningSeverity = 'critical';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  const containers = runCommand('docker ps -q 2>/dev/null');
  if (!containers || containers.trim().length === 0) return { id, name, severity, status: 'skip', detail: 'No running containers' };
  const ids = containers.trim().split('\n');
  const sensitivePatterns = [/\/etc\/shadow/, /\/etc\/passwd/, /\.ssh/, /\.aws/, /\.kube/, /\.gnupg/, /\/root/];
  const issues: string[] = [];
  for (const cid of ids.slice(0, 10)) {
    const mounts = runCommand(`docker inspect --format '{{json .Mounts}}' ${cid} 2>/dev/null`);
    const name_ = runCommand(`docker inspect --format '{{.Name}}' ${cid} 2>/dev/null`)?.replace(/^\//, '') ?? cid;
    if (mounts) {
      for (const pattern of sensitivePatterns) {
        if (pattern.test(mounts)) {
          issues.push(`${name_} mounts ${pattern.source}`);
        }
      }
    }
  }
  if (issues.length === 0) return { id, name, severity, status: 'pass', detail: 'No sensitive paths mounted into containers' };
  return { id, name, severity, status: 'fail', detail: issues.slice(0, 5).join('; ') };
}

function probeImageVerification(skipDocker: boolean): HardeningCheck {
  const id = 'OC-H-063';
  const name = 'Container image verification';
  const severity: HardeningSeverity = 'medium';
  if (skipDocker || !dockerAvailable()) return { id, name, severity, status: 'skip', detail: 'Docker not available' };
  // Check if Docker Content Trust is enabled
  const dct = runCommand('echo $DOCKER_CONTENT_TRUST 2>/dev/null');
  if (dct === '1') {
    return { id, name, severity, status: 'pass', detail: 'Docker Content Trust is enabled' };
  }
  // Check if cosign/notation is available
  const cosign = runCommand('which cosign 2>/dev/null');
  const notation = runCommand('which notation 2>/dev/null');
  if (cosign || notation) {
    return { id, name, severity, status: 'pass', detail: `Image signing tool available: ${cosign ? 'cosign' : 'notation'}` };
  }
  return { id, name, severity, status: 'fail', detail: 'No image verification: DOCKER_CONTENT_TRUST not set, no cosign/notation found' };
}

// ── Session Transcript Forensics ──────────────────────────────────────────

function probeSessionForensics(agentDataPath?: string): HardeningCheck {
  const id = 'OC-H-037';
  const name = 'Session transcript forensics';
  const severity: HardeningSeverity = 'critical';

  if (!agentDataPath) {
    return { id, name, severity, status: 'skip', detail: 'No agentDataPath provided — skipped' };
  }

  if (!fs.existsSync(agentDataPath)) {
    return { id, name, severity, status: 'skip', detail: `Agent data path does not exist: ${agentDataPath}` };
  }

  try {
    const results = scanSessionTranscripts(agentDataPath);
    const summary = getForensicsSummary(results);

    if (summary.totalFindings === 0) {
      return {
        id, name, severity, status: 'pass',
        detail: 'No suspicious commands detected in session transcripts',
      };
    }

    const typeBreakdown = Object.entries(summary.byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([type, count]) => `${type}: ${count}`)
      .join(', ');

    return {
      id, name, severity, status: 'fail',
      detail: `${summary.totalFindings} suspicious findings in ${summary.affectedAgents.length} agent(s): ${typeBreakdown}`,
    };
  } catch (err) {
    return { id, name, severity, status: 'error', detail: `Session forensics scan failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}

// ── Main Export ────────────────────────────────────────────────────────────

export async function auditOpenClawDeployment(
  options: DeploymentAuditOptions = {}
): Promise<DeploymentAuditResult> {
  const skipDocker = options.skipDocker ?? false;
  const checks: HardeningCheck[] = [];

  // Run all probes, collecting results
  // Synchronous probes
  checks.push(probeEgressFiltering());
  checks.push(probeDockerSocket(skipDocker, options.composePath));
  checks.push(probeCrossAgentFilesystem(options.agentDataPath));
  checks.push(probeAuditLogging());
  checks.push(probeToolCallLogging(options.agentDataPath));
  checks.push(probeFileAccessAuditing(options.agentDataPath));
  checks.push(probeNetworkConnectionLogging());
  checks.push(probeBackupMechanism(options.agentDataPath));
  checks.push(probeContainerRootUser(skipDocker));
  checks.push(probeDockerLogRotation(skipDocker, options.dockerDaemonConfigPath));
  checks.push(probeSharedNetwork(skipDocker));
  checks.push(probeSessionEncryption(options.agentDataPath));
  checks.push(probeImageScanning());
  checks.push(probeBackupEncryption(options.agentDataPath));
  checks.push(probeKernelRebootPending());
  checks.push(probeTailscaleAccount());
  checks.push(probeSessionForensics(options.agentDataPath));

  // Container deep audit
  checks.push(probeCapDrop(skipDocker));
  checks.push(probeNoNewPrivileges(skipDocker));
  checks.push(probeReadOnlyRootfs(skipDocker));
  checks.push(probeResourceLimits(skipDocker));
  checks.push(probeNetworkMode(skipDocker));
  checks.push(probeBonjourDisabled(skipDocker));
  checks.push(probeSensitiveVolumes(skipDocker));
  checks.push(probeImageVerification(skipDocker));

  // Async probes
  const [secretDupResult, overprivResult] = await Promise.all([
    probeSecretDuplication(options.agentDataPath),
    probeOverprivilegedEnv(options.agentDataPath),
  ]);
  checks.push(secretDupResult);
  checks.push(overprivResult);

  // Sort by probe ID for consistent ordering
  checks.sort((a, b) => a.id.localeCompare(b.id));

  // Run agent config scan for result attachment
  let agentConfigResult: AgentConfigScanResult | undefined;
  if (options.agentDataPath && fs.existsSync(options.agentDataPath)) {
    try {
      agentConfigResult = await scanAgentConfigs({ agentDataPath: options.agentDataPath });
    } catch { /* non-fatal */ }
  }

  // Run egress scan for result attachment
  let egressResult: import('../endpoint/egress-monitor.js').EgressScanResult | undefined;
  if (options.egressAllowlist) {
    try {
      egressResult = await scanEgress({ allowlist: options.egressAllowlist, perContainer: true });
    } catch { /* non-fatal */ }
  }

  // Run session forensics for result attachment
  let forensicsResults: SessionForensicsResult[] | undefined;
  if (options.agentDataPath && fs.existsSync(options.agentDataPath)) {
    try {
      forensicsResults = scanSessionTranscripts(options.agentDataPath);
    } catch { /* non-fatal */ }
  }

  // Build summary
  const passed = checks.filter(c => c.status === 'pass').length;
  const failed = checks.filter(c => c.status === 'fail').length;
  const errors = checks.filter(c => c.status === 'error').length;
  const skipped = checks.filter(c => c.status === 'skip').length;

  const hasCriticalFail = checks.some(c => c.status === 'fail' && c.severity === 'critical');
  const hasHighFail = checks.some(c => c.status === 'fail' && c.severity === 'high');

  const overallStatus: DeploymentAuditResult['summary']['overallStatus'] =
    hasCriticalFail ? 'critical' : hasHighFail ? 'warn' : 'secure';

  return {
    checks,
    agentConfigResult,
    egressResult,
    forensicsResults,
    summary: {
      total: checks.length,
      passed,
      failed,
      errors,
      skipped,
      overallStatus,
    },
  };
}

// ── Deployment Fix Actions ────────────────────────────────────────────────

export interface FixAction {
  checkId: string;
  description: string;
  applied: boolean;
  backupPath?: string;
  error?: string;
}

export interface DeploymentFixOptions {
  agentDataPath?: string;
  dockerDaemonConfigPath?: string;
  dryRun?: boolean;
}

export async function fixDeploymentFindings(
  result: DeploymentAuditResult,
  options: DeploymentFixOptions = {},
): Promise<FixAction[]> {
  const actions: FixAction[] = [];
  const failedIds = new Set(result.checks.filter(c => c.status === 'fail').map(c => c.id));

  // OC-H-022: Fix credential file permissions
  if (failedIds.has('OC-H-022') && options.agentDataPath && fs.existsSync(options.agentDataPath)) {
    try {
      const entries = fs.readdirSync(options.agentDataPath);
      for (const entry of entries) {
        const agentDir = path.join(options.agentDataPath, entry);
        try {
          if (!fs.statSync(agentDir).isDirectory()) continue;
        } catch { continue; }

        const secretFiles = ['.env', '.env.local', 'credentials.json', 'secrets.json', 'config.json'];
        for (const file of secretFiles) {
          const filePath = path.join(agentDir, file);
          if (!fs.existsSync(filePath)) continue;

          const stat = fs.statSync(filePath);
          const mode = stat.mode & 0o777;
          if (mode === 0o600) continue; // already secure

          if (options.dryRun) {
            actions.push({
              checkId: 'OC-H-022',
              description: `Would chmod 600 ${filePath} (current: ${mode.toString(8)})`,
              applied: false,
            });
          } else {
            const backupPath = `${filePath}.backup.${Date.now()}`;
            fs.copyFileSync(filePath, backupPath);
            fs.chmodSync(filePath, 0o600);
            actions.push({
              checkId: 'OC-H-022',
              description: `chmod 600 ${filePath} (was: ${mode.toString(8)})`,
              applied: true,
              backupPath,
            });
          }
        }
      }
    } catch (err) {
      actions.push({
        checkId: 'OC-H-022',
        description: 'Fix credential permissions',
        applied: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // OC-H-026: Fix Docker log rotation
  if (failedIds.has('OC-H-026')) {
    const daemonJsonPath = options.dockerDaemonConfigPath ?? '/etc/docker/daemon.json';
    try {
      let existing: Record<string, unknown> = {};
      if (fs.existsSync(daemonJsonPath)) {
        existing = JSON.parse(fs.readFileSync(daemonJsonPath, 'utf-8'));
      }

      const merged = {
        ...existing,
        'log-driver': 'json-file',
        'log-opts': {
          ...(existing['log-opts'] as Record<string, unknown> ?? {}),
          'max-size': '50m',
          'max-file': '3',
        },
      };

      if (options.dryRun) {
        actions.push({
          checkId: 'OC-H-026',
          description: `Would write log rotation config to ${daemonJsonPath}`,
          applied: false,
        });
      } else {
        const backupPath = `${daemonJsonPath}.backup.${Date.now()}`;
        if (fs.existsSync(daemonJsonPath)) {
          fs.copyFileSync(daemonJsonPath, backupPath);
        }
        fs.writeFileSync(daemonJsonPath, JSON.stringify(merged, null, 2) + '\n', 'utf-8');
        actions.push({
          checkId: 'OC-H-026',
          description: `Wrote log rotation config to ${daemonJsonPath} (restart Docker required)`,
          applied: true,
          backupPath: fs.existsSync(backupPath) ? backupPath : undefined,
        });
      }
    } catch (err) {
      actions.push({
        checkId: 'OC-H-026',
        description: 'Fix Docker log rotation',
        applied: false,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // OC-H-028: Session encryption — guidance only
  if (failedIds.has('OC-H-028')) {
    actions.push({
      checkId: 'OC-H-028',
      description: 'Session encryption requires manual setup: enable encryption-at-rest with LUKS/dm-crypt or application-level AES-256-GCM',
      applied: false,
    });
  }

  return actions;
}

// ── AI Audit Analysis ─────────────────────────────────────────────────────

export interface AIAuditInsight {
  attackChains: Array<{
    name: string;
    severity: 'critical' | 'high' | 'medium';
    failedChecks: string[];
    narrative: string;
  }>;
  prioritizedRemediation: Array<{
    order: number;
    checkId: string;
    reason: string;
    blocksChains: string[];
  }>;
  overallRiskNarrative: string;
}

export async function analyzeAuditWithAI(
  result: DeploymentAuditResult,
  provider: import('../ai/provider.js').AIProvider,
): Promise<AIAuditInsight> {
  const failedChecks = result.checks.filter(c => c.status === 'fail');
  if (failedChecks.length === 0) {
    return { attackChains: [], prioritizedRemediation: [], overallRiskNarrative: 'No failed checks — deployment appears secure.' };
  }

  const checkList = failedChecks.map(c =>
    `- ${c.id} (${c.severity}): ${c.name} — ${c.detail}`
  ).join('\n');

  const prompt = `You are a security analyst reviewing an OpenClaw AI agent deployment audit.

The following host-level security checks FAILED:

${checkList}

Environment: ${result.summary.total} total checks, ${result.summary.passed} passed, ${result.summary.failed} failed.

Analyze these failures and respond with ONLY valid JSON (no markdown, no code fences):
{
  "attackChains": [
    {
      "name": "chain name",
      "severity": "critical|high|medium",
      "failedChecks": ["OC-H-XXX", ...],
      "narrative": "How these failures chain together to enable an attack"
    }
  ],
  "prioritizedRemediation": [
    {
      "order": 1,
      "checkId": "OC-H-XXX",
      "reason": "Why fix this first",
      "blocksChains": ["chain name", ...]
    }
  ],
  "overallRiskNarrative": "Overall risk assessment paragraph"
}`;

  try {
    const response = await provider.analyze(prompt, '');

    // Try to parse JSON from the response
    let cleaned = response.trim();
    // Strip markdown code fences if present
    if (cleaned.startsWith('```')) {
      cleaned = cleaned.replace(/^```(?:json)?\n?/, '').replace(/\n?```$/, '');
    }

    const parsed = JSON.parse(cleaned);

    return {
      attackChains: Array.isArray(parsed.attackChains) ? parsed.attackChains : [],
      prioritizedRemediation: Array.isArray(parsed.prioritizedRemediation) ? parsed.prioritizedRemediation : [],
      overallRiskNarrative: typeof parsed.overallRiskNarrative === 'string' ? parsed.overallRiskNarrative : 'AI analysis completed.',
    };
  } catch {
    return {
      attackChains: [],
      prioritizedRemediation: failedChecks.map((c, i) => ({
        order: i + 1,
        checkId: c.id,
        reason: `${c.severity} severity: ${c.name}`,
        blocksChains: [],
      })),
      overallRiskNarrative: 'AI analysis failed to produce structured output. Remediation ordered by severity.',
    };
  }
}
