import * as path from 'node:path';
import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import * as os from 'node:os';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface AuditdRuleSet {
  /** The generated auditd rules (auditctl format) */
  rules: string[];
  /** Rules grouped by purpose */
  sections: AuditdSection[];
  /** Path to write rules file (default: /etc/audit/rules.d/g0-openclaw.rules) */
  rulesFilePath: string;
}

export interface AuditdSection {
  title: string;
  description: string;
  rules: string[];
}

export interface AuditdRuleOptions {
  /** OpenClaw agent data path to monitor */
  agentDataPath: string;
  /** Additional paths to watch for file access */
  additionalWatchPaths?: string[];
  /** Container runtime socket path (default: /var/run/docker.sock) */
  dockerSocketPath?: string;
  /** Include network syscall monitoring (default: true) */
  networkSyscalls?: boolean;
  /** Include process execution monitoring (default: true) */
  processExecution?: boolean;
  /** Audit rule key prefix (default: g0-openclaw) */
  keyPrefix?: string;
  /** Output file path (default: /etc/audit/rules.d/g0-openclaw.rules) */
  outputPath?: string;
}

// ─── Rule Generation ─────────────────────────────────────────────────────────

/**
 * Generate auditd rules for monitoring an OpenClaw deployment.
 *
 * Covers:
 * - File access monitoring on agent data directories (C5)
 * - Network syscall auditing for outbound connection tracking (C5/C1)
 * - Process execution tracking for agent containers
 * - Docker socket access monitoring
 * - Credential file access monitoring
 */
export function generateAuditdRules(options: AuditdRuleOptions): AuditdRuleSet {
  const key = options.keyPrefix ?? 'g0-openclaw';
  const agentPath = options.agentDataPath;
  const dockerSocket = options.dockerSocketPath ?? '/var/run/docker.sock';
  const networkSyscalls = options.networkSyscalls ?? true;
  const processExecution = options.processExecution ?? true;
  const outputPath = options.outputPath ?? '/etc/audit/rules.d/g0-openclaw.rules';

  const sections: AuditdSection[] = [];
  const allRules: string[] = [];

  // Header
  allRules.push(`## g0 OpenClaw auditd rules — generated ${new Date().toISOString()}`);
  allRules.push(`## Install: sudo cp ${outputPath} /etc/audit/rules.d/ && sudo augenrules --load`);
  allRules.push('');

  // ── Section 1: Agent data directory monitoring ──────────────────────
  const fileRules: string[] = [];

  // Watch the entire agent data directory tree
  fileRules.push(`-w ${agentPath} -p rwxa -k ${key}-agent-data`);

  // Watch individual sensitive files if agent subdirectories exist
  try {
    const entries = fs.readdirSync(agentPath, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const agentDir = path.join(agentPath, entry.name);
        // Watch .env files specifically (credential access)
        fileRules.push(`-w ${agentDir}/.env -p ra -k ${key}-cred-access`);
        // Watch session transcripts
        const sessionsDir = path.join(agentDir, 'sessions');
        if (fs.existsSync(sessionsDir)) {
          fileRules.push(`-w ${sessionsDir} -p rwa -k ${key}-session-access`);
        }
        // Watch logs directory
        const logsDir = path.join(agentDir, 'logs');
        if (fs.existsSync(logsDir)) {
          fileRules.push(`-w ${logsDir} -p wa -k ${key}-log-tamper`);
        }
      }
    }
  } catch {
    // agentPath doesn't exist yet or not readable — use the base watch rule
  }

  // Additional watch paths
  if (options.additionalWatchPaths) {
    for (const p of options.additionalWatchPaths) {
      fileRules.push(`-w ${p} -p rwxa -k ${key}-custom-watch`);
    }
  }

  sections.push({
    title: 'File Access Monitoring',
    description: 'Watch agent data directories, credential files, session transcripts, and logs for unauthorized access or tampering.',
    rules: fileRules,
  });

  allRules.push('## File access monitoring');
  allRules.push(...fileRules);
  allRules.push('');

  // ── Section 2: Docker socket monitoring ─────────────────────────────
  const dockerRules: string[] = [];

  dockerRules.push(`-w ${dockerSocket} -p rwxa -k ${key}-docker-socket`);
  // Also watch Docker daemon config
  dockerRules.push(`-w /etc/docker/daemon.json -p wa -k ${key}-docker-config`);
  // Watch docker-compose files in common locations
  dockerRules.push(`-w /opt -p wa -k ${key}-docker-compose`);

  sections.push({
    title: 'Docker Socket & Config Monitoring',
    description: 'Detect unauthorized Docker API access and configuration changes.',
    rules: dockerRules,
  });

  allRules.push('## Docker socket and config monitoring');
  allRules.push(...dockerRules);
  allRules.push('');

  // ── Section 3: Network syscall monitoring ───────────────────────────
  if (networkSyscalls) {
    const netRules: string[] = [];

    // Monitor connect() syscall — all outbound TCP connections
    netRules.push(`-a always,exit -F arch=b64 -S connect -k ${key}-net-connect`);
    netRules.push(`-a always,exit -F arch=b32 -S connect -k ${key}-net-connect`);

    // Monitor sendto/sendmsg for UDP egress (DNS exfiltration, etc.)
    netRules.push(`-a always,exit -F arch=b64 -S sendto -S sendmsg -k ${key}-net-send`);
    netRules.push(`-a always,exit -F arch=b32 -S sendto -S sendmsg -k ${key}-net-send`);

    // Monitor socket creation
    netRules.push(`-a always,exit -F arch=b64 -S socket -F a0=2 -k ${key}-net-socket-ipv4`);
    netRules.push(`-a always,exit -F arch=b64 -S socket -F a0=10 -k ${key}-net-socket-ipv6`);

    // Monitor bind() — detect if agents start listening on unexpected ports
    netRules.push(`-a always,exit -F arch=b64 -S bind -k ${key}-net-bind`);
    netRules.push(`-a always,exit -F arch=b32 -S bind -k ${key}-net-bind`);

    sections.push({
      title: 'Network Syscall Monitoring',
      description: 'Track all outbound connections (connect), data sends (sendto/sendmsg), socket creation, and port binds from agent processes.',
      rules: netRules,
    });

    allRules.push('## Network syscall monitoring');
    allRules.push(...netRules);
    allRules.push('');
  }

  // ── Section 4: Process execution tracking ───────────────────────────
  if (processExecution) {
    const execRules: string[] = [];

    // Monitor execve — every process execution
    execRules.push(`-a always,exit -F arch=b64 -S execve -k ${key}-exec`);
    execRules.push(`-a always,exit -F arch=b32 -S execve -k ${key}-exec`);

    // Monitor execveat (newer kernel alternative)
    execRules.push(`-a always,exit -F arch=b64 -S execveat -k ${key}-exec`);

    // Watch sensitive system binaries
    execRules.push(`-w /usr/bin/curl -p x -k ${key}-exec-curl`);
    execRules.push(`-w /usr/bin/wget -p x -k ${key}-exec-wget`);
    execRules.push(`-w /usr/bin/nc -p x -k ${key}-exec-netcat`);
    execRules.push(`-w /usr/bin/ncat -p x -k ${key}-exec-netcat`);
    execRules.push(`-w /usr/bin/ssh -p x -k ${key}-exec-ssh`);
    execRules.push(`-w /usr/bin/scp -p x -k ${key}-exec-scp`);

    sections.push({
      title: 'Process Execution Tracking',
      description: 'Track all process execution (execve) and monitor sensitive binary usage (curl, wget, nc, ssh, scp).',
      rules: execRules,
    });

    allRules.push('## Process execution tracking');
    allRules.push(...execRules);
    allRules.push('');
  }

  // ── Section 5: Credential & config file monitoring ──────────────────
  const credRules: string[] = [];

  credRules.push(`-w /etc/passwd -p wa -k ${key}-identity`);
  credRules.push(`-w /etc/shadow -p rwa -k ${key}-identity`);
  credRules.push(`-w /etc/sudoers -p wa -k ${key}-priv-esc`);
  credRules.push(`-w /etc/sudoers.d -p wa -k ${key}-priv-esc`);
  // OpenClaw config files
  credRules.push(`-w /etc/openclaw -p rwxa -k ${key}-oc-config`);

  sections.push({
    title: 'Credential & Identity Monitoring',
    description: 'Detect modifications to system identity files and OpenClaw configuration.',
    rules: credRules,
  });

  allRules.push('## Credential and identity monitoring');
  allRules.push(...credRules);
  allRules.push('');

  return {
    rules: allRules,
    sections,
    rulesFilePath: outputPath,
  };
}

// ─── Formatting & Application ────────────────────────────────────────────────

/** Format rules as a file ready to write to /etc/audit/rules.d/ */
export function formatAuditdRulesFile(ruleSet: AuditdRuleSet): string {
  return ruleSet.rules.join('\n') + '\n';
}

/** Format rules as a human-readable report with explanations */
export function formatAuditdReport(ruleSet: AuditdRuleSet): string {
  const lines: string[] = [];

  lines.push('# OpenClaw auditd Configuration');
  lines.push('');
  lines.push(`Total rules: ${ruleSet.sections.reduce((n, s) => n + s.rules.length, 0)}`);
  lines.push(`Output: ${ruleSet.rulesFilePath}`);
  lines.push('');

  for (const section of ruleSet.sections) {
    lines.push(`## ${section.title}`);
    lines.push(section.description);
    lines.push('');
    for (const rule of section.rules) {
      lines.push(`  ${rule}`);
    }
    lines.push('');
  }

  lines.push('## Installation');
  lines.push(`  sudo cp <rules-file> ${ruleSet.rulesFilePath}`);
  lines.push('  sudo augenrules --load');
  lines.push('  sudo systemctl restart auditd');
  lines.push('');
  lines.push('## Verify');
  lines.push('  sudo auditctl -l | grep g0-openclaw');
  lines.push('');

  return lines.join('\n');
}

export interface ApplyAuditdResult {
  applied: boolean;
  rulesLoaded: number;
  errors: string[];
}

/** Apply auditd rules by writing the rules file and reloading auditd */
export function applyAuditdRules(
  ruleSet: AuditdRuleSet,
  logger?: { info: (msg: string) => void; warn: (msg: string) => void; error: (msg: string) => void },
): ApplyAuditdResult {
  if (os.platform() !== 'linux') {
    return { applied: false, rulesLoaded: 0, errors: ['auditd rules can only be applied on Linux'] };
  }

  const errors: string[] = [];
  const ruleCount = ruleSet.sections.reduce((n, s) => n + s.rules.length, 0);

  // Write the rules file
  try {
    const dir = path.dirname(ruleSet.rulesFilePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(ruleSet.rulesFilePath, formatAuditdRulesFile(ruleSet), { mode: 0o640 });
    logger?.info(`auditd rules written to ${ruleSet.rulesFilePath}`);
  } catch (err) {
    const msg = `Failed to write rules file: ${err instanceof Error ? err.message : err}`;
    errors.push(msg);
    logger?.error(msg);
    return { applied: false, rulesLoaded: 0, errors };
  }

  // Reload auditd rules
  try {
    execFileSync('augenrules', ['--load'], {
      encoding: 'utf-8',
      timeout: 10_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    logger?.info('auditd rules reloaded via augenrules');
  } catch {
    // Fallback: try auditctl directly
    try {
      execFileSync('auditctl', ['-R', ruleSet.rulesFilePath], {
        encoding: 'utf-8',
        timeout: 10_000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      logger?.info('auditd rules loaded via auditctl -R');
    } catch (err2) {
      const msg = `Failed to reload auditd: ${err2 instanceof Error ? err2.message : err2}`;
      errors.push(msg);
      logger?.error(msg);
      return { applied: false, rulesLoaded: 0, errors };
    }
  }

  return { applied: true, rulesLoaded: ruleCount, errors };
}
