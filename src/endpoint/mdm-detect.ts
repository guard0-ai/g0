import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import * as os from 'node:os';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface MDMDetectionResult {
  managed: boolean;
  provider: string | null;
  details: MDMDetail[];
  enrollmentStatus: 'enrolled' | 'unenrolled' | 'unknown';
}

export interface MDMDetail {
  check: string;
  found: boolean;
  evidence?: string;
}

/** Injectable I/O context for testability. */
export interface MDMIOContext {
  platform(): NodeJS.Platform;
  pathExists(p: string): boolean;
  dirExists(p: string): boolean;
  tryExec(cmd: string): string | null;
}

// ─── Default I/O ─────────────────────────────────────────────────────────────

const defaultIO: MDMIOContext = {
  platform: () => os.platform(),

  pathExists(p: string): boolean {
    try {
      return fs.existsSync(p);
    } catch {
      return false;
    }
  },

  dirExists(p: string): boolean {
    try {
      return fs.existsSync(p) && fs.statSync(p).isDirectory();
    } catch {
      return false;
    }
  },

  /**
   * Execute a shell command safely. All commands here are hardcoded strings
   * (no user input), so execSync is acceptable.
   */
  tryExec(cmd: string): string | null {
    try {
      return execSync(cmd, { encoding: 'utf-8', timeout: 5_000, stdio: ['pipe', 'pipe', 'pipe'] }).trim();
    } catch {
      return null;
    }
  },
};

// ─── macOS checks ────────────────────────────────────────────────────────────

interface ProviderCheck {
  provider: string;
  path: string;
  checkName: string;
}

const MACOS_PROVIDERS: ProviderCheck[] = [
  { provider: 'jamf', path: '/Library/Application Support/JAMF/', checkName: 'jamf-agent-directory' },
  { provider: 'intune', path: '/Library/Intune/', checkName: 'intune-agent-directory' },
  { provider: 'mosyle', path: '/Library/Application Support/Mosyle/', checkName: 'mosyle-agent-directory' },
  { provider: 'kandji', path: '/Library/Kandji/', checkName: 'kandji-agent-directory' },
  { provider: 'workspace-one', path: '/Library/Application Support/AirWatch/', checkName: 'workspace-one-agent-directory' },
];

function detectMacOS(io: MDMIOContext): MDMDetectionResult {
  const details: MDMDetail[] = [];
  let provider: string | null = null;
  let enrollmentStatus: MDMDetectionResult['enrollmentStatus'] = 'unknown';

  // 1. profiles status -type enrollment
  const enrollmentOutput = io.tryExec('profiles status -type enrollment 2>/dev/null');
  if (enrollmentOutput !== null) {
    const enrolled = /enrolled to an mdm server/i.test(enrollmentOutput) ||
                     /Yes/i.test(enrollmentOutput);
    const unenrolled = /not enrolled/i.test(enrollmentOutput) ||
                       /No/i.test(enrollmentOutput);
    if (enrolled) {
      enrollmentStatus = 'enrolled';
    } else if (unenrolled) {
      enrollmentStatus = 'unenrolled';
    }
    details.push({
      check: 'profiles-enrollment-status',
      found: enrolled,
      evidence: enrollmentOutput.slice(0, 200),
    });
  } else {
    details.push({ check: 'profiles-enrollment-status', found: false });
  }

  // 2. Provider directories
  for (const pc of MACOS_PROVIDERS) {
    const found = io.dirExists(pc.path);
    details.push({
      check: pc.checkName,
      found,
      ...(found ? { evidence: `Directory exists: ${pc.path}` } : {}),
    });
    if (found && !provider) {
      provider = pc.provider;
    }
  }

  // 3. Managed Preferences
  const managedPrefsPath = '/Library/Managed Preferences/';
  const managedPrefsFound = io.dirExists(managedPrefsPath);
  details.push({
    check: 'managed-preferences',
    found: managedPrefsFound,
    ...(managedPrefsFound ? { evidence: `Directory exists: ${managedPrefsPath}` } : {}),
  });

  // 4. profiles list — count configuration profiles
  const profilesListOutput = io.tryExec('profiles list 2>/dev/null');
  if (profilesListOutput !== null) {
    const profileLines = profilesListOutput.split('\n').filter((l) => l.trim().length > 0);
    const count = profileLines.length;
    details.push({
      check: 'configuration-profiles-count',
      found: count > 0,
      evidence: `${count} profile line(s) detected`,
    });
  } else {
    details.push({ check: 'configuration-profiles-count', found: false });
  }

  const managed = enrollmentStatus === 'enrolled' || !!provider || managedPrefsFound;

  // If managed but no specific provider identified, mark unknown
  if (managed && !provider) {
    provider = 'unknown';
  }

  return { managed, provider, details, enrollmentStatus };
}

// ─── Linux checks ────────────────────────────────────────────────────────────

interface LinuxProviderCheck {
  provider: string;
  paths: string[];
  checkName: string;
}

const LINUX_PROVIDERS: LinuxProviderCheck[] = [
  { provider: 'landscape', paths: ['/etc/landscape/client.conf'], checkName: 'ubuntu-landscape' },
  { provider: 'sccm', paths: ['/opt/microsoft/scep/'], checkName: 'microsoft-sccm' },
  { provider: 'puppet', paths: ['/etc/puppetlabs/', '/opt/puppetlabs/'], checkName: 'puppet-agent' },
  { provider: 'chef', paths: ['/etc/chef/'], checkName: 'chef-agent' },
  { provider: 'ansible', paths: ['/etc/ansible/'], checkName: 'ansible-managed' },
  { provider: 'saltstack', paths: ['/etc/salt/'], checkName: 'saltstack-agent' },
];

function detectLinux(io: MDMIOContext): MDMDetectionResult {
  const details: MDMDetail[] = [];
  let provider: string | null = null;

  for (const lp of LINUX_PROVIDERS) {
    let found = false;
    let evidencePath: string | undefined;
    for (const p of lp.paths) {
      if (io.pathExists(p)) {
        found = true;
        evidencePath = p;
        break;
      }
    }
    details.push({
      check: lp.checkName,
      found,
      ...(found ? { evidence: `Path exists: ${evidencePath}` } : {}),
    });
    if (found && !provider) {
      provider = lp.provider;
    }
  }

  const managed = !!provider;

  return {
    managed,
    provider,
    details,
    enrollmentStatus: managed ? 'enrolled' : 'unknown',
  };
}

// ─── Public API ──────────────────────────────────────────────────────────────

export function detectMDM(io: MDMIOContext = defaultIO): MDMDetectionResult {
  const platform = io.platform();

  if (platform === 'darwin') {
    return detectMacOS(io);
  }

  if (platform === 'linux') {
    return detectLinux(io);
  }

  // Unsupported platform
  return {
    managed: false,
    provider: null,
    details: [{ check: 'unsupported-platform', found: false, evidence: `Platform: ${platform}` }],
    enrollmentStatus: 'unknown',
  };
}

export function getMDMSummary(result: MDMDetectionResult): string {
  if (!result.managed) {
    return 'No MDM enrollment detected. Host appears unmanaged.';
  }

  const providerLabel = result.provider === 'unknown'
    ? 'an unknown MDM provider'
    : result.provider;

  const checksFound = result.details.filter((d) => d.found).length;
  const totalChecks = result.details.length;

  return `MDM detected: ${providerLabel} (enrollment: ${result.enrollmentStatus}, ${checksFound}/${totalChecks} checks matched).`;
}
