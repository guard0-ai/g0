import { execSync } from 'node:child_process';
import * as os from 'node:os';
import type { HardeningCheck, HardeningSeverity } from '../mcp/openclaw-hardening.js';

// Note: execSync is used for host-level system probes. All command strings
// are hardcoded constants — no user input is interpolated.

function runCommand(cmd: string): string | null {
  try {
    return execSync(cmd, {
      encoding: 'utf-8',
      timeout: 10_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
  } catch {
    return null;
  }
}

function isMacOS(): boolean {
  return os.platform() === 'darwin';
}

function isLinux(): boolean {
  return os.platform() === 'linux';
}

function isWindows(): boolean {
  return os.platform() === 'win32';
}

// ── macOS Checks ──────────────────────────────────────────────────────────

function probeMacFirewall(): HardeningCheck {
  const id = 'OC-H-040';
  const name = 'macOS firewall enabled';
  const severity: HardeningSeverity = 'high';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query firewall state' };

  if (result.includes('enabled')) {
    // Check stealth mode
    const stealth = runCommand('/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null');
    if (stealth && !stealth.includes('enabled')) {
      return { id, name, severity, status: 'fail', detail: 'Firewall enabled but stealth mode is off' };
    }
    return { id, name, severity, status: 'pass', detail: 'Firewall enabled with stealth mode' };
  }

  return { id, name, severity, status: 'fail', detail: 'macOS firewall is disabled' };
}

function probeMacFileVault(): HardeningCheck {
  const id = 'OC-H-041';
  const name = 'FileVault disk encryption';
  const severity: HardeningSeverity = 'critical';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('fdesetup status 2>/dev/null');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query FileVault status' };

  if (result.includes('On')) {
    return { id, name, severity, status: 'pass', detail: 'FileVault disk encryption is enabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'FileVault is not enabled — disk is unencrypted' };
}

function probeMacSIP(): HardeningCheck {
  const id = 'OC-H-042';
  const name = 'System Integrity Protection (SIP)';
  const severity: HardeningSeverity = 'critical';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('csrutil status 2>/dev/null');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query SIP status' };

  if (result.includes('enabled')) {
    return { id, name, severity, status: 'pass', detail: 'SIP is enabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'SIP is disabled — system integrity compromised' };
}

function probeMacGatekeeper(): HardeningCheck {
  const id = 'OC-H-043';
  const name = 'Gatekeeper enabled';
  const severity: HardeningSeverity = 'high';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('spctl --status 2>/dev/null');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query Gatekeeper status' };

  if (result.includes('enabled') || result.includes('assessments enabled')) {
    return { id, name, severity, status: 'pass', detail: 'Gatekeeper is enabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'Gatekeeper is disabled' };
}

function probeMacRemoteLogin(): HardeningCheck {
  const id = 'OC-H-044';
  const name = 'Remote login disabled';
  const severity: HardeningSeverity = 'medium';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('systemsetup -getremotelogin 2>/dev/null');
  if (result === null) return { id, name, severity, status: 'skip', detail: 'Could not query remote login (may need admin privileges)' };

  if (result.toLowerCase().includes('off')) {
    return { id, name, severity, status: 'pass', detail: 'Remote login (SSH) is disabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'Remote login (SSH) is enabled' };
}

function probeMacScreenSharing(): HardeningCheck {
  const id = 'OC-H-045';
  const name = 'Screen sharing disabled';
  const severity: HardeningSeverity = 'medium';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('launchctl list 2>/dev/null | grep -c com.apple.screensharing');
  if (result === null || result === '0') {
    return { id, name, severity, status: 'pass', detail: 'Screen sharing is not running' };
  }

  return { id, name, severity, status: 'fail', detail: 'Screen sharing is enabled' };
}

function probeMacAutoLogin(): HardeningCheck {
  const id = 'OC-H-046';
  const name = 'Automatic login disabled';
  const severity: HardeningSeverity = 'high';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null');
  if (result === null) {
    return { id, name, severity, status: 'pass', detail: 'Automatic login is disabled' };
  }

  return { id, name, severity, status: 'fail', detail: `Automatic login is enabled for user: ${result}` };
}

function probeMacAirDrop(): HardeningCheck {
  const id = 'OC-H-047';
  const name = 'AirDrop disabled or contacts-only';
  const severity: HardeningSeverity = 'low';

  if (!isMacOS()) return { id, name, severity, status: 'skip', detail: 'Not macOS' };

  const result = runCommand('defaults read com.apple.sharingd DiscoverableMode 2>/dev/null');
  if (result === null || result === 'Off' || result === 'Contacts Only') {
    return { id, name, severity, status: 'pass', detail: 'AirDrop is disabled or contacts-only' };
  }

  return { id, name, severity, status: 'fail', detail: 'AirDrop is set to "Everyone" — potential data exfiltration vector' };
}

// ── Linux Checks ──────────────────────────────────────────────────────────

function probeLinuxFirewall(): HardeningCheck {
  const id = 'OC-H-048';
  const name = 'Linux firewall active';
  const severity: HardeningSeverity = 'high';

  if (!isLinux()) return { id, name, severity, status: 'skip', detail: 'Not Linux' };

  // Check UFW
  const ufw = runCommand('ufw status 2>/dev/null');
  if (ufw && ufw.includes('active')) {
    return { id, name, severity, status: 'pass', detail: 'UFW firewall is active' };
  }

  // Check iptables rules count
  const iptables = runCommand('iptables -L -n 2>/dev/null | wc -l');
  if (iptables && parseInt(iptables) > 8) {
    return { id, name, severity, status: 'pass', detail: 'iptables has active rules' };
  }

  // Check nftables
  const nft = runCommand('nft list ruleset 2>/dev/null | wc -l');
  if (nft && parseInt(nft) > 3) {
    return { id, name, severity, status: 'pass', detail: 'nftables has active rules' };
  }

  return { id, name, severity, status: 'fail', detail: 'No active firewall detected (UFW/iptables/nftables)' };
}

function probeLinuxDiskEncryption(): HardeningCheck {
  const id = 'OC-H-049';
  const name = 'Disk encryption (LUKS)';
  const severity: HardeningSeverity = 'critical';

  if (!isLinux()) return { id, name, severity, status: 'skip', detail: 'Not Linux' };

  const lsblk = runCommand('lsblk -o NAME,TYPE,FSTYPE 2>/dev/null');
  if (lsblk && (lsblk.includes('crypto_LUKS') || lsblk.includes('crypt'))) {
    return { id, name, severity, status: 'pass', detail: 'LUKS disk encryption detected' };
  }

  const dmsetup = runCommand('dmsetup ls --target crypt 2>/dev/null');
  if (dmsetup && dmsetup.trim().length > 0 && !dmsetup.includes('No devices found')) {
    return { id, name, severity, status: 'pass', detail: 'dm-crypt encryption detected' };
  }

  return { id, name, severity, status: 'fail', detail: 'No disk encryption (LUKS/dm-crypt) detected' };
}

function probeLinuxSSHHardening(): HardeningCheck {
  const id = 'OC-H-050';
  const name = 'SSH hardening';
  const severity: HardeningSeverity = 'high';

  if (!isLinux()) return { id, name, severity, status: 'skip', detail: 'Not Linux' };

  // Check if SSH is even running
  const sshd = runCommand('pgrep sshd 2>/dev/null');
  if (sshd === null) {
    return { id, name, severity, status: 'pass', detail: 'SSH daemon is not running' };
  }

  const issues: string[] = [];

  // Check config
  const sshdConfig = runCommand('cat /etc/ssh/sshd_config 2>/dev/null');
  if (sshdConfig) {
    if (/^\s*PermitRootLogin\s+yes/m.test(sshdConfig)) {
      issues.push('root login permitted');
    }
    if (/^\s*PasswordAuthentication\s+yes/m.test(sshdConfig)) {
      issues.push('password authentication enabled (prefer key-only)');
    }
  }

  // Check fail2ban
  const fail2ban = runCommand('systemctl is-active fail2ban 2>/dev/null');
  if (fail2ban !== 'active') {
    issues.push('fail2ban not active');
  }

  if (issues.length === 0) {
    return { id, name, severity, status: 'pass', detail: 'SSH hardening checks passed' };
  }

  return { id, name, severity, status: 'fail', detail: issues.join('; ') };
}

function probeLinuxAutoUpdates(): HardeningCheck {
  const id = 'OC-H-051';
  const name = 'Automatic security updates';
  const severity: HardeningSeverity = 'medium';

  if (!isLinux()) return { id, name, severity, status: 'skip', detail: 'Not Linux' };

  // Debian/Ubuntu: unattended-upgrades
  const unattended = runCommand('dpkg -l unattended-upgrades 2>/dev/null');
  if (unattended && unattended.includes('ii')) {
    return { id, name, severity, status: 'pass', detail: 'unattended-upgrades is installed' };
  }

  // RHEL/CentOS: dnf-automatic
  const dnfAutomatic = runCommand('systemctl is-active dnf-automatic.timer 2>/dev/null');
  if (dnfAutomatic === 'active') {
    return { id, name, severity, status: 'pass', detail: 'dnf-automatic is active' };
  }

  // yum-cron
  const yumCron = runCommand('systemctl is-active yum-cron 2>/dev/null');
  if (yumCron === 'active') {
    return { id, name, severity, status: 'pass', detail: 'yum-cron is active' };
  }

  return { id, name, severity, status: 'fail', detail: 'No automatic security update mechanism detected' };
}

function probeLinuxOpenPorts(): HardeningCheck {
  const id = 'OC-H-052';
  const name = 'Unnecessary open ports';
  const severity: HardeningSeverity = 'medium';

  if (!isLinux()) return { id, name, severity, status: 'skip', detail: 'Not Linux' };

  const ss = runCommand('ss -tlnp 2>/dev/null');
  if (ss === null) return { id, name, severity, status: 'error', detail: 'Could not list open ports' };

  const lines = ss.split('\n').filter(l => l.includes('LISTEN'));

  const wildcardPorts: string[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    // ss -tlnp: LISTEN Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process
    // Find the local address field (4th or 5th column depending on format)
    const localAddr = parts.find(p => p.includes(':') && /:\d+$/.test(p));
    if (!localAddr) continue;

    // Parse bind address from local address field
    // Formats: 0.0.0.0:22, 127.0.0.1:8080, [::]:22, [::1]:8080, *:22,
    //          100.64.249.40:443, [2a01:4f8:...]:443
    let bindAddr: string;
    let port: string;

    if (localAddr.startsWith('[')) {
      const closeBracket = localAddr.lastIndexOf(']');
      bindAddr = localAddr.slice(1, closeBracket);
      port = localAddr.slice(closeBracket + 2);
    } else {
      const lastColon = localAddr.lastIndexOf(':');
      bindAddr = localAddr.slice(0, lastColon);
      port = localAddr.slice(lastColon + 1);
    }

    if (!port || isNaN(parseInt(port))) continue;

    // Only flag ports bound to all interfaces: 0.0.0.0, ::, or *
    // Ports on loopback (127.0.0.1, ::1) or specific IPs are not exposed
    if (bindAddr === '0.0.0.0' || bindAddr === '::' || bindAddr === '*') {
      wildcardPorts.push(port);
    }
  }

  if (wildcardPorts.length === 0) {
    return { id, name, severity, status: 'pass', detail: `${lines.length} listening ports, all on loopback or specific addresses` };
  }

  return {
    id, name, severity, status: 'fail',
    detail: `${wildcardPorts.length} ports listening on all interfaces (0.0.0.0/::): ${wildcardPorts.slice(0, 5).join(', ')}${wildcardPorts.length > 5 ? '...' : ''}`,
  };
}

// ── Windows Checks ────────────────────────────────────────────────────────

function probeWinFirewall(): HardeningCheck {
  const id = 'OC-H-053';
  const name = 'Windows Firewall enabled';
  const severity: HardeningSeverity = 'high';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('netsh advfirewall show allprofiles state');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query Windows Firewall state' };

  const offCount = (result.match(/OFF/gi) || []).length;
  if (offCount === 0) {
    return { id, name, severity, status: 'pass', detail: 'Windows Firewall is enabled on all profiles' };
  }

  return { id, name, severity, status: 'fail', detail: `Windows Firewall has ${offCount} profile(s) disabled` };
}

function probeWinBitLocker(): HardeningCheck {
  const id = 'OC-H-054';
  const name = 'BitLocker disk encryption';
  const severity: HardeningSeverity = 'critical';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('manage-bde -status C:');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query BitLocker status (may need admin privileges)' };

  if (/Protection Status:\s+Protection On/i.test(result)) {
    return { id, name, severity, status: 'pass', detail: 'BitLocker encryption is active on C:' };
  }

  return { id, name, severity, status: 'fail', detail: 'BitLocker is not enabled on C: — disk is unencrypted' };
}

function probeWinDefender(): HardeningCheck {
  const id = 'OC-H-055';
  const name = 'Windows Defender active';
  const severity: HardeningSeverity = 'high';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('powershell -NoProfile -NonInteractive -Command "(Get-MpComputerStatus).AntivirusEnabled"');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query Windows Defender status' };

  if (result.trim().toLowerCase() === 'true') {
    return { id, name, severity, status: 'pass', detail: 'Windows Defender antivirus is enabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'Windows Defender antivirus is disabled' };
}

function probeWinRDP(): HardeningCheck {
  const id = 'OC-H-065';
  const name = 'Remote Desktop disabled';
  const severity: HardeningSeverity = 'medium';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query RDP registry key' };

  // fDenyTSConnections = 0x1 means RDP is disabled (good)
  if (/0x1/i.test(result)) {
    return { id, name, severity, status: 'pass', detail: 'Remote Desktop is disabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'Remote Desktop (RDP) is enabled' };
}

function probeWinAutoLogin(): HardeningCheck {
  const id = 'OC-H-066';
  const name = 'Auto-login disabled';
  const severity: HardeningSeverity = 'high';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon');
  if (result === null) {
    // Key not found means auto-login is not configured (good)
    return { id, name, severity, status: 'pass', detail: 'Auto-login is not configured' };
  }

  if (/0x0/i.test(result) || /REG_SZ\s+0/i.test(result)) {
    return { id, name, severity, status: 'pass', detail: 'Auto-login is disabled' };
  }

  return { id, name, severity, status: 'fail', detail: 'Auto-login is enabled — credentials may be stored in registry' };
}

function probeWinOpenPorts(): HardeningCheck {
  const id = 'OC-H-067';
  const name = 'Listening ports audit';
  const severity: HardeningSeverity = 'medium';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('powershell -NoProfile -NonInteractive -Command "Get-NetTCPConnection -State Listen | Select-Object -Property LocalAddress,LocalPort | ConvertTo-Csv -NoTypeInformation"');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not enumerate listening ports' };

  const lines = result.split('\n').filter(l => l.trim() && !l.startsWith('"LocalAddress"'));
  const wildcardPorts: string[] = [];

  for (const line of lines) {
    const match = line.match(/"([^"]+)","(\d+)"/);
    if (!match) continue;
    const addr = match[1];
    const port = match[2];
    if (addr === '0.0.0.0' || addr === '::') {
      wildcardPorts.push(port);
    }
  }

  if (wildcardPorts.length === 0) {
    return { id, name, severity, status: 'pass', detail: `${lines.length} listening ports, all on loopback or specific addresses` };
  }

  return {
    id, name, severity, status: 'fail',
    detail: `${wildcardPorts.length} ports listening on all interfaces: ${wildcardPorts.slice(0, 5).join(', ')}${wildcardPorts.length > 5 ? '...' : ''}`,
  };
}

function probeWinUpdates(): HardeningCheck {
  const id = 'OC-H-068';
  const name = 'Windows Update recent';
  const severity: HardeningSeverity = 'medium';

  if (!isWindows()) return { id, name, severity, status: 'skip', detail: 'Not Windows' };

  const result = runCommand('powershell -NoProfile -NonInteractive -Command "Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1 -ExpandProperty InstalledOn"');
  if (result === null) return { id, name, severity, status: 'error', detail: 'Could not query Windows Update history' };

  try {
    const lastUpdate = new Date(result.trim());
    const daysSince = Math.floor((Date.now() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24));

    if (daysSince <= 60) {
      return { id, name, severity, status: 'pass', detail: `Last update installed ${daysSince} days ago` };
    }

    return { id, name, severity, status: 'fail', detail: `Last update was ${daysSince} days ago (>60 days)` };
  } catch {
    return { id, name, severity, status: 'error', detail: 'Could not parse update date' };
  }
}

// ── Main Export ────────────────────────────────────────────────────────────

export interface HostHardeningResult {
  checks: HardeningCheck[];
  platform: string;
  summary: {
    total: number;
    passed: number;
    failed: number;
    skipped: number;
    errors: number;
  };
}

/**
 * Run all host-level hardening checks for the current platform
 */
export function auditHostHardening(): HostHardeningResult {
  const checks: HardeningCheck[] = [];
  const platform = os.platform();

  // macOS checks
  checks.push(probeMacFirewall());
  checks.push(probeMacFileVault());
  checks.push(probeMacSIP());
  checks.push(probeMacGatekeeper());
  checks.push(probeMacRemoteLogin());
  checks.push(probeMacScreenSharing());
  checks.push(probeMacAutoLogin());
  checks.push(probeMacAirDrop());

  // Linux checks
  checks.push(probeLinuxFirewall());
  checks.push(probeLinuxDiskEncryption());
  checks.push(probeLinuxSSHHardening());
  checks.push(probeLinuxAutoUpdates());
  checks.push(probeLinuxOpenPorts());

  // Windows checks
  checks.push(probeWinFirewall());
  checks.push(probeWinBitLocker());
  checks.push(probeWinDefender());
  checks.push(probeWinRDP());
  checks.push(probeWinAutoLogin());
  checks.push(probeWinOpenPorts());
  checks.push(probeWinUpdates());

  // Filter out skipped checks so results only show relevant platform probes
  const relevant = checks.filter(c => c.status !== 'skip');

  const passed = relevant.filter(c => c.status === 'pass').length;
  const failed = relevant.filter(c => c.status === 'fail').length;
  const skipped = 0;
  const errors = relevant.filter(c => c.status === 'error').length;

  return {
    checks: relevant,
    platform,
    summary: { total: relevant.length, passed, failed, skipped, errors },
  };
}
