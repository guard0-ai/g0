import { execFileSync } from 'node:child_process';
import * as os from 'node:os';
import * as dns from 'node:dns';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface EgressConfig {
  /** Allowed destination hostnames/IPs */
  allowlist: string[];
  /** Include container/process mapping */
  perContainer: boolean;
}

export interface OutboundConnection {
  /** Local address:port */
  local: string;
  /** Remote address:port */
  remote: string;
  /** Remote hostname (resolved) */
  remoteHost?: string;
  /** Process ID */
  pid?: number;
  /** Process name */
  process?: string;
  /** Container name (if detectable) */
  container?: string;
  /** Connection state */
  state: string;
}

export interface EgressViolation {
  connection: OutboundConnection;
  reason: string;
  severity: 'critical' | 'high';
}

export interface EgressFinding {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium';
  detail: string;
  connection?: OutboundConnection;
}

export interface EgressScanResult {
  timestamp: string;
  totalConnections: number;
  allowedConnections: number;
  violations: EgressViolation[];
  connections: OutboundConnection[];
  findings: EgressFinding[];
  duration: number;
}

// ─── Private-Network Helpers ─────────────────────────────────────────────────

/** Check if an IP is loopback */
function isLoopback(ip: string): boolean {
  return ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0';
}

/** Check if an IP falls within the Docker bridge subnet 172.17.0.0/16 */
function isDockerBridge(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts[0] === '172' && parts[1] === '17';
}

/** Check if an IP is in a private RFC 1918 range (excluding Docker bridge) */
function isPrivateNonDocker(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;

  const a = parseInt(parts[0], 10);
  const b = parseInt(parts[1], 10);

  // 10.0.0.0/8
  if (a === 10) return true;

  // 172.16.0.0/12 — but NOT 172.17.0.0/16 (Docker bridge)
  if (a === 172 && b >= 16 && b <= 31) {
    if (b === 17) return false; // Docker bridge — keep for lateral movement detection
    return true;
  }

  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;

  return false;
}

/** Extract the IP portion from an address:port string */
function extractIp(addrPort: string): string {
  // Handle IPv6 bracket notation [::1]:port
  const ipv6Match = addrPort.match(/^\[(.+)\]:(\d+)$/);
  if (ipv6Match) return ipv6Match[1];

  // Handle IPv4 addr:port
  const lastColon = addrPort.lastIndexOf(':');
  if (lastColon === -1) return addrPort;
  return addrPort.slice(0, lastColon);
}

// ─── Connection Enumeration ──────────────────────────────────────────────────

/**
 * Parse Linux `ss -tnp state established` output.
 *
 * Example lines:
 *   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port  Process
 *   0       0       10.0.0.5:42310      142.250.80.46:443  users:(("curl",pid=1234,fd=3))
 */
export function parseLinuxSs(output: string): OutboundConnection[] {
  const connections: OutboundConnection[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip header and empty lines
    if (!trimmed || trimmed.startsWith('Recv-Q') || trimmed.startsWith('State')) continue;

    // ss state filter output has no State column, format:
    // Recv-Q Send-Q Local_Address:Port Peer_Address:Port Process
    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;

    // Determine which columns hold the addresses depending on presence of state
    let localAddr: string;
    let peerAddr: string;
    let rest: string;

    // If column 0 looks like a state word (ESTAB, ESTABLISHED, etc.), shift
    if (/^[A-Z]/.test(parts[0]) && !/^\d/.test(parts[0]) && !parts[0].includes(':')) {
      // State RecvQ SendQ Local Peer [Process]
      localAddr = parts[3] ?? '';
      peerAddr = parts[4] ?? '';
      rest = parts.slice(5).join(' ');
    } else {
      // RecvQ SendQ Local Peer [Process]
      localAddr = parts[2] ?? '';
      peerAddr = parts[3] ?? '';
      rest = parts.slice(4).join(' ');
    }

    if (!peerAddr || !peerAddr.includes(':')) continue;

    // Extract PID and process name from users:(("name",pid=123,fd=4))
    let pid: number | undefined;
    let processName: string | undefined;
    const usersMatch = rest.match(/users:\(\("([^"]+)",pid=(\d+)/);
    if (usersMatch) {
      processName = usersMatch[1];
      pid = parseInt(usersMatch[2], 10);
    }

    connections.push({
      local: localAddr,
      remote: peerAddr,
      pid,
      process: processName,
      state: 'ESTABLISHED',
    });
  }

  return connections;
}

/**
 * Parse macOS `lsof -iTCP -sTCP:ESTABLISHED -P -n -F pcn` output.
 *
 * lsof -F output uses single-char field prefixes:
 *   p<pid>
 *   c<command>
 *   n<local>-><remote>
 */
export function parseMacOsLsof(output: string): OutboundConnection[] {
  const connections: OutboundConnection[] = [];
  let currentPid: number | undefined;
  let currentProcess: string | undefined;

  for (const line of output.split('\n')) {
    if (!line) continue;
    const code = line[0];
    const value = line.slice(1);

    switch (code) {
      case 'p':
        currentPid = parseInt(value, 10);
        break;
      case 'c':
        currentProcess = value;
        break;
      case 'n': {
        // Format: "10.0.0.5:42310->142.250.80.46:443" or "[::1]:42310->[::1]:443"
        const arrowIdx = value.indexOf('->');
        if (arrowIdx === -1) break;

        const local = value.slice(0, arrowIdx);
        const remote = value.slice(arrowIdx + 2);

        // Skip entries without port info
        if (!remote.includes(':')) break;

        connections.push({
          local,
          remote,
          pid: currentPid,
          process: currentProcess,
          state: 'ESTABLISHED',
        });
        break;
      }
    }
  }

  return connections;
}

/** Enumerate established outbound TCP connections for the current platform */
function enumerateOutboundConnections(): OutboundConnection[] {
  const platform = os.platform();

  if (platform === 'darwin') {
    try {
      const output = execFileSync('lsof', ['-iTCP', '-sTCP:ESTABLISHED', '-P', '-n', '-F', 'pcn'], {
        encoding: 'utf-8',
        timeout: 15000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return parseMacOsLsof(output);
    } catch {
      return [];
    }
  }

  if (platform === 'linux') {
    try {
      const output = execFileSync('ss', ['-tnp', 'state', 'established'], {
        encoding: 'utf-8',
        timeout: 15000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      return parseLinuxSs(output);
    } catch {
      return [];
    }
  }

  // Unsupported platform
  return [];
}

// ─── DNS Resolution ──────────────────────────────────────────────────────────

const DNS_TIMEOUT_MS = 2000;

/** Reverse-resolve an IP to a hostname with a timeout guard */
async function reverseResolve(ip: string): Promise<string | undefined> {
  try {
    const hostnames = await Promise.race([
      dns.promises.reverse(ip),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('dns timeout')), DNS_TIMEOUT_MS),
      ),
    ]);
    return hostnames[0];
  } catch {
    return undefined;
  }
}

/** Resolve hostnames for all unique remote IPs, returning a cache map */
async function resolveHostnames(connections: OutboundConnection[]): Promise<Map<string, string>> {
  const cache = new Map<string, string>();
  const uniqueIps = new Set<string>();

  for (const conn of connections) {
    const ip = extractIp(conn.remote);
    uniqueIps.add(ip);
  }

  // Resolve in parallel with concurrency limit of 10
  const ips = [...uniqueIps];
  const CONCURRENCY = 10;
  for (let i = 0; i < ips.length; i += CONCURRENCY) {
    const batch = ips.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async (ip) => {
        const host = await reverseResolve(ip);
        return { ip, host };
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.host) {
        cache.set(result.value.ip, result.value.host);
      }
    }
  }

  return cache;
}

// ─── Container Mapping ───────────────────────────────────────────────────────

/**
 * Build a map of host PID → container name using `docker ps` and
 * `docker inspect` to read the container's init PID.
 */
export function getContainerMap(): Map<number, string> {
  const containerMap = new Map<number, string>();

  try {
    const output = execFileSync(
      'docker',
      ['ps', '--format', '{{.ID}} {{.Names}}'],
      { encoding: 'utf-8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'] },
    );

    for (const line of output.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const spaceIdx = trimmed.indexOf(' ');
      if (spaceIdx === -1) continue;

      const containerId = trimmed.slice(0, spaceIdx);
      const containerName = trimmed.slice(spaceIdx + 1).trim();

      // Get the container's init PID on the host
      try {
        const inspectOutput = execFileSync(
          'docker',
          ['inspect', '--format', '{{.State.Pid}}', containerId],
          { encoding: 'utf-8', timeout: 5000, stdio: ['pipe', 'pipe', 'pipe'] },
        );
        const pid = parseInt(inspectOutput.trim(), 10);
        if (!isNaN(pid) && pid > 0) {
          containerMap.set(pid, containerName);
        }
      } catch {
        // Inspect failed for this container — skip
      }
    }
  } catch {
    // Docker not available or not running
  }

  return containerMap;
}

/** Look up a PID in the container map, also checking parent PIDs on Linux */
export function mapPidToContainer(pid: number, containerMap: Map<number, string>): string | undefined {
  // Direct match
  const direct = containerMap.get(pid);
  if (direct) return direct;

  // On Linux, walk up the process tree by reading /proc/<pid>/status
  if (os.platform() === 'linux') {
    let currentPid = pid;
    const visited = new Set<number>();

    while (currentPid > 1 && !visited.has(currentPid)) {
      visited.add(currentPid);

      try {
        const status = execFileSync('cat', [`/proc/${currentPid}/status`], {
          encoding: 'utf-8',
          timeout: 1000,
          stdio: ['pipe', 'pipe', 'pipe'],
        });

        const ppidMatch = status.match(/^PPid:\s+(\d+)/m);
        if (!ppidMatch) break;

        currentPid = parseInt(ppidMatch[1], 10);
        const mapped = containerMap.get(currentPid);
        if (mapped) return mapped;
      } catch {
        break;
      }
    }
  }

  return undefined;
}

// ─── Allowlist Matching ──────────────────────────────────────────────────────

/**
 * Check whether a connection's remote host/IP is covered by the allowlist.
 *
 * Supports:
 *  - Exact hostname: "api.anthropic.com"
 *  - Wildcard hostname: "*.openai.com"
 *  - Exact IP: "142.250.80.46"
 *  - CIDR: IPv4 (/8, /16, /24, etc.) and IPv6 (/32, /48, /64, etc.)
 */
export function isAllowlisted(host: string | undefined, ip: string, allowlist: string[]): boolean {
  for (const entry of allowlist) {
    // CIDR notation
    if (entry.includes('/')) {
      if (matchCidr(ip, entry)) return true;
      continue;
    }

    // Wildcard hostname matching: *.example.com
    if (entry.startsWith('*.')) {
      const suffix = entry.slice(1); // ".example.com"
      if (host && (host.endsWith(suffix) || host === entry.slice(2))) return true;
      continue;
    }

    // Exact IP match
    if (entry === ip) return true;

    // Exact hostname match
    if (host && entry === host) return true;
  }

  return false;
}

/**
 * CIDR matching for both IPv4 and IPv6.
 * IPv4: bitwise comparison on 32-bit integers.
 * IPv6: bitwise comparison on 128-bit BigInts.
 */
function matchCidr(ip: string, cidr: string): boolean {
  const [cidrIp, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);

  if (isNaN(prefix) || prefix < 0) return false;

  const isIpv6 = ip.includes(':');
  const isCidrIpv6 = (cidrIp ?? '').includes(':');

  // Don't compare IPv4 against IPv6 or vice versa
  if (isIpv6 !== isCidrIpv6) return false;

  if (isIpv6) {
    return matchCidrV6(ip, cidrIp ?? '', prefix);
  }

  return matchCidrV4(ip, cidrIp ?? '', prefix);
}

/** IPv4 CIDR matching */
function matchCidrV4(ip: string, cidrIp: string, prefix: number): boolean {
  if (prefix > 32) return false;

  const ipParts = ip.split('.').map(Number);
  const cidrParts = cidrIp.split('.').map(Number);

  if (ipParts.length !== 4 || cidrParts.length !== 4) return false;
  if (ipParts.some(isNaN) || cidrParts.some(isNaN)) return false;

  const ipNum = ((ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3]) >>> 0;
  const cidrNum = ((cidrParts[0] << 24) | (cidrParts[1] << 16) | (cidrParts[2] << 8) | cidrParts[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;

  return (ipNum & mask) === (cidrNum & mask);
}

/** Expand an IPv6 address to its full 8-group representation. */
function expandIpv6(ip: string): string[] | null {
  const halves = ip.split('::');
  if (halves.length > 2) return null;

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  const missing = 8 - left.length - right.length;
  if (halves.length === 2 && missing < 0) return null;
  if (halves.length === 1 && left.length !== 8) return null;

  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right];
  if (groups.length !== 8) return null;

  return groups;
}

/** IPv6 CIDR matching using BigInt for 128-bit comparison */
function matchCidrV6(ip: string, cidrIp: string, prefix: number): boolean {
  if (prefix > 128) return false;

  const ipGroups = expandIpv6(ip);
  const cidrGroups = expandIpv6(cidrIp);

  if (!ipGroups || !cidrGroups) return false;

  let ipNum = 0n;
  let cidrNum = 0n;
  for (let i = 0; i < 8; i++) {
    const ipVal = parseInt(ipGroups[i], 16);
    const cidrVal = parseInt(cidrGroups[i], 16);
    if (isNaN(ipVal) || isNaN(cidrVal)) return false;
    ipNum = (ipNum << 16n) | BigInt(ipVal);
    cidrNum = (cidrNum << 16n) | BigInt(cidrVal);
  }

  const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) << BigInt(128 - prefix);

  return (ipNum & mask) === (cidrNum & mask);
}

// ─── Filtering ───────────────────────────────────────────────────────────────

/**
 * Filter connections to only outbound-relevant entries.
 * Removes loopback and private-network connections, but keeps Docker bridge
 * traffic (172.17.0.0/16) as potential lateral movement.
 */
function filterOutbound(connections: OutboundConnection[]): OutboundConnection[] {
  return connections.filter(conn => {
    const remoteIp = extractIp(conn.remote);

    // Always exclude loopback
    if (isLoopback(remoteIp)) return false;

    // Keep Docker bridge (potential lateral movement)
    if (isDockerBridge(remoteIp)) return true;

    // Exclude other private ranges
    if (isPrivateNonDocker(remoteIp)) return false;

    return true;
  });
}

// ─── Finding Generation ──────────────────────────────────────────────────────

function generateFindings(
  violations: EgressViolation[],
  connections: OutboundConnection[],
  config: EgressConfig,
): EgressFinding[] {
  const findings: EgressFinding[] = [];

  // OC-EGRESS-003: No allowlist configured (advisory)
  if (config.allowlist.length === 0) {
    findings.push({
      id: 'OC-EGRESS-003',
      title: 'No egress allowlist configured',
      severity: 'high',
      detail:
        'No egress allowlist has been defined. All outbound connections are unmonitored. ' +
        'Configure an allowlist to detect unauthorized network activity.',
    });
  }

  // OC-EGRESS-001: Per-violation findings
  for (const violation of violations) {
    findings.push({
      id: 'OC-EGRESS-001',
      title: 'Outbound connection to non-allowlisted destination',
      severity: 'critical',
      detail: violation.reason,
      connection: violation.connection,
    });
  }

  // OC-EGRESS-002: Container with unrestricted egress (3+ violations from same container)
  if (config.perContainer) {
    const containerViolationCounts = new Map<string, number>();
    for (const v of violations) {
      const name = v.connection.container;
      if (name) {
        containerViolationCounts.set(name, (containerViolationCounts.get(name) ?? 0) + 1);
      }
    }
    for (const [containerName, count] of containerViolationCounts) {
      if (count >= 3) {
        findings.push({
          id: 'OC-EGRESS-002',
          title: 'Container with unrestricted egress',
          severity: 'critical',
          detail:
            `Container "${containerName}" has ${count} outbound connections to non-allowlisted ` +
            `destinations, indicating unrestricted egress. Apply network policies to limit outbound traffic.`,
        });
      }
    }
  }

  // OC-EGRESS-004: Lateral movement detection (Docker bridge traffic)
  for (const conn of connections) {
    const remoteIp = extractIp(conn.remote);
    if (isDockerBridge(remoteIp)) {
      findings.push({
        id: 'OC-EGRESS-004',
        title: 'Lateral movement detected',
        severity: 'high',
        detail:
          `Connection to Docker bridge network ${conn.remote} detected from ` +
          `${conn.process ?? 'unknown process'} (PID ${conn.pid ?? 'unknown'}). ` +
          `This may indicate container-to-container lateral movement.`,
        connection: conn,
      });
    }
  }

  return findings;
}

// ─── Main Scanner ────────────────────────────────────────────────────────────

export async function scanEgress(config: EgressConfig): Promise<EgressScanResult> {
  const startTime = Date.now();

  // Step 1: Enumerate connections
  const rawConnections = enumerateOutboundConnections();

  // If enumeration returned nothing, check if it's because the tool is missing
  if (rawConnections.length === 0) {
    const platform = os.platform();
    const tool = platform === 'darwin' ? 'lsof' : platform === 'linux' ? 'ss' : 'network tools';
    const canEnumerate = platform === 'darwin' || platform === 'linux';

    const findings: EgressFinding[] = [];

    if (!canEnumerate) {
      findings.push({
        id: 'OC-EGRESS-ERR',
        title: 'Cannot enumerate connections',
        severity: 'medium',
        detail: `Platform "${platform}" is not supported for egress monitoring. Supported: linux, darwin.`,
      });
    }

    // Still generate the no-allowlist finding if applicable
    if (config.allowlist.length === 0) {
      findings.push({
        id: 'OC-EGRESS-003',
        title: 'No egress allowlist configured',
        severity: 'high',
        detail:
          'No egress allowlist has been defined. All outbound connections are unmonitored. ' +
          'Configure an allowlist to detect unauthorized network activity.',
      });
    }

    return {
      timestamp: new Date().toISOString(),
      totalConnections: 0,
      allowedConnections: 0,
      violations: [],
      connections: [],
      findings,
      duration: Date.now() - startTime,
    };
  }

  // Step 2: Filter to outbound-relevant connections
  const outbound = filterOutbound(rawConnections);

  // Step 3: Resolve hostnames
  const hostnameCache = await resolveHostnames(outbound);
  for (const conn of outbound) {
    const ip = extractIp(conn.remote);
    const resolved = hostnameCache.get(ip);
    if (resolved) conn.remoteHost = resolved;
  }

  // Step 4: Map to containers (if requested)
  let containerMap: Map<number, string> | undefined;
  if (config.perContainer) {
    containerMap = getContainerMap();
    for (const conn of outbound) {
      if (conn.pid !== undefined) {
        const name = mapPidToContainer(conn.pid, containerMap);
        if (name) conn.container = name;
      }
    }
  }

  // Step 5: Check against allowlist
  const violations: EgressViolation[] = [];
  let allowedCount = 0;

  for (const conn of outbound) {
    const remoteIp = extractIp(conn.remote);

    // Docker bridge connections are flagged separately as lateral movement,
    // don't double-count as allowlist violations
    if (isDockerBridge(remoteIp)) continue;

    if (config.allowlist.length === 0) {
      // No allowlist = advisory mode, don't generate per-connection violations
      continue;
    }

    if (isAllowlisted(conn.remoteHost, remoteIp, config.allowlist)) {
      allowedCount++;
    } else {
      const dest = conn.remoteHost
        ? `${conn.remoteHost} (${remoteIp})`
        : remoteIp;

      violations.push({
        connection: conn,
        reason: `Destination ${dest} not in allowlist`,
        severity: 'critical',
      });
    }
  }

  // Step 6: Generate findings
  const findings = generateFindings(violations, outbound, config);

  return {
    timestamp: new Date().toISOString(),
    totalConnections: outbound.length,
    allowedConnections: allowedCount,
    violations,
    connections: outbound,
    findings,
    duration: Date.now() - startTime,
  };
}

// Exported for testing
export {
  extractIp,
  isLoopback,
  isDockerBridge,
  isPrivateNonDocker,
  filterOutbound,
  matchCidr,
  reverseResolve,
  resolveHostnames,
  generateFindings,
};
