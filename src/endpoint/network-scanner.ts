import { execFileSync } from 'node:child_process';
import * as os from 'node:os';
import * as http from 'node:http';
import * as https from 'node:https';
import { KNOWN_PORTS, PROBES, AI_PROCESS_PATTERNS, AUTH_PROBE_PATHS } from './fingerprints.js';
import type {
  ListeningService,
  NetworkFinding,
  NetworkScanResult,
  AIServiceType,
} from '../types/endpoint.js';
import type { MCPScanResult } from '../types/mcp-scan.js';

// ─── Port Enumeration ────────────────────────────────────────────────────────

interface RawPort {
  port: number;
  pid: number;
  process: string;
  bindAddress: string;
}

/**
 * Enumerate all listening TCP ports on the machine.
 */
export function enumerateListeningPorts(): RawPort[] {
  const platform = os.platform();

  if (platform === 'darwin') return parseLsof();
  if (platform === 'linux') return parseSs();

  // Windows: best-effort with netstat
  return parseNetstat();
}

function parseLsof(): RawPort[] {
  let output: string;
  try {
    output = execFileSync('lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n', '-F', 'pcn'], {
      encoding: 'utf-8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    return [];
  }

  const ports: RawPort[] = [];
  let currentPid = 0;
  let currentProcess = '';

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
        // Format: "127.0.0.1:3001" or "*:8080" or "[::1]:3001"
        const match = value.match(/^(\*|[\d.]+|\[.*?\]):(\d+)$/);
        if (match) {
          const bindAddress = match[1] === '*' ? '0.0.0.0' : match[1].replace(/^\[|\]$/g, '');
          const port = parseInt(match[2], 10);
          // Deduplicate — lsof can report the same port multiple times
          if (!ports.some(p => p.port === port && p.pid === currentPid)) {
            ports.push({ port, pid: currentPid, process: currentProcess, bindAddress });
          }
        }
        break;
      }
    }
  }

  return ports;
}

function parseSs(): RawPort[] {
  let output: string;
  try {
    output = execFileSync('ss', ['-tlnp'], {
      encoding: 'utf-8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    return [];
  }

  const ports: RawPort[] = [];

  for (const line of output.split('\n').slice(1)) {
    // Format: LISTEN 0 128 127.0.0.1:3001 0.0.0.0:* users:(("node",pid=1234,fd=3))
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;

    const localAddr = parts[3];
    const match = localAddr.match(/^([\d.*]+|\[.*?\]|::):(\d+)$/);
    if (!match) continue;

    let bindAddress = match[1];
    if (bindAddress === '*' || bindAddress === '::' || bindAddress === '0.0.0.0') {
      bindAddress = '0.0.0.0';
    }
    const port = parseInt(match[2], 10);

    // Extract PID from users field
    let pid = 0;
    let processName = '';
    const usersMatch = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
    if (usersMatch) {
      processName = usersMatch[1];
      pid = parseInt(usersMatch[2], 10);
    }

    if (!ports.some(p => p.port === port)) {
      ports.push({ port, pid, process: processName, bindAddress });
    }
  }

  return ports;
}

function parseNetstat(): RawPort[] {
  // Try PowerShell first for full PID + process resolution
  const psResult = parsePowerShell();
  if (psResult.length > 0) return psResult;

  // Fallback to basic netstat
  let output: string;
  try {
    output = execFileSync('netstat', ['-an', '-p', 'tcp'], {
      encoding: 'utf-8',
      timeout: 10000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    return [];
  }

  const ports: RawPort[] = [];

  for (const line of output.split('\n')) {
    if (!line.includes('LISTEN')) continue;
    const match = line.match(/([\d.]+):(\d+)\s+/);
    if (match) {
      const port = parseInt(match[2], 10);
      const bindAddress = match[1] === '0.0.0.0' ? '0.0.0.0' : match[1];
      if (!ports.some(p => p.port === port)) {
        ports.push({ port, pid: 0, process: '', bindAddress });
      }
    }
  }

  return ports;
}

function parsePowerShell(): RawPort[] {
  // Use Get-NetTCPConnection for full PID + process name resolution on Windows
  const psScript = `
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  "$($_.LocalAddress)|$($_.LocalPort)|$($_.OwningProcess)|$($proc.ProcessName)"
}`.trim();

  let output: string;
  try {
    output = execFileSync('powershell', [
      '-NoProfile', '-NonInteractive', '-Command', psScript,
    ], {
      encoding: 'utf-8',
      timeout: 15000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    return [];
  }

  const ports: RawPort[] = [];

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split('|');
    if (parts.length < 4) continue;

    let bindAddress = parts[0];
    if (bindAddress === '::' || bindAddress === '0.0.0.0') bindAddress = '0.0.0.0';
    if (bindAddress === '::1') bindAddress = '127.0.0.1';

    const port = parseInt(parts[1], 10);
    const pid = parseInt(parts[2], 10);
    const processName = parts[3] || '';

    if (isNaN(port)) continue;

    if (!ports.some(p => p.port === port && p.pid === pid)) {
      ports.push({ port, pid, process: processName, bindAddress });
    }
  }

  return ports;
}

// ─── Port Filtering ──────────────────────────────────────────────────────────

/** Filter ports likely to be AI-related before expensive HTTP probing */
function isAICandidate(raw: RawPort): boolean {
  // Always probe known AI ports
  if (KNOWN_PORTS.some(k => k.port === raw.port)) return true;

  // Check process name against AI patterns
  const procLower = raw.process.toLowerCase();
  if (AI_PROCESS_PATTERNS.some(p => procLower.includes(p))) return true;

  // Probe common development ports (3000-9999) as they may host MCP servers
  if (raw.port >= 3000 && raw.port <= 9999) return true;

  return false;
}

// ─── HTTP Probing ────────────────────────────────────────────────────────────

interface ProbeResult {
  type: AIServiceType;
  authenticated: boolean | null;
  tlsEnabled: boolean;
  corsWildcard: boolean | null;
}

async function probePort(port: number, bindAddress: string): Promise<ProbeResult | null> {
  const host = bindAddress === '0.0.0.0' ? '127.0.0.1' : bindAddress;

  // Try TLS first, fall back to plain HTTP
  const useTls = false;
  let serviceType: AIServiceType | null = null;

  // First check if it's a known port
  const known = KNOWN_PORTS.find(k => k.port === port);

  // Run fingerprint probes
  for (const probe of PROBES) {
    try {
      const result = await httpRequest({
        host,
        port,
        path: probe.path,
        method: probe.method,
        body: probe.body,
        headers: {
          ...(probe.accept ? { 'Accept': probe.accept } : {}),
          ...(probe.contentType ? { 'Content-Type': probe.contentType } : {}),
        },
        timeout: 2000,
        useTls: false,
      });

      serviceType = probe.match(result.status, result.headers, result.body);
      if (serviceType) break;
    } catch {
      // Probe failed, try next
    }
  }

  // If no probe matched but it's a known port, use the known type
  if (!serviceType && known) {
    serviceType = known.type;
  }

  if (!serviceType) return null;

  // Check authentication
  const authenticated = await checkAuth(host, port, useTls);

  // Check CORS
  const corsWildcard = await checkCors(host, port, useTls);

  return {
    type: serviceType,
    authenticated,
    tlsEnabled: useTls,
    corsWildcard,
  };
}

async function checkAuth(host: string, port: number, useTls: boolean): Promise<boolean | null> {
  for (const path of AUTH_PROBE_PATHS) {
    try {
      const result = await httpRequest({
        host, port, path, method: 'GET',
        headers: {}, timeout: 2000, useTls,
      });

      if (result.status === 401 || result.status === 403) return true;
      if (result.status === 200) return false;
    } catch {
      continue;
    }
  }
  return null;
}

async function checkCors(host: string, port: number, useTls: boolean): Promise<boolean | null> {
  try {
    const result = await httpRequest({
      host, port, path: '/', method: 'GET',
      headers: { 'Origin': 'https://evil.com' },
      timeout: 2000, useTls,
    });

    const acao = result.headers['access-control-allow-origin'] || '';
    if (acao === '*') return true;
    if (acao) return false;
    return null;
  } catch {
    return null;
  }
}

// ─── HTTP Request Helper ─────────────────────────────────────────────────────

interface HttpRequestOptions {
  host: string;
  port: number;
  path: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  timeout: number;
  useTls: boolean;
}

interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

// Only relax TLS verification for localhost hosts that commonly use
// self-signed certificates. Remote hosts always use full verification.
function isLocalhostHost(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === 'localhost' || lower === '127.0.0.1' || lower === '::1';
}

function httpRequest(opts: HttpRequestOptions): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const requestOpts: http.RequestOptions = {
      hostname: opts.host,
      port: opts.port,
      path: opts.path,
      method: opts.method,
      headers: opts.headers,
      timeout: opts.timeout,
    };

    const lib = opts.useTls ? https : http;
    const req = lib.request(requestOpts, (res) => {
      let body = '';
      res.setEncoding('utf-8');
      // Limit response size to 64KB
      let received = 0;
      res.on('data', (chunk: string) => {
        received += chunk.length;
        if (received < 65536) body += chunk;
      });
      res.on('end', () => {
        const headers: Record<string, string> = {};
        for (const [key, val] of Object.entries(res.headers)) {
          if (typeof val === 'string') headers[key.toLowerCase()] = val;
          else if (Array.isArray(val)) headers[key.toLowerCase()] = val[0];
        }
        resolve({ status: res.statusCode ?? 0, headers, body });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('timeout'));
    });

    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ─── Cross-Reference with MCP Config ─────────────────────────────────────────

function isDeclaredInConfig(port: number, mcpResult: MCPScanResult): boolean {
  // Check if any MCP server config references this port
  for (const server of mcpResult.servers) {
    // Check server args for port references
    const argsStr = server.args.join(' ');
    if (argsStr.includes(`:${port}`) || argsStr.includes(`port ${port}`) || argsStr.includes(`--port=${port}`)) {
      return true;
    }
    // Check env vars for port references
    for (const val of Object.values(server.env)) {
      if (val.includes(`:${port}`) || val === String(port)) return true;
    }
    // Check command itself
    if (server.command.includes(`:${port}`)) return true;
  }
  return false;
}

// ─── Main Scanner ────────────────────────────────────────────────────────────

export async function scanNetwork(mcpResult: MCPScanResult): Promise<NetworkScanResult> {
  const rawPorts = enumerateListeningPorts();
  const candidates = rawPorts.filter(isAICandidate);

  const services: ListeningService[] = [];
  const findings: NetworkFinding[] = [];

  // Probe candidates in parallel with concurrency limit
  const CONCURRENCY = 10;
  for (let i = 0; i < candidates.length; i += CONCURRENCY) {
    const batch = candidates.slice(i, i + CONCURRENCY);
    const results = await Promise.allSettled(
      batch.map(async (raw) => {
        const probe = await probePort(raw.port, raw.bindAddress);
        return { raw, probe };
      }),
    );

    for (const result of results) {
      if (result.status !== 'fulfilled' || !result.value.probe) continue;

      const { raw, probe } = result.value;

      // Deduplicate by port (lsof can report same port for IPv4 and IPv6)
      if (services.some(s => s.port === raw.port)) continue;

      const declared = isDeclaredInConfig(raw.port, mcpResult);

      services.push({
        port: raw.port,
        pid: raw.pid,
        process: raw.process,
        bindAddress: raw.bindAddress,
        type: probe.type,
        authenticated: probe.authenticated,
        declaredInConfig: declared,
        tlsEnabled: probe.tlsEnabled,
        corsWildcard: probe.corsWildcard,
      });
    }
  }

  // Generate findings
  for (const svc of services) {
    const label = serviceLabel(svc.type);

    // Shadow service — not in any config
    if (!svc.declaredInConfig) {
      findings.push({
        severity: svc.bindAddress === '0.0.0.0' || svc.authenticated === false ? 'critical' : 'high',
        type: 'shadow-service',
        title: `Shadow ${label} on port ${svc.port}`,
        description: `${label} running on :${svc.port} is not declared in any MCP client config. Process: ${svc.process} (PID ${svc.pid}).`,
        port: svc.port,
        service: svc.type,
      });
    }

    // No authentication
    if (svc.authenticated === false) {
      findings.push({
        severity: svc.bindAddress === '0.0.0.0' ? 'critical' : 'high',
        type: 'no-auth',
        title: `${label} on :${svc.port} requires no authentication`,
        description: `Anyone ${svc.bindAddress === '0.0.0.0' ? 'on the network' : 'on localhost'} can access this ${label} without credentials.`,
        port: svc.port,
        service: svc.type,
      });
    }

    // Bound to 0.0.0.0 — accessible from network
    if (svc.bindAddress === '0.0.0.0') {
      findings.push({
        severity: 'high',
        type: 'network-exposed',
        title: `${label} on :${svc.port} is bound to 0.0.0.0`,
        description: `This service is accessible from the network, not just localhost. Consider binding to 127.0.0.1.`,
        port: svc.port,
        service: svc.type,
      });
    }

    // CORS wildcard
    if (svc.corsWildcard === true) {
      findings.push({
        severity: 'medium',
        type: 'cors-wildcard',
        title: `${label} on :${svc.port} allows any origin (CORS *)`,
        description: `Access-Control-Allow-Origin: * means any website can make requests to this service from a browser.`,
        port: svc.port,
        service: svc.type,
      });
    }

    // No TLS on network-exposed service
    if (svc.bindAddress === '0.0.0.0' && !svc.tlsEnabled) {
      findings.push({
        severity: 'medium',
        type: 'no-tls',
        title: `${label} on :${svc.port} has no TLS on network-accessible port`,
        description: `Unencrypted traffic on a network-accessible port can be intercepted.`,
        port: svc.port,
        service: svc.type,
      });
    }
  }

  const aiServices = services.filter(s => s.type !== 'non-http' && s.type !== 'unknown-http');

  return {
    services,
    findings,
    summary: {
      totalListening: rawPorts.length,
      aiServices: aiServices.length,
      shadowServices: aiServices.filter(s => !s.declaredInConfig).length,
      unauthenticated: aiServices.filter(s => s.authenticated === false).length,
      exposedToNetwork: aiServices.filter(s => s.bindAddress === '0.0.0.0').length,
    },
  };
}

function serviceLabel(type: AIServiceType): string {
  switch (type) {
    case 'mcp-sse': return 'MCP SSE server';
    case 'mcp-streamable': return 'MCP Streamable HTTP server';
    case 'openai-compatible': return 'OpenAI-compatible endpoint';
    case 'a2a': return 'A2A agent';
    case 'ollama': return 'Ollama';
    case 'lm-studio': return 'LM Studio';
    case 'vllm': return 'vLLM';
    case 'llama-cpp': return 'llama.cpp server';
    case 'jan': return 'Jan';
    case 'unknown-http': return 'HTTP service';
    case 'non-http': return 'Service';
    default: return type;
  }
}

// Exported for testing
export { parseLsof, parseSs, isAICandidate, probePort, isDeclaredInConfig, serviceLabel };
