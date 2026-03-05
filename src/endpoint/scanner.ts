import * as os from 'node:os';
import * as fs from 'node:fs';
import { getAllClientDefs } from '../mcp/well-known-paths.js';
import { scanAllMCPConfigs } from '../mcp/analyzer.js';
import { getMachineId } from '../platform/machine-id.js';
import { detectRunningTools } from './process-detector.js';
import { scanNetwork } from './network-scanner.js';
import { scanArtifacts } from './artifact-scanner.js';
import { computeEndpointScore } from './scoring.js';
import type {
  AITool,
  EndpointScanResult,
  EndpointScanOptions,
  NetworkScanResult,
  ArtifactScanResult,
  CrossReferenceFinding,
  ForensicsScanResult,
  BrowserScanResult,
  RemediationResult,
} from '../types/endpoint.js';
import type { MCPScanResult } from '../types/mcp-scan.js';

// ─── Empty Results (for when layers are skipped) ─────────────────────────────

const EMPTY_NETWORK: NetworkScanResult = {
  services: [],
  findings: [],
  summary: { totalListening: 0, aiServices: 0, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 },
};

const EMPTY_ARTIFACTS: ArtifactScanResult = {
  credentials: [],
  dataStores: [],
  findings: [],
  summary: { totalCredentials: 0, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
};

const EMPTY_MCP: MCPScanResult = {
  clients: [],
  servers: [],
  tools: [],
  findings: [],
  summary: {
    totalClients: 0,
    totalServers: 0,
    totalTools: 0,
    totalFindings: 0,
    findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
    overallStatus: 'ok' as const,
  },
};

// ─── Cross-Reference Engine ──────────────────────────────────────────────────

function buildCrossReference(
  mcp: MCPScanResult,
  network: NetworkScanResult,
  tools: AITool[],
): CrossReferenceFinding[] {
  const findings: CrossReferenceFinding[] = [];

  // Find network services that are AI-related but not declared in any config
  for (const svc of network.services) {
    if (svc.type === 'non-http' || svc.type === 'unknown-http') continue;

    if (!svc.declaredInConfig) {
      // Shadow service — already captured in network findings, but add a
      // cross-reference finding with richer context
      const matchedTool = tools.find(t => t.running && t.name.toLowerCase().includes(svc.process.toLowerCase()));
      findings.push({
        severity: svc.bindAddress === '0.0.0.0' || svc.authenticated === false ? 'critical' : 'high',
        type: 'shadow-service',
        title: `Undeclared ${svc.type} on :${svc.port}`,
        description: matchedTool
          ? `${svc.type} on :${svc.port} appears related to ${matchedTool.name} but is not in its MCP config.`
          : `${svc.type} on :${svc.port} (process: ${svc.process}) is not tracked by any MCP client.`,
        status: 'shadow-service',
        port: svc.port,
        service: svc.type,
      });
    }
  }

  // Find configured servers that reference ports but nothing is listening
  for (const server of mcp.servers) {
    const argsStr = [server.command, ...server.args].join(' ');
    const portMatch = argsStr.match(/(?::|\bport[= ]+)(\d{4,5})\b/);
    if (portMatch) {
      const configPort = parseInt(portMatch[1], 10);
      const listening = network.services.some(s => s.port === configPort);
      if (!listening) {
        findings.push({
          severity: 'low',
          type: 'config-mismatch',
          title: `Configured server "${server.name}" port ${configPort} is not listening`,
          description: `MCP server "${server.name}" (${server.client}) references port ${configPort} but nothing is listening there.`,
          status: 'orphaned-config',
          port: configPort,
          configRef: server.configFile,
        });
      }
    }
  }

  return findings;
}

// ─── Daemon Detection ────────────────────────────────────────────────────────

function isDaemonRunning(): boolean {
  try {
    const pidPath = `${os.homedir()}/.g0/daemon.pid`;
    const pidStr = fs.readFileSync(pidPath, 'utf-8').trim();
    const pid = parseInt(pidStr, 10);
    if (isNaN(pid)) return false;
    // Check if process exists (signal 0 doesn't kill, just checks)
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// ─── Main Orchestrator ───────────────────────────────────────────────────────

export async function scanEndpoint(
  options: EndpointScanOptions = {},
): Promise<EndpointScanResult> {
  const startTime = Date.now();
  const platform = os.platform() as 'darwin' | 'linux' | 'win32';
  const runNetwork = options.network !== false;
  const runArtifacts = options.artifacts !== false;
  const runForensics = options.forensics === true;
  const runBrowser = options.browser === true;
  const runFix = options.fix === true;

  const layersRun: EndpointScanResult['layersRun'] = ['config', 'process', 'mcp'];
  if (runNetwork) layersRun.push('network');
  if (runArtifacts) layersRun.push('artifacts');
  if (runForensics) layersRun.push('forensics');
  if (runBrowser) layersRun.push('browser');

  // ── Layer 1: Config-based tool discovery ──
  const allDefs = getAllClientDefs();
  const runningTools = detectRunningTools();

  // ── Layer 2: MCP security scan ──
  let mcp: MCPScanResult;
  try {
    mcp = scanAllMCPConfigs();
  } catch {
    mcp = EMPTY_MCP;
  }

  // ── Build tools list ──
  const tools: AITool[] = [];
  for (const def of allDefs) {
    const configPath = def.paths[platform];
    if (!configPath) continue;

    const installed = fs.existsSync(configPath);
    const running = runningTools.has(def.name);
    const servers = mcp.servers.filter(s => s.client === def.name);

    tools.push({
      name: def.name,
      configPath,
      installed,
      running,
      mcpServerCount: servers.length,
      servers,
    });
  }

  // ── Layer 3 & 4: Network + Artifacts (run in parallel) ──
  const [network, artifacts] = await Promise.all([
    runNetwork ? scanNetwork(mcp) : Promise.resolve(EMPTY_NETWORK),
    runArtifacts ? Promise.resolve(scanArtifacts(mcp)) : Promise.resolve(EMPTY_ARTIFACTS),
  ]);

  // ── Layer 5: Forensics (opt-in) ──
  let forensics: ForensicsScanResult | undefined;
  if (runForensics) {
    try {
      const { scanForensics } = await import('./forensics-scanner.js');
      forensics = scanForensics();
    } catch { /* skip */ }
  }

  // ── Layer 6: Browser history (opt-in) ──
  let browser: BrowserScanResult | undefined;
  if (runBrowser) {
    try {
      const { scanBrowserHistory } = await import('./browser-scanner.js');
      browser = scanBrowserHistory();
    } catch { /* skip */ }
  }

  // ── Cross-Reference Engine ──
  const crossReference = runNetwork
    ? buildCrossReference(mcp, network, tools)
    : [];

  // ── Score Computation ──
  const detectedTools = tools.filter(t => t.installed || t.running);
  const daemonRunning = isDaemonRunning();

  const score = computeEndpointScore({
    mcp,
    network,
    artifacts,
    crossReference,
    daemonRunning,
    toolCount: detectedTools.length,
  });

  // ── Build Summary ──
  const allFindings = [
    ...mcp.findings,
    ...network.findings,
    ...artifacts.findings,
    ...crossReference,
  ];

  const findingsBySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of allFindings) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
  }

  let overallStatus: 'ok' | 'warn' | 'critical' = 'ok';
  if (findingsBySeverity.critical > 0) overallStatus = 'critical';
  else if (findingsBySeverity.high > 0 || findingsBySeverity.medium > 0) overallStatus = 'warn';

  // ── Remediation (opt-in, runs after scoring) ──
  let remediation: RemediationResult | undefined;

  const duration = Date.now() - startTime;

  // Build the result first (remediation needs it)
  const scanResult: EndpointScanResult = {
    machineId: getMachineId(),
    hostname: os.hostname(),
    timestamp: new Date().toISOString(),
    tools,
    mcp,
    network,
    artifacts,
    crossReference,
    score,
    forensics,
    browser,
    remediation,
    summary: {
      totalTools: detectedTools.length,
      runningTools: tools.filter(t => t.running).length,
      totalServers: mcp.summary.totalServers,
      totalFindings: allFindings.length,
      findingsBySeverity,
      networkServices: network.summary.aiServices,
      shadowServices: network.summary.shadowServices,
      credentialExposures: artifacts.summary.totalCredentials,
      dataStores: artifacts.summary.totalDataStores,
      overallStatus,
    },
    duration,
    layersRun,
  };

  // Run remediation after building the result (it needs the full scan data)
  if (runFix) {
    try {
      const { runRemediation } = await import('./remediation.js');
      scanResult.remediation = runRemediation(scanResult);
    } catch { /* skip */ }
  }

  return scanResult;
}
