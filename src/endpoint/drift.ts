import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { EndpointScanResult, DriftEvent, DriftResult } from '../types/endpoint.js';

const G0_DIR = path.join(os.homedir(), '.g0');
const LAST_SCAN_PATH = path.join(G0_DIR, 'last-endpoint-scan.json');

// ─── Persistence ─────────────────────────────────────────────────────────────

export function saveLastScan(result: EndpointScanResult): void {
  try {
    fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(LAST_SCAN_PATH, JSON.stringify(result, null, 2), { mode: 0o600 });
  } catch {
    // Non-fatal
  }
}

export function loadLastScan(): EndpointScanResult | null {
  try {
    const raw = fs.readFileSync(LAST_SCAN_PATH, 'utf-8');
    return JSON.parse(raw) as EndpointScanResult;
  } catch {
    return null;
  }
}

// ─── Drift Detection ─────────────────────────────────────────────────────────

export function detectDrift(
  previous: EndpointScanResult,
  current: EndpointScanResult,
): DriftResult {
  const events: DriftEvent[] = [];
  const now = new Date().toISOString();

  // 1. New shadow services
  const prevShadowPorts = new Set(
    previous.network.services.filter(s => !s.declaredInConfig).map(s => s.port),
  );
  for (const svc of current.network.services) {
    if (!svc.declaredInConfig && !prevShadowPorts.has(svc.port)) {
      events.push({
        type: 'new-shadow-service',
        severity: svc.bindAddress === '0.0.0.0' ? 'critical' : 'high',
        title: `New shadow service on :${svc.port}`,
        description: `${svc.type} appeared on port ${svc.port} (process: ${svc.process}).`,
        timestamp: now,
      });
    }
  }

  // 2. New credential exposures
  const prevCredKeys = new Set(
    previous.artifacts.credentials.map(c => `${c.location}:${c.keyType}`),
  );
  for (const cred of current.artifacts.credentials) {
    const key = `${cred.location}:${cred.keyType}`;
    if (!prevCredKeys.has(key)) {
      events.push({
        type: 'new-credential-exposure',
        severity: cred.severity,
        title: `New ${cred.keyType} key exposure`,
        description: `${cred.keyType} key found in ${cred.location}.`,
        timestamp: now,
      });
    }
  }

  // 3. Score drop
  const scoreDelta = current.score.total - previous.score.total;
  if (scoreDelta <= -10) {
    events.push({
      type: 'score-drop',
      severity: scoreDelta <= -20 ? 'high' : 'medium',
      title: `Endpoint score dropped ${Math.abs(scoreDelta)} points`,
      description: `Score went from ${previous.score.total} to ${current.score.total} (${previous.score.grade} → ${current.score.grade}).`,
      timestamp: now,
    });
  }

  // 4. New tool installed
  const prevToolNames = new Set(
    previous.tools.filter(t => t.installed || t.running).map(t => t.name),
  );
  for (const tool of current.tools) {
    if ((tool.installed || tool.running) && !prevToolNames.has(tool.name)) {
      events.push({
        type: 'new-tool-installed',
        severity: 'low',
        title: `New AI tool detected: ${tool.name}`,
        description: `${tool.name} was ${tool.running ? 'started' : 'installed'} since last scan.`,
        timestamp: now,
      });
    }
  }

  // 5. Findings resolved (positive events)
  const currentFindingKeys = new Set([
    ...current.network.findings.map(f => `net:${f.type}:${f.port}`),
    ...current.artifacts.findings.map(f => `art:${f.type}:${f.location}`),
  ]);

  for (const f of previous.network.findings) {
    const key = `net:${f.type}:${f.port}`;
    if (!currentFindingKeys.has(key)) {
      events.push({
        type: 'finding-resolved',
        severity: 'low',
        title: `Resolved: ${f.title}`,
        description: `Previously flagged issue is no longer detected.`,
        timestamp: now,
      });
    }
  }

  // 6. Service secured (had no auth, now has auth)
  const prevUnauthPorts = new Set(
    previous.network.services.filter(s => s.authenticated === false).map(s => s.port),
  );
  for (const svc of current.network.services) {
    if (svc.authenticated === true && prevUnauthPorts.has(svc.port)) {
      events.push({
        type: 'service-secured',
        severity: 'low',
        title: `Service on :${svc.port} now requires authentication`,
        description: `Previously unauthenticated ${svc.type} is now secured.`,
        timestamp: now,
      });
    }
  }

  return {
    events,
    scoreDelta,
    previousScore: previous.score.total,
    currentScore: current.score.total,
  };
}
