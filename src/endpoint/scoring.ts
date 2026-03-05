import type {
  EndpointScore,
  EndpointGrade,
  CategoryScore,
  NetworkScanResult,
  ArtifactScanResult,
  CrossReferenceFinding,
} from '../types/endpoint.js';
import type { MCPFindingSeverity } from '../types/mcp-scan.js';
import type { MCPScanResult } from '../types/mcp-scan.js';

// ─── Deduction Weights ───────────────────────────────────────────────────────

const SEVERITY_DEDUCTIONS: Record<MCPFindingSeverity, number> = {
  critical: 15,
  high: 10,
  medium: 5,
  low: 2,
};

// ─── Category Weights ────────────────────────────────────────────────────────

const CATEGORY_MAX = {
  configuration: 30,
  credentials: 30,
  network: 25,
  discovery: 15,
} as const;

// ─── Score Computation ───────────────────────────────────────────────────────

export interface ScoreInput {
  mcp: MCPScanResult;
  network: NetworkScanResult;
  artifacts: ArtifactScanResult;
  crossReference: CrossReferenceFinding[];
  daemonRunning: boolean;
  toolCount: number;
}

export function computeEndpointScore(input: ScoreInput): EndpointScore {
  const configuration = computeConfigurationScore(input.mcp, input.crossReference);
  const credentials = computeCredentialsScore(input.artifacts);
  const network = computeNetworkScore(input.network);
  const discovery = computeDiscoveryScore(input.daemonRunning, input.toolCount);

  const total = configuration.score + credentials.score + network.score + discovery.score;
  const grade = computeGrade(total);

  return {
    total,
    grade,
    categories: {
      configuration,
      credentials,
      network,
      discovery,
    },
  };
}

// ─── Configuration Score (30 max) ────────────────────────────────────────────

function computeConfigurationScore(
  mcp: MCPScanResult,
  crossRef: CrossReferenceFinding[],
): CategoryScore {
  const max = CATEGORY_MAX.configuration;
  const deductions: CategoryScore['deductions'] = [];

  // MCP findings
  for (const finding of mcp.findings) {
    deductions.push({
      finding: finding.title,
      severity: finding.severity,
      points: SEVERITY_DEDUCTIONS[finding.severity],
    });
  }

  // Cross-reference findings
  for (const finding of crossRef) {
    deductions.push({
      finding: finding.title,
      severity: finding.severity,
      points: SEVERITY_DEDUCTIONS[finding.severity],
    });
  }

  const totalDeduction = deductions.reduce((sum, d) => sum + d.points, 0);
  const score = Math.max(0, max - totalDeduction);

  return { score, max, deductions };
}

// ─── Credentials Score (30 max) ──────────────────────────────────────────────

function computeCredentialsScore(artifacts: ArtifactScanResult): CategoryScore {
  const max = CATEGORY_MAX.credentials;
  const deductions: CategoryScore['deductions'] = [];

  for (const cred of artifacts.credentials) {
    deductions.push({
      finding: `${cred.keyType} key in ${shortenPath(cred.location)}`,
      severity: cred.severity,
      points: SEVERITY_DEDUCTIONS[cred.severity],
    });
  }

  // Data store findings
  for (const finding of artifacts.findings) {
    if (finding.type === 'data-store-exposure') {
      deductions.push({
        finding: finding.title,
        severity: finding.severity,
        points: SEVERITY_DEDUCTIONS[finding.severity],
      });
    }
  }

  const totalDeduction = deductions.reduce((sum, d) => sum + d.points, 0);
  const score = Math.max(0, max - totalDeduction);

  return { score, max, deductions };
}

// ─── Network Score (25 max) ──────────────────────────────────────────────────

function computeNetworkScore(network: NetworkScanResult): CategoryScore {
  const max = CATEGORY_MAX.network;
  const deductions: CategoryScore['deductions'] = [];

  for (const finding of network.findings) {
    deductions.push({
      finding: finding.title,
      severity: finding.severity,
      points: SEVERITY_DEDUCTIONS[finding.severity],
    });
  }

  const totalDeduction = deductions.reduce((sum, d) => sum + d.points, 0);
  const score = Math.max(0, max - totalDeduction);

  return { score, max, deductions };
}

// ─── Discovery Score (15 max) ────────────────────────────────────────────────

function computeDiscoveryScore(daemonRunning: boolean, toolCount: number): CategoryScore {
  const max = CATEGORY_MAX.discovery;
  const deductions: CategoryScore['deductions'] = [];

  // Daemon not running: -5
  if (!daemonRunning) {
    deductions.push({
      finding: 'g0 daemon is not running — no continuous monitoring',
      severity: 'medium',
      points: 5,
    });
  }

  // No tools detected: -5 (something is wrong or g0 isn't configured)
  if (toolCount === 0) {
    deductions.push({
      finding: 'No AI developer tools detected — scan may be incomplete',
      severity: 'low',
      points: 2,
    });
  }

  const totalDeduction = deductions.reduce((sum, d) => sum + d.points, 0);
  const score = Math.max(0, max - totalDeduction);

  return { score, max, deductions };
}

// ─── Grade Computation ───────────────────────────────────────────────────────

function computeGrade(total: number): EndpointGrade {
  if (total >= 90) return 'A';
  if (total >= 75) return 'B';
  if (total >= 60) return 'C';
  if (total >= 40) return 'D';
  return 'F';
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function shortenPath(p: string): string {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  if (home && p.startsWith(home)) return '~' + p.slice(home.length);
  return p;
}

export { computeGrade, SEVERITY_DEDUCTIONS, CATEGORY_MAX };
