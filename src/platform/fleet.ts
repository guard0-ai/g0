/**
 * Local-first fleet control plane.
 *
 * A "fleet" is the set of assets (repos and machines) an org tracks with g0.
 * Point scanners answer "is this one target safe?"; the fleet store answers
 * "what does our whole agent estate look like, who owns it, and how is it
 * changing?" — by accumulating timestamped snapshots on disk and rolling them
 * up. It is local-first (no backend required) and structured so it can later
 * sync to the Guard0 platform.
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import type { GitMeta } from './types.js';
import { getMachineId } from './machine-id.js';
import type { Finding } from '../types/finding.js';
import type { ScanScore } from '../types/score.js';
import type { InventoryResult } from '../types/inventory.js';
import { fingerprintFinding } from '../ci/baseline.js';

export const FLEET_SNAPSHOT_SCHEMA = 'g0-fleet-snapshot/1';

const DEFAULT_FLEET_DIR = path.join(os.homedir(), '.g0', 'fleet');

export function fleetDir(override?: string): string {
  return override ?? process.env.G0_FLEET_DIR ?? DEFAULT_FLEET_DIR;
}

export interface FleetSnapshot {
  schema: string;
  assetId: string;
  kind: 'repo' | 'machine';
  name: string;
  owner?: string;
  path: string;
  git?: GitMeta;
  machine: { machineId: string; hostname: string; platform: string };
  timestamp: string;
  score: number;
  grade: string;
  capReason?: string;
  findings: { total: number; bySeverity: Record<string, number>; fingerprints: string[] };
  inventory: {
    agents: number; tools: number; models: number; mcpServers: number; vectorDBs: number;
    frameworks: string[];
  };
  ecosystems: string[];
}

/** Collect git metadata for a repo path (best-effort; undefined if not a repo). */
export function collectGitMeta(repoPath: string): GitMeta | undefined {
  const git = (args: string[]): string | undefined => {
    try {
      return execFileSync('git', ['-C', repoPath, ...args], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return undefined;
    }
  };
  const remote = git(['config', '--get', 'remote.origin.url']);
  const branch = git(['rev-parse', '--abbrev-ref', 'HEAD']);
  const commit = git(['rev-parse', 'HEAD']);
  if (remote === undefined && commit === undefined) return undefined;
  const status = git(['status', '--porcelain']);
  return { remote, branch, commit, dirty: status !== undefined && status.length > 0 };
}

/** Absolute path of the git repo root containing `repoPath`, or undefined. */
export function gitToplevel(repoPath: string): string | undefined {
  try {
    return execFileSync('git', ['-C', repoPath, 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return undefined;
  }
}

/**
 * The stable identity string for a scanned target: the git remote plus the
 * sub-path from the repo root, so two agent projects inside one monorepo are
 * distinct assets rather than collapsing onto the same remote. Falls back to the
 * absolute path when the target is not in a git repo.
 */
export function assetIdentity(targetPath: string, remote?: string): string {
  const resolved = path.resolve(targetPath);
  if (remote) {
    const top = gitToplevel(targetPath);
    const sub = top ? path.relative(top, resolved) : '';
    return sub ? `${remote}#${sub}` : remote;
  }
  return resolved;
}

/**
 * Stable asset id: derived from the git remote when available (so the same repo
 * checked out on two machines is one asset), otherwise from the absolute path.
 */
export function computeAssetId(kind: 'repo' | 'machine', identity: string): string {
  const normalized = identity
    .replace(/\.git$/, '')
    .replace(/^git@([^:]+):/, 'https://$1/')
    .toLowerCase();
  const hash = crypto.createHash('sha256').update(`${kind}:${normalized}`).digest('hex').slice(0, 12);
  const slug = normalized.replace(/^https?:\/\//, '').replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 40);
  return `${slug || kind}-${hash}`;
}

function assetDir(dir: string, assetId: string): string {
  return path.join(dir, 'assets', assetId);
}

/** Persist a snapshot; returns the file path written. */
export function writeSnapshot(snapshot: FleetSnapshot, dir = fleetDir()): string {
  const aDir = assetDir(dir, snapshot.assetId);
  fs.mkdirSync(aDir, { recursive: true });
  const safeTs = snapshot.timestamp.replace(/[:.]/g, '-');
  const file = path.join(aDir, `${safeTs}.json`);
  fs.writeFileSync(file, JSON.stringify(snapshot, null, 2) + '\n', 'utf-8');
  return file;
}

/** List all asset ids currently in the fleet store. */
export function listAssetIds(dir = fleetDir()): string[] {
  const base = path.join(dir, 'assets');
  try {
    return fs.readdirSync(base).filter(d => {
      try { return fs.statSync(path.join(base, d)).isDirectory(); } catch { return false; }
    });
  } catch {
    return [];
  }
}

/** All snapshots for an asset, sorted oldest → newest. */
export function getSnapshots(assetId: string, dir = fleetDir()): FleetSnapshot[] {
  const aDir = assetDir(dir, assetId);
  let files: string[];
  try {
    files = fs.readdirSync(aDir).filter(f => f.endsWith('.json'));
  } catch {
    return [];
  }
  const snaps: FleetSnapshot[] = [];
  for (const f of files) {
    try {
      snaps.push(JSON.parse(fs.readFileSync(path.join(aDir, f), 'utf-8')));
    } catch {
      // skip malformed
    }
  }
  return snaps.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

export function latestSnapshot(assetId: string, dir = fleetDir()): FleetSnapshot | undefined {
  const snaps = getSnapshots(assetId, dir);
  return snaps[snaps.length - 1];
}

export interface FleetSummary {
  assetCount: number;
  totals: {
    agents: number; tools: number; models: number; mcpServers: number;
    findings: number; criticals: number; highs: number;
  };
  ecosystems: Record<string, number>;
  owners: Record<string, number>;
  assets: Array<{
    assetId: string; name: string; kind: 'repo' | 'machine'; owner?: string;
    score: number; grade: string; totalFindings: number; criticals: number; lastSeen: string;
  }>;
}

/** Roll up the latest snapshot of every asset into an estate view. */
export function computeFleetSummary(dir = fleetDir()): FleetSummary {
  const totals = { agents: 0, tools: 0, models: 0, mcpServers: 0, findings: 0, criticals: 0, highs: 0 };
  const ecosystems: Record<string, number> = {};
  const owners: Record<string, number> = {};
  const assets: FleetSummary['assets'] = [];

  for (const assetId of listAssetIds(dir)) {
    const snap = latestSnapshot(assetId, dir);
    if (!snap) continue;

    totals.agents += snap.inventory.agents;
    totals.tools += snap.inventory.tools;
    totals.models += snap.inventory.models;
    totals.mcpServers += snap.inventory.mcpServers;
    totals.findings += snap.findings.total;
    totals.criticals += snap.findings.bySeverity.critical ?? 0;
    totals.highs += snap.findings.bySeverity.high ?? 0;

    for (const eco of snap.ecosystems) ecosystems[eco] = (ecosystems[eco] ?? 0) + 1;
    if (snap.owner) owners[snap.owner] = (owners[snap.owner] ?? 0) + 1;

    assets.push({
      assetId: snap.assetId,
      name: snap.name,
      kind: snap.kind,
      owner: snap.owner,
      score: snap.score,
      grade: snap.grade,
      totalFindings: snap.findings.total,
      criticals: snap.findings.bySeverity.critical ?? 0,
      lastSeen: snap.timestamp,
    });
  }

  // Worst first: lowest score, then most criticals.
  assets.sort((a, b) => a.score - b.score || b.criticals - a.criticals);

  return { assetCount: assets.length, totals, ecosystems, owners, assets };
}

export interface FleetDrift {
  assetId: string;
  name: string;
  from?: string;
  to: string;
  scoreDelta: number;
  gradeFrom?: string;
  gradeTo: string;
  newFindings: number;
  resolvedFindings: number;
  inventoryDelta: { agents: number; tools: number; models: number; mcpServers: number };
}

/** Compare an asset's two most recent snapshots. Null if fewer than one exists. */
export function computeDrift(assetId: string, dir = fleetDir()): FleetDrift | null {
  const snaps = getSnapshots(assetId, dir);
  if (snaps.length === 0) return null;
  const to = snaps[snaps.length - 1];
  const from = snaps.length >= 2 ? snaps[snaps.length - 2] : undefined;

  const prevFps = new Set(from?.findings.fingerprints ?? []);
  const currFps = new Set(to.findings.fingerprints);
  const newFindings = [...currFps].filter(f => !prevFps.has(f)).length;
  const resolvedFindings = [...prevFps].filter(f => !currFps.has(f)).length;

  return {
    assetId,
    name: to.name,
    from: from?.timestamp,
    to: to.timestamp,
    scoreDelta: from ? to.score - from.score : 0,
    gradeFrom: from?.grade,
    gradeTo: to.grade,
    newFindings,
    resolvedFindings,
    inventoryDelta: {
      agents: to.inventory.agents - (from?.inventory.agents ?? 0),
      tools: to.inventory.tools - (from?.inventory.tools ?? 0),
      models: to.inventory.models - (from?.inventory.models ?? 0),
      mcpServers: to.inventory.mcpServers - (from?.inventory.mcpServers ?? 0),
    },
  };
}

/** Machine metadata for a snapshot (host, platform, stable machine id). */
export function machineInfo(): { machineId: string; hostname: string; platform: string } {
  return { machineId: getMachineId(), hostname: os.hostname(), platform: process.platform };
}

/** Assemble a fleet snapshot from a scan's score/findings and its inventory. */
export function buildSnapshot(params: {
  targetPath: string;
  name: string;
  owner?: string;
  score: ScanScore;
  findings: Finding[];
  inventory: InventoryResult;
  timestamp: string;
}): FleetSnapshot {
  const { targetPath, name, owner, score, findings, inventory, timestamp } = params;
  const git = collectGitMeta(targetPath);
  const identity = assetIdentity(targetPath, git?.remote);
  const assetId = computeAssetId('repo', identity);

  const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;

  const frameworks = [...new Set(inventory.frameworks.map(f => f.name))].sort();

  return {
    schema: FLEET_SNAPSHOT_SCHEMA,
    assetId,
    kind: 'repo',
    name,
    ...(owner ? { owner } : {}),
    path: path.resolve(targetPath),
    ...(git ? { git } : {}),
    machine: machineInfo(),
    timestamp,
    score: score.overall,
    grade: score.grade,
    ...(score.capReason ? { capReason: score.capReason } : {}),
    findings: {
      total: findings.length,
      bySeverity,
      fingerprints: [...new Set(findings.map(fingerprintFinding))].sort(),
    },
    inventory: {
      agents: inventory.summary.totalAgents,
      tools: inventory.summary.totalTools,
      models: inventory.summary.totalModels,
      mcpServers: inventory.summary.totalMCPServers,
      vectorDBs: inventory.summary.totalVectorDBs,
      frameworks,
    },
    ecosystems: frameworks,
  };
}
