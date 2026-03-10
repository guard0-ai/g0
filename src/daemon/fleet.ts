import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

const G0_DIR = path.join(os.homedir(), '.g0');
const FLEET_FILE = path.join(G0_DIR, 'fleet-state.json');

// ── Types ──────────────────────────────────────────────────────────────────

export interface FleetMember {
  machineId: string;
  hostname: string;
  platform: string;
  group?: string;
  tags: string[];
  lastSeen: string;
  scores: FleetScores;
  agentCount?: number;
}

export interface FleetScores {
  endpointScore?: number;
  endpointGrade?: string;
  hostHardeningPassed?: number;
  hostHardeningFailed?: number;
  openclawStatus?: string;
  openclawFailedChecks?: number;
  scanGrade?: string;
  scanFindings?: number;
}

export interface FleetState {
  members: FleetMember[];
  lastUpdated: string;
}

export interface FleetSummary {
  totalMembers: number;
  byGroup: Record<string, number>;
  byPlatform: Record<string, number>;
  avgEndpointScore: number;
  worstGrade: string;
  criticalMembers: FleetMember[];
  aggregateScore: number;
  aggregateGrade: string;
}

// ── Fleet State Management ─────────────────────────────────────────────────

export function loadFleetState(): FleetState {
  try {
    const raw = fs.readFileSync(FLEET_FILE, 'utf-8');
    return JSON.parse(raw);
  } catch {
    return { members: [], lastUpdated: new Date().toISOString() };
  }
}

export function saveFleetState(state: FleetState): void {
  fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
  state.lastUpdated = new Date().toISOString();
  fs.writeFileSync(FLEET_FILE, JSON.stringify(state, null, 2) + '\n', { mode: 0o600 });
}

/**
 * Register or update a fleet member
 */
export function registerMember(
  machineId: string,
  scores: FleetScores,
  options?: { group?: string; tags?: string[]; agentCount?: number },
): FleetMember {
  const state = loadFleetState();

  const member: FleetMember = {
    machineId,
    hostname: os.hostname(),
    platform: `${os.platform()}-${os.arch()}`,
    group: options?.group,
    tags: options?.tags ?? [],
    lastSeen: new Date().toISOString(),
    scores,
    agentCount: options?.agentCount,
  };

  const idx = state.members.findIndex(m => m.machineId === machineId);
  if (idx >= 0) {
    state.members[idx] = member;
  } else {
    state.members.push(member);
  }

  saveFleetState(state);
  return member;
}

/**
 * Remove stale members not seen in N hours
 */
export function pruneStaleMembers(maxAgeHours: number = 72): number {
  const state = loadFleetState();
  const cutoff = Date.now() - maxAgeHours * 60 * 60 * 1000;
  const before = state.members.length;
  state.members = state.members.filter(m => new Date(m.lastSeen).getTime() > cutoff);
  const pruned = before - state.members.length;
  if (pruned > 0) saveFleetState(state);
  return pruned;
}

// ── Fleet Aggregation ──────────────────────────────────────────────────────

const GRADE_ORDER: Record<string, number> = { A: 0, B: 1, C: 2, D: 3, F: 4 };
const GRADE_REVERSE: Record<number, string> = { 0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'F' };

/**
 * Compute aggregate fleet summary
 */
export function getFleetSummary(state?: FleetState): FleetSummary {
  const s = state ?? loadFleetState();
  const members = s.members;

  const byGroup: Record<string, number> = {};
  const byPlatform: Record<string, number> = {};
  const endpointScores: number[] = [];
  let worstGradeIdx = 0;

  for (const m of members) {
    byGroup[m.group ?? 'default'] = (byGroup[m.group ?? 'default'] ?? 0) + 1;
    byPlatform[m.platform] = (byPlatform[m.platform] ?? 0) + 1;
    if (m.scores.endpointScore !== undefined) endpointScores.push(m.scores.endpointScore);

    const grade = m.scores.endpointGrade ?? m.scores.scanGrade;
    if (grade) {
      const idx = GRADE_ORDER[grade.toUpperCase()] ?? 4;
      if (idx > worstGradeIdx) worstGradeIdx = idx;
    }
  }

  const avgEndpointScore = endpointScores.length > 0
    ? Math.round(endpointScores.reduce((a, b) => a + b, 0) / endpointScores.length)
    : 0;

  const criticalMembers = members.filter(m =>
    m.scores.openclawStatus === 'critical' ||
    (m.scores.endpointGrade && GRADE_ORDER[m.scores.endpointGrade.toUpperCase()] >= 3),
  );

  // Aggregate score: average of endpoint scores, penalized by critical members
  const penalty = criticalMembers.length * 5;
  const aggregateScore = Math.max(0, avgEndpointScore - penalty);
  const aggregateGradeIdx = aggregateScore >= 90 ? 0 : aggregateScore >= 70 ? 1 : aggregateScore >= 50 ? 2 : aggregateScore >= 30 ? 3 : 4;

  return {
    totalMembers: members.length,
    byGroup,
    byPlatform,
    avgEndpointScore,
    worstGrade: GRADE_REVERSE[worstGradeIdx] ?? 'A',
    criticalMembers,
    aggregateScore,
    aggregateGrade: GRADE_REVERSE[aggregateGradeIdx] ?? 'A',
  };
}

/**
 * Cross-machine correlation: find common failures across fleet
 */
export function findCommonFailures(state?: FleetState): Array<{
  issue: string;
  affectedCount: number;
  affectedMembers: string[];
}> {
  const s = state ?? loadFleetState();
  const failureMap: Record<string, string[]> = {};

  for (const m of s.members) {
    if (m.scores.openclawStatus === 'critical' || m.scores.openclawStatus === 'warn') {
      const key = `openclaw-${m.scores.openclawStatus}`;
      if (!failureMap[key]) failureMap[key] = [];
      failureMap[key].push(m.hostname);
    }

    if (m.scores.hostHardeningFailed && m.scores.hostHardeningFailed > 0) {
      const key = `host-hardening-failures`;
      if (!failureMap[key]) failureMap[key] = [];
      failureMap[key].push(m.hostname);
    }

    const grade = m.scores.endpointGrade ?? m.scores.scanGrade;
    if (grade && GRADE_ORDER[grade.toUpperCase()] >= 3) {
      const key = `poor-grade-${grade}`;
      if (!failureMap[key]) failureMap[key] = [];
      failureMap[key].push(m.hostname);
    }
  }

  return Object.entries(failureMap)
    .filter(([, members]) => members.length > 1) // Only cross-machine issues
    .map(([issue, members]) => ({
      issue,
      affectedCount: members.length,
      affectedMembers: members,
    }))
    .sort((a, b) => b.affectedCount - a.affectedCount);
}
