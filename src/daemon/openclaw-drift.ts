import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { DeploymentAuditResult } from '../mcp/openclaw-deployment.js';
import type { HardeningCheck } from '../mcp/openclaw-hardening.js';

const G0_DIR = path.join(os.homedir(), '.g0');
const LAST_AUDIT_PATH = path.join(G0_DIR, 'last-openclaw-audit.json');

// ── Drift Event Types ─────────────────────────────────────────────────────

export interface OpenClawDriftEvent {
  type: 'new-failure' | 'regression' | 'resolved' | 'status-change' | 'new-secret-duplication' | 'new-egress-violation' | 'cognitive-drift';
  severity: 'critical' | 'high' | 'medium' | 'low';
  checkId?: string;
  title: string;
  detail: string;
  timestamp: string;
}

export interface OpenClawDriftResult {
  events: OpenClawDriftEvent[];
  previousStatus: 'secure' | 'warn' | 'critical' | null;
  currentStatus: 'secure' | 'warn' | 'critical';
  previousFailed: number;
  currentFailed: number;
}

// ── Persistence ───────────────────────────────────────────────────────────

export function saveLastAudit(result: DeploymentAuditResult): void {
  try {
    fs.mkdirSync(G0_DIR, { recursive: true, mode: 0o700 });
    const serializable = {
      checks: result.checks,
      summary: result.summary,
      agentConfigDuplicateCount: result.agentConfigResult?.duplicateGroups.length ?? 0,
      egressViolationCount: result.egressResult?.violations.length ?? 0,
      timestamp: new Date().toISOString(),
    };
    fs.writeFileSync(LAST_AUDIT_PATH, JSON.stringify(serializable, null, 2), { mode: 0o600 });
  } catch {
    // Non-fatal
  }
}

interface SavedAudit {
  checks: HardeningCheck[];
  summary: DeploymentAuditResult['summary'];
  agentConfigDuplicateCount: number;
  egressViolationCount: number;
  timestamp: string;
}

export function loadLastAudit(): SavedAudit | null {
  try {
    const raw = fs.readFileSync(LAST_AUDIT_PATH, 'utf-8');
    return JSON.parse(raw) as SavedAudit;
  } catch {
    return null;
  }
}

// ── Drift Detection ───────────────────────────────────────────────────────

export function detectOpenClawDrift(
  current: DeploymentAuditResult,
): OpenClawDriftResult {
  const previous = loadLastAudit();
  const now = new Date().toISOString();
  const events: OpenClawDriftEvent[] = [];

  const currentFailed = current.summary.failed;
  const previousFailed = previous?.summary.failed ?? 0;
  const previousStatus = previous?.summary.overallStatus ?? null;
  const currentStatus = current.summary.overallStatus;

  if (!previous) {
    // First run — report all failures as new
    for (const check of current.checks) {
      if (check.status === 'fail') {
        events.push({
          type: 'new-failure',
          severity: check.severity,
          checkId: check.id,
          title: `${check.name} — FAIL`,
          detail: check.detail,
          timestamp: now,
        });
      }
    }

    return { events, previousStatus, currentStatus, previousFailed, currentFailed };
  }

  // Build lookup of previous check statuses
  const prevCheckMap = new Map<string, HardeningCheck>();
  for (const check of previous.checks) {
    prevCheckMap.set(check.id, check);
  }

  for (const check of current.checks) {
    const prev = prevCheckMap.get(check.id);

    if (check.status === 'fail' && (!prev || prev.status !== 'fail')) {
      // New failure or regression (was pass/skip/error, now fail)
      events.push({
        type: prev ? 'regression' : 'new-failure',
        severity: check.severity,
        checkId: check.id,
        title: prev
          ? `REGRESSION: ${check.name} (was ${prev.status}, now fail)`
          : `NEW FAILURE: ${check.name}`,
        detail: check.detail,
        timestamp: now,
      });
    }

    if (check.status === 'pass' && prev?.status === 'fail') {
      // Resolved
      events.push({
        type: 'resolved',
        severity: 'low',
        checkId: check.id,
        title: `RESOLVED: ${check.name}`,
        detail: `Previously failing check is now passing.`,
        timestamp: now,
      });
    }
  }

  // Overall status change
  if (previousStatus && currentStatus !== previousStatus) {
    const worsened = currentStatus === 'critical' || (currentStatus === 'warn' && previousStatus === 'secure');
    events.push({
      type: 'status-change',
      severity: worsened ? 'critical' : 'low',
      title: `Overall status changed: ${previousStatus.toUpperCase()} → ${currentStatus.toUpperCase()}`,
      detail: `Failed checks: ${previousFailed} → ${currentFailed}`,
      timestamp: now,
    });
  }

  // Secret duplication change
  const currentDupCount = current.agentConfigResult?.duplicateGroups.length ?? 0;
  const prevDupCount = previous.agentConfigDuplicateCount ?? 0;
  if (currentDupCount > prevDupCount) {
    events.push({
      type: 'new-secret-duplication',
      severity: 'critical',
      title: `New credential duplication detected`,
      detail: `Duplicate credential groups increased from ${prevDupCount} to ${currentDupCount}.`,
      timestamp: now,
    });
  }

  // Egress violation change
  const currentEgressCount = current.egressResult?.violations.length ?? 0;
  const prevEgressCount = previous.egressViolationCount ?? 0;
  if (currentEgressCount > prevEgressCount) {
    events.push({
      type: 'new-egress-violation',
      severity: 'critical',
      title: `New egress violations detected`,
      detail: `Violations increased from ${prevEgressCount} to ${currentEgressCount}.`,
      timestamp: now,
    });
  }

  return { events, previousStatus, currentStatus, previousFailed, currentFailed };
}

// ── Cognitive File Integrity Monitoring ───────────────────────────────────

import * as crypto from 'node:crypto';

const COGNITIVE_BASELINE_PATH = path.join(G0_DIR, 'cognitive-baselines.json');

const COGNITIVE_FILES = [
  'SOUL.md',
  'MEMORY.md',
  'IDENTITY.md',
  'AGENTS.md',
  'openclaw.json',
];

export interface CognitiveFileEntry {
  path: string;
  hash: string;
  size: number;
  modifiedAt: string;
}

export interface CognitiveBaseline {
  files: CognitiveFileEntry[];
  createdAt: string;
  updatedAt: string;
}

export interface CognitiveDriftEvent {
  type: 'cognitive-file-modified' | 'cognitive-file-deleted' | 'cognitive-file-created';
  severity: 'critical' | 'high' | 'medium';
  file: string;
  detail: string;
  previousHash?: string;
  currentHash?: string;
  timestamp: string;
  injectionDetected?: boolean;
}

export interface CognitiveDriftResult {
  events: CognitiveDriftEvent[];
  baseline: CognitiveBaseline;
  filesChecked: number;
}

function computeFileHash(filePath: string): string | null {
  try {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Save (or update) the cognitive baseline for an OpenClaw data directory
 */
export function saveCognitiveBaseline(openclawDir: string, baselinePath?: string): CognitiveBaseline {
  const bPath = baselinePath ?? COGNITIVE_BASELINE_PATH;
  const now = new Date().toISOString();
  const files: CognitiveFileEntry[] = [];

  for (const name of COGNITIVE_FILES) {
    const filePath = path.join(openclawDir, name);
    if (!fs.existsSync(filePath)) continue;

    const hash = computeFileHash(filePath);
    if (!hash) continue;

    const stat = fs.statSync(filePath);
    files.push({
      path: filePath,
      hash,
      size: stat.size,
      modifiedAt: stat.mtime.toISOString(),
    });
  }

  const baseline: CognitiveBaseline = {
    files,
    createdAt: now,
    updatedAt: now,
  };

  try {
    fs.mkdirSync(path.dirname(bPath), { recursive: true, mode: 0o700 });
    fs.writeFileSync(bPath, JSON.stringify(baseline, null, 2), { mode: 0o600 });
  } catch {
    // Non-fatal
  }

  return baseline;
}

/**
 * Load a previously saved cognitive baseline
 */
export function loadCognitiveBaseline(baselinePath?: string): CognitiveBaseline | null {
  const bPath = baselinePath ?? COGNITIVE_BASELINE_PATH;
  try {
    if (!fs.existsSync(bPath)) return null;
    const raw = fs.readFileSync(bPath, 'utf-8');
    return JSON.parse(raw) as CognitiveBaseline;
  } catch {
    return null;
  }
}

/**
 * Detect drift in cognitive files by comparing current state against baseline.
 * Also scans modified files for injection patterns.
 */
export function detectCognitiveDrift(
  openclawDir: string,
  opts?: { baselinePath?: string; injectionScanner?: (content: string) => { detected: boolean; patterns: string[] } },
): CognitiveDriftResult {
  const baselinePath = opts?.baselinePath;
  const baseline = loadCognitiveBaseline(baselinePath);
  const now = new Date().toISOString();
  const events: CognitiveDriftEvent[] = [];

  // Build current state
  const currentFiles = new Map<string, { hash: string; size: number }>();
  for (const name of COGNITIVE_FILES) {
    const filePath = path.join(openclawDir, name);
    const hash = computeFileHash(filePath);
    if (hash) {
      const stat = fs.statSync(filePath);
      currentFiles.set(filePath, { hash, size: stat.size });
    }
  }

  if (!baseline) {
    // No baseline — save current state as baseline, report all files as new
    const newBaseline = saveCognitiveBaseline(openclawDir, baselinePath);
    for (const entry of newBaseline.files) {
      events.push({
        type: 'cognitive-file-created',
        severity: 'medium',
        file: entry.path,
        detail: `Initial baseline recorded for ${path.basename(entry.path)}`,
        currentHash: entry.hash,
        timestamp: now,
      });
    }
    return { events, baseline: newBaseline, filesChecked: currentFiles.size };
  }

  // Compare against baseline
  const baselineMap = new Map<string, CognitiveFileEntry>();
  for (const entry of baseline.files) {
    baselineMap.set(entry.path, entry);
  }

  // Check for modifications and deletions
  for (const [filePath, entry] of baselineMap) {
    const current = currentFiles.get(filePath);

    if (!current) {
      // File was deleted
      events.push({
        type: 'cognitive-file-deleted',
        severity: 'critical',
        file: filePath,
        detail: `Cognitive file deleted: ${path.basename(filePath)} (was ${entry.size} bytes)`,
        previousHash: entry.hash,
        timestamp: now,
      });
      continue;
    }

    if (current.hash !== entry.hash) {
      // File was modified
      let injectionDetected = false;
      if (opts?.injectionScanner) {
        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          const scanResult = opts.injectionScanner(content);
          injectionDetected = scanResult.detected;
        } catch {
          // Non-fatal
        }
      }

      const severity = injectionDetected ? 'critical' : (
        path.basename(filePath) === 'SOUL.md' ? 'critical' : 'high'
      );

      events.push({
        type: 'cognitive-file-modified',
        severity,
        file: filePath,
        detail: `Cognitive file modified: ${path.basename(filePath)}${injectionDetected ? ' — INJECTION PATTERNS DETECTED' : ''}`,
        previousHash: entry.hash,
        currentHash: current.hash,
        timestamp: now,
        injectionDetected,
      });
    }
  }

  // Check for new files
  for (const [filePath, current] of currentFiles) {
    if (!baselineMap.has(filePath)) {
      events.push({
        type: 'cognitive-file-created',
        severity: 'high',
        file: filePath,
        detail: `New cognitive file detected: ${path.basename(filePath)} (${current.size} bytes)`,
        currentHash: current.hash,
        timestamp: now,
      });
    }
  }

  // Update baseline with current state
  const updatedBaseline = saveCognitiveBaseline(openclawDir, baselinePath);

  return { events, baseline: updatedBaseline, filesChecked: currentFiles.size };
}
