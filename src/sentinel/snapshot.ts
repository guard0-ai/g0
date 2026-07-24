import * as fs from 'node:fs';
import * as path from 'node:path';
import type { PiiCounts } from './pii.js';
import { mergeCounts } from './pii.js';
import type { ToolExposure } from './exposure.js';
import type { BrowserExtension } from './browser-extensions.js';

/** Machine snapshot (schema v2): footprint + per-tool PII exposure + governance verdict. */
export interface MachineSnapshot {
  schemaVersion: 2;
  generatedAtMs: number;
  sentinelVersion: string;
  host: { hostname: string; platform: string; arch: string };
  tools: Array<{ name: string; installed: boolean; running: boolean; mcpServerCount: number }>;
  /** Per-tool PII-exposure records (installed tools only). */
  exposures: ToolExposure[];
  /** Installed AI-related browser extensions with permissions + risk. */
  aiBrowserExtensions?: BrowserExtension[];
  /** Fleet-mergeable roll-up of PII classes+counts across all tools (no raw values). */
  piiSummary: PiiCounts;
  /** Governance verdicts per tool, when a policy is applied. */
  governance?: SnapshotGovernance;
  endpointScore?: number;
}

export interface SnapshotGovernance {
  policyName?: string;
  verdicts: Array<{ tool: string; verdict: 'allow' | 'deny' | 'monitor'; rule?: string }>;
  compliant: boolean;
}

export interface SnapshotContext {
  hostname: string;
  platform: string;
  arch: string;
  sentinelVersion: string;
  generatedAtMs: number;
}

/** Only the fields the snapshot needs from the endpoint scan result. */
interface Endpointish {
  score?: number;
  tools?: Array<{ name: string; installed: boolean; running: boolean; mcpServerCount: number }>;
}

export function buildSnapshot(
  result: Endpointish,
  ctx: SnapshotContext,
  exposures: ToolExposure[] = [],
  governance?: SnapshotGovernance,
  aiBrowserExtensions: BrowserExtension[] = [],
): MachineSnapshot {
  return {
    schemaVersion: 2,
    generatedAtMs: ctx.generatedAtMs,
    sentinelVersion: ctx.sentinelVersion,
    host: { hostname: ctx.hostname, platform: ctx.platform, arch: ctx.arch },
    tools: (result.tools ?? []).map((t) => ({
      name: t.name,
      installed: t.installed,
      running: t.running,
      mcpServerCount: t.mcpServerCount,
    })),
    exposures,
    aiBrowserExtensions,
    piiSummary: mergeCounts(exposures.map((e) => e.evidenced)),
    governance,
    endpointScore: result.score,
  };
}

export function defaultSnapshotPath(platform: NodeJS.Platform): string {
  if (platform === 'win32') {
    return path.join(process.env.ProgramData ?? 'C:\\ProgramData', 'guard0', 'snapshot.json');
  }
  if (platform === 'darwin') {
    return '/Library/Application Support/guard0/snapshot.json';
  }
  return '/var/lib/guard0/snapshot.json';
}

export function writeSnapshotAtomic(filePath: string, snap: MachineSnapshot): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(snap, null, 2));
  fs.renameSync(tmp, filePath);
}
