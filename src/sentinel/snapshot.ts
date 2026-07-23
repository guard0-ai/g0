import * as fs from 'node:fs';
import * as path from 'node:path';

/** A minimal Phase-0 machine snapshot. Extended with PII/exposure in later phases. */
export interface MachineSnapshot {
  schemaVersion: 1;
  generatedAtMs: number;
  sentinelVersion: string;
  host: { hostname: string; platform: string; arch: string };
  tools: Array<{ name: string; installed: boolean; running: boolean; mcpServerCount: number }>;
  endpointScore?: number;
}

export interface SnapshotContext {
  hostname: string;
  platform: string;
  arch: string;
  sentinelVersion: string;
  generatedAtMs: number;
}

/** Only the fields Phase 0 needs from the endpoint scan result. */
interface Endpointish {
  score?: number;
  tools?: Array<{ name: string; installed: boolean; running: boolean; mcpServerCount: number }>;
}

export function buildSnapshot(result: Endpointish, ctx: SnapshotContext): MachineSnapshot {
  return {
    schemaVersion: 1,
    generatedAtMs: ctx.generatedAtMs,
    sentinelVersion: ctx.sentinelVersion,
    host: { hostname: ctx.hostname, platform: ctx.platform, arch: ctx.arch },
    tools: (result.tools ?? []).map((t) => ({
      name: t.name,
      installed: t.installed,
      running: t.running,
      mcpServerCount: t.mcpServerCount,
    })),
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
