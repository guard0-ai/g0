/**
 * Drives `g0 protect` across surface adapters: plan (dry-run), apply (with
 * session manifest), status, off (undo from the latest manifest). Adapters
 * are independent — one surface failing is recorded on that surface's
 * result and never blocks or rolls back the others (spec §11).
 */

import { claudeAdapter } from './adapters/claude.js';
import { watchAdapter } from './adapters/watch.js';
import { mcpAdapter } from './adapters/mcp.js';
import { readLatestManifest, writeManifest } from './manifest.js';
import type { ProtectManifest } from './manifest.js';
import type {
  ProtectAdapter, ProtectContext, SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult,
} from './types.js';

export const DEFAULT_ADAPTERS: ProtectAdapter[] = [mcpAdapter, claudeAdapter, watchAdapter];

export function resolveSurfaces(list: string | undefined, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS): ProtectAdapter[] {
  if (!list) return adapters;
  const names = list.split(',').map((s) => s.trim()).filter(Boolean);
  const known = new Set(adapters.map((a) => a.surface as string));
  const unknown = names.filter((n) => !known.has(n));
  if (unknown.length > 0) {
    throw new Error(`unknown surface(s): ${unknown.join(', ')} (available: ${[...known].join(', ')})`);
  }
  return adapters.filter((a) => names.includes(a.surface));
}

export async function protectPlan(ctx: ProtectContext, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS): Promise<SurfacePlan[]> {
  const plans: SurfacePlan[] = [];
  for (const adapter of adapters) {
    try {
      plans.push(await adapter.plan(ctx));
    } catch (err) {
      plans.push({
        surface: adapter.surface,
        steps: [],
        advisories: [{
          id: `${adapter.surface}:plan-error`,
          severity: 'high',
          description: `planning failed: ${err instanceof Error ? err.message : String(err)}`,
        }],
      });
    }
  }
  return plans;
}

export async function protectApply(
  ctx: ProtectContext, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS,
): Promise<{ results: SurfaceApplyResult[]; manifestPath: string }> {
  const results: SurfaceApplyResult[] = [];
  const manifest: ProtectManifest = {
    id: new Date().toISOString().replace(/[:.]/g, '-'),
    timestamp: new Date().toISOString(),
    surfaces: {},
  };
  for (const adapter of adapters) {
    try {
      const result = await adapter.apply(ctx);
      results.push(result);
      manifest.surfaces[adapter.surface] = result.undo;
    } catch (err) {
      results.push({
        surface: adapter.surface, applied: [], skipped: [], undo: {},
        errors: [err instanceof Error ? err.message : String(err)],
      });
    }
  }
  const manifestPath = writeManifest(manifest, ctx.stateDir);
  return { results, manifestPath };
}

export async function protectStatus(ctx: ProtectContext, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS): Promise<SurfaceStatus[]> {
  const statuses: SurfaceStatus[] = [];
  for (const adapter of adapters) {
    try {
      statuses.push(await adapter.status(ctx));
    } catch (err) {
      statuses.push({
        surface: adapter.surface,
        protected: false,
        summary: `status failed: ${err instanceof Error ? err.message : String(err)}`,
        detail: [],
      });
    }
  }
  return statuses;
}

export async function protectOff(
  ctx: ProtectContext, opts: { force?: boolean } = {}, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS,
): Promise<{ results: SurfaceUndoResult[]; manifestPath: string | null }> {
  const latest = readLatestManifest(ctx.stateDir);
  const results: SurfaceUndoResult[] = [];
  for (const adapter of adapters) {
    // No manifest still undoes what can be undone from the wrapped ops' own
    // records (proxy uninstall reads the installer manifest); quarantine
    // undo is skipped without a recorded handle.
    const handle = latest?.manifest.surfaces[adapter.surface] ?? {};
    try {
      results.push(await adapter.undo(ctx, handle, opts));
    } catch (err) {
      results.push({
        surface: adapter.surface, restored: [], skipped: [],
        errors: [err instanceof Error ? err.message : String(err)],
      });
    }
  }
  return { results, manifestPath: latest?.path ?? null };
}
