/**
 * The `g0 protect` surface-adapter contract. Each surface (mcp today;
 * claude, codex, browser, watch in later phases) implements `ProtectAdapter`
 * and the orchestrator drives plan / apply / status / undo across them —
 * dry-run by default, every write recorded in the session manifest with an
 * undo handle, mirroring `endpoint quarantine`'s safety grammar.
 */

import type { MCPClient } from '../types/mcp-scan.js';

export type ProtectSurface = 'mcp';
export const ALL_SURFACES: readonly ProtectSurface[] = ['mcp'] as const;

export interface ProtectContext {
  /** Protect state root. Default: $G0_STATE_DIR/protect, else ~/.g0/protect. */
  stateDir?: string;
  /** Test injection — forwarded to installer/quarantine client discovery. */
  clientPaths?: MCPClient[];
  /** Forwarded to installer `dir` (proxy manifest/policy dir). */
  proxyDir?: string;
  quarantineDir?: string;
  g0Bin?: string;
}

export interface PlanStep { id: string; description: string; files: string[]; }
export interface Advisory { id: string; severity: 'critical' | 'high' | 'medium' | 'low'; description: string; }
export interface SurfacePlan { surface: ProtectSurface; steps: PlanStep[]; advisories: Advisory[]; }

/** What a surface needs later to undo its apply. Recorded in the manifest. */
export interface McpUndoHandle { quarantineManifestPath?: string | null; }

export interface SurfaceApplyResult {
  surface: ProtectSurface;
  applied: string[];
  skipped: { id?: string; reason: string }[];
  errors: string[];
  undo: McpUndoHandle;
}
export interface SurfaceStatus { surface: ProtectSurface; protected: boolean; summary: string; detail: string[]; }
export interface SurfaceUndoResult {
  surface: ProtectSurface;
  restored: string[];
  skipped: { id?: string; reason: string }[];
  errors: string[];
}

export interface ProtectAdapter {
  readonly surface: ProtectSurface;
  plan(ctx: ProtectContext): Promise<SurfacePlan>;
  apply(ctx: ProtectContext): Promise<SurfaceApplyResult>;
  status(ctx: ProtectContext): Promise<SurfaceStatus>;
  undo(ctx: ProtectContext, handle: McpUndoHandle, opts?: { force?: boolean }): Promise<SurfaceUndoResult>;
}
