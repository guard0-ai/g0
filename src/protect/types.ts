/**
 * The `g0 protect` surface-adapter contract. Each surface (mcp today;
 * claude, codex, browser, watch in later phases) implements `ProtectAdapter`
 * and the orchestrator drives plan / apply / status / undo across them —
 * dry-run by default, every write recorded in the session manifest with an
 * undo handle, mirroring `endpoint quarantine`'s safety grammar.
 */

import type { MCPClient } from '../types/mcp-scan.js';

export type ProtectSurface = 'mcp' | 'claude' | 'watch';
export const ALL_SURFACES: readonly ProtectSurface[] = ['mcp', 'claude', 'watch'] as const;

export interface ProtectContext {
  /** Protect state root. Default: $G0_STATE_DIR/protect, else ~/.g0/protect. */
  stateDir?: string;
  /** Test injection — forwarded to installer/quarantine client discovery. */
  clientPaths?: MCPClient[];
  /** Forwarded to installer `dir` (proxy manifest/policy dir). */
  proxyDir?: string;
  quarantineDir?: string;
  g0Bin?: string;
  /** Claude Code settings file. Default: ~/.claude/settings.json. */
  claudeSettingsPath?: string;
  /** Hook config dir override (policy.yaml/audit.jsonl). Default: ~/.g0/hook. */
  hookConfigDir?: string;
  /** Command written into Claude Code hook entries. Default: 'g0-hook'. */
  hookCommand?: string;
  /** watch surface test seam: unit-file directory override (default: platform autostart dir). */
  watchUnitDir?: string;
  /** watch surface test seam: service-manager exec (launchctl/systemctl). */
  serviceExec?: (cmd: string, args: string[]) => void;
}

export interface PlanStep { id: string; description: string; files: string[]; }
export interface Advisory { id: string; severity: 'critical' | 'high' | 'medium' | 'low'; description: string; }
export interface SurfacePlan { surface: ProtectSurface; steps: PlanStep[]; advisories: Advisory[]; }

/** What a surface needs later to undo its apply. Recorded in the manifest. */
export interface UndoHandle {
  quarantineManifestPath?: string | null;
  /** claude surface: the settings file that was modified. */
  settingsPath?: string;
  /** claude surface: byte-exact pre-image (null = file didn't exist). */
  settingsBackupPath?: string | null;
  /** claude surface: sha256 of the file as apply left it (undo refuses on drift unless force). */
  postApplySha256?: string;
  /** watch surface: the autostart unit file that was written (null = registration skipped). */
  watchUnitPath?: string | null;
}
export type McpUndoHandle = UndoHandle;

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
