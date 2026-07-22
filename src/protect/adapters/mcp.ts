/**
 * The `mcp` protect surface — wires three existing capabilities behind the
 * adapter contract: proxy routing (`installProxy`), known-malicious server
 * quarantine (`planQuarantine`/`applyQuarantine`), and OpenClaw config
 * hardening recommendations (advisories in the plan; report-only in Phase A,
 * the hardener's own CLI applies them).
 */

import { installProxy, uninstallProxy, listInstalls } from '../../proxy/installer.js';
import {
  planQuarantine, applyQuarantine, undoQuarantine,
  findLatestManifestPath, defaultQuarantineDir,
} from '../../endpoint/quarantine.js';
import { hardenOpenClawConfig } from '../../endpoint/openclaw-config-hardener.js';
import type {
  Advisory, McpUndoHandle, PlanStep, ProtectAdapter, ProtectContext,
  SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult,
} from '../types.js';

export const mcpAdapter: ProtectAdapter = {
  surface: 'mcp',

  async plan(ctx: ProtectContext): Promise<SurfacePlan> {
    const steps: PlanStep[] = [];

    const install = await installProxy({
      dryRun: true, clientPaths: ctx.clientPaths, dir: ctx.proxyDir, g0Bin: ctx.g0Bin,
    });
    for (const entry of install.wrapped) {
      steps.push({
        id: `wrap:${entry.client}/${entry.serverName}`,
        description: `Route MCP server "${entry.serverName}" (${entry.client}) through g0 proxy`,
        files: [entry.configPath],
      });
    }

    const quarantine = planQuarantine({ clients: ctx.clientPaths });
    for (const candidate of quarantine.candidates) {
      steps.push({
        id: `quarantine:${candidate.client}/${candidate.serverName}`,
        description: `Remove known-malicious MCP server "${candidate.serverName}" (${candidate.client})`,
        files: [candidate.configPath],
      });
    }

    const advisories: Advisory[] = [];
    try {
      const hardened = hardenOpenClawConfig();
      for (const rec of hardened.recommendations) {
        advisories.push({ id: `openclaw:${rec.path}`, severity: rec.severity, description: rec.reason });
      }
    } catch {
      // no OpenClaw on this machine — nothing to advise
    }

    return { surface: 'mcp', steps, advisories };
  },

  async apply(ctx: ProtectContext): Promise<SurfaceApplyResult> {
    const applied: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];

    const install = await installProxy({
      clientPaths: ctx.clientPaths, dir: ctx.proxyDir, g0Bin: ctx.g0Bin,
    });
    applied.push(...install.wrapped.map((e) => `wrap:${e.client}/${e.serverName}`));
    skipped.push(
      ...install.skippedAlreadyWrapped.map((s) => ({ reason: `already wrapped: ${s}` })),
      ...install.unproxyable.map((s) => ({ reason: `unproxyable (non-stdio): ${s}` })),
    );
    errors.push(...install.errors.map((e) => `${e.client}: ${e.message}`));

    const quarantine = await applyQuarantine({ clients: ctx.clientPaths, quarantineDir: ctx.quarantineDir });
    applied.push(
      ...quarantine.applied.flatMap((e) => e.removedServers.map((s) => `quarantine:${e.client}/${s}`)),
    );
    skipped.push(...quarantine.skipped.map((s) => ({ reason: s.reason })));

    return {
      surface: 'mcp', applied, skipped, errors,
      undo: { quarantineManifestPath: quarantine.manifestPath },
    };
  },

  async status(ctx: ProtectContext): Promise<SurfaceStatus> {
    const installs = listInstalls(ctx.proxyDir);
    const latestQuarantine = findLatestManifestPath(ctx.quarantineDir ?? defaultQuarantineDir());
    const isProtected = installs.length > 0;
    return {
      surface: 'mcp',
      protected: isProtected,
      summary: isProtected
        ? `proxy active on ${installs.length} MCP server(s)`
        : 'not protected — no MCP servers routed through g0 proxy',
      detail: [
        `${installs.length} MCP server(s) routed through g0 proxy`,
        latestQuarantine ? `last quarantine manifest: ${latestQuarantine}` : 'no quarantine has been applied',
      ],
    };
  },

  async undo(ctx: ProtectContext, handle: McpUndoHandle, opts?: { force?: boolean }): Promise<SurfaceUndoResult> {
    const restored: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];

    const uninstall = await uninstallProxy({ clientPaths: ctx.clientPaths, dir: ctx.proxyDir, g0Bin: ctx.g0Bin });
    restored.push(...uninstall.restored.map((e) => `unwrap:${e.client}/${e.serverName}`));
    errors.push(...uninstall.errors.map((e) => `${e.client}: ${e.message}`));

    if (handle.quarantineManifestPath) {
      const undone = await undoQuarantine({
        manifestPath: handle.quarantineManifestPath,
        quarantineDir: ctx.quarantineDir,
        force: opts?.force,
      });
      restored.push(...undone.restored.map((r) => `restore:${r.configPath}`));
      skipped.push(...undone.skipped.map((s) => ({ reason: s.reason })));
    }

    return { surface: 'mcp', restored, skipped, errors };
  },
};
