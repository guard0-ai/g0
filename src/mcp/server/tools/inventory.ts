import { z } from 'zod';
import { runDiscovery, runGraphBuild } from '../../../pipeline.js';
import { buildInventory } from '../../../inventory/builder.js';
import { toCycloneDX, type BomMeta } from '../../../inventory/cyclonedx.js';
import { G0_VERSION } from '../../../utils/version.js';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { resolveToolPath, textResult, type ToolContext, type ToolResult } from './util.js';

export const inventoryInputShape = {
  path: z.string().optional().describe("Path to the agent project (default: '.')"),
  format: z.enum(['summary', 'cyclonedx']).optional().describe(
    "'summary' (default) returns a compact markdown + JSON summary of models/tools/MCP servers/agents. " +
    "'cyclonedx' returns a full, UNSIGNED CycloneDX 1.6 AI-BOM JSON document — signing it for tamper-evidence " +
    "requires an ed25519 private key via `g0 inventory --sign-key`, which is out of scope for this tool.",
  ),
};

export interface InventoryInput {
  path?: string;
  format?: 'summary' | 'cyclonedx';
}

export const inventoryDescription =
  'Generate an AI Asset Inventory (AI Bill of Materials) for a local agent project: models, ' +
  'frameworks, tools, MCP servers, agents, and vector DBs. Read-only. Supports a compact summary or a ' +
  'full (unsigned) CycloneDX 1.6 AI-BOM document.';

export async function inventory(args: InventoryInput, ctx: ToolContext = {}): Promise<ToolResult> {
  const resolution = resolveToolPath(args.path ?? '.', ctx);
  if (!resolution.ok) return resolution.result;
  const resolvedPath = resolution.path;

  const discovery = await runDiscovery(resolvedPath);
  const graph = runGraphBuild(resolvedPath, discovery);
  const inv = buildInventory(graph, discovery);

  if (args.format === 'cyclonedx') {
    const meta: BomMeta = {
      projectName: path.basename(resolvedPath),
      toolVersion: G0_VERSION,
      timestamp: new Date().toISOString(),
      serialNumber: `urn:uuid:${randomUUID()}`,
    };
    const bom = toCycloneDX(inv, meta);
    const markdown =
      `# g0 AI-BOM (CycloneDX 1.6, unsigned)\n\n` +
      'This document is **unsigned**. To produce a tamper-evident, signed AI-BOM run ' +
      '`g0 inventory . --cyclonedx --sign-key <key>` locally.\n\n' +
      '```json\n' + JSON.stringify(bom, null, 2) + '\n```\n';
    return textResult(markdown, { bom: bom as unknown as Record<string, unknown> });
  }

  const lines: string[] = [];
  lines.push('# g0 AI asset inventory');
  lines.push('');
  lines.push(`**Models:** ${inv.summary.totalModels}   **Frameworks:** ${inv.summary.totalFrameworks}`);
  lines.push(`**Tools:** ${inv.tools.length}   **MCP servers:** ${inv.mcpServers.length}   **Agents:** ${inv.agents.length}   **Vector DBs:** ${inv.vectorDBs.length}`);
  if (inv.risks.length > 0) {
    lines.push('');
    lines.push('## Risks');
    for (const r of inv.risks) lines.push(`- [${r.level}] ${r.description}`);
  }
  const markdown = lines.join('\n') + '\n';

  return textResult(markdown, {
    summary: inv.summary,
    models: inv.models,
    frameworks: inv.frameworks,
    tools: inv.tools,
    mcpServers: inv.mcpServers,
    agents: inv.agents,
    vectorDBs: inv.vectorDBs,
    risks: inv.risks,
  });
}
