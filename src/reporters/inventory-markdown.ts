import * as fs from 'node:fs';
import type { InventoryResult } from '../types/inventory.js';

export function reportInventoryMarkdown(
  inventory: InventoryResult,
  outputPath?: string,
): string {
  const lines: string[] = [];

  lines.push('# AI Agent Bill of Materials (AI-BOM)');
  lines.push('');

  // Models
  if (inventory.models.length > 0) {
    lines.push('## Models');
    lines.push('| Name | Provider | Framework | Location |');
    lines.push('|------|----------|-----------|----------|');
    for (const m of inventory.models) {
      lines.push(`| ${m.name} | ${m.provider} | ${m.framework} | ${m.file}:${m.line} |`);
    }
    lines.push('');
  }

  // Frameworks
  if (inventory.frameworks.length > 0) {
    lines.push('## Frameworks & Dependencies');
    lines.push('| Name | Version | Source |');
    lines.push('|------|---------|--------|');
    for (const f of inventory.frameworks) {
      lines.push(`| ${f.name} | ${f.version ?? 'unpinned'} | ${f.file} |`);
    }
    lines.push('');
  }

  // Agents
  if (inventory.agents.length > 0) {
    lines.push('## Agents');
    lines.push('| Name | Framework | Tools | Model | Delegation | Location |');
    lines.push('|------|-----------|-------|-------|------------|----------|');
    for (const a of inventory.agents) {
      lines.push(`| ${a.name} | ${a.framework} | ${a.toolCount} | ${a.model ?? '-'} | ${a.hasDelegation ? 'Yes' : 'No'} | ${a.file}:${a.line} |`);
    }
    lines.push('');
  }

  // Tools
  if (inventory.tools.length > 0) {
    lines.push('## Tools');
    lines.push('| Name | Capabilities | Side Effects | Validated | Location |');
    lines.push('|------|-------------|--------------|-----------|----------|');
    for (const t of inventory.tools) {
      lines.push(`| ${t.name} | ${t.capabilities.join(', ')} | ${t.hasSideEffects ? 'Yes' : 'No'} | ${t.hasValidation ? 'Yes' : 'No'} | ${t.file}:${t.line} |`);
    }
    lines.push('');
  }

  // MCP Servers
  if (inventory.mcpServers.length > 0) {
    lines.push('## MCP Servers');
    lines.push('| Name | Command | Pinned | Secrets | Source |');
    lines.push('|------|---------|--------|---------|--------|');
    for (const s of inventory.mcpServers) {
      lines.push(`| ${s.name} | ${s.command} | ${s.isPinned ? 'Yes' : 'No'} | ${s.hasSecrets ? 'Yes' : 'No'} | ${s.file} |`);
    }
    lines.push('');
  }

  // Vector DBs
  if (inventory.vectorDBs.length > 0) {
    lines.push('## Vector Databases');
    lines.push('| Name | Framework | Location |');
    lines.push('|------|-----------|----------|');
    for (const v of inventory.vectorDBs) {
      lines.push(`| ${v.name} | ${v.framework} | ${v.file}:${v.line} |`);
    }
    lines.push('');
  }

  // Risks
  if (inventory.risks.length > 0) {
    lines.push('## Risks');
    lines.push('| Level | Category | Description | Location |');
    lines.push('|-------|----------|-------------|----------|');
    for (const r of inventory.risks) {
      const loc = r.file ? `${r.file}${r.line ? ':' + r.line : ''}` : '-';
      lines.push(`| ${r.level.toUpperCase()} | ${r.category} | ${r.description} | ${loc} |`);
    }
    lines.push('');
  }

  // Security Metadata
  const e = inventory.summary.enrichment;
  if (e) {
    lines.push('## Security Metadata');
    lines.push('| Metric | Count | Notes |');
    lines.push('|--------|-------|-------|');
    if (e.totalAPIEndpoints > 0) lines.push(`| API Endpoints | ${e.totalAPIEndpoints} | ${e.totalExternalAPIs} external |`);
    if (e.totalDatabaseAccesses > 0) lines.push(`| Database Accesses | ${e.totalDatabaseAccesses} | ${e.unparameterizedQueries} unparameterized |`);
    if (e.totalAuthFlows > 0) lines.push(`| Auth Flows | ${e.totalAuthFlows} | |`);
    if (e.totalPermissionChecks > 0) lines.push(`| Permission Checks | ${e.totalPermissionChecks} | |`);
    if (e.totalPermissions > 0) lines.push(`| Prompt Permissions | ${e.totalPermissions} | |`);
    if (e.totalPIIReferences > 0) lines.push(`| PII References | ${e.totalPIIReferences} | ${e.piiWithoutMasking} unmasked |`);
    if (e.totalMessageQueues > 0) lines.push(`| Message Queues | ${e.totalMessageQueues} | |`);
    if (e.totalRateLimits > 0) lines.push(`| Rate Limits | ${e.totalRateLimits} | |`);
    if (e.totalCallGraphEdges > 0) lines.push(`| Call Graph Edges | ${e.totalCallGraphEdges} | |`);
    lines.push('');
  }

  // Summary
  const s = inventory.summary;
  lines.push('## Summary');
  lines.push(`- **Models:** ${s.totalModels}`);
  lines.push(`- **Frameworks:** ${s.totalFrameworks}`);
  lines.push(`- **Tools:** ${s.totalTools}`);
  lines.push(`- **Agents:** ${s.totalAgents}`);
  lines.push(`- **MCP Servers:** ${s.totalMCPServers}`);
  lines.push(`- **Vector DBs:** ${s.totalVectorDBs}`);
  lines.push(`- **Risks:** ${s.totalRisks} (${s.riskBreakdown.critical} critical, ${s.riskBreakdown.high} high, ${s.riskBreakdown.medium} medium, ${s.riskBreakdown.low} low)`);
  lines.push('');

  const md = lines.join('\n');

  if (outputPath) {
    fs.writeFileSync(outputPath, md, 'utf-8');
  }

  return md;
}
