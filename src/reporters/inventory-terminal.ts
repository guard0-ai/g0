import chalk from 'chalk';
import type { InventoryResult, RiskLevel } from '../types/inventory.js';

export function reportInventoryTerminal(inventory: InventoryResult): void {
  console.log(chalk.bold('\n  AI Agent Bill of Materials (AI-BOM)'));
  console.log(chalk.dim('  ' + '═'.repeat(60)));

  // Models
  if (inventory.models.length > 0) {
    console.log(chalk.bold.cyan('\n  Models'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const m of inventory.models) {
      console.log(`  ${chalk.bold(m.name)} ${chalk.dim(`(${m.provider})`)} ${chalk.dim(`[${m.framework}]`)} ${chalk.dim(`${m.file}:${m.line}`)}`);
    }
  }

  // Frameworks
  if (inventory.frameworks.length > 0) {
    console.log(chalk.bold.cyan('\n  Frameworks & Dependencies'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const f of inventory.frameworks) {
      const ver = f.version ? chalk.green(`v${f.version}`) : chalk.yellow('unpinned');
      console.log(`  ${chalk.bold(f.name)} ${ver} ${chalk.dim(f.file)}`);
    }
  }

  // Agents
  if (inventory.agents.length > 0) {
    console.log(chalk.bold.cyan('\n  Agents'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const a of inventory.agents) {
      const model = a.model ? chalk.dim(` model=${a.model}`) : '';
      const delegation = a.hasDelegation ? chalk.yellow(' [delegation]') : '';
      console.log(`  ${chalk.bold(a.name)} ${chalk.dim(`[${a.framework}]`)} tools=${a.toolCount}${model}${delegation} ${chalk.dim(`${a.file}:${a.line}`)}`);
    }
  }

  // Tools
  if (inventory.tools.length > 0) {
    console.log(chalk.bold.cyan('\n  Tools'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const t of inventory.tools) {
      const caps = t.capabilities.join(',');
      const sideEffect = t.hasSideEffects ? chalk.red(' [side-effects]') : '';
      const validated = t.hasValidation ? chalk.green(' [validated]') : '';
      const desc = t.description ? chalk.dim(` "${t.description.substring(0, 50)}${t.description.length > 50 ? '...' : ''}"`) : '';
      console.log(`  ${chalk.bold(t.name)} ${chalk.dim(`(${caps})`)}${sideEffect}${validated}${desc}`);
      console.log(`    ${chalk.dim(`${t.file}:${t.line}`)}`);
    }
  }

  // MCP Servers
  if (inventory.mcpServers.length > 0) {
    console.log(chalk.bold.cyan('\n  MCP Servers'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const s of inventory.mcpServers) {
      const pinned = s.isPinned ? chalk.green(' [pinned]') : chalk.yellow(' [unpinned]');
      const secrets = s.hasSecrets ? chalk.red(' [secrets]') : '';
      console.log(`  ${chalk.bold(s.name)} ${chalk.dim(s.command)}${pinned}${secrets} ${chalk.dim(s.file)}`);
    }
  }

  // Vector DBs
  if (inventory.vectorDBs.length > 0) {
    console.log(chalk.bold.cyan('\n  Vector Databases'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const v of inventory.vectorDBs) {
      console.log(`  ${chalk.bold(v.name)} ${chalk.dim(`[${v.framework}]`)} ${chalk.dim(`${v.file}:${v.line}`)}`);
    }
  }

  // Risks
  if (inventory.risks.length > 0) {
    console.log(chalk.bold.red('\n  Risks'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    for (const r of inventory.risks) {
      const badge = riskBadge(r.level);
      const loc = r.file ? chalk.dim(` ${r.file}${r.line ? ':' + r.line : ''}`) : '';
      console.log(`  ${badge} ${r.description}${loc}`);
    }
  }

  // Enrichment
  const e = inventory.summary.enrichment;
  if (e) {
    console.log(chalk.bold.cyan('\n  Security Metadata'));
    console.log(chalk.dim('  ' + '─'.repeat(60)));
    const items: string[] = [];
    if (e.totalAPIEndpoints > 0) items.push(`API Endpoints: ${e.totalAPIEndpoints} (${e.totalExternalAPIs} external)`);
    if (e.totalDatabaseAccesses > 0) {
      let db = `DB Accesses: ${e.totalDatabaseAccesses}`;
      if (e.unparameterizedQueries > 0) db += chalk.red(` (${e.unparameterizedQueries} unparameterized)`);
      items.push(db);
    }
    if (e.totalAuthFlows > 0) items.push(`Auth Flows: ${e.totalAuthFlows}`);
    if (e.totalPermissionChecks > 0) items.push(`Permission Checks: ${e.totalPermissionChecks}`);
    if (e.totalPermissions > 0) items.push(`Prompt Permissions: ${e.totalPermissions}`);
    if (e.totalPIIReferences > 0) {
      let pii = `PII References: ${e.totalPIIReferences}`;
      if (e.piiWithoutMasking > 0) pii += chalk.yellow(` (${e.piiWithoutMasking} unmasked)`);
      items.push(pii);
    }
    if (e.totalMessageQueues > 0) items.push(`Message Queues: ${e.totalMessageQueues}`);
    if (e.totalRateLimits > 0) items.push(`Rate Limits: ${e.totalRateLimits}`);
    if (e.totalCallGraphEdges > 0) items.push(`Call Graph Edges: ${e.totalCallGraphEdges}`);
    for (const item of items) {
      console.log(`  ${item}`);
    }
  }

  // Summary
  console.log(chalk.bold('\n  Summary'));
  console.log(chalk.dim('  ' + '─'.repeat(60)));
  const s = inventory.summary;
  console.log(`  Models: ${s.totalModels}  Frameworks: ${s.totalFrameworks}  Tools: ${s.totalTools}  Agents: ${s.totalAgents}`);
  if (s.totalMCPServers > 0) console.log(`  MCP Servers: ${s.totalMCPServers}  Vector DBs: ${s.totalVectorDBs}`);
  if (s.totalRisks > 0) {
    const rb = s.riskBreakdown;
    console.log(`  Risks: ${chalk.bgRed.white.bold(` ${rb.critical} CRIT `)} ${chalk.red.bold(`${rb.high} HIGH`)} ${chalk.yellow(`${rb.medium} MED`)} ${chalk.blue(`${rb.low} LOW`)}`);
  }
  console.log('');
}

function riskBadge(level: RiskLevel): string {
  switch (level) {
    case 'critical': return chalk.bgRed.white.bold(' CRIT ');
    case 'high': return chalk.red.bold(' HIGH ');
    case 'medium': return chalk.yellow(' MED  ');
    case 'low': return chalk.blue(' LOW  ');
  }
}
