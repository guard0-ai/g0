import { z } from 'zod';
import { verifyNpmPackage } from '../../npm-verify.js';
import type { MCPVerifyResult, MCPVerifyRisk } from '../../npm-verify.js';
import { textResult, type ToolResult } from './util.js';

export const verifyMcpPackageInputShape = {
  package: z.string().describe('npm package name to verify, e.g. "@modelcontextprotocol/server-filesystem"'),
};

export interface VerifyMcpPackageInput {
  package: string;
}

export const verifyMcpPackageDescription =
  'Check whether an npm package is safe to install as an MCP server: install scripts, package age, ' +
  'download counts, maintainer count, and repository presence. NETWORK CALL: this tool queries the ' +
  'public npm registry (registry.npmjs.org and api.npmjs.org) for the package — it does not download ' +
  'or execute the package itself.';

export type VerifyRecommendation = 'safe-to-install' | 'review' | 'do-not-install';

/**
 * Pure mapping from `verifyNpmPackage`'s overall risk to an install
 * recommendation. Exported separately so it's trivially unit-testable
 * without a network call.
 */
export function mapRiskToRecommendation(overallRisk: MCPVerifyResult['overallRisk']): VerifyRecommendation {
  switch (overallRisk) {
    case 'low':
      return 'safe-to-install';
    case 'medium':
      return 'review';
    case 'high':
    case 'critical':
      return 'do-not-install';
    default:
      return 'review';
  }
}

function formatRisk(risk: MCPVerifyRisk): string {
  return `- [${risk.severity.toUpperCase()}] ${risk.type}: ${risk.description}`;
}

/**
 * `verify_mcp_package` tool handler. The one read-only network exception in
 * the MCP tool surface — makes a request to the npm registry.
 */
export async function verifyMcpPackage(args: VerifyMcpPackageInput): Promise<ToolResult> {
  const result = await verifyNpmPackage(args.package);
  const recommendation = mapRiskToRecommendation(result.overallRisk);

  const lines: string[] = [];
  lines.push(`# npm package verification: ${result.package}`);
  lines.push('');
  if (!result.found) {
    lines.push('**Package not found on the npm registry.**');
  } else {
    lines.push(`**Version:** ${result.version}`);
    lines.push(`**Overall risk:** ${result.overallRisk}`);
    lines.push(`**Recommendation:** ${recommendation}`);
    if (result.publisher) lines.push(`**Publisher:** ${result.publisher}`);
    if (result.maintainers.length) lines.push(`**Maintainers:** ${result.maintainers.join(', ')}`);
    if (result.packageAge !== undefined) lines.push(`**Package age:** ${result.packageAge} days`);
    if (result.weeklyDownloads !== undefined) lines.push(`**Weekly downloads:** ${result.weeklyDownloads}`);
    if (result.license) lines.push(`**License:** ${result.license}`);
    if (result.repository) lines.push(`**Repository:** ${result.repository}`);
  }

  if (result.risks.length > 0) {
    lines.push('');
    lines.push('## Signals');
    for (const risk of result.risks) lines.push(formatRisk(risk));
  }

  const markdown = lines.join('\n') + '\n';

  return textResult(markdown, {
    package: result.package,
    version: result.version,
    found: result.found,
    overallRisk: result.overallRisk,
    recommendation,
    risks: result.risks,
    hasInstallScripts: result.hasInstallScripts,
    packageAge: result.packageAge,
    weeklyDownloads: result.weeklyDownloads,
    maintainers: result.maintainers,
    repository: result.repository,
    license: result.license,
  });
}
