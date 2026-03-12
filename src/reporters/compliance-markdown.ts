import type { ScanResult } from '../types/score.js';
import * as fs from 'node:fs';
import { generateCompliance, SUPPORTED_STANDARDS } from './compliance-html.js';

export { SUPPORTED_STANDARDS };

function statusIcon(s: string): string {
  return s === 'pass' ? '✅' : s === 'fail' ? '❌' : '⚠️';
}

export function reportComplianceMarkdown(
  result: ScanResult,
  standard: string,
  outputPath: string,
): void {
  const compliance = generateCompliance(standard, result);
  const date = new Date().toISOString().split('T')[0];

  const lines: string[] = [];

  lines.push(`# ${compliance.standardName} — Compliance Report`);
  lines.push('');
  lines.push(`**Score:** ${result.score.overall}/100 (${result.score.grade})  `);
  lines.push(`**Findings:** ${result.findings.length}  `);
  lines.push(`**Generated:** ${date} by Guard0`);
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Compliance Score | ${Math.round(compliance.overallScore)}% |`);
  lines.push(`| Pass | ${compliance.passCount} |`);
  lines.push(`| Partial | ${compliance.partialCount} |`);
  lines.push(`| Fail | ${compliance.failCount} |`);
  lines.push('');

  // Controls table
  lines.push('## Controls');
  lines.push('');
  lines.push('| Status | Control | Name | Findings | Notes |');
  lines.push('|--------|---------|------|----------|-------|');

  for (const c of compliance.controls) {
    const icon = statusIcon(c.status);
    const findings = c.findings.length > 0 ? c.findings.map((f) => `\`${f}\``).join(', ') : '—';
    lines.push(`| ${icon} ${c.status.toUpperCase()} | \`${c.id}\` | ${c.name} | ${findings} | ${c.notes} |`);
  }

  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push(`*Guard0 AI Agent Security Scanner · guard0.ai*  `);
  lines.push(`*Standard: ${compliance.standardName} · ${compliance.controls.length} controls assessed*`);
  lines.push('');

  fs.writeFileSync(outputPath, lines.join('\n'), 'utf-8');
}
