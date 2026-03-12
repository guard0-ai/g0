import * as fs from 'node:fs';
import type { ScanResult } from '../types/score.js';
import type { Finding } from '../types/finding.js';

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

export function reportJunit(result: ScanResult, outputPath?: string): string {
  // Group findings by domain
  const byDomain = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const domain = finding.domain;
    if (!byDomain.has(domain)) {
      byDomain.set(domain, []);
    }
    byDomain.get(domain)!.push(finding);
  }

  const totalTests = result.findings.length;
  const totalFailures = result.findings.filter(
    f => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium',
  ).length;

  const lines: string[] = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="g0-scan" tests="${totalTests}" failures="${totalFailures}">`,
  ];

  for (const [domain, findings] of byDomain) {
    const suiteFailures = findings.filter(
      f => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium',
    ).length;

    lines.push(`  <testsuite name="${escapeXml(domain)}" tests="${findings.length}" failures="${suiteFailures}">`);

    for (const finding of findings) {
      const isFail = finding.severity === 'critical' || finding.severity === 'high' || finding.severity === 'medium';
      lines.push(`    <testcase name="${escapeXml(finding.ruleId)}" classname="${escapeXml(domain)}">`);

      if (isFail) {
        const message = escapeXml(finding.title);
        const body = `File: ${finding.location.file}:${finding.location.line}\nRule: ${finding.ruleId} - ${finding.title}${finding.remediation ? `\nRemediation: ${finding.remediation}` : ''}`;
        lines.push(`      <failure message="${message}" type="${escapeXml(finding.severity)}">`);
        lines.push(`        ${escapeXml(body)}`);
        lines.push('      </failure>');
      }

      lines.push('    </testcase>');
    }

    lines.push('  </testsuite>');
  }

  lines.push('</testsuites>');

  const xml = lines.join('\n');

  if (outputPath) {
    fs.writeFileSync(outputPath, xml, 'utf-8');
  }

  return xml;
}
