import type { ScanResult } from '../types/score.js';
import type { Finding } from '../types/finding.js';
import * as fs from 'node:fs';

interface Control {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'partial';
  findings: string[];
  notes: string;
}

interface ComplianceResult {
  standard: string;
  standardName: string;
  controls: Control[];
  overallScore: number;
  passCount: number;
  failCount: number;
  partialCount: number;
}

const STANDARD_NAMES: Record<string, string> = {
  'owasp-agentic': 'OWASP Agentic Security Top 10',
  'aiuc1': 'AIUC-1 AI Agent Security',
  'iso42001': 'ISO 42001 AI Management System',
  'nist-ai-rmf': 'NIST AI Risk Management Framework',
  'iso23894': 'ISO 23894 AI Risk Management',
  'owasp-aivss': 'OWASP AI Verification Standard',
  'owasp-agentic-top10': 'OWASP Agentic AI Top 10',
  'soc2': 'SOC 2 Trust Criteria',
  'eu-ai-act': 'EU AI Act',
};

const STANDARD_CONTROLS: Record<string, Array<{ id: string; name: string; domains: string[] }>> = {
  'owasp-agentic': [
    { id: 'ASI01', name: 'Prompt Injection', domains: ['goal-integrity'] },
    { id: 'ASI02', name: 'Excessive Tool Access', domains: ['tool-safety'] },
    { id: 'ASI03', name: 'Privilege Escalation', domains: ['identity-access'] },
    { id: 'ASI04', name: 'Supply Chain Vulnerabilities', domains: ['supply-chain'] },
    { id: 'ASI05', name: 'Unsafe Code Execution', domains: ['code-execution'] },
    { id: 'ASI06', name: 'Data Leakage', domains: ['data-leakage'] },
    { id: 'ASI07', name: 'Memory/Context Manipulation', domains: ['memory-context'] },
    { id: 'ASI08', name: 'Cascading Failures', domains: ['cascading-failures'] },
    { id: 'ASI09', name: 'Improper Session Handling', domains: ['memory-context', 'identity-access'] },
    { id: 'ASI10', name: 'Excessive Autonomy', domains: ['goal-integrity', 'tool-safety', 'human-oversight', 'rogue-agent'] },
  ],
  'aiuc1': [
    { id: 'A001', name: 'Agent Identity', domains: ['identity-access'] },
    { id: 'A002', name: 'Agent Authentication', domains: ['identity-access'] },
    { id: 'B001', name: 'Tool Validation', domains: ['tool-safety'] },
    { id: 'B002', name: 'Permission Boundaries', domains: ['tool-safety', 'identity-access'] },
    { id: 'C001', name: 'Data Classification', domains: ['data-leakage'] },
    { id: 'C002', name: 'Data Flow Control', domains: ['data-leakage', 'memory-context'] },
    { id: 'D001', name: 'Execution Sandboxing', domains: ['code-execution'] },
    { id: 'D002', name: 'Resource Limits', domains: ['cascading-failures'] },
    { id: 'E001', name: 'Prompt Hardening', domains: ['goal-integrity'] },
    { id: 'E002', name: 'Injection Prevention', domains: ['goal-integrity', 'code-execution'] },
    { id: 'F001', name: 'Supply Chain Verification', domains: ['supply-chain'] },
    { id: 'F002', name: 'Quarterly Security Testing', domains: ['goal-integrity', 'tool-safety', 'identity-access', 'supply-chain', 'code-execution', 'memory-context', 'data-leakage', 'cascading-failures', 'human-oversight', 'inter-agent', 'reliability-bounds', 'rogue-agent'] },
  ],
  'nist-ai-rmf': [
    { id: 'GOVERN-1', name: 'AI Risk Policies', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: 'MAP-1', name: 'Context Mapping', domains: ['goal-integrity'] },
    { id: 'MAP-2', name: 'Task Purpose', domains: ['goal-integrity', 'tool-safety'] },
    { id: 'MEASURE-1', name: 'Risk Metrics', domains: ['goal-integrity', 'tool-safety', 'identity-access', 'data-leakage'] },
    { id: 'MEASURE-2', name: 'Performance Testing', domains: ['cascading-failures'] },
    { id: 'MANAGE-1', name: 'Risk Treatment', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: 'MANAGE-2', name: 'Deploy Monitoring', domains: ['cascading-failures', 'memory-context'] },
    { id: 'MANAGE-3', name: 'Incident Response', domains: ['cascading-failures'] },
    { id: 'MANAGE-4', name: 'Third Party Risk', domains: ['supply-chain', 'inter-agent'] },
    { id: 'MANAGE-5', name: 'Reliability & Bounds', domains: ['reliability-bounds'] },
  ],
  'iso42001': [
    { id: 'A.5.1', name: 'AI Policy', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: 'A.5.2', name: 'AI Roles', domains: ['identity-access'] },
    { id: 'A.6.1', name: 'Risk Assessment', domains: ['goal-integrity', 'tool-safety', 'identity-access', 'data-leakage'] },
    { id: 'A.6.2', name: 'Risk Treatment', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: 'A.7.1', name: 'AI Development', domains: ['code-execution', 'tool-safety'] },
    { id: 'A.7.2', name: 'Testing & Validation', domains: ['cascading-failures'] },
    { id: 'A.8.1', name: 'Data Management', domains: ['data-leakage', 'memory-context'] },
    { id: 'A.9.1', name: 'Third Party', domains: ['supply-chain'] },
    { id: 'A.10.1', name: 'Monitoring & Review', domains: ['cascading-failures', 'goal-integrity'] },
  ],
  'soc2': [
    { id: 'CC6.1', name: 'Logical Access', domains: ['identity-access'] },
    { id: 'CC6.3', name: 'Access Restrictions', domains: ['identity-access', 'tool-safety'] },
    { id: 'CC6.6', name: 'System Boundaries', domains: ['code-execution', 'cascading-failures'] },
    { id: 'CC6.7', name: 'Data Transmission', domains: ['data-leakage'] },
    { id: 'CC6.8', name: 'Unauthorized Software', domains: ['supply-chain'] },
    { id: 'CC7.1', name: 'Monitoring', domains: ['cascading-failures'] },
    { id: 'CC7.2', name: 'Anomaly Detection', domains: ['goal-integrity'] },
    { id: 'CC7.3', name: 'Security Evaluation', domains: ['goal-integrity', 'tool-safety', 'identity-access', 'data-leakage'] },
    { id: 'CC8.1', name: 'Change Management', domains: ['supply-chain'] },
  ],
  'eu-ai-act': [
    { id: 'Art.9.1', name: 'Risk Management', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: 'Art.9.2', name: 'Risk Identification', domains: ['goal-integrity', 'tool-safety'] },
    { id: 'Art.10.2', name: 'Data Quality', domains: ['data-leakage', 'memory-context'] },
    { id: 'Art.10.3', name: 'Data Governance', domains: ['data-leakage', 'identity-access'] },
    { id: 'Art.15.1', name: 'Accuracy', domains: ['goal-integrity'] },
    { id: 'Art.15.2', name: 'Resilience', domains: ['cascading-failures', 'code-execution'] },
    { id: 'Art.14.1', name: 'Human Oversight', domains: ['human-oversight'] },
    { id: 'Art.15.3', name: 'Cybersecurity', domains: ['identity-access', 'supply-chain'] },
  ],
  'iso23894': [
    { id: '6.1', name: 'Risk Identification', domains: ['goal-integrity', 'tool-safety'] },
    { id: '6.2', name: 'Risk Analysis', domains: ['goal-integrity', 'tool-safety', 'identity-access', 'data-leakage'] },
    { id: '6.3', name: 'Risk Evaluation', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: '6.4', name: 'Risk Treatment', domains: ['goal-integrity', 'tool-safety', 'identity-access'] },
    { id: '7.1', name: 'Communication', domains: ['cascading-failures'] },
    { id: '7.2', name: 'Monitoring', domains: ['cascading-failures', 'memory-context'] },
  ],
  'owasp-aivss': [
    { id: 'L1.1', name: 'Input Validation', domains: ['goal-integrity', 'code-execution'] },
    { id: 'L1.2', name: 'Output Validation', domains: ['code-execution', 'data-leakage'] },
    { id: 'L1.3', name: 'Model Security', domains: ['supply-chain'] },
    { id: 'L2.1', name: 'Data Protection', domains: ['data-leakage', 'memory-context'] },
    { id: 'L2.2', name: 'Access Control', domains: ['identity-access'] },
    { id: 'L2.3', name: 'Tool Security', domains: ['tool-safety'] },
    { id: 'L3.1', name: 'Advanced Threat Protection', domains: ['goal-integrity', 'cascading-failures'] },
    { id: 'L3.2', name: 'Supply Chain Security', domains: ['supply-chain'] },
  ],
  'owasp-agentic-top10': [
    { id: 'AAT-1', name: 'Agent Authorization Hijacking', domains: ['identity-access', 'tool-safety'] },
    { id: 'AAT-2', name: 'Agent Untraceability', domains: ['rogue-agent'] },
    { id: 'AAT-3', name: 'Agent Critical Systems Interaction', domains: ['code-execution', 'tool-safety'] },
    { id: 'AAT-4', name: 'Agent Alignment Faking', domains: ['reliability-bounds', 'rogue-agent'] },
    { id: 'AAT-5', name: 'Agent Goal Manipulation', domains: ['goal-integrity'] },
    { id: 'AAT-6', name: 'Agent Impact Chain / Blast Radius', domains: ['data-leakage', 'cascading-failures'] },
    { id: 'AAT-7', name: 'Agent Memory/Context Manipulation', domains: ['memory-context'] },
    { id: 'AAT-8', name: 'Multi-Agent Exploitation', domains: ['inter-agent'] },
    { id: 'AAT-9', name: 'Agent Supply Chain / Dependency Attacks', domains: ['supply-chain'] },
    { id: 'AAT-10', name: 'Agent Checker Out of Loop', domains: ['human-oversight'] },
  ],
};

function assessControl(
  controlDomains: string[],
  findingsByDomain: Map<string, Finding[]>,
): { status: 'pass' | 'fail' | 'partial'; matchedFindings: Finding[] } {
  const matched: Finding[] = [];
  for (const domain of controlDomains) {
    const domainFindings = findingsByDomain.get(domain) ?? [];
    matched.push(...domainFindings);
  }

  if (matched.length === 0) return { status: 'pass', matchedFindings: [] };

  const hasCriticalOrHigh = matched.some(
    (f) => f.severity === 'critical' || f.severity === 'high'
  );
  return {
    status: hasCriticalOrHigh ? 'fail' : 'partial',
    matchedFindings: matched,
  };
}

export function generateCompliance(standard: string, result: ScanResult): ComplianceResult {
  const controls = STANDARD_CONTROLS[standard];
  if (!controls) {
    throw new Error(`Unknown standard: ${standard}. Supported: ${Object.keys(STANDARD_CONTROLS).join(', ')}`);
  }

  // Group findings by domain
  const findingsByDomain = new Map<string, Finding[]>();
  for (const f of result.findings) {
    const existing = findingsByDomain.get(f.domain) ?? [];
    existing.push(f);
    findingsByDomain.set(f.domain, existing);
  }

  const assessed: Control[] = controls.map((c) => {
    const { status, matchedFindings } = assessControl(c.domains, findingsByDomain);
    const uniqueRules = [...new Set(matchedFindings.map((f) => f.ruleId))];

    let notes = '';
    if (status === 'pass') notes = 'No findings detected for mapped domains.';
    else if (status === 'fail') notes = `${matchedFindings.length} findings with critical/high severity.`;
    else notes = `${matchedFindings.length} findings (medium/low severity).`;

    return { id: c.id, name: c.name, status, findings: uniqueRules, notes };
  });

  const passCount = assessed.filter((c) => c.status === 'pass').length;
  const failCount = assessed.filter((c) => c.status === 'fail').length;
  const partialCount = assessed.filter((c) => c.status === 'partial').length;
  const overallScore = ((passCount + partialCount * 0.5) / assessed.length) * 100;

  return {
    standard,
    standardName: STANDARD_NAMES[standard] || standard,
    controls: assessed,
    overallScore,
    passCount,
    failCount,
    partialCount,
  };
}

export function reportComplianceHtml(
  result: ScanResult,
  standard: string,
  outputPath: string
): void {
  const compliance = generateCompliance(standard, result);

  const statusIcon = (s: string) =>
    s === 'pass' ? '&#x2705;' : s === 'fail' ? '&#x274C;' : '&#x26A0;';
  const statusColor = (s: string) =>
    s === 'pass' ? '#22c55e' : s === 'fail' ? '#ef4444' : '#f59e0b';

  const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>${compliance.standardName} — Guard0 Compliance Report</title>
<style>
body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e4e4e7;margin:0;padding:2rem;max-width:900px;margin:0 auto}
h1{font-size:1.5rem;font-weight:300;margin-bottom:.25rem}
.meta{color:#71717a;font-size:.875rem;margin-bottom:2rem}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.card{background:#18181b;border:1px solid #27272a;border-radius:.5rem;padding:1rem;text-align:center}
.card .value{font-size:2rem;font-weight:600}
.card .label{font-size:.75rem;color:#71717a;margin-top:.25rem}
table{width:100%;border-collapse:collapse;margin-top:1rem}
th{text-align:left;font-size:.75rem;color:#71717a;border-bottom:1px solid #27272a;padding:.5rem}
td{padding:.75rem .5rem;border-bottom:1px solid #18181b;font-size:.875rem;vertical-align:top}
.status{font-weight:600}
.findings{font-family:monospace;font-size:.75rem;color:#71717a}
.notes{font-size:.75rem;color:#a1a1aa;max-width:300px}
footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #27272a;font-size:.75rem;color:#52525b}
</style></head>
<body>
<h1>${compliance.standardName}</h1>
<div class="meta">
Score: ${result.score.overall}/100 (${result.score.grade}) &middot;
${result.findings.length} total findings &middot;
Generated ${new Date().toISOString().split('T')[0]} by Guard0
</div>
<div class="summary">
<div class="card"><div class="value" style="color:#3b82f6">${Math.round(compliance.overallScore)}%</div><div class="label">Compliance Score</div></div>
<div class="card"><div class="value" style="color:#22c55e">${compliance.passCount}</div><div class="label">Pass</div></div>
<div class="card"><div class="value" style="color:#f59e0b">${compliance.partialCount}</div><div class="label">Partial</div></div>
<div class="card"><div class="value" style="color:#ef4444">${compliance.failCount}</div><div class="label">Fail</div></div>
</div>
<table>
<thead><tr><th>Status</th><th>Control</th><th>Name</th><th>Findings</th><th>Notes</th></tr></thead>
<tbody>
${compliance.controls
  .map(
    (c) => `<tr>
<td class="status" style="color:${statusColor(c.status)}">${statusIcon(c.status)} ${c.status.toUpperCase()}</td>
<td><code>${c.id}</code></td>
<td>${c.name}</td>
<td class="findings">${c.findings.length > 0 ? c.findings.join(', ') : '—'}</td>
<td class="notes">${c.notes}</td>
</tr>`
  )
  .join('')}
</tbody></table>
<footer>
<p>Guard0 AI Agent Security Scanner &middot; guard0.ai</p>
<p>Standard: ${compliance.standardName} &middot; ${compliance.controls.length} controls assessed</p>
</footer>
</body></html>`;

  fs.writeFileSync(outputPath, html, 'utf-8');
}

export const SUPPORTED_STANDARDS = Object.keys(STANDARD_CONTROLS);
