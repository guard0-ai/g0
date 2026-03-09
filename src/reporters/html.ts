import * as fs from 'node:fs';
import Handlebars from 'handlebars';
import type { ScanResult } from '../types/score.js';

const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>g0 Security Report — {{framework}}</title>
<style>
  :root { --bg: #0f172a; --surface: #1e293b; --border: #334155; --text: #e2e8f0; --dim: #94a3b8; --green: #22c55e; --yellow: #eab308; --red: #ef4444; --blue: #3b82f6; --cyan: #06b6d4; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); padding: 2rem; max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.5rem; margin-bottom: 0.5rem; }
  h2 { font-size: 1.2rem; margin: 2rem 0 1rem; color: var(--cyan); }
  .meta { color: var(--dim); font-size: 0.875rem; margin-bottom: 2rem; }
  .grade-box { display: inline-flex; align-items: center; gap: 1rem; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem 2rem; margin: 1rem 0; }
  .grade { font-size: 3rem; font-weight: 800; }
  .grade-a { color: var(--green); }
  .grade-b { color: var(--green); }
  .grade-c { color: var(--yellow); }
  .grade-d { color: var(--red); }
  .grade-f { color: var(--red); }
  .score-num { font-size: 1.5rem; color: var(--dim); }
  .bar-container { background: var(--surface); border-radius: 4px; height: 8px; width: 200px; }
  .bar-fill { height: 8px; border-radius: 4px; }
  .bar-green { background: var(--green); }
  .bar-yellow { background: var(--yellow); }
  .bar-red { background: var(--red); }
  .summary { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
  .summary-item { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 0.75rem 1rem; text-align: center; min-width: 80px; }
  .summary-count { font-size: 1.5rem; font-weight: 700; }
  .summary-label { font-size: 0.75rem; color: var(--dim); text-transform: uppercase; }
  .crit .summary-count { color: var(--red); }
  .high .summary-count { color: #f97316; }
  .med .summary-count { color: var(--yellow); }
  .low .summary-count { color: var(--blue); }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.875rem; }
  th { color: var(--dim); font-weight: 600; }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin: 0.75rem 0; }
  .finding-header { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
  .badge-critical { background: var(--red); color: white; }
  .badge-high { background: #f97316; color: white; }
  .badge-medium { background: var(--yellow); color: #000; }
  .badge-low { background: var(--blue); color: white; }
  .badge-info { background: var(--dim); color: white; }
  .finding-title { font-weight: 600; }
  .finding-desc { color: var(--dim); font-size: 0.875rem; margin: 0.25rem 0; }
  .finding-loc { color: var(--dim); font-size: 0.8rem; font-family: monospace; }
  .finding-fix { color: var(--cyan); font-size: 0.85rem; margin-top: 0.5rem; }
  .footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--dim); font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<h1>g0 Security Report</h1>
<div class="meta">
  <div>Target: {{target}} | Framework: {{framework}}</div>
  <div>{{timestamp}} | Duration: {{duration}}s | Files: {{fileCount}}{{#if activePreset}} | Preset: {{activePreset}}{{/if}}</div>
  {{#if analyzability}}<div>Analyzability: {{analyzability.score}}% ({{analyzability.opaqueFileCount}} opaque files)</div>{{/if}}
</div>

<div class="grade-box">
  <div class="grade grade-{{gradeLower}}">{{grade}}</div>
  <div>
    <div class="score-num">{{overall}} / 100</div>
    <div class="bar-container"><div class="bar-fill {{barColor}}" style="width: {{overall}}%"></div></div>
  </div>
</div>

<div class="summary">
  <div class="summary-item crit"><div class="summary-count">{{critical}}</div><div class="summary-label">Critical</div></div>
  <div class="summary-item high"><div class="summary-count">{{high}}</div><div class="summary-label">High</div></div>
  <div class="summary-item med"><div class="summary-count">{{medium}}</div><div class="summary-label">Medium</div></div>
  <div class="summary-item low"><div class="summary-count">{{low}}</div><div class="summary-label">Low</div></div>
</div>

<h2>Domain Scores</h2>
<table>
  <thead><tr><th>Domain</th><th>Score</th><th>Findings</th></tr></thead>
  <tbody>
  {{#each domains}}
  <tr><td>{{label}}</td><td>{{score}}</td><td>{{findings}}</td></tr>
  {{/each}}
  </tbody>
</table>

{{#if hasFindings}}
<h2>Findings ({{findingCount}})</h2>
{{#each findings}}
<div class="finding">
  <div class="finding-header">
    <span class="badge badge-{{severity}}">{{severity}}</span>
    <span class="finding-title">{{title}}</span>
    <span class="finding-loc">[{{ruleId}}]</span>
  </div>
  <div class="finding-desc">{{description}}</div>
  <div class="finding-loc">{{file}}:{{line}}</div>
  {{#if remediation}}<div class="finding-fix">Fix: {{remediation}}</div>{{/if}}
  {{#if standardsText}}<div class="finding-loc">Standards: {{standardsText}}</div>{{/if}}
</div>
{{/each}}
{{/if}}

<div class="footer">Generated by g0 v0.1.0 — AI Agent Security Scanner by Guard0.ai</div>
</body>
</html>`;

export function reportHtml(result: ScanResult, outputPath: string): void {
  const template = Handlebars.compile(HTML_TEMPLATE);

  const data = {
    target: result.graph.rootPath,
    framework: result.graph.primaryFramework,
    timestamp: result.timestamp,
    duration: (result.duration / 1000).toFixed(1),
    fileCount: result.graph.files.all.length,
    grade: result.score.grade,
    gradeLower: result.score.grade.toLowerCase(),
    overall: result.score.overall,
    barColor: result.score.overall >= 80 ? 'bar-green' : result.score.overall >= 60 ? 'bar-yellow' : 'bar-red',
    activePreset: result.activePreset,
    analyzability: result.analyzability ? {
      score: result.analyzability.score,
      opaqueFileCount: result.analyzability.opaqueFiles.length,
    } : undefined,
    critical: result.findings.filter(f => f.severity === 'critical').length,
    high: result.findings.filter(f => f.severity === 'high').length,
    medium: result.findings.filter(f => f.severity === 'medium').length,
    low: result.findings.filter(f => f.severity === 'low').length,
    domains: result.score.domains,
    hasFindings: result.findings.length > 0,
    findingCount: result.findings.length,
    findings: result.findings.map(f => {
      const refs: string[] = [];
      if (f.standards.owaspAgentic?.length) refs.push(`OWASP: ${f.standards.owaspAgentic.join(', ')}`);
      if (f.standards.aiuc1?.length) refs.push(`AIUC-1: ${f.standards.aiuc1.join(', ')}`);
      if (f.standards.iso42001?.length) refs.push(`ISO 42001: ${f.standards.iso42001.join(', ')}`);
      if (f.standards.nistAiRmf?.length) refs.push(`NIST AI RMF: ${f.standards.nistAiRmf.join(', ')}`);
      return {
        severity: f.severity,
        title: f.title,
        ruleId: f.ruleId,
        description: f.description,
        file: f.location.file,
        line: f.location.line,
        remediation: f.remediation,
        standardsText: refs.join(' | '),
      };
    }),
  };

  const html = template(data);
  fs.writeFileSync(outputPath, html, 'utf-8');
}
