// Org-wide HTML report renderer for sentinel snapshots.
//
// Takes a fleet of MachineSnapshots and renders a single self-contained HTML
// document: fleet summary, aggregate PII exposure (classes + counts only), and
// a per-machine breakdown of tools, exposures, and governance verdicts.
//
// Contract, inherited from the snapshot/exposure engines: this report carries
// PII CLASSES and COUNTS only — never raw values. File locators (which may embed
// usernames as host identity) are HTML-escaped but otherwise shown as-is.

import type { MachineSnapshot } from './snapshot.js';
import type { PiiCounts } from './pii.js';
import type { ToolExposure } from './exposure.js';

export interface OrgReportSummary {
  machines: number;
  totalTools: number; // distinct installed tool names across the fleet
  totalPii: number; // sum of all piiSummary counts across machines
  nonCompliant: number; // machines whose governance.compliant === false
  topTools: Array<{ name: string; machines: number }>; // most-common installed tools, desc
}

/** Escape a value for safe interpolation into HTML text/attributes. */
function esc(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Sum per-class PII counts across many count maps. */
function accumulate(list: PiiCounts[]): PiiCounts {
  const out: Record<string, number> = {};
  for (const counts of list) {
    for (const [cls, n] of Object.entries(counts ?? {})) {
      out[cls] = (out[cls] ?? 0) + (n ?? 0);
    }
  }
  return out as PiiCounts;
}

/**
 * PII classes+counts for one snapshot. Prefers the precomputed piiSummary; for
 * older/edge snapshots that lack it, falls back to merging per-tool evidenced
 * counts so the report stays accurate.
 */
function snapshotPii(snap: MachineSnapshot): PiiCounts {
  if (snap.piiSummary) return snap.piiSummary;
  return accumulate((snap.exposures ?? []).map((e) => e.evidenced ?? {}));
}

/** Total distinct PII items in a count map. */
function sumCounts(counts: PiiCounts): number {
  let total = 0;
  for (const n of Object.values(counts ?? {})) total += n ?? 0;
  return total;
}

export function summarizeOrg(snapshots: MachineSnapshot[]): OrgReportSummary {
  const installedByTool = new Map<string, number>();
  let totalPii = 0;
  let nonCompliant = 0;

  for (const snap of snapshots) {
    const seen = new Set<string>();
    for (const t of snap.tools ?? []) {
      if (!t.installed || seen.has(t.name)) continue;
      seen.add(t.name);
      installedByTool.set(t.name, (installedByTool.get(t.name) ?? 0) + 1);
    }
    totalPii += sumCounts(snapshotPii(snap));
    if (snap.governance && snap.governance.compliant === false) nonCompliant += 1;
  }

  const topTools = [...installedByTool.entries()]
    .map(([name, machines]) => ({ name, machines }))
    .sort((a, b) => b.machines - a.machines || a.name.localeCompare(b.name));

  return {
    machines: snapshots.length,
    totalTools: installedByTool.size,
    totalPii,
    nonCompliant,
    topTools,
  };
}

/** Render a PII count map as an escaped "class:count, ..." fragment. */
function renderPiiInline(counts: PiiCounts): string {
  const entries = Object.entries(counts ?? {}).filter(([, n]) => (n ?? 0) > 0);
  if (entries.length === 0) return '<span class="muted">none</span>';
  return entries
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0))
    .map(([cls, n]) => `<span class="pii">${esc(cls)}:${esc(n)}</span>`)
    .join(' ');
}

/** Fleet-wide PII table (classes + counts, descending). */
function renderFleetPii(snapshots: MachineSnapshot[]): string {
  const fleet = accumulate(snapshots.map(snapshotPii));
  const rows = Object.entries(fleet)
    .filter(([, n]) => (n ?? 0) > 0)
    .sort((a, b) => (b[1] ?? 0) - (a[1] ?? 0));
  if (rows.length === 0) {
    return '<p class="muted">No PII evidenced across the fleet.</p>';
  }
  const body = rows
    .map(([cls, n]) => `<tr><td>${esc(cls)}</td><td class="num">${esc(n)}</td></tr>`)
    .join('\n');
  return `<table class="tbl">
  <thead><tr><th>PII class</th><th class="num">Count (fleet)</th></tr></thead>
  <tbody>
${body}
  </tbody>
</table>`;
}

/** Per-tool exposure rows for one machine, including governance verdicts if present. */
function renderExposureTable(
  exposures: ToolExposure[],
  verdicts: Map<string, { verdict: string; rule?: string }>,
  hasGovernance: boolean,
): string {
  if (exposures.length === 0) {
    return '<p class="muted">No tool exposures recorded.</p>';
  }
  const govHead = hasGovernance ? '<th>Verdict</th>' : '';
  const rows = exposures
    .map((exp) => {
      const mcp = (exp.reach?.mcpServers ?? []).map((s) => esc(s)).join(', ') || '<span class="muted">none</span>';
      let govCell = '';
      if (hasGovernance) {
        const v = verdicts.get(exp.tool);
        if (v) {
          const rule = v.rule ? ` <span class="muted">(${esc(v.rule)})</span>` : '';
          govCell = `<td><span class="verdict verdict-${esc(v.verdict)}">${esc(v.verdict)}</span>${rule}</td>`;
        } else {
          govCell = '<td class="muted">—</td>';
        }
      }
      const locators = (exp.locators ?? []).filter((l) => l && l.path);
      const evidence =
        locators.length > 0
          ? `<div class="locators">evidence: ${locators
              .map((l) => `${esc(l.path)} (${renderPiiInline(l.counts)})`)
              .join('; ')}</div>`
          : '';
      return `<tr>
      <td>${esc(exp.tool)}${evidence}</td>
      <td>${esc(exp.category)}</td>
      <td class="num">${esc(exp.riskScore)}</td>
      <td>${renderPiiInline(exp.evidenced ?? {})}</td>
      <td>${mcp}</td>
      ${govCell}
    </tr>`;
    })
    .join('\n');
  return `<table class="tbl">
  <thead><tr><th>Tool</th><th>Category</th><th class="num">Risk</th><th>PII (class:count)</th><th>MCP reach</th>${govHead}</tr></thead>
  <tbody>
${rows}
  </tbody>
</table>`;
}

/** One machine section: host identity, endpoint score, tools, exposures, compliance. */
function renderMachine(snap: MachineSnapshot): string {
  const host = snap.host ?? { hostname: 'unknown', platform: 'unknown', arch: 'unknown' };
  const installed = (snap.tools ?? []).filter((t) => t.installed);
  const toolNames =
    installed.length > 0
      ? installed.map((t) => `<span class="chip">${esc(t.name)}</span>`).join(' ')
      : '<span class="muted">none installed</span>';

  const gov = snap.governance;
  const hasGovernance = !!gov;
  const verdicts = new Map<string, { verdict: string; rule?: string }>();
  for (const v of gov?.verdicts ?? []) verdicts.set(v.tool, { verdict: v.verdict, rule: v.rule });

  let badge: string;
  if (!gov) {
    badge = '<span class="badge badge-neutral">no policy</span>';
  } else if (gov.compliant === false) {
    badge = '<span class="badge badge-bad">NON-COMPLIANT</span>';
  } else {
    badge = '<span class="badge badge-ok">compliant</span>';
  }
  const policy = gov?.policyName ? ` <span class="muted">policy: ${esc(gov.policyName)}</span>` : '';

  const score = typeof snap.endpointScore === 'number' ? esc(snap.endpointScore) : '—';

  return `<section class="machine">
  <h3>${esc(host.hostname)} ${badge}</h3>
  <div class="meta">
    <span>${esc(host.platform)} / ${esc(host.arch)}</span>
    <span>endpoint score: <strong>${score}</strong></span>
    <span>${esc(installed.length)} tool(s) installed</span>${policy}
  </div>
  <div class="tools">${toolNames}</div>
  ${renderExposureTable(snap.exposures ?? [], verdicts, hasGovernance)}
</section>`;
}

const STYLE = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1a1a1a; background: #f6f7f9; }
.wrap { max-width: 1040px; margin: 0 auto; padding: 32px 20px 64px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 12px; border-bottom: 1px solid #d9dce1; padding-bottom: 6px; }
h3 { font-size: 15px; margin: 0 0 8px; display: flex; align-items: center; gap: 10px; }
.sub { color: #6b7280; margin: 0 0 20px; }
.cards { display: flex; flex-wrap: wrap; gap: 12px; }
.card { flex: 1 1 160px; background: #fff; border: 1px solid #e4e6ea; border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 700; }
.card .l { color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.card.bad .n { color: #c0392b; }
.machine { background: #fff; border: 1px solid #e4e6ea; border-radius: 10px; padding: 16px 18px; margin: 14px 0; }
.meta { display: flex; flex-wrap: wrap; gap: 14px; color: #4b5563; font-size: 13px; margin-bottom: 10px; }
.tools { margin-bottom: 12px; }
.chip { display: inline-block; background: #eef1f5; border-radius: 6px; padding: 2px 8px; font-size: 12px; margin: 0 4px 4px 0; }
.tbl { width: 100%; border-collapse: collapse; font-size: 13px; }
.tbl th, .tbl td { text-align: left; padding: 7px 10px; border-bottom: 1px solid #edeff2; vertical-align: top; }
.tbl th { color: #6b7280; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; }
.tbl .num { text-align: right; font-variant-numeric: tabular-nums; }
.pii { display: inline-block; background: #fdecea; color: #b03a2e; border-radius: 5px; padding: 1px 6px; font-size: 12px; margin: 0 3px 3px 0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.muted { color: #9aa1ab; }
.locators { color: #8a919c; font-size: 11px; margin-top: 4px; word-break: break-all; }
.badge { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; text-transform: uppercase; letter-spacing: .04em; }
.badge-ok { background: #e6f4ea; color: #1e7e34; }
.badge-bad { background: #fbe3e0; color: #c0392b; }
.badge-neutral { background: #eef1f5; color: #6b7280; }
.verdict { font-weight: 600; }
.verdict-allow { color: #1e7e34; }
.verdict-deny { color: #c0392b; }
.verdict-monitor { color: #b7791f; }
footer { color: #9aa1ab; font-size: 12px; margin-top: 32px; }
@media (prefers-color-scheme: dark) {
  body { background: #16181d; color: #e6e8ec; }
  .card, .machine { background: #1e2127; border-color: #2c303a; }
  .card .l, .sub, .meta, .tbl th, .muted, footer { color: #9aa1ab; }
  h2 { border-color: #2c303a; }
  .chip { background: #2a2e37; }
  .tbl th, .tbl td { border-color: #2a2e37; }
  .pii { background: #3a2320; color: #f0a89e; }
  .badge-ok { background: #14351f; color: #6bbf7f; }
  .badge-bad { background: #3a1f1c; color: #ef8a7d; }
  .badge-neutral { background: #2a2e37; color: #9aa1ab; }
}
`;

export function renderOrgReportHtml(snapshots: MachineSnapshot[]): string {
  const list = snapshots ?? [];
  const summary = summarizeOrg(list);
  const generatedAt = new Date().toISOString();

  const machines = list.map(renderMachine).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>g0 sentinel — org report</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
  <h1>g0 sentinel — org report</h1>
  <p class="sub">Fleet AI-tool PII exposure and governance. Classes and counts only — no raw values.</p>

  <div class="cards">
    <div class="card"><div class="n">${esc(summary.machines)}</div><div class="l">Machines</div></div>
    <div class="card"><div class="n">${esc(summary.totalTools)}</div><div class="l">Distinct tools</div></div>
    <div class="card"><div class="n">${esc(summary.totalPii)}</div><div class="l">PII items</div></div>
    <div class="card ${summary.nonCompliant > 0 ? 'bad' : ''}"><div class="n">${esc(summary.nonCompliant)}</div><div class="l">Non-compliant</div></div>
  </div>

  <h2>Fleet PII exposure</h2>
  ${renderFleetPii(list)}

  <h2>Machines (${esc(list.length)})</h2>
  ${machines || '<p class="muted">No machines in report.</p>'}

  <footer>Generated ${esc(generatedAt)} · g0 sentinel</footer>
</div>
</body>
</html>`;
}
