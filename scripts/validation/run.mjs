import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const G0 = '/Users/jayesh/guard0-ai/g0/dist/bin/g0.js';

// Expected-detection keywords per vuln target (efficacy ground truth).
const EXPECT = {
  v1_shell_injection: /shell|subprocess/i,
  v2_eval: /\beval\b/i,
  v3_hardcoded_key: /hardcoded|api key|secret/i,
  v4_prompt_injection: /injection|user input|system prompt/i,
  v5_sql_injection: /sql/i,
  v6_shared_memory: /memory/i,
  v7_pickle: /pickle|deserial/i,
  v8_ssrf: /ssrf|request|url|fetch/i,
};

function listDirs(base, label, limit=999) {
  try {
    return fs.readdirSync(base)
      .map(d => path.join(base, d))
      .filter(p => { try { return fs.statSync(p).isDirectory(); } catch { return false; } })
      .slice(0, limit)
      .map(p => ({ label, name: `${label}:${path.basename(p)}`, path: p }));
  } catch { return []; }
}

const targets = [];
// Labeled synthetic
for (const d of listDirs('/private/tmp/g0val/corpus/vuln', 'vuln')) targets.push(d);
for (const d of listDirs('/private/tmp/g0val/corpus/clean', 'clean')) targets.push(d);
for (const d of listDirs('/private/tmp/g0val/corpus/nonagent', 'nonagent')) targets.push(d);
// Real repos (diverse)
for (const d of listDirs('/private/tmp/pubtest/crewai-ex/crews', 'real-crewai', 17)) targets.push(d);
for (const d of listDirs('/private/tmp/pubtest/crewai-ex/flows', 'real-crewai-flow', 7)) targets.push(d);
for (const d of listDirs('/private/tmp/pubtest/oai-agents/examples', 'real-openai', 14)) targets.push(d);
for (const d of listDirs('/private/tmp/pubtest/mcp-servers/src', 'real-mcp', 7)) targets.push(d);

const results = [];
let i = 0;
for (const t of targets) {
  i++;
  const started = Date.now();
  let rec = { ...t, ok: false };
  try {
    const out = execFileSync('node', [G0, 'scan', t.path, '--json'], { encoding: 'utf-8', maxBuffer: 64*1024*1024, stdio: ['ignore','pipe','ignore'] });
    const j = JSON.parse(out);
    const findings = j.findings || [];
    const bySev = k => findings.filter(f => f.severity === k).length;
    const agents = Array.isArray(j.graph?.agents) ? j.graph.agents.length : (j.graph?.agents ?? 0);
    const tools = Array.isArray(j.graph?.tools) ? j.graph.tools.length : (j.graph?.tools ?? 0);
    rec = {
      ...t, ok: true,
      framework: j.framework,
      files: j.graph?.files?.length ?? j.filesScanned ?? null,
      agents, tools,
      crit: bySev('critical'), high: bySev('high'), med: bySev('medium'), low: bySev('low'),
      total: findings.length,
      grade: j.score?.grade, score: j.score?.overall, capReason: j.score?.capReason ?? null,
      analyzability: j.analyzability?.score ?? null,
      // reachability breakdown of findings
      reach: findings.reduce((a,f)=>{const r=f.reachability||'unknown';a[r]=(a[r]||0)+1;return a;},{}),
      confidence: findings.reduce((a,f)=>{const c=f.confidence||'?';a[c]=(a[c]||0)+1;return a;},{}),
      durationMs: Date.now()-started,
    };
    // Efficacy check for vuln targets
    const base = path.basename(t.path);
    if (t.label === 'vuln' && EXPECT[base]) {
      const hay = findings.map(f=>`${f.ruleId} ${f.title}`).join(' | ');
      rec.detected = EXPECT[base].test(hay);
    }
  } catch (e) {
    rec.error = (e.message||String(e)).slice(0,160);
  }
  results.push(rec);
  process.stderr.write(`[${i}/${targets.length}] ${t.name} ${rec.ok?('grade '+rec.grade+' '+rec.total+'f'):('ERROR')}\n`);
}
fs.writeFileSync('/private/tmp/g0val/results.json', JSON.stringify(results, null, 2));
console.log('WROTE', results.length, 'results');
