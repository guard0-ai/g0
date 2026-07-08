import * as fs from 'node:fs';
const R = JSON.parse(fs.readFileSync('/private/tmp/g0val/results.json','utf-8'));
const by = lbl => R.filter(r => r.label === lbl);
const sum = (arr,k) => arr.reduce((a,r)=>a+(r[k]||0),0);

console.log('\n===== RUN OVERVIEW =====');
console.log('targets:', R.length, '| ok:', R.filter(r=>r.ok).length, '| errors:', R.filter(r=>!r.ok).length);
const totalMs = sum(R,'durationMs');
console.log('avg scan time:', Math.round(totalMs/R.length)+'ms', '| total:', (totalMs/1000).toFixed(1)+'s');

console.log('\n===== EFFICACY (vuln set — planted vuln detected?) =====');
const vuln = by('vuln');
let det=0;
for (const v of vuln) {
  const mark = v.detected ? 'DETECTED ' : 'MISSED   ';
  console.log(`  ${mark} ${v.name.padEnd(28)} grade ${v.grade}  crit=${v.crit} high=${v.high}`);
  if (v.detected) det++;
}
console.log(`  Efficacy: ${det}/${vuln.length} = ${(100*det/vuln.length).toFixed(0)}% planted vulns detected`);

console.log('\n===== FALSE POSITIVES (clean set — should have ~0 crit/high) =====');
const clean = by('clean');
let cleanFP=0;
for (const c of clean) {
  const fp = c.crit + c.high;
  cleanFP += fp;
  console.log(`  ${c.name.padEnd(26)} grade ${c.grade}  crit=${c.crit} high=${c.high} med=${c.med} low=${c.low}  ${fp>0?'<-- '+fp+' FP(crit/high)':'clean'}`);
}
console.log(`  Clean-set critical/high false positives: ${cleanFP} across ${clean.length} hardened agents`);

console.log('\n===== FALSE POSITIVES (nonagent set — should be near-silent) =====');
const non = by('nonagent');
for (const n of non) {
  console.log(`  ${n.name.padEnd(26)} grade ${n.grade}  crit=${n.crit} high=${n.high} med=${n.med} low=${n.low} total=${n.total} agents=${n.agents}`);
}
console.log(`  Nonagent crit/high total: ${sum(non,'crit')+sum(non,'high')}`);

console.log('\n===== REAL CORPUS =====');
for (const lbl of ['real-crewai','real-crewai-flow','real-openai','real-mcp']) {
  const g = by(lbl);
  if (!g.length) continue;
  const discovered = g.filter(r => (r.agents+r.tools) > 0).length;
  console.log(`  ${lbl.padEnd(18)} n=${g.length}  discovered agents/tools in ${discovered}/${g.length}  avg findings=${(sum(g,'total')/g.length).toFixed(1)}  crit=${sum(g,'crit')} high=${sum(g,'high')}`);
}

console.log('\n===== GRADE DISTRIBUTION (all) =====');
const grades = {};
for (const r of R.filter(r=>r.ok)) grades[r.grade]=(grades[r.grade]||0)+1;
console.log(' ', JSON.stringify(grades));

console.log('\n===== REACHABILITY of all findings (FP signal) =====');
const reach = {};
for (const r of R) for (const [k,v] of Object.entries(r.reach||{})) reach[k]=(reach[k]||0)+v;
console.log(' ', JSON.stringify(reach));
const totF = Object.values(reach).reduce((a,b)=>a+b,0);
console.log(`  utility-code (low-risk/likely-noise) share: ${((100*(reach['utility-code']||0)/totF)).toFixed(0)}% of ${totF} findings`);
