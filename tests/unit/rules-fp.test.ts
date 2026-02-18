import { describe, it, expect } from 'vitest';
import { interAgentRules } from '../../src/analyzers/rules/inter-agent.js';
import { humanOversightRules } from '../../src/analyzers/rules/human-oversight.js';
import { reliabilityBoundsRules } from '../../src/analyzers/rules/reliability-bounds.js';
import { rogueAgentRules } from '../../src/analyzers/rules/rogue-agent.js';
import { cascadingFailuresRules } from '../../src/analyzers/rules/cascading-failures.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

/** Create a temporary file with content and return a minimal AgentGraph */
function makeGraph(content: string, ext: string = '.py'): { graph: AgentGraph; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fp-'));
  const filePath = path.join(dir, `test${ext}`);
  fs.writeFileSync(filePath, content);

  const language = ext === '.py' ? 'python' : ext === '.ts' ? 'typescript' : 'javascript';
  const fileInfo = { path: filePath, relativePath: `test${ext}`, language, size: content.length };
  const files = {
    python: language === 'python' ? [fileInfo] : [],
    typescript: language === 'typescript' ? [fileInfo] : [],
    javascript: language === 'javascript' ? [fileInfo] : [],
    java: [], go: [], yaml: [], json: [], configs: [], other: [], all: [fileInfo],
  };

  const graph: AgentGraph = {
    rootPath: dir,
    files,
    agents: [],
    tools: [],
    models: [],
    prompts: [],
    flows: [],
    permissions: [],
    apiEndpoints: [],
    databaseAccesses: [],
    authFlows: [],
    permissionChecks: [],
    piiReferences: [],
    messageQueues: [],
    rateLimits: [],
    callGraph: [],
    primaryFramework: 'unknown',
  };

  return { graph, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

function findRule(rules: any[], id: string) {
  return rules.find((r: any) => r.id === id);
}

describe('False-positive reduction — comment line skipping', () => {
  it('inter-agent: comment lines are skipped (AA-IC-001)', () => {
    const { graph, cleanup } = makeGraph('# send_message(data)\n# emit(event)\n');
    try {
      const rule = findRule(interAgentRules, 'AA-IC-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('inter-agent: JS comment lines are skipped (AA-IC-001)', () => {
    const { graph, cleanup } = makeGraph('// send_message(data)\n// emit(event)\n', '.ts');
    try {
      const rule = findRule(interAgentRules, 'AA-IC-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('human-oversight: comment lines are skipped (AA-HO-001)', () => {
    const { graph, cleanup } = makeGraph('# auto_execute = True\n');
    try {
      const rule = findRule(humanOversightRules, 'AA-HO-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('reliability-bounds: comment lines are skipped (AA-RB-006)', () => {
    const { graph, cleanup } = makeGraph('# retry = 3\n');
    try {
      const rule = findRule(reliabilityBoundsRules, 'AA-RB-006');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('rogue-agent: comment lines are skipped (AA-RA-001)', () => {
    const { graph, cleanup } = makeGraph('# self.instructions = new_val\n');
    try {
      const rule = findRule(rogueAgentRules, 'AA-RA-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('cascading-failures: comment lines are skipped (AA-CF-013)', () => {
    const { graph, cleanup } = makeGraph('# except: pass\n# except:\n#   pass\n');
    try {
      const rule = findRule(cascadingFailuresRules, 'AA-CF-013');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });
});

describe('False-positive reduction — tightened regexes', () => {
  it('AA-IC-001: generic emit() does not fire', () => {
    const { graph, cleanup } = makeGraph('emitter.emit("click")\neventBus.emit("data")\n');
    try {
      const rule = findRule(interAgentRules, 'AA-IC-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-IC-001: agent-specific send_message still fires', () => {
    const { graph, cleanup } = makeGraph('send_message(target_agent, payload)\n');
    try {
      const rule = findRule(interAgentRules, 'AA-IC-001');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-HO-003: generic "def run" does not fire', () => {
    const { graph, cleanup } = makeGraph('def run(self):\n    pass\n');
    graph.agents = [{ name: 'test', file: 'test.py', line: 1, framework: 'unknown', tools: [], prompts: [], delegationTargets: [] } as any];
    try {
      const rule = findRule(humanOversightRules, 'AA-HO-003');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-HO-003: agent-specific execute_tool still fires without logging', () => {
    const { graph, cleanup } = makeGraph('def execute_tool(tool_name, args):\n    result = tool.run(args)\n    return result\n');
    graph.agents = [{ name: 'test', file: 'test.py', line: 1, framework: 'unknown', tools: [], prompts: [], delegationTargets: [] } as any];
    try {
      const rule = findRule(humanOversightRules, 'AA-HO-003');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-HO-009: standard authorize() does not fire', () => {
    const { graph, cleanup } = makeGraph('authorize(user, resource)\nauthorization(token)\n');
    try {
      const rule = findRule(humanOversightRules, 'AA-HO-009');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-RB-003: generic JSON.parse(data) does not fire', () => {
    const { graph, cleanup } = makeGraph('const config = JSON.parse(readFileSync("config.json"))\n');
    try {
      const rule = findRule(reliabilityBoundsRules, 'AA-RB-003');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-RB-003: JSON.parse(response) still fires', () => {
    const { graph, cleanup } = makeGraph('const parsed = JSON.parse(response.body)\n');
    try {
      const rule = findRule(reliabilityBoundsRules, 'AA-RB-003');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-RB-011: plain Express app without LLM context does not fire', () => {
    const { graph, cleanup } = makeGraph('const app = express();\napp.get("/api/users", handler);\n', '.ts');
    try {
      const rule = findRule(reliabilityBoundsRules, 'AA-RB-011');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-RA-004: generic task=user_input does not fire', () => {
    const { graph, cleanup } = makeGraph('task = user_input\nobjective = message\n');
    try {
      const rule = findRule(rogueAgentRules, 'AA-RA-004');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-RA-004: agent_goal=user_input still fires', () => {
    const { graph, cleanup } = makeGraph('agent_goal = user_input\n');
    try {
      const rule = findRule(rogueAgentRules, 'AA-RA-004');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-RA-007: generic process.env access does not fire', () => {
    const { graph, cleanup } = makeGraph('const port = process.env.PORT\nconst dbUrl = os.environ["DATABASE_URL"]\n', '.ts');
    try {
      const rule = findRule(rogueAgentRules, 'AA-RA-007');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-RA-007: secret env access in agent context still fires', () => {
    const { graph, cleanup } = makeGraph('def agent_tool():\n    key = os.environ["API_KEY"]\n    return key\n');
    try {
      const rule = findRule(rogueAgentRules, 'AA-RA-007');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-CF-042: standard process.env read does not fire', () => {
    const { graph, cleanup } = makeGraph('const port = process.env["PORT"];\n', '.ts');
    try {
      const rule = findRule(cascadingFailuresRules, 'AA-CF-042');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-CF-011: generic .save() calls do not fire', () => {
    const { graph, cleanup } = makeGraph('canvas.save()\nctx.save()\nfile.save()\n', '.ts');
    try {
      const rule = findRule(cascadingFailuresRules, 'AA-CF-011');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-RB-019: generic query=request does not fire', () => {
    const { graph, cleanup } = makeGraph('const query = request.query\nprompt = req.body\n', '.ts');
    try {
      const rule = findRule(reliabilityBoundsRules, 'AA-RB-019');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });
});
