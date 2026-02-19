import { describe, it, expect } from 'vitest';
import { interAgentRules } from '../../src/analyzers/rules/inter-agent.js';
import { humanOversightRules } from '../../src/analyzers/rules/human-oversight.js';
import { reliabilityBoundsRules } from '../../src/analyzers/rules/reliability-bounds.js';
import { rogueAgentRules } from '../../src/analyzers/rules/rogue-agent.js';
import { cascadingFailuresRules } from '../../src/analyzers/rules/cascading-failures.js';
import { codeExecutionRules } from '../../src/analyzers/rules/code-execution.js';
import { dataLeakageRules } from '../../src/analyzers/rules/data-leakage.js';
import { memoryContextRules } from '../../src/analyzers/rules/memory-context.js';
import { goalIntegrityRules } from '../../src/analyzers/rules/goal-integrity.js';
import { identityAccessRules } from '../../src/analyzers/rules/identity-access.js';
import { supplyChainRules } from '../../src/analyzers/rules/supply-chain.js';
import { toolSafetyRules } from '../../src/analyzers/rules/tool-safety.js';
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

// ─── code-execution domain FP tests ───────────────────────────────

describe('False-positive reduction — code-execution', () => {
  it('AA-CE-001: eval with string literal does not fire', () => {
    const { graph, cleanup } = makeGraph('result = eval("2 + 2")\n');
    try {
      const rule = findRule(codeExecutionRules, 'AA-CE-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-CE-001: eval in comment does not fire', () => {
    const { graph, cleanup } = makeGraph('# eval(user_input)\n');
    try {
      const rule = findRule(codeExecutionRules, 'AA-CE-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-CE-001: eval with dynamic input still fires', () => {
    const { graph, cleanup } = makeGraph('result = eval(user_input)\n');
    try {
      const rule = findRule(codeExecutionRules, 'AA-CE-001');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-CE-002: python exec with string literal does not fire', () => {
    const { graph, cleanup } = makeGraph('exec("print(42)")\n');
    try {
      const rule = findRule(codeExecutionRules, 'AA-CE-002');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-CE-003: new Function in JS comment does not fire', () => {
    const { graph, cleanup } = makeGraph('// Anti-pattern: new Function() allows arbitrary code\n', '.ts');
    try {
      const rule = findRule(codeExecutionRules, 'AA-CE-003');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-CE-003: actual new Function still fires', () => {
    const { graph, cleanup } = makeGraph('const fn = new Function("return " + expr)\n', '.ts');
    try {
      const rule = findRule(codeExecutionRules, 'AA-CE-003');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });
});

// ─── data-leakage domain FP tests ─────────────────────────────────

describe('False-positive reduction — data-leakage', () => {
  it('AA-DL-001: verbose=True in comment does not fire', () => {
    const { graph, cleanup } = makeGraph('# verbose=True\n');
    try {
      const rule = findRule(dataLeakageRules, 'AA-DL-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-DL-001: verbose=False does not fire', () => {
    const { graph, cleanup } = makeGraph('agent = AgentExecutor(llm=llm, verbose=False)\n');
    try {
      const rule = findRule(dataLeakageRules, 'AA-DL-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-DL-001: verbose=True still fires', () => {
    const { graph, cleanup } = makeGraph('agent = AgentExecutor(llm=llm, verbose=True)\n');
    try {
      const rule = findRule(dataLeakageRules, 'AA-DL-001');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-DL-002: return_intermediate_steps=False does not fire', () => {
    const { graph, cleanup } = makeGraph('agent = AgentExecutor(tools=tools, return_intermediate_steps=False)\n');
    try {
      const rule = findRule(dataLeakageRules, 'AA-DL-002');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });
});

// ─── memory-context domain FP tests ───────────────────────────────

describe('False-positive reduction — memory-context', () => {
  it('AA-MP-001: ConversationBufferWindowMemory does not fire', () => {
    const { graph, cleanup } = makeGraph(
      'from langchain.memory import ConversationBufferWindowMemory\nmemory = ConversationBufferWindowMemory(k=5)\n',
    );
    try {
      const rule = findRule(memoryContextRules, 'AA-MP-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-MP-001: ConversationBufferMemory still fires', () => {
    const { graph, cleanup } = makeGraph(
      'from langchain.memory import ConversationBufferMemory\nmemory = ConversationBufferMemory()\n',
    );
    try {
      const rule = findRule(memoryContextRules, 'AA-MP-001');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });
});

// ─── goal-integrity domain FP tests ───────────────────────────────

describe('False-positive reduction — goal-integrity', () => {
  it('AA-GI-001: system prompt with scope boundaries does not fire', () => {
    const graph: AgentGraph = {
      rootPath: '/tmp',
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [], other: [], all: [] },
      agents: [], tools: [], models: [],
      prompts: [{
        type: 'system',
        content: 'You are a helpful assistant. You must only answer questions about cooking.',
        file: 'test.py', line: 1,
        scopeClarity: 'present',
        hasInstructionGuarding: true,
        hasSecrets: false,
      } as any],
      flows: [], permissions: [], apiEndpoints: [], databaseAccesses: [],
      authFlows: [], permissionChecks: [], piiReferences: [],
      messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    const rule = findRule(goalIntegrityRules, 'AA-GI-001');
    const findings = rule.check(graph);
    expect(findings).toHaveLength(0);
  });

  it('AA-GI-005: agent with max_iterations set does not fire', () => {
    const graph: AgentGraph = {
      rootPath: '/tmp',
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [], other: [], all: [] },
      agents: [{ name: 'test', file: 'test.py', line: 1, framework: 'langchain', tools: [], prompts: [], delegationTargets: [], maxIterations: 10 } as any],
      tools: [], models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'langchain',
    };
    const rule = findRule(goalIntegrityRules, 'AA-GI-005');
    const findings = rule.check(graph);
    expect(findings).toHaveLength(0);
  });
});

// ─── identity-access domain FP tests ──────────────────────────────

describe('False-positive reduction — identity-access', () => {
  it('AA-IA-001: import line with key-like pattern does not fire', () => {
    const { graph, cleanup } = makeGraph('from openai import sk_live_test_key_value_123456\n');
    try {
      const rule = findRule(identityAccessRules, 'AA-IA-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { cleanup(); }
  });

  it('AA-IA-001: actual hardcoded key still fires', () => {
    const { graph, cleanup } = makeGraph('api_key = "sk-abc123def456ghi789jkl012mno"\n');
    try {
      const rule = findRule(identityAccessRules, 'AA-IA-001');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { cleanup(); }
  });

  it('AA-IA-002: placeholder values do not fire', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fp-'));
    const filePath = path.join(dir, 'config.yaml');
    fs.writeFileSync(filePath, 'api_key: "your_api_key_here"\ntoken: "<INSERT_TOKEN>"\nsecret: "TODO_replace_me"\n');
    const fileInfo = { path: filePath, relativePath: 'config.yaml', language: 'yaml' as const, size: 100 };
    const graph: AgentGraph = {
      rootPath: dir,
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [fileInfo], json: [], configs: [fileInfo], other: [], all: [fileInfo] },
      agents: [], tools: [], models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    try {
      const rule = findRule(identityAccessRules, 'AA-IA-002');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('AA-IA-002: env var references do not fire', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fp-'));
    const filePath = path.join(dir, 'config.yaml');
    fs.writeFileSync(filePath, 'api_key: "${API_KEY}"\ntoken: "$SECRET_TOKEN"\n');
    const fileInfo = { path: filePath, relativePath: 'config.yaml', language: 'yaml' as const, size: 60 };
    const graph: AgentGraph = {
      rootPath: dir,
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [fileInfo], json: [], configs: [fileInfo], other: [], all: [fileInfo] },
      agents: [], tools: [], models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    try {
      const rule = findRule(identityAccessRules, 'AA-IA-002');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// ─── supply-chain domain FP tests ─────────────────────────────────

describe('False-positive reduction — supply-chain', () => {
  it('AA-SC-001: pinned dependency does not fire', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fp-'));
    const filePath = path.join(dir, 'requirements.txt');
    fs.writeFileSync(filePath, 'langchain==0.1.0\nopenai==1.3.5\nfastapi>=0.100.0\n');
    const fileInfo = { path: filePath, relativePath: 'requirements.txt', language: 'other' as const, size: 50 };
    const graph: AgentGraph = {
      rootPath: dir,
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [fileInfo], other: [fileInfo], all: [fileInfo] },
      agents: [], tools: [], models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    try {
      const rule = findRule(supplyChainRules, 'AA-SC-001');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('AA-SC-001: unpinned dependency still fires', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fp-'));
    const filePath = path.join(dir, 'requirements.txt');
    fs.writeFileSync(filePath, 'langchain\n');
    const fileInfo = { path: filePath, relativePath: 'requirements.txt', language: 'other' as const, size: 10 };
    const graph: AgentGraph = {
      rootPath: dir,
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [fileInfo], other: [fileInfo], all: [fileInfo] },
      agents: [], tools: [], models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    try {
      const rule = findRule(supplyChainRules, 'AA-SC-001');
      const findings = rule.check(graph);
      expect(findings.length).toBeGreaterThan(0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });

  it('AA-SC-002: pinned npm dependency does not fire', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fp-'));
    const filePath = path.join(dir, 'package.json');
    fs.writeFileSync(filePath, JSON.stringify({
      dependencies: { 'openai': '^4.0.0', '@langchain/core': '~0.1.0' },
    }));
    const fileInfo = { path: filePath, relativePath: 'package.json', language: 'json' as const, size: 100 };
    const graph: AgentGraph = {
      rootPath: dir,
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [fileInfo], configs: [fileInfo], other: [], all: [fileInfo] },
      agents: [], tools: [], models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    try {
      const rule = findRule(supplyChainRules, 'AA-SC-002');
      const findings = rule.check(graph);
      expect(findings).toHaveLength(0);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
});

// ─── tool-safety domain FP tests ──────────────────────────────────

describe('False-positive reduction — tool-safety', () => {
  it('AA-TS-001: tool without shell capability does not fire', () => {
    const graph: AgentGraph = {
      rootPath: '/tmp',
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [], other: [], all: [] },
      agents: [],
      tools: [{ name: 'search', file: 'tools.py', line: 1, capabilities: ['web-search'], hasInputValidation: true, hasSandboxing: false, hasSideEffects: false } as any],
      models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    const rule = findRule(toolSafetyRules, 'AA-TS-001');
    const findings = rule.check(graph);
    expect(findings).toHaveLength(0);
  });

  it('AA-TS-002: database tool with input validation does not fire', () => {
    const graph: AgentGraph = {
      rootPath: '/tmp',
      files: { python: [], typescript: [], javascript: [], java: [], go: [], yaml: [], json: [], configs: [], other: [], all: [] },
      agents: [],
      tools: [{ name: 'db-query', file: 'tools.py', line: 1, capabilities: ['database'], hasInputValidation: true, hasSandboxing: false, hasSideEffects: true } as any],
      models: [], prompts: [], flows: [], permissions: [],
      apiEndpoints: [], databaseAccesses: [], authFlows: [], permissionChecks: [],
      piiReferences: [], messageQueues: [], rateLimits: [], callGraph: [],
      primaryFramework: 'unknown',
    };
    const rule = findRule(toolSafetyRules, 'AA-TS-002');
    const findings = rule.check(graph);
    expect(findings).toHaveLength(0);
  });
});
