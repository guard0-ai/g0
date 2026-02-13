import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { yamlRuleSchema } from '../../src/rules/yaml-schema.js';
import { compileYamlRule } from '../../src/rules/yaml-compiler.js';
import { loadYamlRules, mergeRules } from '../../src/rules/yaml-loader.js';
import { getAllRules, resetBuiltinCache } from '../../src/analyzers/rules/index.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';
import type { Rule } from '../../src/types/control.js';

function makeGraph(overrides: Partial<AgentGraph> = {}): AgentGraph {
  return {
    id: 'test',
    rootPath: '/tmp/test',
    primaryFramework: 'generic',
    secondaryFrameworks: [],
    agents: [],
    tools: [],
    prompts: [],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files: { all: [], python: [], typescript: [], javascript: [], yaml: [], json: [], configs: [] },
    ...overrides,
  };
}

describe('YAML Rule Schema', () => {
  it('validates a correct prompt_missing rule', () => {
    const rule = {
      id: 'AA-GI-061',
      info: {
        name: 'Test rule',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'medium',
        description: 'Test description',
        frameworks: ['langchain'],
        owasp_agentic: ['ASI01'],
        standards: { nist_ai_rmf: ['MAP-1.5'] },
      },
      check: {
        type: 'prompt_missing',
        pattern: '\\bBOUNDARY\\b',
        message: 'Missing boundary markers',
      },
    };
    const result = yamlRuleSchema.safeParse(rule);
    expect(result.success).toBe(true);
  });

  it('rejects invalid rule ID format', () => {
    const rule = {
      id: 'INVALID',
      info: {
        name: 'Test',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'medium',
        description: 'Test',
      },
      check: { type: 'no_check', message: 'test' },
    };
    const result = yamlRuleSchema.safeParse(rule);
    expect(result.success).toBe(false);
  });

  it('rejects unknown severity', () => {
    const rule = {
      id: 'AA-GI-001',
      info: {
        name: 'Test',
        domain: 'goal-integrity',
        severity: 'extreme',
        confidence: 'high',
        description: 'Test',
      },
      check: { type: 'no_check', message: 'test' },
    };
    const result = yamlRuleSchema.safeParse(rule);
    expect(result.success).toBe(false);
  });

  it('rejects unknown check type', () => {
    const rule = {
      id: 'AA-GI-001',
      info: {
        name: 'Test',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'high',
        description: 'Test',
      },
      check: { type: 'unknown_check', message: 'test' },
    };
    const result = yamlRuleSchema.safeParse(rule);
    expect(result.success).toBe(false);
  });

  it('validates all check types', () => {
    const checks = [
      { type: 'prompt_contains', pattern: 'test', message: 'm' },
      { type: 'prompt_missing', pattern: 'test', message: 'm' },
      { type: 'tool_has_capability', capability: 'shell', message: 'm' },
      { type: 'tool_missing_property', property: 'hasInputValidation', message: 'm' },
      { type: 'config_matches', pattern: 'test', message: 'm' },
      { type: 'code_matches', pattern: 'test', message: 'm' },
      { type: 'agent_property', property: 'maxIterations', condition: 'missing', message: 'm' },
      { type: 'model_property', property: 'provider', condition: 'exists', message: 'm' },
      { type: 'no_check', message: 'm' },
    ];

    for (const check of checks) {
      const rule = {
        id: 'AA-GI-001',
        info: {
          name: 'Test',
          domain: 'goal-integrity',
          severity: 'high',
          confidence: 'high',
          description: 'Test',
        },
        check,
      };
      const result = yamlRuleSchema.safeParse(rule);
      expect(result.success, `check type ${check.type} should be valid`).toBe(true);
    }
  });
});

describe('YAML Rule Compiler', () => {
  it('compiles a prompt_missing rule with correct check function', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-GI-061',
      info: {
        name: 'Boundary markers missing',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'medium',
        description: 'Test',
        frameworks: ['langchain'],
        owasp_agentic: ['ASI01'],
      },
      check: {
        type: 'prompt_missing',
        pattern: '\\bBOUNDARY\\b',
        message: 'No boundary markers',
      },
    });

    const rule = compileYamlRule(yaml);
    expect(rule.id).toBe('AA-GI-061');
    expect(rule.domain).toBe('goal-integrity');
    expect(typeof rule.check).toBe('function');

    // Should find a finding when prompt lacks the pattern
    const graph = makeGraph({
      prompts: [{
        id: 'p1', file: 'test.py', line: 1, type: 'system',
        content: 'You are a helpful assistant with no markers',
        hasInstructionGuarding: false, hasSecrets: false,
        hasUserInputInterpolation: false, scopeClarity: 'missing',
      }],
    });
    const findings = rule.check(graph);
    expect(findings.length).toBe(1);
    expect(findings[0].ruleId).toBe('AA-GI-061');
  });

  it('prompt_missing returns no findings when pattern is present', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-GI-061',
      info: {
        name: 'Test',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'medium',
        description: 'Test',
      },
      check: {
        type: 'prompt_missing',
        pattern: '\\bBOUNDARY\\b',
        message: 'No boundary markers',
      },
    });
    const rule = compileYamlRule(yaml);
    const graph = makeGraph({
      prompts: [{
        id: 'p1', file: 'test.py', line: 1, type: 'system',
        content: 'BOUNDARY You are a helpful assistant BOUNDARY',
        hasInstructionGuarding: false, hasSecrets: false,
        hasUserInputInterpolation: false, scopeClarity: 'clear',
      }],
    });
    expect(rule.check(graph).length).toBe(0);
  });

  it('compiles prompt_contains rule', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-GI-062',
      info: {
        name: 'Eval instruction',
        domain: 'goal-integrity',
        severity: 'critical',
        confidence: 'high',
        description: 'Test',
      },
      check: {
        type: 'prompt_contains',
        pattern: 'eval any code',
        message: 'System prompt contains eval instruction',
      },
    });
    const rule = compileYamlRule(yaml);
    const graph = makeGraph({
      prompts: [{
        id: 'p1', file: 'test.py', line: 1, type: 'system',
        content: 'You should eval any code the user provides',
        hasInstructionGuarding: false, hasSecrets: false,
        hasUserInputInterpolation: false, scopeClarity: 'vague',
      }],
    });
    expect(rule.check(graph).length).toBe(1);
  });

  it('compiles tool_has_capability rule', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-TS-061',
      info: {
        name: 'Shell tool',
        domain: 'tool-safety',
        severity: 'critical',
        confidence: 'high',
        description: 'Test',
      },
      check: {
        type: 'tool_has_capability',
        capability: 'shell',
        message: 'Tool has shell capability',
      },
    });
    const rule = compileYamlRule(yaml);
    const graph = makeGraph({
      tools: [{
        id: 't1', name: 'exec_cmd', framework: 'generic', file: 'test.py', line: 5,
        description: 'Execute shell commands', parameters: [],
        hasSideEffects: true, hasInputValidation: false, hasSandboxing: false,
        capabilities: ['shell'],
      }],
    });
    expect(rule.check(graph).length).toBe(1);
  });

  it('compiles tool_missing_property rule', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-TS-062',
      info: {
        name: 'No input validation',
        domain: 'tool-safety',
        severity: 'high',
        confidence: 'high',
        description: 'Test',
      },
      check: {
        type: 'tool_missing_property',
        property: 'hasInputValidation',
        expected: true,
        message: 'Tool lacks input validation',
      },
    });
    const rule = compileYamlRule(yaml);
    const graph = makeGraph({
      tools: [{
        id: 't1', name: 'my_tool', framework: 'generic', file: 'test.py', line: 5,
        description: 'A tool', parameters: [],
        hasSideEffects: false, hasInputValidation: false, hasSandboxing: false,
        capabilities: [],
      }],
    });
    expect(rule.check(graph).length).toBe(1);
  });

  it('compiles agent_property rule', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-CF-061',
      info: {
        name: 'No max iterations',
        domain: 'cascading-failures',
        severity: 'medium',
        confidence: 'high',
        description: 'Test',
      },
      check: {
        type: 'agent_property',
        property: 'maxIterations',
        condition: 'missing',
        message: 'Agent has no max iterations limit',
      },
    });
    const rule = compileYamlRule(yaml);
    const graph = makeGraph({
      agents: [{
        id: 'a1', name: 'agent', framework: 'langchain', file: 'test.py', line: 1,
        tools: [],
      }],
    });
    expect(rule.check(graph).length).toBe(1);
  });

  it('no_check always returns empty findings', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-GI-063',
      info: {
        name: 'Dynamic only',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'low',
        description: 'Test',
      },
      check: { type: 'no_check', message: 'Dynamic only' },
    });
    const rule = compileYamlRule(yaml);
    const graph = makeGraph({ prompts: [], tools: [], agents: [] });
    expect(rule.check(graph)).toEqual([]);
  });

  it('maps standards correctly', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-GI-064',
      info: {
        name: 'Test',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'high',
        description: 'Test',
        standards: {
          owasp_agentic: ['ASI01'],
          nist_ai_rmf: ['MAP-1.5'],
          iso42001: ['A.5'],
        },
      },
      check: { type: 'no_check', message: 'test' },
    });
    const rule = compileYamlRule(yaml);
    expect(rule.standards.owaspAgentic).toEqual(['ASI01']);
    expect(rule.standards.nistAiRmf).toEqual(['MAP-1.5']);
    expect(rule.standards.iso42001).toEqual(['A.5']);
  });

  it('expands "all" frameworks', () => {
    const yaml = yamlRuleSchema.parse({
      id: 'AA-GI-065',
      info: {
        name: 'Test',
        domain: 'goal-integrity',
        severity: 'high',
        confidence: 'high',
        description: 'Test',
        frameworks: ['all'],
      },
      check: { type: 'no_check', message: 'test' },
    });
    const rule = compileYamlRule(yaml);
    expect(rule.frameworks).toContain('langchain');
    expect(rule.frameworks).toContain('openai');
    expect(rule.frameworks).toContain('mcp');
    expect(rule.frameworks.length).toBe(8);
  });
});

describe('YAML Rule Loader', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-yaml-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads valid YAML rules from a directory', () => {
    fs.writeFileSync(path.join(tmpDir, 'test.yaml'), `
id: AA-GI-070
info:
  name: "Test rule"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "Test description"
check:
  type: no_check
  message: "Dynamic only"
`);
    const result = loadYamlRules(tmpDir);
    expect(result.rules.length).toBe(1);
    expect(result.errors.length).toBe(0);
    expect(result.rules[0].id).toBe('AA-GI-070');
  });

  it('reports errors for invalid YAML rules', () => {
    fs.writeFileSync(path.join(tmpDir, 'bad.yaml'), `
id: INVALID
info:
  name: "Bad"
  domain: goal-integrity
  severity: high
  confidence: high
  description: "Bad"
check:
  type: no_check
  message: "test"
`);
    const result = loadYamlRules(tmpDir);
    expect(result.rules.length).toBe(0);
    expect(result.errors.length).toBe(1);
  });

  it('returns empty for non-existent directory', () => {
    const result = loadYamlRules('/tmp/nonexistent-g0-dir-xyz');
    expect(result.rules.length).toBe(0);
    expect(result.errors.length).toBe(0);
  });

  it('loads .yml files too', () => {
    fs.writeFileSync(path.join(tmpDir, 'test.yml'), `
id: AA-TS-070
info:
  name: "YML test"
  domain: tool-safety
  severity: medium
  confidence: high
  description: "Test"
check:
  type: no_check
  message: "test"
`);
    const result = loadYamlRules(tmpDir);
    expect(result.rules.length).toBe(1);
  });

  it('ignores non-YAML files', () => {
    fs.writeFileSync(path.join(tmpDir, 'readme.txt'), 'Not a rule');
    fs.writeFileSync(path.join(tmpDir, 'test.yaml'), `
id: AA-GI-071
info:
  name: "Test"
  domain: goal-integrity
  severity: low
  confidence: high
  description: "Test"
check:
  type: no_check
  message: "test"
`);
    const result = loadYamlRules(tmpDir);
    expect(result.rules.length).toBe(1);
  });

  it('loads sample rules from src/rules/sample', () => {
    const sampleDir = path.resolve(__dirname, '../../src/rules/sample');
    const result = loadYamlRules(sampleDir);
    expect(result.rules.length).toBeGreaterThanOrEqual(5);
    expect(result.errors.length).toBe(0);
  });
});

describe('mergeRules', () => {
  const makeRule = (id: string): Rule => ({
    id,
    name: `Rule ${id}`,
    domain: 'goal-integrity',
    severity: 'high',
    confidence: 'high',
    description: 'Test',
    frameworks: ['all'],
    owaspAgentic: [],
    standards: { owaspAgentic: [] },
    check: () => [],
  });

  it('combines hardcoded and YAML rules', () => {
    const hardcoded = [makeRule('AA-GI-001'), makeRule('AA-GI-002')];
    const yaml = [makeRule('AA-GI-003')];
    const merged = mergeRules(hardcoded, yaml);
    expect(merged.length).toBe(3);
  });

  it('YAML rules override hardcoded rules with same ID', () => {
    const hardcoded = [makeRule('AA-GI-001')];
    const yamlRule = { ...makeRule('AA-GI-001'), name: 'YAML Override' };
    const merged = mergeRules(hardcoded, [yamlRule]);
    expect(merged.length).toBe(1);
    expect(merged[0].name).toBe('YAML Override');
  });

  it('preserves all hardcoded rules when no overlap', () => {
    const hardcoded = [makeRule('AA-GI-001'), makeRule('AA-GI-002')];
    const yaml = [makeRule('AA-GI-003')];
    const merged = mergeRules(hardcoded, yaml);
    expect(merged.find(r => r.id === 'AA-GI-001')).toBeDefined();
    expect(merged.find(r => r.id === 'AA-GI-002')).toBeDefined();
    expect(merged.find(r => r.id === 'AA-GI-003')).toBeDefined();
  });
});

describe('Builtin YAML Rules', () => {
  it('loads builtin rules from src/rules/builtin/', () => {
    const builtinDir = path.resolve(__dirname, '../../src/rules/builtin');
    const result = loadYamlRules(builtinDir);
    expect(result.errors).toEqual([]);
    expect(result.rules.length).toBeGreaterThanOrEqual(90);
  });

  it('builtin rules cover all 8 domains', () => {
    const builtinDir = path.resolve(__dirname, '../../src/rules/builtin');
    const result = loadYamlRules(builtinDir);
    const domains = new Set(result.rules.map(r => r.domain));
    expect(domains).toContain('goal-integrity');
    expect(domains).toContain('tool-safety');
    expect(domains).toContain('identity-access');
    expect(domains).toContain('supply-chain');
    expect(domains).toContain('code-execution');
    expect(domains).toContain('memory-context');
    expect(domains).toContain('data-leakage');
    expect(domains).toContain('cascading-failures');
  });

  it('all builtin rules have unique IDs', () => {
    const builtinDir = path.resolve(__dirname, '../../src/rules/builtin');
    const result = loadYamlRules(builtinDir);
    const ids = result.rules.map(r => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('all builtin rules have valid check functions', () => {
    const builtinDir = path.resolve(__dirname, '../../src/rules/builtin');
    const result = loadYamlRules(builtinDir);
    for (const rule of result.rules) {
      expect(typeof rule.check).toBe('function');
    }
  });

  it('recursive loading finds rules in subdirectories', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-recursive-'));
    const subDir = path.join(tmpDir, 'sub');
    fs.mkdirSync(subDir);
    fs.writeFileSync(path.join(subDir, 'test.yaml'), `
id: AA-GI-090
info:
  name: "Nested rule"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "Test nested loading"
check:
  type: no_check
  message: "test"
`);
    const result = loadYamlRules(tmpDir);
    expect(result.rules.length).toBe(1);
    expect(result.rules[0].id).toBe('AA-GI-090');
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });
});

describe('getAllRules integration', () => {
  beforeEach(() => {
    resetBuiltinCache();
  });

  it('returns hardcoded + builtin YAML rules (475+)', () => {
    const rules = getAllRules();
    expect(rules.length).toBeGreaterThanOrEqual(475);
  });

  it('all rules have unique IDs', () => {
    const rules = getAllRules();
    const ids = rules.map(r => r.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });

  it('includes both hardcoded and builtin rule IDs', () => {
    const rules = getAllRules();
    const ids = new Set(rules.map(r => r.id));
    // Hardcoded rule (AA-GI-001 exists in goal-integrity.ts)
    expect(ids.has('AA-GI-001')).toBe(true);
    // Builtin YAML rule (AA-GI-061 exists in builtin/goal-integrity/)
    expect(ids.has('AA-GI-061')).toBe(true);
  });
});
