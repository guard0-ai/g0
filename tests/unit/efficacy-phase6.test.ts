import { describe, it, expect } from 'vitest';
import { filterTestFiles } from '../../src/discovery/graph.js';
import { deduplicateCrossRule, capPromptMissing } from '../../src/analyzers/engine.js';
import type { Finding } from '../../src/types/finding.js';
import type { FileInventory } from '../../src/types/common.js';

function makeFinding(overrides: Partial<Finding> & { ruleId: string; domain: string }): Finding {
  return {
    id: `${overrides.ruleId}-0`,
    title: 'test',
    description: 'test',
    severity: 'medium',
    confidence: 'medium',
    location: { file: 'src/agent.ts', line: 10 },
    remediation: 'fix it',
    standards: { owaspAgentic: [] },
    ...overrides,
  } as Finding;
}

describe('filterTestFiles', () => {
  it('removes test files from language arrays but keeps them in purpose', () => {
    const files: FileInventory = {
      all: [
        { path: 'src/agent.ts', relativePath: 'src/agent.ts', size: 100, language: 'typescript' },
        { path: 'tests/agent.test.ts', relativePath: 'tests/agent.test.ts', size: 100, language: 'typescript' },
        { path: 'src/__tests__/helper.ts', relativePath: 'src/__tests__/helper.ts', size: 100, language: 'typescript' },
      ],
      python: [],
      typescript: [
        { path: 'src/agent.ts', relativePath: 'src/agent.ts', size: 100, language: 'typescript' },
        { path: 'tests/agent.test.ts', relativePath: 'tests/agent.test.ts', size: 100, language: 'typescript' },
        { path: 'src/__tests__/helper.ts', relativePath: 'src/__tests__/helper.ts', size: 100, language: 'typescript' },
      ],
      javascript: [],
      yaml: [{ path: 'config.yaml', relativePath: 'config.yaml', size: 50, language: 'yaml' }],
      json: [],
      configs: [],
    };

    const filtered = filterTestFiles(files);

    // Language arrays should be filtered
    expect(filtered.typescript).toHaveLength(1);
    expect(filtered.typescript[0].path).toBe('src/agent.ts');
    expect(filtered.all).toHaveLength(1);
    expect(filtered.all[0].path).toBe('src/agent.ts');

    // YAML/JSON/configs remain untouched
    expect(filtered.yaml).toHaveLength(1);
  });

  it('passes through when no test files exist', () => {
    const files: FileInventory = {
      all: [{ path: 'src/main.py', relativePath: 'src/main.py', size: 100, language: 'python' }],
      python: [{ path: 'src/main.py', relativePath: 'src/main.py', size: 100, language: 'python' }],
      typescript: [],
      javascript: [],
      yaml: [],
      json: [],
      configs: [],
    };
    const filtered = filterTestFiles(files);
    expect(filtered.python).toHaveLength(1);
  });
});

describe('deduplicateCrossRule', () => {
  it('keeps max 1 finding per domain per file:line', () => {
    const findings = [
      makeFinding({ ruleId: 'AA-TS-001', domain: 'tool-safety', severity: 'high', location: { file: 'a.ts', line: 5 } }),
      makeFinding({ ruleId: 'AA-TS-002', domain: 'tool-safety', severity: 'medium', location: { file: 'a.ts', line: 5 } }),
      makeFinding({ ruleId: 'AA-DL-001', domain: 'data-leakage', severity: 'low', location: { file: 'a.ts', line: 5 } }),
    ];
    const result = deduplicateCrossRule(findings);
    // Should keep 2: highest-severity tool-safety + data-leakage
    expect(result).toHaveLength(2);
    const ts = result.find(f => f.domain === 'tool-safety');
    expect(ts!.severity).toBe('high');
    expect(result.find(f => f.domain === 'data-leakage')).toBeTruthy();
  });

  it('keeps all findings on different lines', () => {
    const findings = [
      makeFinding({ ruleId: 'AA-TS-001', domain: 'tool-safety', location: { file: 'a.ts', line: 5 } }),
      makeFinding({ ruleId: 'AA-TS-002', domain: 'tool-safety', location: { file: 'a.ts', line: 10 } }),
    ];
    const result = deduplicateCrossRule(findings);
    expect(result).toHaveLength(2);
  });

  it('passes through single findings untouched', () => {
    const findings = [
      makeFinding({ ruleId: 'AA-TS-001', domain: 'tool-safety', location: { file: 'a.ts', line: 5 } }),
    ];
    expect(deduplicateCrossRule(findings)).toHaveLength(1);
  });
});

describe('capPromptMissing', () => {
  it('caps prompt_missing findings at 5 per location', () => {
    const findings: Finding[] = [];
    for (let i = 0; i < 10; i++) {
      findings.push(makeFinding({
        ruleId: `AA-GI-${100 + i}`,
        domain: 'goal-integrity',
        severity: i < 3 ? 'high' : 'medium',
        checkType: 'prompt_missing',
        location: { file: 'src/prompt.ts', line: 5 },
      }));
    }
    const result = capPromptMissing(findings);
    const promptMissing = result.filter(f => f.checkType === 'prompt_missing');
    expect(promptMissing).toHaveLength(5);
    // Should keep highest severity first
    expect(promptMissing.filter(f => f.severity === 'high')).toHaveLength(3);
  });

  it('does not affect non-prompt_missing findings', () => {
    const findings = [
      makeFinding({ ruleId: 'AA-TS-001', domain: 'tool-safety', checkType: 'code_matches' }),
      makeFinding({ ruleId: 'AA-TS-002', domain: 'tool-safety', checkType: 'code_matches' }),
    ];
    expect(capPromptMissing(findings)).toHaveLength(2);
  });

  it('allows 5 from different locations', () => {
    const findings: Finding[] = [];
    for (let i = 0; i < 6; i++) {
      findings.push(makeFinding({
        ruleId: `AA-GI-${100 + i}`,
        domain: 'goal-integrity',
        checkType: 'prompt_missing',
        location: { file: 'src/prompt.ts', line: i + 1 }, // different lines
      }));
    }
    expect(capPromptMissing(findings)).toHaveLength(6);
  });
});

describe('utility-code suppression', () => {
  it('filters findings with utility-code reachability and unlikely exploitability', () => {
    const findings = [
      makeFinding({ ruleId: 'AA-TS-001', domain: 'tool-safety', reachability: 'utility-code', exploitability: 'unlikely' }),
      makeFinding({ ruleId: 'AA-TS-002', domain: 'tool-safety', reachability: 'agent-reachable', exploitability: 'likely' }),
      makeFinding({ ruleId: 'AA-TS-003', domain: 'tool-safety', reachability: 'utility-code', exploitability: 'likely' }),
    ];

    // Simulate the pipeline filter
    const filtered = findings.filter(f =>
      !(f.reachability === 'utility-code' && f.exploitability === 'unlikely'));

    expect(filtered).toHaveLength(2);
    expect(filtered.find(f => f.ruleId === 'AA-TS-001')).toBeUndefined();
  });

  it('showAll bypasses suppression', () => {
    const findings = [
      makeFinding({ ruleId: 'AA-TS-001', domain: 'tool-safety', reachability: 'utility-code', exploitability: 'unlikely' }),
    ];
    const showAll = true;
    const filtered = showAll ? findings : findings.filter(f =>
      !(f.reachability === 'utility-code' && f.exploitability === 'unlikely'));
    expect(filtered).toHaveLength(1);
  });
});
