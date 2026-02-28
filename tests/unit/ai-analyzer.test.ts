import { describe, it, expect, vi } from 'vitest';
import { runAIAnalysis } from '../../src/ai/analyzer.js';
import type { AIProvider } from '../../src/ai/provider.js';
import type { Finding } from '../../src/types/finding.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';

function createMockProvider(responses: string[]): AIProvider {
  let callIndex = 0;
  return {
    name: 'mock',
    model: 'mock-model',
    async analyze(_prompt: string, _context: string): Promise<string> {
      return responses[callIndex++] ?? '{}';
    },
  };
}

function createMockGraph(): AgentGraph {
  return {
    id: 'test',
    rootPath: '/tmp/test',
    primaryFramework: 'langchain',
    secondaryFrameworks: [],
    agents: [{
      id: 'agent-1',
      name: 'TestAgent',
      framework: 'langchain',
      file: 'agent.py',
      line: 1,
      tools: [],
    }],
    tools: [],
    prompts: [{
      id: 'prompt-1',
      file: 'agent.py',
      line: 5,
      type: 'system',
      content: 'You are a helpful assistant.',
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: false,
      scopeClarity: 'vague',
    }],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files: { all: [], python: [], typescript: [], javascript: [], yaml: [], json: [], configs: [] },
  };
}

function createMockFindings(count = 1): Finding[] {
  const findings: Finding[] = [];
  for (let i = 0; i < count; i++) {
    findings.push({
      id: `AA-GI-00${i + 1}-0`,
      ruleId: `AA-GI-00${i + 1}`,
      title: `Finding ${i + 1}`,
      description: `Description for finding ${i + 1}.`,
      severity: i === 0 ? 'high' : 'medium',
      confidence: 'high',
      domain: 'goal-integrity',
      location: { file: 'agent.py', line: 5 + i },
      remediation: 'Add fix.',
      standards: { owaspAgentic: ['ASI01'] },
      checkType: 'prompt_missing',
    });
  }
  return findings;
}

describe('AI Analyzer', () => {
  it('should return enrichments from mock provider', async () => {
    // With batch size 5, 1 finding = 1 batch for explanation + 1 batch for FP + 1 complex = 3 calls
    const provider = createMockProvider([
      JSON.stringify({
        findings: [{
          id: 'AA-GI-001-0',
          explanation: 'The system prompt is too vague.',
          remediation: 'Add explicit role definition.',
        }],
      }),
      JSON.stringify({
        assessments: [{
          id: 'AA-GI-001-0',
          falsePositive: false,
        }],
      }),
      JSON.stringify({
        findings: [],
      }),
    ]);

    const result = await runAIAnalysis(
      createMockFindings(),
      createMockGraph(),
      provider,
    );

    expect(result.provider).toBe('mock');
    expect(result.enrichments.size).toBeGreaterThan(0);
    expect(result.duration).toBeGreaterThanOrEqual(0);
  });

  it('should handle provider errors gracefully', async () => {
    const provider: AIProvider = {
      name: 'failing',
      model: 'fail-model',
      async analyze(): Promise<string> {
        throw new Error('API failure');
      },
    };

    const result = await runAIAnalysis(
      createMockFindings(),
      createMockGraph(),
      provider,
    );

    expect(result.provider).toBe('failing');
    expect(result.enrichments.size).toBe(0);
    expect(result.complexFindings.length).toBe(0);
  });

  it('should handle empty findings', async () => {
    const provider = createMockProvider(['{}', '{}', '{}']);
    const result = await runAIAnalysis([], createMockGraph(), provider);
    expect(result.enrichments.size).toBe(0);
  });

  it('should strip markdown code fences from LLM response', async () => {
    const provider = createMockProvider([
      '```json\n{"findings": [{"id": "AA-GI-001-0", "explanation": "test", "remediation": "fix"}]}\n```',
      '```\n{"assessments": [{"id": "AA-GI-001-0", "falsePositive": true, "reason": "test code"}]}\n```',
      '{"findings": []}',
    ]);

    const result = await runAIAnalysis(
      createMockFindings(),
      createMockGraph(),
      provider,
    );

    expect(result.enrichments.size).toBe(1);
    const enrichment = result.enrichments.get('AA-GI-001-0');
    expect(enrichment?.explanation).toBe('test');
    expect(enrichment?.falsePositive).toBe(true);
    expect(enrichment?.falsePositiveReason).toBe('test code');
  });

  it('should skip low confidence findings', async () => {
    const findings: Finding[] = [{
      id: 'AA-GI-001-0',
      ruleId: 'AA-GI-001',
      title: 'Low confidence finding',
      description: 'desc',
      severity: 'medium',
      confidence: 'low',
      domain: 'goal-integrity',
      location: { file: 'agent.py', line: 5 },
      remediation: 'Fix.',
      standards: { owaspAgentic: ['ASI01'] },
    }];

    let callCount = 0;
    const provider: AIProvider = {
      name: 'counter',
      model: 'counter-model',
      async analyze(): Promise<string> {
        callCount++;
        return '{"findings": []}';
      },
    };

    await runAIAnalysis(findings, createMockGraph(), provider);
    // Only the complex pattern pass should run (1 call), no explanation/FP passes
    expect(callCount).toBe(1);
  });

  it('should batch findings in groups of 5', async () => {
    const findings = createMockFindings(8); // 8 findings = 2 batches

    let callCount = 0;
    const provider: AIProvider = {
      name: 'counter',
      model: 'counter-model',
      async analyze(): Promise<string> {
        callCount++;
        return '{"findings": [], "assessments": []}';
      },
    };

    await runAIAnalysis(findings, createMockGraph(), provider);
    // 2 explanation batches + 2 FP batches + 1 complex = 5 calls
    expect(callCount).toBe(5);
  });

  it('should include checkType in finding context', async () => {
    const capturedContexts: string[] = [];
    const provider: AIProvider = {
      name: 'capture',
      model: 'capture-model',
      async analyze(_prompt: string, context: string): Promise<string> {
        capturedContexts.push(context);
        return '{"findings": [], "assessments": []}';
      },
    };

    await runAIAnalysis(createMockFindings(), createMockGraph(), provider);
    // First call is the explanation pass which includes finding metadata
    const firstContext = capturedContexts[0];
    expect(firstContext).toContain('prompt_missing');
    expect(firstContext).toContain('confidence');
    expect(firstContext).toContain('domain');
  });
});
