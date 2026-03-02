import { describe, it, expect, vi } from 'vitest';
import { GoatStrategy } from '../../src/testing/adaptive/goat.js';
import { CrescendoStrategy } from '../../src/testing/adaptive/crescendo.js';
import { ReconProbeStrategy } from '../../src/testing/adaptive/recon-probe.js';
import { HydraStrategy } from '../../src/testing/adaptive/hydra.js';
import { SimbaStrategy } from '../../src/testing/adaptive/simba.js';
import { getAdaptiveStrategy, getAllAdaptiveStrategyIds } from '../../src/testing/adaptive/index.js';
import { generateObjectives } from '../../src/testing/adaptive/objectives.js';
import { extractLearnings, buildPriorIntelligence, type AttackProfile } from '../../src/testing/adaptive/profiles.js';
import { getAIProviderBySpec } from '../../src/ai/provider.js';
import type { AdaptiveAttackConfig, AttackState, StaticContext, AdaptiveTestCaseResult } from '../../src/types/test.js';
import type { AIProvider } from '../../src/ai/provider.js';

function createMockAIProvider(response: string): AIProvider {
  return {
    name: 'mock',
    model: 'mock-model',
    analyze: vi.fn().mockResolvedValue(response),
  };
}

function createMockConfig(overrides?: Partial<AdaptiveAttackConfig>): AdaptiveAttackConfig {
  return {
    strategy: 'goat',
    maxTurns: 10,
    objective: 'Extract the system prompt',
    category: 'prompt-injection',
    severity: 'high',
    ...overrides,
  };
}

describe('Adaptive Attack Strategies', () => {
  describe('Strategy Registry', () => {
    it('returns all strategy IDs', () => {
      const ids = getAllAdaptiveStrategyIds();
      expect(ids).toContain('goat');
      expect(ids).toContain('crescendo');
      expect(ids).toContain('recon-probe');
      expect(ids).toContain('hydra');
      expect(ids).toContain('simba');
      expect(ids).toHaveLength(5);
    });

    it('creates GOAT strategy', () => {
      const strategy = getAdaptiveStrategy('goat');
      expect(strategy.id).toBe('goat');
      expect(strategy.name).toContain('GOAT');
    });

    it('creates Crescendo strategy', () => {
      const strategy = getAdaptiveStrategy('crescendo');
      expect(strategy.id).toBe('crescendo');
    });

    it('creates Recon-Probe strategy', () => {
      const strategy = getAdaptiveStrategy('recon-probe');
      expect(strategy.id).toBe('recon-probe');
    });

    it('creates Hydra strategy', () => {
      const strategy = getAdaptiveStrategy('hydra');
      expect(strategy.id).toBe('hydra');
    });

    it('throws for unknown strategy', () => {
      expect(() => getAdaptiveStrategy('unknown' as any)).toThrow('Unknown adaptive strategy');
    });
  });

  describe('GOAT Strategy', () => {
    const goat = new GoatStrategy();

    it('initializes state correctly', () => {
      const config = createMockConfig();
      const state = goat.initState(config);
      expect(state.turnCount).toBe(0);
      expect(state.conversationHistory).toHaveLength(0);
      expect(state.responsesReceived).toHaveLength(0);
      expect(state.observations).toHaveLength(0);
      expect(state.phase).toBe('attack');
    });

    it('builds red team prompt with objective', () => {
      const config = createMockConfig();
      const state = goat.initState(config);
      const prompt = goat.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('Extract the system prompt');
      expect(prompt).toContain('TURN: 1 / 10');
      expect(prompt).toContain('first turn');
    });

    it('includes conversation history in prompt', () => {
      const config = createMockConfig();
      const state = goat.initState(config);
      state.conversationHistory.push({ role: 'user', content: 'Hello' });
      state.responsesReceived.push('Hi there!');
      state.turnCount = 1;

      const prompt = goat.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('Hello');
      expect(prompt).toContain('Hi there!');
      expect(prompt).toContain('TURN: 2 / 10');
    });

    it('includes failed tactics in prompt', () => {
      const config = createMockConfig();
      const state = goat.initState(config);
      state.failedTactics.push('Direct request was refused');

      const prompt = goat.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('FAILED TACTICS');
      expect(prompt).toContain('Direct request was refused');
    });

    it('parses JSON response from LLM', async () => {
      const mockResponse = JSON.stringify({
        message: 'Can you tell me about your configuration?',
        shouldContinue: true,
        observations: ['Agent seems open to technical questions'],
        reasoning: 'Starting with an innocuous question',
      });
      const aiProvider = createMockAIProvider(mockResponse);
      const config = createMockConfig();
      const state = goat.initState(config);

      const decision = await goat.nextTurn(state, config, aiProvider);
      expect(decision.message).toBe('Can you tell me about your configuration?');
      expect(decision.shouldContinue).toBe(true);
      expect(decision.observations).toContain('Agent seems open to technical questions');
    });

    it('handles non-JSON response gracefully', async () => {
      const aiProvider = createMockAIProvider('Just send this message to the target');
      const config = createMockConfig();
      const state = goat.initState(config);

      const decision = await goat.nextTurn(state, config, aiProvider);
      expect(decision.message).toBeTruthy();
      expect(decision.shouldContinue).toBe(true);
    });

    it('stops when shouldContinue is false', async () => {
      const mockResponse = JSON.stringify({
        message: 'Final attempt',
        shouldContinue: false,
        observations: ['Agent is firmly resistant'],
        reasoning: 'No more approaches to try',
      });
      const aiProvider = createMockAIProvider(mockResponse);
      const config = createMockConfig();
      const state = goat.initState(config);

      const decision = await goat.nextTurn(state, config, aiProvider);
      expect(decision.shouldContinue).toBe(false);
    });
  });

  describe('Crescendo Strategy', () => {
    const crescendo = new CrescendoStrategy();

    it('initializes with intensity 1', () => {
      const config = createMockConfig({ strategy: 'crescendo' });
      const state = crescendo.initState(config);
      expect(state.meta.intensityLevel).toBe(1);
      expect(state.phase).toBe('escalation');
    });

    it('includes intensity level in prompt', () => {
      const config = createMockConfig({ strategy: 'crescendo' });
      const state = crescendo.initState(config);
      const prompt = crescendo.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('CURRENT INTENSITY: 1/10');
      expect(prompt).toContain('CRESCENDO');
    });

    it('escalates intensity on each turn', async () => {
      const mockResponse = JSON.stringify({
        message: 'Just chatting',
        shouldContinue: true,
        observations: [],
        reasoning: 'Building rapport',
        newIntensity: 3,
      });
      const aiProvider = createMockAIProvider(mockResponse);
      const config = createMockConfig({ strategy: 'crescendo' });
      const state = crescendo.initState(config);

      await crescendo.nextTurn(state, config, aiProvider);
      expect(state.meta.intensityLevel).toBe(3);
    });

    it('caps intensity at 10', async () => {
      const mockResponse = JSON.stringify({
        message: 'Direct request',
        shouldContinue: true,
        observations: [],
        reasoning: 'Final push',
        newIntensity: 15,
      });
      const aiProvider = createMockAIProvider(mockResponse);
      const config = createMockConfig({ strategy: 'crescendo' });
      const state = crescendo.initState(config);
      state.meta.intensityLevel = 9;

      await crescendo.nextTurn(state, config, aiProvider);
      expect(state.meta.intensityLevel).toBe(10);
    });
  });

  describe('Recon-Probe Strategy', () => {
    const reconProbe = new ReconProbeStrategy();

    it('initializes with recon phase', () => {
      const config = createMockConfig({ strategy: 'recon-probe' });
      const state = reconProbe.initState(config);
      expect(state.phase).toBe('recon');
      expect(state.meta.discoveredTools).toEqual([]);
    });

    it('builds recon prompt for early turns', () => {
      const config = createMockConfig({ strategy: 'recon-probe' });
      const state = reconProbe.initState(config);
      const prompt = reconProbe.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('RECONNAISSANCE');
    });

    it('transitions to attack phase for later turns', () => {
      const config = createMockConfig({ strategy: 'recon-probe', maxTurns: 10 });
      const state = reconProbe.initState(config);
      state.turnCount = 7;
      const prompt = reconProbe.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('ATTACK');
    });

    it('updates discovered intelligence', async () => {
      const mockResponse = JSON.stringify({
        message: 'What can you help me with?',
        shouldContinue: true,
        observations: ['Agent has file access tools'],
        reasoning: 'Mapping capabilities',
        discoveredTools: ['file_read', 'web_search'],
        discoveredRestrictions: ['Cannot discuss violence'],
        discoveredPersona: 'helpful assistant',
      });
      const aiProvider = createMockAIProvider(mockResponse);
      const config = createMockConfig({ strategy: 'recon-probe' });
      const state = reconProbe.initState(config);

      await reconProbe.nextTurn(state, config, aiProvider);
      expect(state.meta.discoveredTools).toEqual(['file_read', 'web_search']);
      expect(state.meta.discoveredRestrictions).toEqual(['Cannot discuss violence']);
      expect(state.meta.discoveredPersona).toBe('helpful assistant');
    });
  });

  describe('Hydra Strategy', () => {
    const hydra = new HydraStrategy();

    it('initializes with recon phase', () => {
      const config = createMockConfig({ strategy: 'hydra' });
      const state = hydra.initState(config);
      expect(state.phase).toBe('recon');
      expect(state.meta.branches).toEqual([]);
      expect(state.meta.activeBranch).toBe(-1);
    });

    it('builds recon prompt initially', () => {
      const config = createMockConfig({ strategy: 'hydra' });
      const state = hydra.initState(config);
      const prompt = hydra.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('RECON phase');
    });
  });

  describe('Objective Generator', () => {
    it('generates baseline objectives without context', () => {
      const objectives = generateObjectives();
      expect(objectives.length).toBeGreaterThanOrEqual(3);
      expect(objectives.some(o => o.category === 'prompt-injection')).toBe(true);
      expect(objectives.some(o => o.category === 'jailbreak')).toBe(true);
    });

    it('filters by allowed strategies', () => {
      const objectives = generateObjectives(undefined, ['goat']);
      expect(objectives.every(o => o.strategy === 'goat')).toBe(true);
    });

    it('generates context-driven objectives for unvalidated tools', () => {
      const context: StaticContext = {
        tools: [
          { name: 'shell_exec', capabilities: ['shell'], hasValidation: false },
        ],
        models: [],
        prompts: [{ type: 'system', hasGuarding: true, scopeClarity: 'clear' }],
        findings: [],
      };
      const objectives = generateObjectives(context);
      expect(objectives.some(o => o.category === 'tool-abuse')).toBe(true);
    });

    it('generates data exfiltration objectives for data-leakage findings', () => {
      const context: StaticContext = {
        tools: [],
        models: [],
        prompts: [],
        findings: [{ ruleId: 'DL-001', domain: 'data-leakage', severity: 'high' }],
      };
      const objectives = generateObjectives(context);
      expect(objectives.some(o => o.category === 'data-exfiltration')).toBe(true);
    });

    it('generates goal-hijacking objectives for goal-integrity findings', () => {
      const context: StaticContext = {
        tools: [],
        models: [],
        prompts: [],
        findings: [{ ruleId: 'GI-001', domain: 'goal-integrity', severity: 'high' }],
      };
      const objectives = generateObjectives(context);
      expect(objectives.some(o => o.category === 'goal-hijacking')).toBe(true);
    });

    it('generates prompt injection objectives for unguarded prompts', () => {
      const context: StaticContext = {
        tools: [],
        models: [],
        prompts: [{ type: 'system', hasGuarding: false, scopeClarity: 'vague' }],
        findings: [],
      };
      const objectives = generateObjectives(context);
      expect(objectives.some(o => o.strategy === 'hydra')).toBe(true);
    });

    it('sets default maxTurns', () => {
      const objectives = generateObjectives();
      for (const obj of objectives) {
        expect(obj.maxTurns).toBeGreaterThanOrEqual(10);
      }
    });

    it('generates framework-specific objectives when framework is in context', () => {
      const context: StaticContext = {
        tools: [],
        models: [],
        prompts: [],
        findings: [],
        framework: { id: 'langchain' },
      };
      const objectives = generateObjectives(context);
      expect(objectives.some(o => o.frameworkId === 'langchain')).toBe(true);
      expect(objectives.some(o => o.objective.includes('langchain'))).toBe(true);
    });
  });

  describe('SIMBA Strategy', () => {
    const simba = new SimbaStrategy();

    it('initializes state correctly', () => {
      const config = createMockConfig({ strategy: 'simba' });
      const state = simba.initState(config);
      expect(state.turnCount).toBe(0);
      expect(state.phase).toBe('expand');
      expect(state.meta.tree).toEqual([]);
      expect(state.meta.branchFactor).toBe(3);
      expect(state.meta.pruneThreshold).toBe(4);
    });

    it('builds red team prompt requesting variants', () => {
      const config = createMockConfig({ strategy: 'simba' });
      const state = simba.initState(config);
      const prompt = simba.buildRedTeamPrompt(config, state);
      expect(prompt).toContain('SIMBA');
      expect(prompt).toContain('variants');
      expect(prompt).toContain('Extract the system prompt');
    });

    it('parses variant responses and queues pending', async () => {
      const mockResponse = JSON.stringify({
        variants: ['Try approach A', 'Try approach B', 'Try approach C'],
        observations: ['Target seems to respond to questions'],
        reasoning: 'Testing different angles',
      });
      const aiProvider = createMockAIProvider(mockResponse);
      const config = createMockConfig({ strategy: 'simba' });
      const state = simba.initState(config);

      const decision = await simba.nextTurn(state, config, aiProvider);
      expect(decision.message).toBe('Try approach A');
      expect(decision.shouldContinue).toBe(true);
      expect(state.meta.pendingVariants).toEqual(['Try approach B', 'Try approach C']);
    });

    it('sends pending variants on subsequent turns', async () => {
      const aiProvider = createMockAIProvider('{}');
      const config = createMockConfig({ strategy: 'simba' });
      const state = simba.initState(config);
      state.meta.pendingVariants = ['variant 2', 'variant 3'];

      const decision = await simba.nextTurn(state, config, aiProvider);
      expect(decision.message).toBe('variant 2');
      expect(state.meta.pendingVariants).toEqual(['variant 3']);
    });

    it('creates strategy via registry', () => {
      const strategy = getAdaptiveStrategy('simba');
      expect(strategy.id).toBe('simba');
      expect(strategy.name).toContain('SIMBA');
    });
  });

  describe('Attack Profiles', () => {
    it('extracts learnings from vulnerable results', () => {
      const results: AdaptiveTestCaseResult[] = [
        {
          payloadId: 'test-1',
          payloadName: 'Test',
          category: 'prompt-injection',
          severity: 'high',
          verdict: 'vulnerable',
          judgeLevel: 'llm',
          confidence: 'high',
          messagesSent: [],
          responsesReceived: [],
          evidence: 'Agent revealed system prompt',
          durationMs: 1000,
          strategyId: 'goat',
          turnsExecuted: 5,
          finalState: {
            conversationHistory: [],
            responsesReceived: [],
            observations: [],
            failedTactics: ['direct request'],
            promisingTactics: ['role-play as developer'],
            phase: 'attack',
            turnCount: 5,
            meta: {},
          },
        },
      ];

      const empty: AttackProfile = {
        successfulTactics: [],
        failedTactics: [],
        frameworkWeaknesses: {},
        categoryInsights: {},
        lastUpdated: '',
      };

      const profile = extractLearnings(results, empty);
      expect(profile.successfulTactics).toHaveLength(1);
      expect(profile.successfulTactics[0].tactic).toBe('role-play as developer');
      expect(profile.categoryInsights['prompt-injection']).toBeDefined();
      expect(profile.categoryInsights['prompt-injection'].length).toBeGreaterThan(0);
    });

    it('builds prior intelligence prompt from profile', () => {
      const profile: AttackProfile = {
        successfulTactics: [
          { tactic: 'role-play worked', category: 'prompt-injection', strategy: 'goat', timestamp: '' },
        ],
        failedTactics: [
          { tactic: 'direct ask failed', category: 'prompt-injection', strategy: 'goat', timestamp: '' },
        ],
        frameworkWeaknesses: {},
        categoryInsights: {
          'prompt-injection': ['goat succeeded in 3 turns'],
        },
        lastUpdated: '',
      };

      const intel = buildPriorIntelligence(profile, 'prompt-injection');
      expect(intel).toContain('PRIOR INTELLIGENCE');
      expect(intel).toContain('role-play worked');
      expect(intel).toContain('direct ask failed');
      expect(intel).toContain('goat succeeded in 3 turns');
    });

    it('returns empty string for empty profile', () => {
      const empty: AttackProfile = {
        successfulTactics: [],
        failedTactics: [],
        frameworkWeaknesses: {},
        categoryInsights: {},
        lastUpdated: '',
      };
      expect(buildPriorIntelligence(empty)).toBe('');
    });
  });

  describe('getAIProviderBySpec', () => {
    it('parses anthropic/model format', () => {
      const origKey = process.env.ANTHROPIC_API_KEY;
      process.env.ANTHROPIC_API_KEY = 'test-key';
      try {
        const provider = getAIProviderBySpec('anthropic/claude-sonnet-4-5-20250929');
        expect(provider).not.toBeNull();
        expect(provider!.name).toBe('anthropic');
        expect(provider!.model).toBe('claude-sonnet-4-5-20250929');
      } finally {
        if (origKey) process.env.ANTHROPIC_API_KEY = origKey;
        else delete process.env.ANTHROPIC_API_KEY;
      }
    });

    it('returns null for unknown provider', () => {
      const provider = getAIProviderBySpec('unknown/model');
      expect(provider).toBeNull();
    });

    it('returns null when API key is missing', () => {
      const origKey = process.env.ANTHROPIC_API_KEY;
      delete process.env.ANTHROPIC_API_KEY;
      try {
        const provider = getAIProviderBySpec('anthropic/some-model');
        expect(provider).toBeNull();
      } finally {
        if (origKey) process.env.ANTHROPIC_API_KEY = origKey;
      }
    });

    it('parses ollama/model format', () => {
      const provider = getAIProviderBySpec('ollama/mistral');
      expect(provider).not.toBeNull();
      expect(provider!.name).toBe('ollama');
      expect(provider!.model).toBe('mistral');
    });

    it('uses custom OLLAMA_BASE_URL', () => {
      process.env.OLLAMA_BASE_URL = 'http://custom:11434';
      try {
        const provider = getAIProviderBySpec('ollama/llama3');
        expect(provider).not.toBeNull();
        expect(provider!.name).toBe('ollama');
        expect(provider!.model).toBe('llama3');
      } finally {
        delete process.env.OLLAMA_BASE_URL;
      }
    });

    it('parses huggingface/org/model format', () => {
      process.env.HF_API_TOKEN = 'hf_test_token';
      try {
        const provider = getAIProviderBySpec('huggingface/mistralai/Mistral-7B-Instruct-v0.2');
        expect(provider).not.toBeNull();
        expect(provider!.name).toBe('huggingface');
        expect(provider!.model).toBe('mistralai/Mistral-7B-Instruct-v0.2');
      } finally {
        delete process.env.HF_API_TOKEN;
      }
    });

    it('returns null for huggingface without token', () => {
      delete process.env.HF_API_TOKEN;
      const provider = getAIProviderBySpec('huggingface/org/model');
      expect(provider).toBeNull();
    });

    it('returns null for huggingface without model', () => {
      process.env.HF_API_TOKEN = 'hf_test_token';
      try {
        const provider = getAIProviderBySpec('huggingface');
        expect(provider).toBeNull();
      } finally {
        delete process.env.HF_API_TOKEN;
      }
    });
  });
});
