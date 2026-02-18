import { describe, it, expect } from 'vitest';
import type { AgentGraph } from '../../src/types/agent-graph.js';
import { enrichmentRules } from '../../src/analyzers/rules/enrichment-rules.js';

function makeGraph(overrides?: Partial<AgentGraph>): AgentGraph {
  return {
    id: 'test',
    rootPath: '/tmp/test',
    primaryFramework: 'openai',
    secondaryFrameworks: [],
    agents: [],
    tools: [],
    prompts: [],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files: { all: [], python: [], typescript: [], javascript: [], java: [], go: [] },
    permissions: [],
    apiEndpoints: [],
    databaseAccesses: [],
    authFlows: [],
    permissionChecks: [],
    piiReferences: [],
    messageQueues: [],
    rateLimits: [],
    callGraph: [],
    ...overrides,
  };
}

function findRule(id: string) {
  const rule = enrichmentRules.find(r => r.id === id);
  if (!rule) throw new Error(`Rule ${id} not found`);
  return rule;
}

// ─── AA-DL-200: PII logged without masking ─────────────────────────

describe('AA-DL-200: PII logged without masking', () => {
  const rule = findRule('AA-DL-200');

  it('fires when PII is logged without masking', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'email', file: 'app.py', line: 10, context: 'logging', hasMasking: false, hasEncryption: false },
      ],
    });
    const findings = rule.check(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
  });

  it('does not fire when PII is logged with masking', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'email', file: 'app.py', line: 10, context: 'logging', hasMasking: true, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire for non-logging context', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'email', file: 'app.py', line: 10, context: 'storage', hasMasking: false, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-DL-201: PII transmitted without encryption ─────────────────

describe('AA-DL-201: PII transmitted without encryption', () => {
  const rule = findRule('AA-DL-201');

  it('fires when PII is transmitted without encryption', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'ssn', file: 'api.py', line: 5, context: 'transmission', hasMasking: false, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when encrypted', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'ssn', file: 'api.py', line: 5, context: 'transmission', hasMasking: false, hasEncryption: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-DL-202: PII stored without encryption ──────────────────────

describe('AA-DL-202: PII stored without encryption', () => {
  const rule = findRule('AA-DL-202');

  it('fires when PII is stored without encryption', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'financial', file: 'db.py', line: 20, context: 'storage', hasMasking: false, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
    expect(rule.check(graph)[0].severity).toBe('medium');
  });

  it('does not fire when encrypted', () => {
    const graph = makeGraph({
      piiReferences: [
        { type: 'financial', file: 'db.py', line: 20, context: 'storage', hasMasking: false, hasEncryption: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-TS-200: Unparameterized SQL query ──────────────────────────

describe('AA-TS-200: Unparameterized SQL query', () => {
  const rule = findRule('AA-TS-200');

  it('fires on unparameterized SQL query', () => {
    const graph = makeGraph({
      databaseAccesses: [
        { type: 'sql', operation: 'read', table: 'users', file: 'db.py', line: 10, hasParameterizedQuery: false },
      ],
    });
    const findings = rule.check(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
    expect(findings[0].description).toContain('users');
  });

  it('does not fire on parameterized SQL', () => {
    const graph = makeGraph({
      databaseAccesses: [
        { type: 'sql', operation: 'read', table: 'users', file: 'db.py', line: 10, hasParameterizedQuery: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire on ORM accesses', () => {
    const graph = makeGraph({
      databaseAccesses: [
        { type: 'orm', operation: 'read', file: 'db.ts', line: 10, hasParameterizedQuery: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-TS-201: Admin database operation ────────────────────────────

describe('AA-TS-201: Admin database operation', () => {
  const rule = findRule('AA-TS-201');

  it('fires on admin operation', () => {
    const graph = makeGraph({
      databaseAccesses: [
        { type: 'sql', operation: 'admin', table: 'temp_data', file: 'migrate.sql', line: 1, hasParameterizedQuery: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire on read/write', () => {
    const graph = makeGraph({
      databaseAccesses: [
        { type: 'sql', operation: 'read', table: 'users', file: 'db.py', line: 10, hasParameterizedQuery: true },
        { type: 'sql', operation: 'write', table: 'users', file: 'db.py', line: 20, hasParameterizedQuery: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-IA-200: Auth flow without token validation ──────────────────

describe('AA-IA-200: Auth flow without token validation', () => {
  const rule = findRule('AA-IA-200');

  it('fires when auth flow lacks validation', () => {
    const graph = makeGraph({
      authFlows: [
        { type: 'jwt', file: 'auth.ts', line: 5, hasTokenValidation: false, hasTokenExpiry: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when validation exists', () => {
    const graph = makeGraph({
      authFlows: [
        { type: 'jwt', file: 'auth.ts', line: 5, hasTokenValidation: true, hasTokenExpiry: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-IA-201: Auth flow without token expiry ──────────────────────

describe('AA-IA-201: Auth flow without token expiry', () => {
  const rule = findRule('AA-IA-201');

  it('fires when auth flow lacks expiry', () => {
    const graph = makeGraph({
      authFlows: [
        { type: 'jwt', file: 'auth.ts', line: 5, hasTokenValidation: true, hasTokenExpiry: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when expiry is set', () => {
    const graph = makeGraph({
      authFlows: [
        { type: 'jwt', file: 'auth.ts', line: 5, hasTokenValidation: true, hasTokenExpiry: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-IA-202: External API without auth ───────────────────────────

describe('AA-IA-202: External API call without authentication', () => {
  const rule = findRule('AA-IA-202');

  it('fires when external API has no auth in same file', () => {
    const graph = makeGraph({
      apiEndpoints: [
        { url: 'https://api.example.com/data', file: 'client.py', line: 10, framework: 'openai', isExternal: true },
      ],
      authFlows: [],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when auth exists in same file', () => {
    const graph = makeGraph({
      apiEndpoints: [
        { url: 'https://api.example.com/data', file: 'client.py', line: 10, framework: 'openai', isExternal: true },
      ],
      authFlows: [
        { type: 'api-key', file: 'client.py', line: 5, hasTokenValidation: false, hasTokenExpiry: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire for internal endpoints', () => {
    const graph = makeGraph({
      apiEndpoints: [
        { url: 'http://localhost:3000/api', file: 'app.ts', line: 10, framework: 'openai', isExternal: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-IC-200: Message queue without auth ─────────────────────────

describe('AA-IC-200: Message queue without authentication', () => {
  const rule = findRule('AA-IC-200');

  it('fires when MQ lacks auth', () => {
    const graph = makeGraph({
      messageQueues: [
        { type: 'kafka', file: 'worker.py', line: 5, hasAuthentication: false, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when MQ has auth', () => {
    const graph = makeGraph({
      messageQueues: [
        { type: 'kafka', file: 'worker.py', line: 5, hasAuthentication: true, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-IC-201: Message queue without encryption ───────────────────

describe('AA-IC-201: Message queue without encryption', () => {
  const rule = findRule('AA-IC-201');

  it('fires when MQ lacks encryption', () => {
    const graph = makeGraph({
      messageQueues: [
        { type: 'rabbitmq', file: 'consumer.py', line: 10, hasAuthentication: true, hasEncryption: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when MQ has encryption', () => {
    const graph = makeGraph({
      messageQueues: [
        { type: 'rabbitmq', file: 'consumer.py', line: 10, hasAuthentication: true, hasEncryption: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-GI-200: Contradictory prompt permissions ────────────────────

describe('AA-GI-200: Contradictory prompt permissions', () => {
  const rule = findRule('AA-GI-200');

  it('fires when same prompt has contradictory allowed/forbidden', () => {
    const graph = makeGraph({
      permissions: [
        { type: 'allowed', action: 'access the database directly', source: 'prompt-1', file: 'agent.py', line: 5 },
        { type: 'forbidden', action: 'access the database without authorization', source: 'prompt-1', file: 'agent.py', line: 10 },
      ],
    });
    const findings = rule.check(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe('high');
  });

  it('does not fire when no overlap', () => {
    const graph = makeGraph({
      permissions: [
        { type: 'allowed', action: 'read files from data directory', source: 'prompt-1', file: 'agent.py', line: 5 },
        { type: 'forbidden', action: 'execute shell commands', source: 'prompt-1', file: 'agent.py', line: 10 },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire when from different sources', () => {
    const graph = makeGraph({
      permissions: [
        { type: 'allowed', action: 'access the database', source: 'prompt-1', file: 'agent.py', line: 5 },
        { type: 'forbidden', action: 'access the database', source: 'prompt-2', file: 'other.py', line: 10 },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-GI-201: No boundary constraints ─────────────────────────────

describe('AA-GI-201: No boundary constraints in system prompt', () => {
  const rule = findRule('AA-GI-201');

  it('fires when prompt has allowed but no boundary', () => {
    const graph = makeGraph({
      permissions: [
        { type: 'allowed', action: 'access external APIs', source: 'prompt-1', file: 'agent.py', line: 5 },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when boundary exists', () => {
    const graph = makeGraph({
      permissions: [
        { type: 'allowed', action: 'access external APIs', source: 'prompt-1', file: 'agent.py', line: 5 },
        { type: 'boundary', action: 'read-only operations', source: 'prompt-1', file: 'agent.py', line: 10 },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire when no allowed permissions', () => {
    const graph = makeGraph({
      permissions: [
        { type: 'forbidden', action: 'delete files', source: 'prompt-1', file: 'agent.py', line: 5 },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-CF-200: External API without rate limiting ──────────────────

describe('AA-CF-200: External API without rate limiting', () => {
  const rule = findRule('AA-CF-200');

  it('fires when external API has no rate limit in same file', () => {
    const graph = makeGraph({
      apiEndpoints: [
        { url: 'https://api.example.com/data', file: 'client.py', line: 10, framework: 'openai', isExternal: true },
      ],
      rateLimits: [],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when rate limit exists in same file', () => {
    const graph = makeGraph({
      apiEndpoints: [
        { url: 'https://api.example.com/data', file: 'client.py', line: 10, framework: 'openai', isExternal: true },
      ],
      rateLimits: [
        { file: 'client.py', line: 1, type: 'api', hasLimit: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire for internal endpoints', () => {
    const graph = makeGraph({
      apiEndpoints: [
        { url: 'http://localhost:3000/api', file: 'app.ts', line: 10, framework: 'openai', isExternal: false },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });
});

// ─── AA-RB-200: No rate limiting for LLM calls ─────────────────────

describe('AA-RB-200: No rate limiting for LLM calls', () => {
  const rule = findRule('AA-RB-200');

  it('fires when models exist but no LLM rate limit', () => {
    const graph = makeGraph({
      models: [
        { id: 'model-1', name: 'gpt-4', provider: 'openai', framework: 'openai', file: 'agent.py', line: 5 },
      ],
      rateLimits: [
        { file: 'app.py', line: 1, type: 'api', hasLimit: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(1);
  });

  it('does not fire when LLM rate limit exists', () => {
    const graph = makeGraph({
      models: [
        { id: 'model-1', name: 'gpt-4', provider: 'openai', framework: 'openai', file: 'agent.py', line: 5 },
      ],
      rateLimits: [
        { file: 'config.py', line: 1, type: 'llm', hasLimit: true },
      ],
    });
    expect(rule.check(graph)).toHaveLength(0);
  });

  it('does not fire when no models', () => {
    const graph = makeGraph({ models: [] });
    expect(rule.check(graph)).toHaveLength(0);
  });
});
