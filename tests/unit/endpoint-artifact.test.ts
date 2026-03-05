import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// ─── Key Redaction ───────────────────────────────────────────────────────────

describe('key redaction', () => {
  it('redacts long keys showing first 8 and last 4 chars', async () => {
    const { redactKey } = await import('../../src/endpoint/artifact-scanner.js');

    expect(redactKey('sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890')).toBe('sk-ant-a...7890');
    expect(redactKey('sk-proj-abcdefghijklmnopqrstuvwxyz')).toBe('sk-proj-...wxyz');
  });

  it('redacts short keys showing first 4 and last 4 chars', async () => {
    const { redactKey } = await import('../../src/endpoint/artifact-scanner.js');

    expect(redactKey('abcd1234efgh')).toBe('abcd...efgh');
  });
});

// ─── Key Patterns ────────────────────────────────────────────────────────────

describe('key patterns', () => {
  it('detects Anthropic API key pattern', async () => {
    const { KEY_PATTERNS } = await import('../../src/endpoint/artifact-scanner.js');
    const anthropic = KEY_PATTERNS.find(k => k.type === 'anthropic')!;

    const validKey = 'sk-ant-api03-' + 'a'.repeat(80);
    expect(anthropic.pattern.test(validKey)).toBe(true);
    expect(anthropic.pattern.test('not-a-key')).toBe(false);
  });

  it('detects OpenAI API key pattern', async () => {
    const { KEY_PATTERNS } = await import('../../src/endpoint/artifact-scanner.js');
    const openai = KEY_PATTERNS.find(k => k.type === 'openai' && k.label === 'OpenAI')!;

    const validKey = 'sk-proj-' + 'a'.repeat(48);
    expect(openai.pattern.test(validKey)).toBe(true);
  });

  it('detects GitHub token pattern', async () => {
    const { KEY_PATTERNS } = await import('../../src/endpoint/artifact-scanner.js');
    const github = KEY_PATTERNS.find(k => k.type === 'github')!;

    const validToken = 'ghp_' + 'a'.repeat(36);
    expect(github.pattern.test(validToken)).toBe(true);
    expect(github.pattern.test('not-a-token')).toBe(false);
  });

  it('detects AWS access key pattern', async () => {
    const { KEY_PATTERNS } = await import('../../src/endpoint/artifact-scanner.js');
    const aws = KEY_PATTERNS.find(k => k.type === 'aws')!;

    expect(aws.pattern.test('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    expect(aws.pattern.test('not-an-aws-key')).toBe(false);
  });

  it('detects Hugging Face token pattern', async () => {
    const { KEY_PATTERNS } = await import('../../src/endpoint/artifact-scanner.js');
    const hf = KEY_PATTERNS.find(k => k.type === 'huggingface')!;

    const validToken = 'hf_' + 'a'.repeat(34);
    expect(hf.pattern.test(validToken)).toBe(true);
  });

  it('all KEY_PATTERNS have required fields', async () => {
    const { KEY_PATTERNS } = await import('../../src/endpoint/artifact-scanner.js');

    for (const kp of KEY_PATTERNS) {
      expect(kp.type).toBeTruthy();
      expect(kp.label).toBeTruthy();
      expect(kp.pattern).toBeInstanceOf(RegExp);
      expect(Array.isArray(kp.envVars)).toBe(true);
    }
  });
});

// ─── MCP Config Key Scanning ─────────────────────────────────────────────────

describe('MCP config key scanning', () => {
  it('detects API keys in MCP server env blocks', async () => {
    const { scanMCPConfigKeys } = await import('../../src/endpoint/artifact-scanner.js');

    const mcpResult = {
      clients: [],
      servers: [{
        name: 'test-server',
        command: 'node',
        args: ['server.js'],
        env: { ANTHROPIC_API_KEY: 'sk-ant-api03-' + 'a'.repeat(80) },
        client: 'Claude Desktop',
        configFile: '/test/config.json',
        status: 'ok' as const,
      }],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0, totalServers: 1, totalTools: 0, totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok' as const,
      },
    };

    const exposures = scanMCPConfigKeys(mcpResult);
    expect(exposures.length).toBeGreaterThan(0);
    expect(exposures[0].tool).toBe('MCP:test-server');
    expect(exposures[0].keyType).toBe('anthropic');
    expect(exposures[0].issue).toBe('config-embedded');
    expect(exposures[0].severity).toBe('high');
  });

  it('skips env vars with shell variable references', async () => {
    const { scanMCPConfigKeys } = await import('../../src/endpoint/artifact-scanner.js');

    const mcpResult = {
      clients: [],
      servers: [{
        name: 'test-server',
        command: 'node',
        args: ['server.js'],
        env: { ANTHROPIC_API_KEY: '${ANTHROPIC_API_KEY}' },
        client: 'Claude Desktop',
        configFile: '/test/config.json',
        status: 'ok' as const,
      }],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0, totalServers: 1, totalTools: 0, totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok' as const,
      },
    };

    const exposures = scanMCPConfigKeys(mcpResult);
    expect(exposures.length).toBe(0);
  });
});

// ─── Data Store Scanning ─────────────────────────────────────────────────────

describe('data store locations', () => {
  it('DATA_STORE_LOCATIONS covers major AI tools', async () => {
    const { DATA_STORE_LOCATIONS } = await import('../../src/endpoint/artifact-scanner.js');

    const toolNames = DATA_STORE_LOCATIONS.map(l => l.tool);
    expect(toolNames).toContain('Claude Desktop');
    expect(toolNames).toContain('Claude Code');
    expect(toolNames).toContain('Cursor');
    expect(toolNames).toContain('Ollama');
    expect(toolNames).toContain('LM Studio');
    expect(toolNames).toContain('Continue');
  });

  it('each location has valid store type', async () => {
    const { DATA_STORE_LOCATIONS } = await import('../../src/endpoint/artifact-scanner.js');

    const validTypes = ['sqlite', 'json', 'model-cache', 'log'];
    for (const loc of DATA_STORE_LOCATIONS) {
      expect(validTypes).toContain(loc.storeType);
      expect(loc.paths.length).toBeGreaterThan(0);
    }
  });
});

// ─── Full Artifact Scan ──────────────────────────────────────────────────────

describe('scanArtifacts', () => {
  it('returns valid ArtifactScanResult shape', async () => {
    const { scanArtifacts } = await import('../../src/endpoint/artifact-scanner.js');

    const emptyMcp = {
      clients: [],
      servers: [],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0, totalServers: 0, totalTools: 0, totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok' as const,
      },
    };

    const result = scanArtifacts(emptyMcp);

    expect(result).toHaveProperty('credentials');
    expect(result).toHaveProperty('dataStores');
    expect(result).toHaveProperty('findings');
    expect(result).toHaveProperty('summary');
    expect(Array.isArray(result.credentials)).toBe(true);
    expect(Array.isArray(result.dataStores)).toBe(true);
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.summary.totalCredentials).toBe('number');
    expect(typeof result.summary.totalDataStores).toBe('number');
    expect(typeof result.summary.totalDataSizeBytes).toBe('number');
  });
});
