import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import type { EndpointScanResult } from '../../src/types/endpoint.js';

// ─── Helpers ────────────────────────────────────────────────────────────────

function makeBaseScanResult(overrides?: Partial<EndpointScanResult>): EndpointScanResult {
  return {
    machineId: 'test-machine',
    hostname: 'test-host',
    timestamp: new Date().toISOString(),
    tools: [],
    mcp: {
      clients: [], servers: [], tools: [], findings: [],
      summary: {
        totalClients: 0, totalServers: 0, totalTools: 0, totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok',
      },
    },
    network: {
      services: [], findings: [],
      summary: { totalListening: 0, aiServices: 0, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 },
    },
    artifacts: {
      credentials: [], dataStores: [], findings: [],
      summary: { totalCredentials: 0, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
    },
    crossReference: [],
    score: {
      total: 80, grade: 'B',
      categories: {
        configuration: { score: 25, max: 30, deductions: [] },
        credentials: { score: 25, max: 30, deductions: [] },
        network: { score: 20, max: 25, deductions: [] },
        discovery: { score: 10, max: 15, deductions: [] },
      },
    },
    summary: {
      totalTools: 0, runningTools: 0, totalServers: 0, totalFindings: 0,
      findingsBySeverity: {}, networkServices: 0, shadowServices: 0,
      credentialExposures: 0, dataStores: 0, overallStatus: 'ok',
    },
    duration: 100,
    layersRun: ['config', 'process', 'mcp'],
    ...overrides,
  };
}

// ─── Gitignore Entries ──────────────────────────────────────────────────────

describe('gitignore entries', () => {
  it('includes common sensitive patterns', async () => {
    const { GITIGNORE_ENTRIES } = await import('../../src/endpoint/remediation.js');

    expect(GITIGNORE_ENTRIES).toContain('.env');
    expect(GITIGNORE_ENTRIES).toContain('.claude/');
    expect(GITIGNORE_ENTRIES).toContain('.cursor/');
    expect(GITIGNORE_ENTRIES).toContain('.g0/auth.json');
  });
});

// ─── Rotation URLs ──────────────────────────────────────────────────────────

describe('rotation URLs', () => {
  it('covers major providers', async () => {
    const { ROTATION_URLS } = await import('../../src/endpoint/remediation.js');

    expect(ROTATION_URLS.anthropic).toBeDefined();
    expect(ROTATION_URLS.openai).toBeDefined();
    expect(ROTATION_URLS.google).toBeDefined();
    expect(ROTATION_URLS.aws).toBeDefined();
    expect(ROTATION_URLS.github).toBeDefined();
    expect(ROTATION_URLS.huggingface).toBeDefined();
  });

  it('all URLs are valid HTTPS', async () => {
    const { ROTATION_URLS } = await import('../../src/endpoint/remediation.js');

    for (const url of Object.values(ROTATION_URLS)) {
      expect(url).toMatch(/^https:\/\//);
    }
  });
});

// ─── Key Rotation ───────────────────────────────────────────────────────────

describe('suggestKeyRotation', () => {
  it('generates rotation steps for plaintext credentials', async () => {
    const { suggestKeyRotation } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      artifacts: {
        credentials: [{
          tool: 'shell',
          keyType: 'anthropic',
          location: '~/.zshrc',
          redactedValue: 'sk-ant-...xxxx',
          issue: 'plaintext',
          severity: 'critical',
        }],
        dataStores: [], findings: [],
        summary: { totalCredentials: 1, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
      },
    });

    const steps = suggestKeyRotation(scanResult);
    expect(steps.length).toBe(1);
    expect(steps[0].action).toBe('rotate-key');
    expect(steps[0].target).toBe('anthropic');
    expect(steps[0].description).toContain('anthropic');
  });

  it('deduplicates by key type', async () => {
    const { suggestKeyRotation } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      artifacts: {
        credentials: [
          { tool: 'shell', keyType: 'openai', location: '~/.zshrc', redactedValue: 'sk-proj-...', issue: 'plaintext', severity: 'critical' },
          { tool: 'env', keyType: 'openai', location: '~/.env', redactedValue: 'sk-proj-...', issue: 'plaintext', severity: 'high' },
        ],
        dataStores: [], findings: [],
        summary: { totalCredentials: 2, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
      },
    });

    const steps = suggestKeyRotation(scanResult);
    expect(steps.length).toBe(1); // Only one per provider
  });
});

// ─── Bind Localhost ─────────────────────────────────────────────────────────

describe('suggestBindLocalhost', () => {
  it('suggests binding to localhost for 0.0.0.0 services', async () => {
    const { suggestBindLocalhost } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      network: {
        services: [{
          port: 3001, pid: 123, process: 'node', bindAddress: '0.0.0.0',
          type: 'mcp-sse', authenticated: false, declaredInConfig: false,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 1, unauthenticated: 1, exposedToNetwork: 1 },
      },
    });

    const steps = suggestBindLocalhost(scanResult);
    expect(steps.length).toBe(1);
    expect(steps[0].action).toBe('bind-localhost');
    expect(steps[0].target).toBe(':3001');
  });

  it('skips services already on 127.0.0.1', async () => {
    const { suggestBindLocalhost } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      network: {
        services: [{
          port: 3001, pid: 123, process: 'node', bindAddress: '127.0.0.1',
          type: 'mcp-sse', authenticated: true, declaredInConfig: true,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 },
      },
    });

    const steps = suggestBindLocalhost(scanResult);
    expect(steps.length).toBe(0);
  });
});

// ─── Enable Auth ────────────────────────────────────────────────────────────

describe('suggestEnableAuth', () => {
  it('suggests auth for unauthenticated services', async () => {
    const { suggestEnableAuth } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      network: {
        services: [{
          port: 11434, pid: 456, process: 'ollama', bindAddress: '127.0.0.1',
          type: 'ollama', authenticated: false, declaredInConfig: true,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 0, unauthenticated: 1, exposedToNetwork: 0 },
      },
    });

    const steps = suggestEnableAuth(scanResult);
    expect(steps.length).toBe(1);
    expect(steps[0].action).toBe('enable-auth');
  });

  it('skips authenticated services', async () => {
    const { suggestEnableAuth } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      network: {
        services: [{
          port: 3001, pid: 123, process: 'node', bindAddress: '127.0.0.1',
          type: 'mcp-sse', authenticated: true, declaredInConfig: true,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 },
      },
    });

    const steps = suggestEnableAuth(scanResult);
    expect(steps.length).toBe(0);
  });
});

// ─── Full Remediation ───────────────────────────────────────────────────────

describe('runRemediation', () => {
  it('returns valid RemediationResult shape', async () => {
    const { runRemediation } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult();
    const result = runRemediation(scanResult);

    expect(result).toHaveProperty('steps');
    expect(result).toHaveProperty('summary');
    expect(Array.isArray(result.steps)).toBe(true);
    expect(typeof result.summary.totalSteps).toBe('number');
    expect(typeof result.summary.applied).toBe('number');
    expect(typeof result.summary.skipped).toBe('number');
    expect(typeof result.summary.failed).toBe('number');
  });

  it('generates steps for mixed findings', async () => {
    const { runRemediation } = await import('../../src/endpoint/remediation.js');

    const scanResult = makeBaseScanResult({
      artifacts: {
        credentials: [
          { tool: 'shell', keyType: 'anthropic', location: '~/.zshrc', redactedValue: 'sk-ant-...', issue: 'plaintext', severity: 'critical' },
        ],
        dataStores: [], findings: [],
        summary: { totalCredentials: 1, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
      },
      network: {
        services: [{
          port: 8000, pid: 100, process: 'vllm', bindAddress: '0.0.0.0',
          type: 'vllm', authenticated: false, declaredInConfig: false,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 1, unauthenticated: 1, exposedToNetwork: 1 },
      },
    });

    const result = runRemediation(scanResult);
    // Should have: key rotation + bind localhost + enable auth + possibly gitignore
    expect(result.steps.length).toBeGreaterThanOrEqual(3);

    const actions = result.steps.map(s => s.action);
    expect(actions).toContain('rotate-key');
    expect(actions).toContain('bind-localhost');
    expect(actions).toContain('enable-auth');
  });
});
