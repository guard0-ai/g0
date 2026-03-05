import { describe, it, expect } from 'vitest';
import type { EndpointScanResult } from '../../src/types/endpoint.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeBaseScan(overrides?: Partial<EndpointScanResult>): EndpointScanResult {
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
      total: 80,
      grade: 'B',
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
    layersRun: ['config', 'process', 'mcp', 'network', 'artifacts'],
    ...overrides,
  };
}

// ─── Drift Detection ─────────────────────────────────────────────────────────

describe('detectDrift', () => {
  it('detects new shadow services', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan();
    const current = makeBaseScan({
      network: {
        services: [{
          port: 3001, pid: 123, process: 'node', bindAddress: '127.0.0.1',
          type: 'mcp-sse', authenticated: false, declaredInConfig: false,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 1, unauthenticated: 1, exposedToNetwork: 0 },
      },
    });

    const drift = detectDrift(previous, current);
    const shadowEvent = drift.events.find(e => e.type === 'new-shadow-service');
    expect(shadowEvent).toBeDefined();
    expect(shadowEvent!.title).toContain('3001');
  });

  it('detects new credential exposures', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan();
    const current = makeBaseScan({
      artifacts: {
        credentials: [{
          tool: 'shell', keyType: 'anthropic', location: '~/.zshrc',
          redactedValue: 'sk-ant-...xxxx', issue: 'plaintext', severity: 'critical',
        }],
        dataStores: [], findings: [],
        summary: { totalCredentials: 1, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
      },
    });

    const drift = detectDrift(previous, current);
    const credEvent = drift.events.find(e => e.type === 'new-credential-exposure');
    expect(credEvent).toBeDefined();
    expect(credEvent!.severity).toBe('critical');
  });

  it('detects score drops >= 10 points', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan();
    const current = makeBaseScan({
      score: {
        total: 65, grade: 'C',
        categories: {
          configuration: { score: 15, max: 30, deductions: [] },
          credentials: { score: 20, max: 30, deductions: [] },
          network: { score: 20, max: 25, deductions: [] },
          discovery: { score: 10, max: 15, deductions: [] },
        },
      },
    });

    const drift = detectDrift(previous, current);
    expect(drift.scoreDelta).toBe(-15);
    const scoreEvent = drift.events.find(e => e.type === 'score-drop');
    expect(scoreEvent).toBeDefined();
    expect(scoreEvent!.title).toContain('15');
  });

  it('does not flag score drops < 10 points', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan();
    const current = makeBaseScan({
      score: {
        total: 75, grade: 'B',
        categories: {
          configuration: { score: 20, max: 30, deductions: [] },
          credentials: { score: 25, max: 30, deductions: [] },
          network: { score: 20, max: 25, deductions: [] },
          discovery: { score: 10, max: 15, deductions: [] },
        },
      },
    });

    const drift = detectDrift(previous, current);
    const scoreEvent = drift.events.find(e => e.type === 'score-drop');
    expect(scoreEvent).toBeUndefined();
  });

  it('detects new tools installed', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan();
    const current = makeBaseScan({
      tools: [{
        name: 'Cursor', configPath: '/test', installed: true, running: false,
        mcpServerCount: 0, servers: [],
      }],
    });

    const drift = detectDrift(previous, current);
    const toolEvent = drift.events.find(e => e.type === 'new-tool-installed');
    expect(toolEvent).toBeDefined();
    expect(toolEvent!.title).toContain('Cursor');
  });

  it('detects services that were secured', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan({
      network: {
        services: [{
          port: 3001, pid: 123, process: 'node', bindAddress: '127.0.0.1',
          type: 'mcp-sse', authenticated: false, declaredInConfig: true,
          tlsEnabled: false, corsWildcard: null,
        }],
        findings: [],
        summary: { totalListening: 1, aiServices: 1, shadowServices: 0, unauthenticated: 1, exposedToNetwork: 0 },
      },
    });

    const current = makeBaseScan({
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

    const drift = detectDrift(previous, current);
    const securedEvent = drift.events.find(e => e.type === 'service-secured');
    expect(securedEvent).toBeDefined();
    expect(securedEvent!.title).toContain('3001');
  });

  it('returns empty events when nothing changed', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const scan = makeBaseScan();
    const drift = detectDrift(scan, scan);

    expect(drift.events).toHaveLength(0);
    expect(drift.scoreDelta).toBe(0);
  });

  it('correctly computes scoreDelta', async () => {
    const { detectDrift } = await import('../../src/endpoint/drift.js');

    const previous = makeBaseScan();
    const current = makeBaseScan({
      score: {
        total: 90, grade: 'A',
        categories: {
          configuration: { score: 30, max: 30, deductions: [] },
          credentials: { score: 30, max: 30, deductions: [] },
          network: { score: 20, max: 25, deductions: [] },
          discovery: { score: 10, max: 15, deductions: [] },
        },
      },
    });

    const drift = detectDrift(previous, current);
    expect(drift.scoreDelta).toBe(10);
    expect(drift.previousScore).toBe(80);
    expect(drift.currentScore).toBe(90);
  });
});
