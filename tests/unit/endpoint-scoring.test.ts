import { describe, it, expect } from 'vitest';
import type { MCPScanResult } from '../../src/types/mcp-scan.js';
import type {
  NetworkScanResult,
  ArtifactScanResult,
  CrossReferenceFinding,
  AgenticBrowserScanResult,
  AgenticBrowserDetection,
  RiskyExtensionDetection,
} from '../../src/types/endpoint.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function emptyMcp(): MCPScanResult {
  return {
    clients: [], servers: [], tools: [], findings: [],
    summary: {
      totalClients: 0, totalServers: 0, totalTools: 0, totalFindings: 0,
      findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      overallStatus: 'ok',
    },
  };
}

function emptyNetwork(): NetworkScanResult {
  return {
    services: [], findings: [],
    summary: { totalListening: 0, aiServices: 0, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 },
  };
}

function emptyArtifacts(): ArtifactScanResult {
  return {
    credentials: [], dataStores: [], findings: [],
    summary: { totalCredentials: 0, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
  };
}

function agenticBrowserDetection(overrides: Partial<AgenticBrowserDetection> = {}): AgenticBrowserDetection {
  return {
    name: 'ChatGPT Atlas',
    installed: true,
    running: true,
    capability: 'full-agent',
    findings: [],
    ...overrides,
  };
}

function riskyExtensionDetection(overrides: Partial<RiskyExtensionDetection> = {}): RiskyExtensionDetection {
  return {
    name: 'AI Autopilot',
    extensionId: 'ext-1',
    browser: 'Chrome',
    path: '/fake/manifest.json',
    permissions: ['debugger', '<all_urls>'],
    aiSignals: ['name:"AI Autopilot"'],
    severity: 'critical',
    ...overrides,
  };
}

function agenticBrowserScanResult(overrides: Partial<AgenticBrowserScanResult> = {}): AgenticBrowserScanResult {
  return {
    browsers: [],
    riskyExtensions: [],
    summary: { installed: 0, running: 0, riskyExtensions: 0, findings: 0 },
    ...overrides,
  };
}

// ─── Grade Computation ───────────────────────────────────────────────────────

describe('grade computation', () => {
  it('returns A for score >= 90', async () => {
    const { computeGrade } = await import('../../src/endpoint/scoring.js');
    expect(computeGrade(100)).toBe('A');
    expect(computeGrade(95)).toBe('A');
    expect(computeGrade(90)).toBe('A');
  });

  it('returns B for score 75-89', async () => {
    const { computeGrade } = await import('../../src/endpoint/scoring.js');
    expect(computeGrade(89)).toBe('B');
    expect(computeGrade(80)).toBe('B');
    expect(computeGrade(75)).toBe('B');
  });

  it('returns C for score 60-74', async () => {
    const { computeGrade } = await import('../../src/endpoint/scoring.js');
    expect(computeGrade(74)).toBe('C');
    expect(computeGrade(65)).toBe('C');
    expect(computeGrade(60)).toBe('C');
  });

  it('returns D for score 40-59', async () => {
    const { computeGrade } = await import('../../src/endpoint/scoring.js');
    expect(computeGrade(59)).toBe('D');
    expect(computeGrade(50)).toBe('D');
    expect(computeGrade(40)).toBe('D');
  });

  it('returns F for score < 40', async () => {
    const { computeGrade } = await import('../../src/endpoint/scoring.js');
    expect(computeGrade(39)).toBe('F');
    expect(computeGrade(20)).toBe('F');
    expect(computeGrade(0)).toBe('F');
  });
});

// ─── Severity Deductions ─────────────────────────────────────────────────────

describe('severity deductions', () => {
  it('has correct deduction weights', async () => {
    const { SEVERITY_DEDUCTIONS } = await import('../../src/endpoint/scoring.js');
    expect(SEVERITY_DEDUCTIONS.critical).toBe(15);
    expect(SEVERITY_DEDUCTIONS.high).toBe(10);
    expect(SEVERITY_DEDUCTIONS.medium).toBe(5);
    expect(SEVERITY_DEDUCTIONS.low).toBe(2);
  });
});

// ─── Category Maximums ───────────────────────────────────────────────────────

describe('category maximums', () => {
  it('sum to 100', async () => {
    const { CATEGORY_MAX } = await import('../../src/endpoint/scoring.js');
    const total = CATEGORY_MAX.configuration + CATEGORY_MAX.credentials +
      CATEGORY_MAX.network + CATEGORY_MAX.discovery;
    expect(total).toBe(100);
  });
});

// ─── Full Score Computation ──────────────────────────────────────────────────

describe('computeEndpointScore', () => {
  it('returns perfect score with no findings and daemon running', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
    });

    expect(score.total).toBe(100);
    expect(score.grade).toBe('A');
    expect(score.categories.configuration.score).toBe(30);
    expect(score.categories.credentials.score).toBe(30);
    expect(score.categories.network.score).toBe(25);
    expect(score.categories.discovery.score).toBe(15);
  });

  it('deducts from configuration for MCP findings', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const mcp = emptyMcp();
    mcp.findings = [
      { severity: 'critical', type: 'test', title: 'Critical finding', description: '' },
      { severity: 'high', type: 'test', title: 'High finding', description: '' },
    ];

    const score = computeEndpointScore({
      mcp,
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
    });

    // 30 - 15 (critical) - 10 (high) = 5
    expect(score.categories.configuration.score).toBe(5);
    expect(score.categories.configuration.deductions).toHaveLength(2);
  });

  it('deducts from credentials for exposed keys', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const artifacts = emptyArtifacts();
    artifacts.credentials = [{
      tool: 'shell',
      keyType: 'anthropic',
      location: '~/.zshrc',
      redactedValue: 'sk-ant-...xxxx',
      issue: 'plaintext',
      severity: 'critical',
    }];

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts,
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
    });

    // 30 - 15 (critical) = 15
    expect(score.categories.credentials.score).toBe(15);
  });

  it('deducts from network for findings', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const network = emptyNetwork();
    network.findings = [
      { severity: 'critical', type: 'shadow-service', title: 'Shadow MCP', description: '' },
      { severity: 'high', type: 'no-auth', title: 'No auth', description: '' },
      { severity: 'medium', type: 'cors-wildcard', title: 'CORS *', description: '' },
    ];

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network,
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
    });

    // 25 - 15 - 10 - 5 = 0 (floored)
    expect(score.categories.network.score).toBe(0);
  });

  it('deducts from discovery when daemon not running', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: false,
      toolCount: 3,
    });

    // 15 - 5 (no daemon) = 10
    expect(score.categories.discovery.score).toBe(10);
  });

  it('floors category scores at 0', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const mcp = emptyMcp();
    // Add 5 critical findings = 75 points of deduction against 30 max
    mcp.findings = Array.from({ length: 5 }, (_, i) => ({
      severity: 'critical' as const,
      type: 'test',
      title: `Critical finding ${i}`,
      description: '',
    }));

    const score = computeEndpointScore({
      mcp,
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
    });

    expect(score.categories.configuration.score).toBe(0);
    expect(score.categories.configuration.score).toBeGreaterThanOrEqual(0);
  });

  it('includes cross-reference findings in configuration category', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const crossRef: CrossReferenceFinding[] = [{
      severity: 'high',
      type: 'shadow-service',
      title: 'Undeclared MCP on :3001',
      description: '',
      status: 'shadow-service',
      port: 3001,
    }];

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: crossRef,
      daemonRunning: true,
      toolCount: 3,
    });

    // 30 - 10 (high) = 20
    expect(score.categories.configuration.score).toBe(20);
  });
});

// ─── AI Exposure Surface (agentic browsers, opt-in Layer 6b) ────────────────

describe('computeEndpointScore — agentic browsers (AI exposure surface)', () => {
  it('is byte-identical to a baseline scan when agenticBrowsers is omitted', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const baseInput = {
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
    };

    const withoutField = computeEndpointScore(baseInput);
    const withUndefinedField = computeEndpointScore({ ...baseInput, agenticBrowsers: undefined });

    expect(withoutField).toEqual(withUndefinedField);
    expect(withoutField.categories.configuration.score).toBe(30);
    expect(withoutField.categories.configuration.deductions).toEqual([]);
    expect(withoutField.total).toBe(100);
  });

  it('deducts -10 (high) for a running full-agent browser', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
      agenticBrowsers: agenticBrowserScanResult({
        browsers: [agenticBrowserDetection({ capability: 'full-agent', running: true })],
      }),
    });

    expect(score.categories.configuration.score).toBe(20);
    expect(score.categories.configuration.deductions).toHaveLength(1);
    expect(score.categories.configuration.deductions[0]).toMatchObject({ severity: 'high', points: 10 });
  });

  it('deducts -15 (critical) for a critical risky extension', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
      agenticBrowsers: agenticBrowserScanResult({
        riskyExtensions: [riskyExtensionDetection({ severity: 'critical' })],
      }),
    });

    expect(score.categories.configuration.score).toBe(15);
    expect(score.categories.configuration.deductions).toHaveLength(1);
    expect(score.categories.configuration.deductions[0]).toMatchObject({ severity: 'critical', points: 15 });
  });

  it('combines both deductions (running full-agent browser + critical extension)', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
      agenticBrowsers: agenticBrowserScanResult({
        browsers: [agenticBrowserDetection({ capability: 'full-agent', running: true })],
        riskyExtensions: [riskyExtensionDetection({ severity: 'critical' })],
      }),
    });

    // 30 - 10 (running full-agent) - 15 (critical extension) = 5
    expect(score.categories.configuration.score).toBe(5);
    expect(score.categories.configuration.deductions).toHaveLength(2);
  });

  it('does not deduct for an installed-but-not-running full-agent browser', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
      agenticBrowsers: agenticBrowserScanResult({
        browsers: [agenticBrowserDetection({ capability: 'full-agent', running: false })],
      }),
    });

    expect(score.categories.configuration.score).toBe(30);
    expect(score.categories.configuration.deductions).toEqual([]);
  });

  it('does not deduct for a non-critical risky extension or a non-full-agent capability', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const score = computeEndpointScore({
      mcp: emptyMcp(),
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
      agenticBrowsers: agenticBrowserScanResult({
        browsers: [agenticBrowserDetection({ capability: 'agent-mode', running: true })],
        riskyExtensions: [riskyExtensionDetection({ severity: 'high' })],
      }),
    });

    expect(score.categories.configuration.score).toBe(30);
    expect(score.categories.configuration.deductions).toEqual([]);
  });

  it('floors configuration score at 0 when combined with existing MCP deductions', async () => {
    const { computeEndpointScore } = await import('../../src/endpoint/scoring.js');

    const mcp = emptyMcp();
    mcp.findings = [
      { severity: 'critical', type: 'test', title: 'Critical finding', description: '' },
    ];

    const score = computeEndpointScore({
      mcp,
      network: emptyNetwork(),
      artifacts: emptyArtifacts(),
      crossReference: [],
      daemonRunning: true,
      toolCount: 3,
      agenticBrowsers: agenticBrowserScanResult({
        browsers: [agenticBrowserDetection({ capability: 'full-agent', running: true })],
        riskyExtensions: [
          riskyExtensionDetection({ severity: 'critical', extensionId: 'ext-1' }),
          riskyExtensionDetection({ severity: 'critical', extensionId: 'ext-2' }),
        ],
      }),
    });

    // 30 - 15 (critical MCP) - 10 (running full-agent) - 15 - 15 (two critical exts) = -25 -> floored to 0
    expect(score.categories.configuration.score).toBe(0);
  });
});
