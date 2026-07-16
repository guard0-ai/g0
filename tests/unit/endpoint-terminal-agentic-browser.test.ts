import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { reportEndpointTerminal } from '../../src/reporters/endpoint-terminal.js';
import type { EndpointScanResult, AgenticBrowserScanResult } from '../../src/types/endpoint.js';

// ─────────────────────────────────────────────────────────────────────────
// reportEndpointTerminal — the agentic-browser section (Task E2 wiring).
//
// Mirrors the "Browser History" section: silent when `result.agenticBrowsers`
// is absent, renders browsers/findings/risky-extensions when present.
// ─────────────────────────────────────────────────────────────────────────

function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

function baseResult(overrides: Partial<EndpointScanResult> = {}): EndpointScanResult {
  return {
    machineId: 'test-machine',
    hostname: 'test-host',
    timestamp: new Date().toISOString(),
    tools: [],
    mcp: {
      clients: [],
      servers: [],
      tools: [],
      findings: [],
      summary: {
        totalClients: 0,
        totalServers: 0,
        totalTools: 0,
        totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        overallStatus: 'ok',
      },
    },
    network: {
      services: [],
      findings: [],
      summary: { totalListening: 0, aiServices: 0, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 },
    },
    artifacts: {
      credentials: [],
      dataStores: [],
      findings: [],
      summary: { totalCredentials: 0, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 },
    },
    crossReference: [],
    score: {
      total: 100,
      grade: 'A',
      categories: {
        configuration: { score: 30, max: 30, deductions: [] },
        credentials: { score: 30, max: 30, deductions: [] },
        network: { score: 25, max: 25, deductions: [] },
        discovery: { score: 15, max: 15, deductions: [] },
      },
    },
    summary: {
      totalTools: 0,
      runningTools: 0,
      totalServers: 0,
      totalFindings: 0,
      findingsBySeverity: {},
      networkServices: 0,
      shadowServices: 0,
      credentialExposures: 0,
      dataStores: 0,
      overallStatus: 'ok',
    },
    duration: 42,
    layersRun: ['config', 'process', 'mcp'],
    ...overrides,
  };
}

describe('reportEndpointTerminal — agentic browsers section', () => {
  let output: string[];
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    output = [];
    logSpy = vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      output.push(args.map(String).join(' '));
    });
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('renders nothing when agenticBrowsers is absent (opt-in layer did not run)', () => {
    reportEndpointTerminal(baseResult());
    const text = stripAnsi(output.join('\n'));
    expect(text).not.toContain('Agentic Browsers');
  });

  it('renders detected browsers, their findings, and risky extensions when present', () => {
    const agenticBrowsers: AgenticBrowserScanResult = {
      browsers: [
        {
          name: 'ChatGPT Atlas',
          installed: true,
          running: true,
          capability: 'full-agent',
          findings: [
            {
              severity: 'high',
              title: 'ChatGPT Atlas is running with autonomous agent capability',
              detail: 'test fixture',
            },
          ],
        },
      ],
      riskyExtensions: [
        {
          name: 'AI Autopilot',
          extensionId: 'riskyext01',
          browser: 'Chrome',
          path: '/fake/manifest.json',
          permissions: ['debugger', '<all_urls>'],
          aiSignals: ['name:"AI Autopilot"'],
          severity: 'critical',
        },
      ],
      summary: { installed: 1, running: 1, riskyExtensions: 1, findings: 1 },
    };

    reportEndpointTerminal(baseResult({ agenticBrowsers }));
    const text = stripAnsi(output.join('\n'));

    expect(text).toContain('Agentic Browsers');
    expect(text).toContain('ChatGPT Atlas');
    expect(text).toContain('ChatGPT Atlas is running with autonomous agent capability');
    expect(text).toContain('AI Autopilot');
    expect(text).toContain('Chrome');
  });

  it('shows a "none detected" message when the layer ran but found nothing', () => {
    const agenticBrowsers: AgenticBrowserScanResult = {
      browsers: [],
      riskyExtensions: [],
      summary: { installed: 0, running: 0, riskyExtensions: 0, findings: 0 },
    };

    reportEndpointTerminal(baseResult({ agenticBrowsers }));
    const text = stripAnsi(output.join('\n'));

    expect(text).toContain('Agentic Browsers');
    expect(text).toContain('No agentic browsers or risky AI browser extensions detected.');
  });
});
