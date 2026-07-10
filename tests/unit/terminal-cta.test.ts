import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanResult } from '../../src/types/score.js';
import type { AgentGraph } from '../../src/types/agent-graph.js';
import type { Finding } from '../../src/types/finding.js';

const maybeShowCtaMock = vi.fn();

vi.mock('../../src/platform/cta.js', () => ({
  maybeShowCta: (...args: unknown[]) => maybeShowCtaMock(...args),
}));

function makeGraph(): AgentGraph {
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
    edges: [],
    llmCalls: [],
    dataStores: [],
    apiCalls: [],
  };
}

function makeFinding(severity: Finding['severity'], id: string): Finding {
  return {
    id,
    ruleId: 'RULE-1',
    title: 'Test finding',
    description: 'desc',
    severity,
    confidence: 'high',
    domain: 'prompt-injection',
    location: { file: 'a.ts', line: 1 },
    remediation: 'fix it',
    standards: { owaspAgentic: [] },
  } as Finding;
}

function makeResult(findings: Finding[]): ScanResult {
  return {
    score: {
      overall: 80,
      grade: 'B',
      domains: [],
    },
    findings,
    graph: makeGraph(),
    duration: 1000,
    timestamp: new Date().toISOString(),
  };
}

describe('reportTerminal — CTA wiring', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    maybeShowCtaMock.mockClear();
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('fires scan-complete with no detail when there are no criticals', async () => {
    const { reportTerminal } = await import('../../src/reporters/terminal.js');
    reportTerminal(makeResult([makeFinding('low', 'f1')]));

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('scan-complete', {
      detail: undefined,
      configCta: undefined,
    });
  });

  it('fires criticals-found with a count detail when criticals are present', async () => {
    const { reportTerminal } = await import('../../src/reporters/terminal.js');
    reportTerminal(makeResult([makeFinding('critical', 'f1'), makeFinding('critical', 'f2')]));

    expect(maybeShowCtaMock).toHaveBeenCalledTimes(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('criticals-found', {
      detail: '2 critical finding(s)',
      configCta: undefined,
    });
  });

  it('forwards TerminalOptions.configCta through to maybeShowCta', async () => {
    const { reportTerminal } = await import('../../src/reporters/terminal.js');
    reportTerminal(makeResult([]), { configCta: false });

    expect(maybeShowCtaMock).toHaveBeenCalledWith('scan-complete', {
      detail: undefined,
      configCta: false,
    });
  });

  it('does not print any CTA line itself — that is maybeShowCta\'s job (mocked here to a no-op)', async () => {
    const { reportTerminal } = await import('../../src/reporters/terminal.js');
    reportTerminal(makeResult([]));

    const output = logSpy.mock.calls.map(c => c.join(' ')).join('\n');
    expect(output).not.toContain('guard0.ai');
  });
});
