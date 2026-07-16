import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Command } from 'commander';

// ─────────────────────────────────────────────────────────────────────────
// `g0 endpoint quarantine` CLI wiring. quarantine.ts and scanner.ts are
// mocked so this never touches the real machine or filesystem; the
// module-level logic (safety model, IOC matching, backup/undo) is covered
// separately in tests/unit/quarantine.test.ts against real tmp-dir fixtures.
//
// A fresh module (and fresh Command instance) is imported per test via
// vi.resetModules() — see endpoint-cli-agentic-browser.test.ts for why:
// Commander's Command instance retains option values across repeated
// parseAsync() calls, which would otherwise leak state between tests.
// ─────────────────────────────────────────────────────────────────────────

const scanEndpointMock = vi.fn();
const planQuarantineMock = vi.fn();
const applyQuarantineMock = vi.fn();
const undoQuarantineMock = vi.fn();

vi.mock('../../src/endpoint/scanner.js', () => ({
  scanEndpoint: (...args: unknown[]) => scanEndpointMock(...args),
}));

vi.mock('../../src/endpoint/quarantine.js', () => ({
  planQuarantine: (...args: unknown[]) => planQuarantineMock(...args),
  applyQuarantine: (...args: unknown[]) => applyQuarantineMock(...args),
  undoQuarantine: (...args: unknown[]) => undoQuarantineMock(...args),
  formatQuarantinePlan: () => 'PLAN-OUTPUT',
  formatQuarantineApply: () => 'APPLY-OUTPUT',
  formatQuarantineUndo: () => 'UNDO-OUTPUT',
}));

function fakeScanResult() {
  return {
    machineId: 'm',
    hostname: 'h',
    timestamp: new Date().toISOString(),
    tools: [],
    mcp: {
      clients: [], servers: [], tools: [], findings: [],
      summary: { totalClients: 0, totalServers: 0, totalTools: 0, totalFindings: 0, findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, overallStatus: 'ok' },
    },
    network: { services: [], findings: [], summary: { totalListening: 0, aiServices: 0, shadowServices: 0, unauthenticated: 0, exposedToNetwork: 0 } },
    artifacts: { credentials: [], dataStores: [], findings: [], summary: { totalCredentials: 0, totalDataStores: 0, totalDataSizeBytes: 0, totalFindings: 0 } },
    crossReference: [],
    score: {
      total: 100, grade: 'A',
      categories: {
        configuration: { score: 30, max: 30, deductions: [] },
        credentials: { score: 30, max: 30, deductions: [] },
        network: { score: 25, max: 25, deductions: [] },
        discovery: { score: 15, max: 15, deductions: [] },
      },
    },
    summary: { totalTools: 0, runningTools: 0, totalServers: 0, totalFindings: 0, findingsBySeverity: {}, networkServices: 0, shadowServices: 0, credentialExposures: 0, dataStores: 0, overallStatus: 'ok' },
    duration: 1,
    layersRun: ['config', 'process', 'mcp'],
  };
}

async function freshEndpointCommand(): Promise<Command> {
  vi.resetModules();
  const mod = await import('../../src/cli/commands/endpoint.js');
  return mod.endpointCommand;
}

describe('g0 endpoint quarantine — CLI wiring', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    scanEndpointMock.mockReset();
    scanEndpointMock.mockResolvedValue(fakeScanResult());
    planQuarantineMock.mockReset();
    planQuarantineMock.mockReturnValue({ candidates: [], skipped: [] });
    applyQuarantineMock.mockReset();
    applyQuarantineMock.mockResolvedValue({ manifestPath: null, manifest: null, applied: [], skipped: [] });
    undoQuarantineMock.mockReset();
    undoQuarantineMock.mockResolvedValue({ manifestPath: null, restored: [], skipped: [] });
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });

  it('default invocation (no flags) runs a dry-run plan only — apply/undo never called', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['quarantine'], { from: 'user' });

    expect(planQuarantineMock).toHaveBeenCalledTimes(1);
    expect(applyQuarantineMock).not.toHaveBeenCalled();
    expect(undoQuarantineMock).not.toHaveBeenCalled();
  });

  it('--apply calls applyQuarantine, not undoQuarantine', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['quarantine', '--apply'], { from: 'user' });

    expect(applyQuarantineMock).toHaveBeenCalledTimes(1);
    expect(undoQuarantineMock).not.toHaveBeenCalled();
  });

  it('--undo calls undoQuarantine with no explicit manifestPath', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['quarantine', '--undo'], { from: 'user' });

    expect(undoQuarantineMock).toHaveBeenCalledTimes(1);
    expect(undoQuarantineMock.mock.calls[0][0]).toMatchObject({ manifestPath: undefined });
    expect(applyQuarantineMock).not.toHaveBeenCalled();
  });

  it('--undo <manifest> threads the explicit manifest path through', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['quarantine', '--undo', '/tmp/manifest-123.json'], { from: 'user' });

    expect(undoQuarantineMock).toHaveBeenCalledWith(
      expect.objectContaining({ manifestPath: '/tmp/manifest-123.json' }),
    );
  });

  it('--apply and --undo together errors out without calling either', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['quarantine', '--apply', '--undo'], { from: 'user' });

    expect(applyQuarantineMock).not.toHaveBeenCalled();
    expect(undoQuarantineMock).not.toHaveBeenCalled();
    expect(errorSpy).toHaveBeenCalled();
  });

  it('--json prints JSON for the dry-run plan', async () => {
    planQuarantineMock.mockReturnValue({ candidates: [{ serverName: 'evil' }], skipped: [] });
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['quarantine', '--json'], { from: 'user' });

    const printed = logSpy.mock.calls.map((c) => c[0]).join('\n');
    expect(() => JSON.parse(printed)).not.toThrow();
    expect(JSON.parse(printed).dryRun).toBe(true);
  });

  it('plain "g0 endpoint" scan never touches quarantine functions (opt-in, not part of scan)', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['--json'], { from: 'user' });

    expect(scanEndpointMock).toHaveBeenCalledTimes(1);
    expect(planQuarantineMock).not.toHaveBeenCalled();
    expect(applyQuarantineMock).not.toHaveBeenCalled();
    expect(undoQuarantineMock).not.toHaveBeenCalled();
  });
});
