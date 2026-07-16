import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Command } from 'commander';

// ─────────────────────────────────────────────────────────────────────────
// `g0 endpoint --agentic-browser` — verifies the CLI flag threads through
// to scanEndpoint() as `{ agenticBrowser: true }`, distinct from the
// existing `--browser` (history) flag. scanEndpoint is mocked so this test
// never touches the real machine.
//
// A fresh module (and thus a fresh Command instance) is imported per test
// via vi.resetModules(): Commander's Command retains previously-set option
// values across repeated parseAsync() calls on the same instance, so
// reusing one `endpointCommand` singleton across `it()` blocks would leak
// `--agentic-browser: true` from one test into the next.
// ─────────────────────────────────────────────────────────────────────────

const scanEndpointMock = vi.fn();

vi.mock('../../src/endpoint/scanner.js', () => ({
  scanEndpoint: (...args: unknown[]) => scanEndpointMock(...args),
}));

function fakeResult() {
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

describe('g0 endpoint CLI — --agentic-browser flag threading', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    scanEndpointMock.mockReset();
    scanEndpointMock.mockResolvedValue(fakeResult());
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it('passes agenticBrowser: true to scanEndpoint when --agentic-browser is given', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['--agentic-browser', '--json'], { from: 'user' });

    expect(scanEndpointMock).toHaveBeenCalledTimes(1);
    expect(scanEndpointMock.mock.calls[0][0]).toMatchObject({ agenticBrowser: true });
  });

  it('leaves agenticBrowser undefined when the flag is omitted', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['--json'], { from: 'user' });

    expect(scanEndpointMock).toHaveBeenCalledTimes(1);
    expect(scanEndpointMock.mock.calls[0][0].agenticBrowser).toBeUndefined();
  });

  it('is independent of --browser: only --browser sets browser: true, --agentic-browser stays unset', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['--browser', '--json'], { from: 'user' });

    expect(scanEndpointMock.mock.calls[0][0]).toMatchObject({ browser: true });
    expect(scanEndpointMock.mock.calls[0][0].agenticBrowser).toBeUndefined();
  });

  it('allows both --browser and --agentic-browser to be set together', async () => {
    const cmd = await freshEndpointCommand();
    await cmd.parseAsync(['--browser', '--agentic-browser', '--json'], { from: 'user' });

    expect(scanEndpointMock.mock.calls[0][0]).toMatchObject({ browser: true, agenticBrowser: true });
  });

  // Note: `g0 endpoint scan <flags>` (the subcommand alias) is NOT covered
  // here — it has a pre-existing bug (reproduces identically on main,
  // unrelated to this task) where options passed after `scan` never reach
  // the subcommand's action at all. Confirmed via a direct CLI run against
  // the unmodified branch base. Out of scope for this wiring task; the
  // primary `g0 endpoint --agentic-browser` path (covered above) is unaffected.
});
