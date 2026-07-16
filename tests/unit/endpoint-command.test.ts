import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─────────────────────────────────────────────────────────────────────────
// These tests drive the REAL CLI tree via `createCli()` — not
// `endpointCommand.parseAsync(...)` directly. `g0 endpoint` (the default
// action) and `g0 endpoint scan` (the subcommand alias) both call
// `addScanOptions()`, declaring the SAME option names (`--json`,
// `--no-network`, ...) on both the parent `endpointCommand` and the child
// `scan` subcommand. Calling `endpointCommand.parseAsync()` in isolation
// never exercises that parent/child shadowing, which is exactly why past
// tests missed the bug: going through the full `createCli()` -> `program
// .addCommand(endpointCommand)` tree is required to reproduce it.
//
// All heavy dependencies (system scanning, machine-id, daemon config, MCP
// discovery, auth, proxy audit) are mocked so these tests only exercise CLI
// option routing, not the underlying scan/status logic.
// ─────────────────────────────────────────────────────────────────────────

const scanEndpointMock = vi.fn();
const reportEndpointTerminalMock = vi.fn();
const maybeShowCtaMock = vi.fn();

const FAKE_SCAN_RESULT = {
  machineId: 'test-machine',
  hostname: 'test-host',
  timestamp: '2026-01-01T00:00:00.000Z',
  summary: { credentialExposures: 0, overallStatus: 'ok' },
};

vi.mock('../../src/endpoint/scanner.js', () => ({
  scanEndpoint: (...args: unknown[]) => scanEndpointMock(...args),
}));

vi.mock('../../src/reporters/endpoint-terminal.js', () => ({
  reportEndpointTerminal: (...args: unknown[]) => reportEndpointTerminalMock(...args),
}));

vi.mock('../../src/platform/cta.js', () => ({
  maybeShowCta: (...args: unknown[]) => maybeShowCtaMock(...args),
}));

vi.mock('../../src/platform/machine-id.js', () => ({
  getMachineId: () => 'test-machine-id',
}));

vi.mock('../../src/daemon/config.js', () => ({
  loadDaemonConfig: () => ({
    intervalMinutes: 30,
    watchPaths: [],
    logFile: '/tmp/g0-test/daemon.log',
    pidFile: '/tmp/g0-test/daemon.pid',
    upload: false,
    mcpScan: true,
    mcpPinCheck: true,
    inventoryDiff: true,
    networkScan: true,
    artifactScan: true,
    driftDetection: true,
  }),
}));

vi.mock('../../src/daemon/process.js', () => ({
  readPid: () => null,
}));

vi.mock('../../src/platform/auth.js', () => ({
  getAuthState: () => ({ loggedIn: false, source: 'none' }),
}));

vi.mock('../../src/mcp/analyzer.js', () => ({
  listMCPServers: () => ({ summary: { totalServers: 0 }, servers: [], findings: [], tools: [] }),
}));

vi.mock('../../src/proxy/audit-log.js', () => ({
  summarizeAudit: () => ({
    windowMs: 86400000,
    totalCalls: 0,
    denied: 0,
    alerted: 0,
    redacted: 0,
    byServer: {},
    proxiedServers: [],
  }),
}));

describe('g0 endpoint CLI wiring (via the real createCli() tree)', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    vi.resetModules();
    scanEndpointMock.mockReset();
    reportEndpointTerminalMock.mockReset();
    maybeShowCtaMock.mockReset();
    scanEndpointMock.mockResolvedValue(FAKE_SCAN_RESULT);
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  async function run(argv: string[]) {
    const { createCli } = await import('../../src/cli/index.js');
    const program = createCli();
    program.exitOverride();
    await program.parseAsync(argv, { from: 'user' });
  }

  // ───────────────────────────────────────────────────────────────────────
  // `g0 endpoint scan --json` — Mechanism A: parent/child option shadowing.
  // Fails against unfixed main because the subcommand's own `options` param
  // never sees `--json` (it lands on the parent's parser instead), so the
  // action falls into the human-report branch and calls
  // `reportEndpointTerminal` instead of emitting JSON.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 endpoint scan --json emits parseable JSON, not the human report', async () => {
    await run(['endpoint', 'scan', '--json']);

    expect(reportEndpointTerminalMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledTimes(1);
    const printed = logSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(printed);
    expect(parsed).toEqual(FAKE_SCAN_RESULT);
  });

  // ───────────────────────────────────────────────────────────────────────
  // `g0 endpoint scan --no-network` — same shadowing bug, but for a
  // `--no-*` negatable flag. Fails against unfixed main because the
  // subcommand's own `options.network` comes back `true` (its own default)
  // instead of the `false` the user actually asked for, so `scanEndpoint`
  // never learns the network layer should be skipped.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 endpoint scan --no-network reaches scanEndpoint with network: false', async () => {
    await run(['endpoint', 'scan', '--no-network', '--json']);

    expect(scanEndpointMock).toHaveBeenCalledTimes(1);
    expect(scanEndpointMock).toHaveBeenCalledWith(
      expect.objectContaining({ network: false }),
    );
  });

  it('g0 endpoint scan --json (no --no-network) leaves the network layer enabled', async () => {
    // Sanity check the "normal" positive case too: with no --no-network
    // given, `--no-network` (a negatable option) defaults to `true`
    // (scanEndpoint treats `!== false` as "run the network layer").
    await run(['endpoint', 'scan', '--json']);

    expect(scanEndpointMock).toHaveBeenCalledWith(
      expect.objectContaining({ network: true }),
    );
  });

  // ───────────────────────────────────────────────────────────────────────
  // `g0 endpoint status --json` — same shadowing bug on the status
  // subcommand, which redeclares `--json` itself. Fails against unfixed
  // main because `options.json` (the subcommand's own, un-populated
  // options) is empty/undefined, so it falls through to the human-readable
  // status report instead of JSON.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 endpoint status --json emits parseable JSON', async () => {
    await run(['endpoint', 'status', '--json']);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const printed = logSpy.mock.calls[0][0] as string;
    const parsed = JSON.parse(printed);
    expect(parsed.machineId).toBe('test-machine-id');
    expect(parsed.daemon).toEqual({ running: false });
    expect(parsed.auth).toEqual({ authenticated: false });
  });

  // ───────────────────────────────────────────────────────────────────────
  // Regression guard: the default `g0 endpoint` (no subcommand) path was
  // never affected by the shadowing bug (only one command's action ever
  // runs), and must keep working after the fix.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 endpoint (no subcommand) --json still works (regression guard)', async () => {
    await run(['endpoint', '--json']);

    expect(reportEndpointTerminalMock).not.toHaveBeenCalled();
    expect(logSpy).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(logSpy.mock.calls[0][0] as string);
    expect(parsed).toEqual(FAKE_SCAN_RESULT);
  });

  it('g0 endpoint (no subcommand) --no-network reaches scanEndpoint with network: false (regression guard)', async () => {
    await run(['endpoint', '--no-network', '--json']);

    expect(scanEndpointMock).toHaveBeenCalledWith(
      expect.objectContaining({ network: false }),
    );
  });
});
