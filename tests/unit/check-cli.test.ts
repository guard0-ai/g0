import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Command } from 'commander';
import type { CheckResult } from '../../src/check/runner.js';

// ─────────────────────────────────────────────────────────────────────────
// `g0 check` CLI wiring. The runner, reporter, and CTA are mocked — the
// composition logic itself is covered in check-runner.test.ts and the
// rendering in check-terminal.test.ts. Fresh module per test via
// vi.resetModules() (Commander retains option state across parseAsync).
// ─────────────────────────────────────────────────────────────────────────

const runCheckMock = vi.fn();
const reportCheckTerminalMock = vi.fn();
const maybeShowCtaMock = vi.fn();

vi.mock('../../src/check/runner.js', () => ({
  runCheck: (...args: unknown[]) => runCheckMock(...args),
}));

vi.mock('../../src/reporters/check-terminal.js', () => ({
  reportCheckTerminal: (...args: unknown[]) => reportCheckTerminalMock(...args),
}));

vi.mock('../../src/platform/cta.js', () => ({
  maybeShowCta: (...args: unknown[]) => maybeShowCtaMock(...args),
}));

function cleanResult(): CheckResult {
  return {
    skills: {
      skills: [],
      summary: {
        total: 4,
        trusted: 4,
        caution: 0,
        untrusted: 0,
        malicious: 0,
        totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      },
    },
    infostealerIOCs: [],
    maliciousServers: [],
    verdict: { score: 95, grade: 'A', capped: false, headline: 'No known-malicious components across 4 installed skills' },
  };
}

function maliciousResult(): CheckResult {
  const result = cleanResult();
  result.skills.summary.malicious = 2;
  result.verdict = {
    score: 35,
    grade: 'F',
    capped: true,
    headline: '2 of 4 installed skills are known-malicious',
  };
  return result;
}

async function freshCheckCommand(): Promise<Command> {
  vi.resetModules();
  const mod = await import('../../src/cli/commands/check.js');
  return mod.checkCommand;
}

describe('g0 check — CLI wiring', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;
  const originalExitCode = process.exitCode;

  beforeEach(() => {
    runCheckMock.mockReset();
    runCheckMock.mockResolvedValue(cleanResult());
    reportCheckTerminalMock.mockReset();
    maybeShowCtaMock.mockReset();
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    process.exitCode = originalExitCode;
  });

  it('default invocation runs the full check on cwd and renders the terminal report', async () => {
    const cmd = await freshCheckCommand();
    await cmd.parseAsync([], { from: 'user' });

    expect(runCheckMock).toHaveBeenCalledTimes(1);
    expect(runCheckMock).toHaveBeenCalledWith({ rootPath: process.cwd(), endpoint: true });
    expect(reportCheckTerminalMock).toHaveBeenCalledTimes(1);
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('accepts an explicit path argument', async () => {
    const cmd = await freshCheckCommand();
    await cmd.parseAsync(['/some/project'], { from: 'user' });

    expect(runCheckMock).toHaveBeenCalledWith({ rootPath: '/some/project', endpoint: true });
  });

  it('--no-endpoint skips the endpoint scan', async () => {
    const cmd = await freshCheckCommand();
    await cmd.parseAsync(['--no-endpoint'], { from: 'user' });

    expect(runCheckMock).toHaveBeenCalledWith({ rootPath: process.cwd(), endpoint: false });
  });

  it('--json emits machine-readable output and skips the terminal reporter', async () => {
    const cmd = await freshCheckCommand();
    await cmd.parseAsync(['--json'], { from: 'user' });

    expect(reportCheckTerminalMock).not.toHaveBeenCalled();
    const printed = logSpy.mock.calls.map(args => args.join(' ')).join('\n');
    const parsed = JSON.parse(printed);
    expect(parsed.verdict.grade).toBe('A');
  });

  it('sets exit code 1 and fires the threat-feed CTA when the verdict is capped', async () => {
    runCheckMock.mockResolvedValue(maliciousResult());
    const cmd = await freshCheckCommand();
    await cmd.parseAsync([], { from: 'user' });

    expect(process.exitCode).toBe(1);
    expect(maybeShowCtaMock).toHaveBeenCalledWith('check-malicious', expect.objectContaining({
      detail: expect.stringContaining('2'),
    }));
  });

  it('does not fire the CTA in --json mode (machine output stays clean)', async () => {
    runCheckMock.mockResolvedValue(maliciousResult());
    const cmd = await freshCheckCommand();
    await cmd.parseAsync(['--json'], { from: 'user' });

    expect(maybeShowCtaMock).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(1);
  });
});

describe('check-malicious CTA trigger registry', () => {
  it('is registered with a marketing cooldown', async () => {
    // The vi.mock above replaces the module for the CLI tests; import the
    // real one for this assertion.
    const real = await vi.importActual<typeof import('../../src/platform/cta.js')>('../../src/platform/cta.js');
    expect(real.CTA_TRIGGERS['check-malicious']).toBeDefined();
    expect(real.CTA_TRIGGERS['check-malicious'].cooldownDays).toBeGreaterThan(0);
  });
});
