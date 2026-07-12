import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { Command } from 'commander';

// ─────────────────────────────────────────────────────────────────────────
// Drives the REAL `createCli()` program tree (root program + its preAction
// banner-suppression hook), not `endpointCommand.parseAsync` directly — that
// shortcut hid a bug where `g0 endpoint quarantine --json` printed the ASCII
// banner before the JSON, breaking `JSON.parse(stdout)`.
//
// The quarantine module is mocked so --apply / --undo never touch the real
// machine; the module-level behavior is covered in quarantine.test.ts against
// tmp-dir fixtures. What THIS file proves: for every --json quarantine
// invocation, everything written to stdout parses as JSON (i.e. no banner
// leaked in front of it).
// ─────────────────────────────────────────────────────────────────────────

const planQuarantineMock = vi.fn();
const applyQuarantineMock = vi.fn();
const undoQuarantineMock = vi.fn();

vi.mock('../../src/endpoint/quarantine.js', () => ({
  planQuarantine: (...args: unknown[]) => planQuarantineMock(...args),
  applyQuarantine: (...args: unknown[]) => applyQuarantineMock(...args),
  undoQuarantine: (...args: unknown[]) => undoQuarantineMock(...args),
  formatQuarantinePlan: () => 'PLAN-OUTPUT',
  formatQuarantineApply: () => 'APPLY-OUTPUT',
  formatQuarantineUndo: () => 'UNDO-OUTPUT',
}));

async function freshCli(): Promise<Command> {
  vi.resetModules();
  const mod = await import('../../src/cli/index.js');
  return mod.createCli();
}

describe('g0 endpoint quarantine — real CLI tree, --json banner suppression', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    planQuarantineMock.mockReset().mockReturnValue({ candidates: [{ serverName: 'evil' }], skipped: [] });
    applyQuarantineMock.mockReset().mockResolvedValue({ manifestPath: '/tmp/m.json', manifest: { id: 'm', timestamp: 't', entries: [] }, applied: [], skipped: [] });
    undoQuarantineMock.mockReset().mockResolvedValue({ manifestPath: '/tmp/m.json', restored: [], skipped: [] });
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  function stdout(): string {
    return logSpy.mock.calls.map((c) => c[0]).join('\n');
  }

  it('quarantine --json prints ONLY parseable JSON — no banner in front', async () => {
    const cli = await freshCli();
    await cli.parseAsync(['endpoint', 'quarantine', '--json'], { from: 'user' });

    const out = stdout();
    expect(() => JSON.parse(out)).not.toThrow();
    expect(JSON.parse(out).dryRun).toBe(true);
  });

  it('quarantine --apply --json prints ONLY parseable JSON', async () => {
    const cli = await freshCli();
    await cli.parseAsync(['endpoint', 'quarantine', '--apply', '--json'], { from: 'user' });

    expect(applyQuarantineMock).toHaveBeenCalledTimes(1);
    const out = stdout();
    expect(() => JSON.parse(out)).not.toThrow();
    expect(JSON.parse(out)).toHaveProperty('manifestPath');
  });

  it('quarantine --undo --json prints ONLY parseable JSON', async () => {
    const cli = await freshCli();
    await cli.parseAsync(['endpoint', 'quarantine', '--undo', '--json'], { from: 'user' });

    expect(undoQuarantineMock).toHaveBeenCalledTimes(1);
    const out = stdout();
    expect(() => JSON.parse(out)).not.toThrow();
    expect(JSON.parse(out)).toHaveProperty('restored');
  });

  it('--force threads through to undoQuarantine', async () => {
    const cli = await freshCli();
    await cli.parseAsync(['endpoint', 'quarantine', '--undo', '--force', '--json'], { from: 'user' });

    expect(undoQuarantineMock).toHaveBeenCalledWith(expect.objectContaining({ force: true }));
  });

  it('without --json, the banner IS printed (suppression is specific to machine-readable output)', async () => {
    const cli = await freshCli();
    await cli.parseAsync(['endpoint', 'quarantine'], { from: 'user' });

    const out = stdout();
    // Banner leaked would make this non-JSON; here we WANT it, so assert the
    // human plan output is present and the whole thing is NOT valid JSON.
    expect(out).toContain('PLAN-OUTPUT');
    expect(() => JSON.parse(out)).toThrow();
  });
});
