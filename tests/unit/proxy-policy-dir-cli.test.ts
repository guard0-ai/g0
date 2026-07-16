import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ─────────────────────────────────────────────────────────────────────────
// These tests drive the REAL CLI tree via `createCli()` (not
// `proxyCommand.parseAsync(...)` / the subcommand actions directly), the
// same way tests/unit/endpoint-command.test.ts covers Mechanism A. That
// matters here too: `--policy-dir` is declared on the top-level
// `proxyCommand`, and Commander's parent-first option consumption means a
// subcommand only sees it correctly when read via `optsWithGlobals()` — a
// live parse through the full tree is what proves the wiring actually
// works end to end, for the flag on either side of the subcommand name.
//
// `node:os` is mocked so `os.homedir()` (and therefore every module's
// default `~/.g0/...` constant, computed at import time) resolves to an
// isolated fake home directory instead of the real one — these tests must
// never read or write the developer's actual `~/.g0`.
// ─────────────────────────────────────────────────────────────────────────

let fakeHomeDir: string;
let customPolicyDir: string;

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => fakeHomeDir,
  };
});

function defaultProxyDir(): string {
  return path.join(fakeHomeDir, '.g0', 'proxy');
}

async function seedAuditRecord(dir: string, toolName: string, serverName = 'my-server'): Promise<void> {
  const { appendAudit } = await import('../../src/proxy/audit-log.js');
  appendAudit(
    {
      ts: new Date().toISOString(),
      serverName,
      direction: 'request',
      kind: 'tools/call',
      toolName,
      method: 'tools/call',
      action: 'allow',
    },
    dir,
  );
}

async function run(argv: string[]): Promise<void> {
  const { createCli } = await import('../../src/cli/index.js');
  const program = createCli();
  program.exitOverride();
  await program.parseAsync(argv, { from: 'user' });
}

describe('g0 proxy --policy-dir threading (via the real createCli() tree)', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.resetModules();
    fakeHomeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-fake-home-'));
    customPolicyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-custom-policy-'));
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    fs.rmSync(fakeHomeDir, { recursive: true, force: true });
    fs.rmSync(customPolicyDir, { recursive: true, force: true });
  });

  // ───────────────────────────────────────────────────────────────────────
  // `g0 proxy logs --policy-dir <tmp>` — flag typed AFTER the subcommand.
  // Fails against unfixed main: `logsSubcommand` never declares or reads
  // `--policy-dir`, so `readAudit()` always hits the default `~/.g0/proxy`
  // and never sees the tmp dir's seeded record.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 proxy logs --policy-dir <tmp> reads from the tmp dir, not ~/.g0 (flag after the subcommand)', async () => {
    await seedAuditRecord(defaultProxyDir(), 'default_home_tool');
    await seedAuditRecord(customPolicyDir, 'custom_dir_tool');

    await run(['proxy', 'logs', '--policy-dir', customPolicyDir, '--json']);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const records = JSON.parse(logSpy.mock.calls[0][0] as string) as Array<{ toolName?: string }>;
    expect(records).toHaveLength(1);
    expect(records[0].toolName).toBe('custom_dir_tool');
  });

  // ───────────────────────────────────────────────────────────────────────
  // `g0 proxy --policy-dir <tmp> logs` — flag typed BEFORE the subcommand,
  // on the parent. Also fails against unfixed main for the same reason.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 proxy --policy-dir <tmp> logs (flag before the subcommand, on the parent) also reads from the tmp dir', async () => {
    await seedAuditRecord(defaultProxyDir(), 'default_home_tool');
    await seedAuditRecord(customPolicyDir, 'custom_dir_tool_2');

    await run(['proxy', '--policy-dir', customPolicyDir, 'logs', '--json']);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const records = JSON.parse(logSpy.mock.calls[0][0] as string) as Array<{ toolName?: string }>;
    expect(records).toHaveLength(1);
    expect(records[0].toolName).toBe('custom_dir_tool_2');
  });

  it('without --policy-dir, g0 proxy logs still falls back to the default directory unchanged', async () => {
    await seedAuditRecord(defaultProxyDir(), 'default_home_tool_3');

    await run(['proxy', 'logs', '--json']);

    const records = JSON.parse(logSpy.mock.calls[0][0] as string) as Array<{ toolName?: string }>;
    expect(records).toHaveLength(1);
    expect(records[0].toolName).toBe('default_home_tool_3');
  });

  // ───────────────────────────────────────────────────────────────────────
  // `g0 proxy status --policy-dir <tmp>` — same gap, via summarizeAudit().
  // ───────────────────────────────────────────────────────────────────────
  it('g0 proxy status --policy-dir <tmp> summarizes activity from the tmp dir, not ~/.g0', async () => {
    // Distinguishing data on each side: two records under a different
    // serverName in the default (fake-home) dir, one record under a
    // different serverName in the custom dir. A test that (incorrectly)
    // read from the default dir would report totalCalls: 2 and
    // proxiedServers: ['home-server']; only reading the custom dir yields
    // totalCalls: 1 and proxiedServers: ['custom-server'].
    await seedAuditRecord(defaultProxyDir(), 'default_home_tool', 'home-server');
    await seedAuditRecord(defaultProxyDir(), 'default_home_tool_2', 'home-server');
    await seedAuditRecord(customPolicyDir, 'custom_dir_tool', 'custom-server');

    await run(['proxy', 'status', '--policy-dir', customPolicyDir, '--json']);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(logSpy.mock.calls[0][0] as string) as {
      activity: { totalCalls: number; proxiedServers: string[] };
    };
    expect(parsed.activity.totalCalls).toBe(1);
    expect(parsed.activity.proxiedServers).toEqual(['custom-server']);
  });

  // ───────────────────────────────────────────────────────────────────────
  // `g0 proxy policy init --policy-dir <tmp>` — the policy-file *write*
  // target must also honor --policy-dir, not just the audit-log reads.
  // ───────────────────────────────────────────────────────────────────────
  it('g0 proxy policy init --policy-dir <tmp> writes policy.yaml under the tmp dir, not ~/.g0', async () => {
    await run(['proxy', 'policy', 'init', '--policy-dir', customPolicyDir, '--json']);

    expect(fs.existsSync(path.join(customPolicyDir, 'policy.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(defaultProxyDir(), 'policy.yaml'))).toBe(false);

    const parsed = JSON.parse(logSpy.mock.calls[0][0] as string) as { ok: boolean; path: string };
    expect(parsed.ok).toBe(true);
    expect(parsed.path).toBe(path.join(customPolicyDir, 'policy.yaml'));
  });

  it('without --policy-dir, g0 proxy policy init still writes under the default directory unchanged', async () => {
    await run(['proxy', 'policy', 'init', '--json']);

    expect(fs.existsSync(path.join(defaultProxyDir(), 'policy.yaml'))).toBe(true);
  });
});
