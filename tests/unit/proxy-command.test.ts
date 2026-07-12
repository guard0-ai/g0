import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import YAML from 'yaml';

import {
  resolveRunTarget,
  detectProxyRunOverride,
  writeDefaultPolicyFile,
  DEFAULT_POLICY_YAML,
  proxyCommand,
  resolveFingerprintName,
} from '../../src/cli/commands/proxy.js';

// ─────────────────────────────────────────────────────────────────────────
// resolveRunTarget — the `--` arg-splitting helper behind `g0 proxy -- <cmd>`
// ─────────────────────────────────────────────────────────────────────────

describe('resolveRunTarget', () => {
  it('returns undefined for an empty command (no `--`/args given)', () => {
    expect(resolveRunTarget([], {})).toBeUndefined();
  });

  it('splits command[0] as the executable and the rest as its args', () => {
    const target = resolveRunTarget(['npx', '-y', 'server-x-pkg'], {});
    expect(target).toEqual({ serverName: 'npx', command: 'npx', args: ['-y', 'server-x-pkg'] });
  });

  it('defaults serverName to the basename of the command when --server is omitted', () => {
    const target = resolveRunTarget(['/usr/local/bin/my-server', 'arg1'], {});
    expect(target?.serverName).toBe('my-server');
    expect(target?.command).toBe('/usr/local/bin/my-server');
    expect(target?.args).toEqual(['arg1']);
  });

  it('prefers an explicit --server over the command basename', () => {
    const target = resolveRunTarget(['npx', '-y', 'server-x-pkg'], { server: 'server-x' });
    expect(target).toEqual({ serverName: 'server-x', command: 'npx', args: ['-y', 'server-x-pkg'] });
  });

  it('handles a bare command with no args', () => {
    const target = resolveRunTarget(['my-server-binary'], {});
    expect(target).toEqual({ serverName: 'my-server-binary', command: 'my-server-binary', args: [] });
  });

  it('never mistakes the wrapped command\'s own flags for g0 options (they stay in args)', () => {
    const target = resolveRunTarget(['npx', '-y', 'server-x', '--verbose', '--port', '8080'], { server: 'server-x' });
    expect(target?.args).toEqual(['-y', 'server-x', '--verbose', '--port', '8080']);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// detectProxyRunOverride — the raw-argv guard behind `g0 proxy -- <cmd>`
//
// Regression coverage for the stdout-purity bug: commander's own
// operand/subcommand matching strips a literal `--` without leaving any
// trace it was there, so `g0 proxy -- install foo` and `g0 proxy install
// foo` both parse down to the same `operands = ['install', 'foo']` —
// commander then matches `operands[0]` against the registered `install`
// subcommand and dispatches there, printing a human summary to stdout and
// corrupting the JSON-RPC stream an IDE expects from the run path. These
// tests exercise the pure raw-argv helper directly (not a live commander
// parse) specifically because a live parse would invoke the real
// `install`/`uninstall` subcommand actions, which call `installProxy`/
// `uninstallProxy` against the *actual* discovered IDE configs on whatever
// machine runs the test — exactly the kind of live-config mutation this
// whole module exists to prevent.
// ─────────────────────────────────────────────────────────────────────────

describe('detectProxyRunOverride', () => {
  it(
    'routes `proxy -- install foo` to the run path (command="install", args=["foo"]), ' +
      'never the install subcommand',
    () => {
      const override = detectProxyRunOverride(['proxy', '--', 'install', 'foo']);
      expect(override).toEqual({ command: ['install', 'foo'], options: {} });

      // Fed through the same `resolveRunTarget` the run action itself uses,
      // this must resolve to command='install' (the wrapped binary) with
      // args=['foo'] — proving the run path, not commander's `install`
      // subcommand, is what ultimately handles this invocation.
      const target = resolveRunTarget(override!.command, override!.options);
      expect(target).toEqual({ serverName: 'install', command: 'install', args: ['foo'] });
    },
  );

  it('collides the same way for every registered subcommand name, not just install', () => {
    for (const name of ['install', 'uninstall', 'status', 'logs', 'policy']) {
      const override = detectProxyRunOverride(['proxy', '--', name]);
      expect(override).toEqual({ command: [name], options: {} });
    }
  });

  it('extracts --server and --policy-dir from before the `--`', () => {
    const override = detectProxyRunOverride([
      'proxy',
      '--server',
      'my-server',
      '--policy-dir',
      '/tmp/policies',
      '--',
      'npx',
      '-y',
      'server-x',
    ]);
    expect(override).toEqual({
      command: ['npx', '-y', 'server-x'],
      options: { server: 'my-server', policyDir: '/tmp/policies' },
    });
  });

  it('returns undefined when there is no `--` (a real subcommand invocation, e.g. `proxy install --dry-run`)', () => {
    expect(detectProxyRunOverride(['proxy', 'install', '--dry-run'])).toBeUndefined();
  });

  it('returns undefined when the first token is not `proxy` (leaves other commands alone)', () => {
    expect(detectProxyRunOverride(['scan', '--', 'foo'])).toBeUndefined();
    expect(detectProxyRunOverride([])).toBeUndefined();
  });

  it('returns an empty command for a bare `proxy --` (caller\'s resolveRunTarget reports it as unusable)', () => {
    const override = detectProxyRunOverride(['proxy', '--']);
    expect(override).toEqual({ command: [], options: {} });
    expect(resolveRunTarget(override!.command, override!.options)).toBeUndefined();
  });
});

// ─────────────────────────────────────────────────────────────────────────
// writeDefaultPolicyFile — `g0 proxy policy init`
// ─────────────────────────────────────────────────────────────────────────

describe('writeDefaultPolicyFile', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-proxy-policy-init-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('writes the default (observe-mode) policy to a new file', () => {
    const target = path.join(tmpDir, 'policy.yaml');
    const result = writeDefaultPolicyFile(target);

    expect(result.ok).toBe(true);
    expect(fs.existsSync(target)).toBe(true);
    expect(fs.readFileSync(target, 'utf-8')).toBe(DEFAULT_POLICY_YAML);
  });

  it('creates parent directories as needed (e.g. policies/<server>.yaml)', () => {
    const target = path.join(tmpDir, 'policies', 'my-server.yaml');
    const result = writeDefaultPolicyFile(target);
    expect(result.ok).toBe(true);
    expect(fs.existsSync(target)).toBe(true);
  });

  it('refuses to overwrite an existing policy file without --force', () => {
    const target = path.join(tmpDir, 'policy.yaml');
    fs.writeFileSync(target, 'mode: enforce\n');

    const result = writeDefaultPolicyFile(target);
    expect(result.ok).toBe(false);
    expect(result.message).toMatch(/--force/);
    expect(fs.readFileSync(target, 'utf-8')).toBe('mode: enforce\n'); // untouched
  });

  it('overwrites an existing policy file when force is true', () => {
    const target = path.join(tmpDir, 'policy.yaml');
    fs.writeFileSync(target, 'mode: enforce\n');

    const result = writeDefaultPolicyFile(target, { force: true });
    expect(result.ok).toBe(true);
    expect(fs.readFileSync(target, 'utf-8')).toBe(DEFAULT_POLICY_YAML);
  });

  it('writes the file with 0600 permissions', () => {
    const target = path.join(tmpDir, 'policy.yaml');
    writeDefaultPolicyFile(target);
    const stat = fs.statSync(target);
    expect(stat.mode & 0o777).toBe(0o600);
  });
});

describe('DEFAULT_POLICY_YAML', () => {
  it('is valid YAML defaulting to observe mode with no rules', () => {
    const parsed = YAML.parse(DEFAULT_POLICY_YAML) as { mode: string; rules: unknown[]; onError: string };
    expect(parsed.mode).toBe('observe');
    expect(parsed.onError).toBe('open');
    expect(parsed.rules).toEqual([]);
  });
});

// ─────────────────────────────────────────────────────────────────────────
// resolveFingerprintName — `g0 proxy fingerprint <file> [--name]`
// ─────────────────────────────────────────────────────────────────────────

describe('resolveFingerprintName', () => {
  it('defaults to the corpus file\'s basename with its extension stripped', () => {
    expect(resolveFingerprintName('/some/path/secrets.txt')).toBe('secrets');
    expect(resolveFingerprintName('corpus.csv')).toBe('corpus');
  });

  it('keeps a name with no extension as-is', () => {
    expect(resolveFingerprintName('/some/path/secrets')).toBe('secrets');
  });

  it('prefers an explicit --name over the basename', () => {
    expect(resolveFingerprintName('/some/path/secrets.txt', 'prod-keys')).toBe('prod-keys');
  });

  it('ignores an empty-string --name and falls back to the basename', () => {
    expect(resolveFingerprintName('/some/path/secrets.txt', '')).toBe('secrets');
  });
});

// ─────────────────────────────────────────────────────────────────────────
// proxyCommand wiring
// ─────────────────────────────────────────────────────────────────────────

describe('proxyCommand', () => {
  it('registers install/uninstall/status/logs/policy/fingerprint subcommands', () => {
    const names = proxyCommand.commands.map((c) => c.name());
    expect(names).toEqual(
      expect.arrayContaining(['install', 'uninstall', 'status', 'logs', 'policy', 'fingerprint']),
    );
  });

  it('the policy subcommand nests an init subcommand', () => {
    const policy = proxyCommand.commands.find((c) => c.name() === 'policy');
    expect(policy?.commands.map((c) => c.name())).toContain('init');
  });

  it('defaults --quiet to true so the banner-suppression preAction hook fires on the run path', () => {
    const quietOption = proxyCommand.options.find((o) => o.long === '--quiet');
    expect(quietOption).toBeDefined();
    expect(quietOption?.defaultValue).toBe(true);
  });

  it('the fingerprint subcommand requires a <file> argument and exposes --name/--mode/--shingle-size', () => {
    const fp = proxyCommand.commands.find((c) => c.name() === 'fingerprint');
    expect(fp).toBeDefined();
    expect(fp?.registeredArguments?.[0]?.required).toBe(true);
    const optionNames = fp?.options.map((o) => o.long);
    expect(optionNames).toEqual(expect.arrayContaining(['--name', '--mode', '--shingle-size', '--json']));
  });
});
