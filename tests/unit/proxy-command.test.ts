import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import YAML from 'yaml';

import {
  resolveRunTarget,
  writeDefaultPolicyFile,
  DEFAULT_POLICY_YAML,
  proxyCommand,
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
// proxyCommand wiring
// ─────────────────────────────────────────────────────────────────────────

describe('proxyCommand', () => {
  it('registers install/uninstall/status/logs/policy subcommands', () => {
    const names = proxyCommand.commands.map((c) => c.name());
    expect(names).toEqual(expect.arrayContaining(['install', 'uninstall', 'status', 'logs', 'policy']));
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
});
