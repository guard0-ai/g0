import { describe, it, expect } from 'vitest';
import * as os from 'node:os';
import * as path from 'node:path';

const HOME = os.homedir();

describe('isSensitivePath', () => {
  it('matches ~/.ssh/id_rsa as ssh-key', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.ssh/id_rsa');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('ssh-key');
  });

  it('matches ~/.ssh itself (the directory) as ssh-key', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.ssh');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('ssh-key');
  });

  it('does NOT match a sibling directory that merely shares a prefix (~/.ssh-backup)', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.ssh-backup/notes.txt');
    expect(result.sensitive).toBe(false);
  });

  it('matches an absolute, already-resolved ~/.ssh path too', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath(path.join(HOME, '.ssh', 'id_ed25519'));
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('ssh-key');
  });

  it('matches ~/.aws as cloud-credential', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.aws/credentials');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('cloud-credential');
  });

  it('matches ~/.gnupg as gpg-key', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.gnupg/secring.gpg');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('gpg-key');
  });

  it('matches $HOME/.env as env-file', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.env');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('env-file');
  });

  it('matches a project-local .env (any directory) as env-file', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('/some/project/dir/.env');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('env-file');
  });

  it('matches .env.local / .env.production variants as env-file', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    expect(isSensitivePath('/proj/.env.local').category).toBe('env-file');
    expect(isSensitivePath('/proj/.env.production').category).toBe('env-file');
  });

  it('matches a known credential store (g0 auth.json) as credential-store', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.g0/auth.json');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('credential-store');
  });

  it('matches a shell profile (~/.zshrc) as shell-profile', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.zshrc');
    expect(result.sensitive).toBe(true);
    expect(result.category).toBe('shell-profile');
  });

  it('rejects an ordinary path', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    expect(isSensitivePath('/tmp/scratch/notes.txt').sensitive).toBe(false);
    expect(isSensitivePath('~/projects/foo/bar.py').sensitive).toBe(false);
  });

  it('closes a traversal bypass: ~/.ssh/../.ssh/id_rsa still resolves under ~/.ssh', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    expect(isSensitivePath('~/.ssh/../.ssh/id_rsa').sensitive).toBe(true);
  });

  it('a traversal OUT of ~/.ssh is not falsely flagged sensitive', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const result = isSensitivePath('~/.ssh/../../etc/passwd');
    expect(result.sensitive).toBe(false);
  });

  it('never throws on garbage input', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    for (const weird of [null, undefined, 42, {}, [], Symbol('x'), '']) {
      expect(() => isSensitivePath(weird as unknown as string)).not.toThrow();
      expect(isSensitivePath(weird as unknown as string).sensitive).toBe(false);
    }
  });

  it('is idempotent on an already-resolved absolute path (safe to double-resolve)', async () => {
    const { isSensitivePath } = await import('../../src/endpoint/sensitive-paths.js');
    const already = path.resolve(path.join(HOME, '.ssh', 'id_rsa'));
    expect(isSensitivePath(already).sensitive).toBe(true);
  });
});

describe('SENSITIVE_PATH_ROOTS / shared constants', () => {
  it('every root is a non-empty absolute path with a category and label', async () => {
    const { SENSITIVE_PATH_ROOTS } = await import('../../src/endpoint/sensitive-paths.js');
    expect(SENSITIVE_PATH_ROOTS.length).toBeGreaterThan(0);
    for (const entry of SENSITIVE_PATH_ROOTS) {
      expect(path.isAbsolute(entry.root)).toBe(true);
      expect(entry.category.length).toBeGreaterThan(0);
      expect(entry.label.length).toBeGreaterThan(0);
    }
  });

  it('SHELL_PROFILE_NAMES / ENV_FILE_LOCATIONS / CREDENTIAL_STORE_LOCATIONS are the values artifact-scanner already used', async () => {
    const { SHELL_PROFILE_NAMES, ENV_FILE_LOCATIONS, CREDENTIAL_STORE_LOCATIONS } = await import(
      '../../src/endpoint/sensitive-paths.js'
    );
    expect(SHELL_PROFILE_NAMES).toEqual(['.zshrc', '.bashrc', '.bash_profile', '.profile', '.zshenv', '.zprofile']);
    expect(ENV_FILE_LOCATIONS).toEqual([path.join(HOME, '.env')]);
    expect(CREDENTIAL_STORE_LOCATIONS.map((c) => c.tool)).toEqual(['Cursor', 'Continue', 'Claude Code', 'Augment', 'g0']);
  });
});
