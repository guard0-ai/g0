import { describe, it, expect } from 'vitest';
import * as os from 'node:os';

const HOME = os.homedir();

describe('extractPathLikeArgValues', () => {
  it('picks up a value under a path-shaped key name', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    expect(extractPathLikeArgValues({ path: '~/.ssh/id_rsa' })).toEqual(['~/.ssh/id_rsa']);
    expect(extractPathLikeArgValues({ file_path: 'notes.txt' })).toEqual(['notes.txt']);
  });

  it('picks up a value that looks like a path even under an unrelated key name', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    expect(extractPathLikeArgValues({ whatever: '/etc/passwd' })).toEqual(['/etc/passwd']);
    expect(extractPathLikeArgValues({ whatever: '~/projects/x' })).toEqual(['~/projects/x']);
  });

  it('ignores values that are neither path-keyed nor path-shaped', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    expect(extractPathLikeArgValues({ body: 'please send an email', to: 'a@b.com' })).toEqual([]);
  });

  it('is top-level only — does not recurse into nested objects', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    expect(extractPathLikeArgValues({ nested: { path: '~/.ssh/id_rsa' } })).toEqual([]);
  });

  it('returns [] for non-object / garbage args, never throws', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    for (const weird of [null, undefined, 42, 'a string', [], Symbol('x'), () => {}]) {
      expect(() => extractPathLikeArgValues(weird)).not.toThrow();
      expect(extractPathLikeArgValues(weird)).toEqual([]);
    }
  });

  it('never throws on a circular-reference args object', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    const circular: Record<string, unknown> = { path: '~/x' };
    circular.self = circular;
    expect(() => extractPathLikeArgValues(circular)).not.toThrow();
  });

  it('is bounded — stops scanning after maxValues top-level entries', async () => {
    const { extractPathLikeArgValues } = await import('../../src/proxy/sensitive-read.js');
    const manyArgs: Record<string, string> = {};
    for (let i = 0; i < 1000; i++) manyArgs[`path_${i}`] = `/tmp/file_${i}`;
    const out = extractPathLikeArgValues(manyArgs, 10);
    expect(out.length).toBe(10);
  });
});

describe('detectSensitivePathRead', () => {
  it('detects a request reading ~/.ssh/id_rsa', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    const match = detectSensitivePathRead({ path: '~/.ssh/id_rsa' });
    expect(match).toBeDefined();
    expect(match?.category).toBe('ssh-key');
    expect(match?.label).toBeTruthy();
  });

  it('detects a request reading a .env file', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    const match = detectSensitivePathRead({ path: '/repo/.env' });
    expect(match?.category).toBe('env-file');
  });

  it('detects a request reading a known credential store', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    const match = detectSensitivePathRead({ file_path: '~/.g0/auth.json' });
    expect(match?.category).toBe('credential-store');
  });

  it('returns undefined for a request reading an ordinary path', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    expect(detectSensitivePathRead({ path: '~/projects/foo/bar.py' })).toBeUndefined();
    expect(detectSensitivePathRead({ path: '/tmp/scratch/out.txt' })).toBeUndefined();
  });

  it('returns undefined for args with no path-like values at all', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    expect(detectSensitivePathRead({ to: 'a@b.com', subject: 'hi' })).toBeUndefined();
  });

  it('never throws on garbage/circular args, degrades to undefined', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    for (const weird of [null, undefined, 42, 'a string', [], Symbol('x')]) {
      expect(() => detectSensitivePathRead(weird)).not.toThrow();
      expect(detectSensitivePathRead(weird)).toBeUndefined();
    }
    const circular: Record<string, unknown> = { path: '~/.ssh/id_rsa' };
    circular.self = circular;
    expect(() => detectSensitivePathRead(circular)).not.toThrow();
  });

  it('the match never carries the resolved path or value — category + label only', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    const match = detectSensitivePathRead({ path: '~/.ssh/id_rsa' });
    expect(Object.keys(match ?? {}).sort()).toEqual(['category', 'label']);
    expect(JSON.stringify(match)).not.toContain('id_rsa');
    expect(JSON.stringify(match)).not.toContain(HOME);
  });

  it('expands ~ and resolves .. the same way pathArgs/allowPaths does', async () => {
    const { detectSensitivePathRead } = await import('../../src/proxy/sensitive-read.js');
    expect(detectSensitivePathRead({ path: '~/.ssh/../.ssh/id_rsa' })?.category).toBe('ssh-key');
    expect(detectSensitivePathRead({ path: '~/.ssh/../../etc/passwd' })).toBeUndefined();
  });
});
