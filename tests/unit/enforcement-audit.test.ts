import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { appendJsonlLine } from '../../src/enforcement/audit.js';

describe('appendJsonlLine', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-audit-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('appends records as parseable JSONL, creating parent dirs', () => {
    const file = path.join(tmpDir, 'nested', 'dir', 'audit.jsonl');
    appendJsonlLine(file, { a: 1 });
    appendJsonlLine(file, { b: 2 });
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0])).toEqual({ a: 1 });
    expect(JSON.parse(lines[1])).toEqual({ b: 2 });
  });

  it('keeps working past the size cap and retains the newest record', () => {
    const file = path.join(tmpDir, 'audit.jsonl');
    appendJsonlLine(file, { seed: 'x'.repeat(200) });
    appendJsonlLine(file, { last: true }, 64); // cap far below current size
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(JSON.parse(lines[lines.length - 1])).toEqual({ last: true });
  });

  it('never throws, even when the path is unwritable', () => {
    const blocker = path.join(tmpDir, 'a-file');
    fs.writeFileSync(blocker, '');
    // parent "dir" is a regular file -> mkdir/append must fail internally
    expect(() => appendJsonlLine(path.join(blocker, 'audit.jsonl'), { x: 1 })).not.toThrow();
  });
});
