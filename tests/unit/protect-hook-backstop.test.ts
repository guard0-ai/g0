import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { recordDenial, checkDenials } from '../../src/protect/hooks/backstop.js';

describe('execution-verification backstop', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-backstop-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('alerts when a denied write target changes afterward, once', () => {
    const target = path.join(tmp, 'x.txt');
    fs.writeFileSync(target, 'v1');
    recordDenial({ sessionId: 's', toolName: 'Write', targetPath: target, deniedAt: Date.now() - 1000 }, tmp);
    fs.writeFileSync(target, 'v2'); // mutation after the deny
    const alerts = checkDenials(tmp);
    expect(alerts).toHaveLength(1);
    expect(alerts[0].targetPath).toBe(target);
    expect(checkDenials(tmp)).toHaveLength(0); // alert-once
  });

  it('no alert for untouched targets or stale (>10min) denials', () => {
    const target = path.join(tmp, 'y.txt');
    fs.writeFileSync(target, 'v1');
    recordDenial({ sessionId: 's', toolName: 'Write', targetPath: target, deniedAt: Date.now() + 5000 }, tmp);
    expect(checkDenials(tmp)).toHaveLength(0);
    recordDenial({ sessionId: 's', toolName: 'Write', targetPath: target, deniedAt: Date.now() - 11 * 60_000 }, tmp);
    expect(checkDenials(tmp)).toHaveLength(0);
  });

  it('never throws on a corrupt denial log', () => {
    fs.writeFileSync(path.join(tmp, 'denials.jsonl'), '{broken\n');
    expect(() => checkDenials(tmp)).not.toThrow();
  });
});
