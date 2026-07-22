import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { computeToolsPin, comparePins, loadPin, savePin, saveDrift, loadDrift, clearDrift } from '../../src/enforcement/pinning.js';
import { loadPolicy } from '../../src/enforcement/policy.js';

const TOOLS = { tools: [{ name: 'b', description: 'two' }, { name: 'a', description: 'one' }] };

describe('tools pinning', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-pin-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('semantic hash is order-insensitive and description-sensitive', () => {
    const pin = computeToolsPin(TOOLS)!;
    const reordered = computeToolsPin({ tools: [...TOOLS.tools].reverse() })!;
    expect(reordered.hash).toBe(pin.hash);
    const changed = computeToolsPin({ tools: [{ name: 'a', description: 'CHANGED' }, { name: 'b', description: 'two' }] })!;
    expect(changed.hash).not.toBe(pin.hash);
    expect(comparePins(pin, changed)).toEqual({ added: [], removed: [], changed: ['a'] });
    expect(comparePins(pin, reordered)).toBeNull();
    expect(computeToolsPin({ nope: true })).toBeNull();
  });

  it('pin + drift round trip with sanitized names', () => {
    const pin = computeToolsPin(TOOLS)!;
    savePin('srv/../etc', pin, tmp);
    expect(fs.readdirSync(path.join(tmp, 'pins')).every((n) => !n.includes('/'))).toBe(true);
    expect(loadPin('srv/../etc', tmp)?.hash).toBe(pin.hash);
    expect(loadPin('missing', tmp)).toBeNull();
    saveDrift('srv', pin, tmp);
    expect(loadDrift('srv', tmp)?.hash).toBe(pin.hash);
    clearDrift('srv', tmp);
    expect(loadDrift('srv', tmp)).toBeNull();
  });

  it('policy parses pinning with alert default', () => {
    fs.writeFileSync(path.join(tmp, 'policy.yaml'), 'version: 1\nmode: enforce\npinning: deny\n');
    expect(loadPolicy({ dir: tmp }).pinning).toBe('deny');
    fs.writeFileSync(path.join(tmp, 'policy.yaml'), 'version: 1\nmode: enforce\n');
    expect(loadPolicy({ dir: tmp }).pinning).toBe('alert');
  });
});
