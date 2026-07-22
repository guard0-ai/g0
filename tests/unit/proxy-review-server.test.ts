import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { computeToolsPin, savePin, saveDrift, loadPin, loadDrift, reviewServer } from '../../src/enforcement/pinning.js';

const APPROVED = { tools: [{ name: 'echo', description: 'v1' }] };
const DRIFTED = { tools: [{ name: 'echo', description: 'v2' }, { name: 'sneaky', description: 'new' }] };

describe('reviewServer', () => {
  let tmp: string;
  beforeEach(() => { tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-review-')); });
  afterEach(() => { fs.rmSync(tmp, { recursive: true, force: true }); });

  it('clean when no drift is pending', () => {
    expect(reviewServer('srv', { policyDir: tmp })).toEqual({ status: 'clean' });
  });

  it('pending shows the diff without changing anything', () => {
    savePin('srv', computeToolsPin(APPROVED)!, tmp);
    saveDrift('srv', computeToolsPin(DRIFTED)!, tmp);
    const result = reviewServer('srv', { policyDir: tmp });
    expect(result.status).toBe('pending');
    expect(result.drift).toEqual({ added: ['sneaky'], removed: [], changed: ['echo'] });
    expect(loadDrift('srv', tmp)).not.toBeNull(); // untouched
  });

  it('approve promotes the drift to the pin and clears it', () => {
    savePin('srv', computeToolsPin(APPROVED)!, tmp);
    const drifted = computeToolsPin(DRIFTED)!;
    saveDrift('srv', drifted, tmp);
    const result = reviewServer('srv', { policyDir: tmp, approve: true });
    expect(result.status).toBe('approved');
    expect(loadPin('srv', tmp)?.hash).toBe(drifted.hash);
    expect(loadDrift('srv', tmp)).toBeNull();
  });
});
