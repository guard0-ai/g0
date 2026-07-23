import { describe, it, expect } from 'vitest';
import { handleDelta, type DeltaDeps } from '../../src/daemon/runner.js';
import type { WatchDelta } from '../../src/daemon/watch.js';

function fakes() {
  const calls = { notify: [] as string[], servers: 0, estate: 0, audit: [] as string[] };
  const deps: DeltaDeps = {
    notify: (title) => calls.notify.push(title),
    quarantineServers: () => { calls.servers++; },
    quarantineEstate: () => { calls.estate++; },
    log: () => {},
    audit: (record) => calls.audit.push(String(record.kind)),
  };
  return { calls, deps };
}

const DELTA: WatchDelta = {
  newCriticalComponents: [{ kind: 'skill', name: 'evil', path: '/x', findings: [{ severity: 'critical', rule: 'shell:curl-pipe-sh', detail: '' }] }],
  newMaliciousServers: [],
  hookErrorSpike: { errors: 6, total: 10 },
};

describe('handleDelta', () => {
  it('observe mode notifies + audits, never quarantines', () => {
    const { calls, deps } = fakes();
    handleDelta(DELTA, false, deps);
    expect(calls.notify.length).toBe(2); // component + spike
    expect(calls.audit).toEqual(['estate-critical', 'hook-error-spike']);
    expect(calls.servers + calls.estate).toBe(0);
  });

  it('enforce mode quarantines estate criticals', () => {
    const { calls, deps } = fakes();
    handleDelta(DELTA, true, deps);
    expect(calls.estate).toBe(1);
    expect(calls.servers).toBe(0); // no malicious servers in delta
    expect(calls.notify.some((t) => t.includes('auto-quarantine'))).toBe(true);
  });

  it('empty delta is silent', () => {
    const { calls, deps } = fakes();
    handleDelta({ newCriticalComponents: [], newMaliciousServers: [] }, true, deps);
    expect(calls.notify).toEqual([]);
    expect(calls.servers + calls.estate).toBe(0);
  });
});
