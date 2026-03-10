import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('Kill Switch', () => {
  let tmpDir: string;
  let switchPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-killswitch-test-'));
    switchPath = path.join(tmpDir, '.killswitch');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('activateKillSwitch / deactivateKillSwitch', () => {
    it('creates kill switch state file', async () => {
      const { activateKillSwitch } = await import('../../src/daemon/kill-switch.js');
      const state = activateKillSwitch('Security breach detected', 'admin');
      expect(state.active).toBe(true);
      expect(state.reason).toBe('Security breach detected');
      expect(state.activatedBy).toBe('admin');
      expect(state.timestamp).toBeTruthy();
    });
  });

  describe('isKillSwitchActive', () => {
    it('returns inactive when no file exists', async () => {
      const { isKillSwitchActive } = await import('../../src/daemon/kill-switch.js');
      const state = isKillSwitchActive(switchPath);
      expect(state.active).toBe(false);
    });

    it('returns active when kill switch file exists', async () => {
      const { isKillSwitchActive } = await import('../../src/daemon/kill-switch.js');
      const state = { active: true, reason: 'test', timestamp: new Date().toISOString() };
      fs.writeFileSync(switchPath, JSON.stringify(state));

      const result = isKillSwitchActive(switchPath);
      expect(result.active).toBe(true);
      expect(result.reason).toBe('test');
    });
  });

  describe('KillSwitchMonitor', () => {
    it('does not trigger below threshold', async () => {
      const { createKillSwitchMonitor } = await import('../../src/daemon/kill-switch.js');
      const monitor = createKillSwitchMonitor(
        [{ eventType: 'injection.detected', threshold: 5, windowSeconds: 60 }],
        switchPath,
      );

      for (let i = 0; i < 4; i++) {
        const result = monitor.recordEvent('injection.detected');
        expect(result).toBeNull();
      }
    });

    it('triggers at threshold', async () => {
      const { createKillSwitchMonitor } = await import('../../src/daemon/kill-switch.js');
      const monitor = createKillSwitchMonitor(
        [{ eventType: 'injection.detected', threshold: 3, windowSeconds: 60 }],
        switchPath,
      );

      monitor.recordEvent('injection.detected');
      monitor.recordEvent('injection.detected');
      const result = monitor.recordEvent('injection.detected');

      expect(result).not.toBeNull();
      expect(result!.active).toBe(true);
      expect(result!.activatedBy).toBe('auto-monitor');

      // Verify file was written
      expect(fs.existsSync(switchPath)).toBe(true);
    });

    it('tracks event counts correctly', async () => {
      const { createKillSwitchMonitor } = await import('../../src/daemon/kill-switch.js');
      const monitor = createKillSwitchMonitor(
        [
          { eventType: 'injection.detected', threshold: 10, windowSeconds: 60 },
          { eventType: 'tool.blocked', threshold: 10, windowSeconds: 60 },
        ],
        switchPath,
      );

      monitor.recordEvent('injection.detected');
      monitor.recordEvent('injection.detected');
      monitor.recordEvent('tool.blocked');

      const counts = monitor.getEventCounts();
      expect(counts['injection.detected']).toBe(2);
      expect(counts['tool.blocked']).toBe(1);
    });

    it('resets counters', async () => {
      const { createKillSwitchMonitor } = await import('../../src/daemon/kill-switch.js');
      const monitor = createKillSwitchMonitor(
        [{ eventType: 'test', threshold: 10, windowSeconds: 60 }],
        switchPath,
      );

      monitor.recordEvent('test');
      monitor.recordEvent('test');
      monitor.reset();

      const counts = monitor.getEventCounts();
      expect(counts['test']).toBe(0);
    });

    it('ignores events outside time window', async () => {
      const { createKillSwitchMonitor } = await import('../../src/daemon/kill-switch.js');
      const monitor = createKillSwitchMonitor(
        [{ eventType: 'injection.detected', threshold: 3, windowSeconds: 10 }],
        switchPath,
      );

      // Events from 30 seconds ago
      const oldTime = new Date(Date.now() - 30000).toISOString();
      monitor.recordEvent('injection.detected', oldTime);
      monitor.recordEvent('injection.detected', oldTime);

      // Current event
      const result = monitor.recordEvent('injection.detected');
      expect(result).toBeNull(); // Only 1 in window (the old ones expired)
    });
  });
});
