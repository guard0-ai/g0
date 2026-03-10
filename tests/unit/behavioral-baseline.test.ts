import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('Behavioral Baseline', () => {
  let tmpDir: string;
  let baselinePath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-baseline-test-'));
    baselinePath = path.join(tmpDir, 'baseline.json');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('learning mode', () => {
    it('starts in learning mode', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({ baselinePath });
      expect(mgr.getBaseline().learningMode).toBe(true);
    });

    it('tracks tool calls during learning', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({ baselinePath });

      mgr.recordToolCall('bash');
      mgr.recordToolCall('bash');
      mgr.recordToolCall('read_file');

      const baseline = mgr.getBaseline();
      expect(baseline.toolFrequency['bash'].count).toBe(2);
      expect(baseline.toolFrequency['read_file'].count).toBe(1);
      expect(baseline.totalEvents).toBe(3);
    });

    it('returns no anomalies during learning', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({ baselinePath });

      const anomalies = mgr.recordToolCall('bash');
      expect(anomalies).toHaveLength(0);
    });

    it('transitions out of learning after duration', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({
        baselinePath,
        learningDurationMs: 100, // 100ms for testing
      });

      mgr.recordToolCall('bash');

      // Wait past learning duration
      await new Promise(r => setTimeout(r, 150));

      mgr.recordToolCall('bash');
      expect(mgr.getBaseline().learningMode).toBe(false);
    });
  });

  describe('detection mode', () => {
    it('detects new tools not in baseline', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({
        baselinePath,
        learningDurationMs: 50,
      });

      // Learning: only see 'bash'
      mgr.recordToolCall('bash');
      await new Promise(r => setTimeout(r, 100));
      mgr.recordToolCall('bash'); // exits learning

      // Detection: see new tool
      const anomalies = mgr.recordToolCall('dangerous_tool');
      expect(anomalies.length).toBeGreaterThan(0);
      expect(anomalies[0].type).toBe('new-tool-first-seen');
      expect(anomalies[0].toolName).toBe('dangerous_tool');
    });

    it('detects tool burst', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({
        baselinePath,
        learningDurationMs: 50,
        burstThreshold: 5,
        burstWindowMs: 60000,
      });

      // Learning phase
      mgr.recordToolCall('bash');
      await new Promise(r => setTimeout(r, 100));
      mgr.recordToolCall('bash'); // exits learning

      // Fire many calls quickly
      let burstDetected = false;
      for (let i = 0; i < 10; i++) {
        const anomalies = mgr.recordToolCall('bash');
        if (anomalies.some(a => a.type === 'tool-burst')) {
          burstDetected = true;
          break;
        }
      }
      expect(burstDetected).toBe(true);
    });
  });

  describe('persistence', () => {
    it('saves and loads baseline', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({ baselinePath });

      mgr.recordToolCall('bash');
      mgr.recordToolCall('read_file');
      mgr.save();

      // Create new manager from same path
      const mgr2 = new BaselineManager({ baselinePath });
      const baseline = mgr2.getBaseline();
      expect(baseline.toolFrequency['bash'].count).toBe(1);
      expect(baseline.toolFrequency['read_file'].count).toBe(1);
      expect(baseline.totalEvents).toBe(2);
    });

    it('resets baseline', async () => {
      const { BaselineManager } = await import('../../src/daemon/behavioral-baseline.js');
      const mgr = new BaselineManager({ baselinePath });

      mgr.recordToolCall('bash');
      mgr.reset();

      const baseline = mgr.getBaseline();
      expect(baseline.totalEvents).toBe(0);
      expect(Object.keys(baseline.toolFrequency)).toHaveLength(0);
      expect(baseline.learningMode).toBe(true);
    });
  });
});
