import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

describe('Cost Monitor', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-cost-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('estimateSessionCost', () => {
    it('calculates cost from Anthropic-format usage', async () => {
      const { estimateSessionCost } = await import('../../src/daemon/cost-monitor.js');

      const sessionFile = path.join(tmpDir, 'session.jsonl');
      const lines = [
        JSON.stringify({ model: 'claude-3.5-sonnet', usage: { input_tokens: 1000, output_tokens: 500 }, timestamp: new Date().toISOString() }),
        JSON.stringify({ model: 'claude-3.5-sonnet', usage: { input_tokens: 2000, output_tokens: 1000 }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const details = estimateSessionCost(sessionFile);
      expect(details).toHaveLength(1);
      expect(details[0].model).toContain('sonnet');
      expect(details[0].inputTokens).toBe(3000);
      expect(details[0].outputTokens).toBe(1500);
      expect(details[0].cost).toBeGreaterThan(0);
    });

    it('calculates cost from OpenAI-format usage', async () => {
      const { estimateSessionCost } = await import('../../src/daemon/cost-monitor.js');

      const sessionFile = path.join(tmpDir, 'session.jsonl');
      const lines = [
        JSON.stringify({ model: 'gpt-4o', data: { usage: { prompt_tokens: 5000, completion_tokens: 2000 } }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const details = estimateSessionCost(sessionFile);
      expect(details).toHaveLength(1);
      expect(details[0].model).toBe('gpt-4o');
      expect(details[0].cost).toBeGreaterThan(0);
    });

    it('handles multiple models in same session', async () => {
      const { estimateSessionCost } = await import('../../src/daemon/cost-monitor.js');

      const sessionFile = path.join(tmpDir, 'session.jsonl');
      const lines = [
        JSON.stringify({ model: 'claude-3.5-sonnet', usage: { input_tokens: 1000, output_tokens: 500 }, timestamp: new Date().toISOString() }),
        JSON.stringify({ model: 'gpt-4o', data: { usage: { prompt_tokens: 1000, completion_tokens: 500 } }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const details = estimateSessionCost(sessionFile);
      expect(details).toHaveLength(2);
    });

    it('returns empty for nonexistent file', async () => {
      const { estimateSessionCost } = await import('../../src/daemon/cost-monitor.js');
      const details = estimateSessionCost('/nonexistent');
      expect(details).toHaveLength(0);
    });

    it('skips lines without token usage', async () => {
      const { estimateSessionCost } = await import('../../src/daemon/cost-monitor.js');

      const sessionFile = path.join(tmpDir, 'session.jsonl');
      const lines = [
        JSON.stringify({ type: 'tool.called', data: { toolName: 'bash' } }),
        JSON.stringify({ model: 'claude-3.5-sonnet', usage: { input_tokens: 100, output_tokens: 50 }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const details = estimateSessionCost(sessionFile);
      expect(details).toHaveLength(1);
    });
  });

  describe('getCostSnapshot', () => {
    it('computes snapshot from session files', async () => {
      const { getCostSnapshot } = await import('../../src/daemon/cost-monitor.js');

      const sessionFile = path.join(tmpDir, 'events.jsonl');
      const lines = [
        JSON.stringify({ model: 'claude-3.5-sonnet', usage: { input_tokens: 10000, output_tokens: 5000 }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const snapshot = getCostSnapshot(tmpDir, {});
      expect(snapshot.hourly).toBeGreaterThan(0);
      expect(snapshot.daily).toBeGreaterThan(0);
      expect(snapshot.monthly).toBeGreaterThan(0);
      expect(snapshot.breaker).toBe('ok');
      expect(snapshot.details.length).toBeGreaterThan(0);
    });

    it('trips circuit breaker when limit exceeded', async () => {
      const { getCostSnapshot } = await import('../../src/daemon/cost-monitor.js');

      // Write a huge usage
      const sessionFile = path.join(tmpDir, 'events.jsonl');
      const lines = [
        JSON.stringify({ model: 'gpt-4', usage: { input_tokens: 1000000, output_tokens: 500000 }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const snapshot = getCostSnapshot(tmpDir, {
        hourlyLimitUsd: 1.0,
        circuitBreakerEnabled: true,
      });
      expect(snapshot.breaker).toBe('tripped');
    });

    it('warns at 80% threshold', async () => {
      const { getCostSnapshot } = await import('../../src/daemon/cost-monitor.js');

      const sessionFile = path.join(tmpDir, 'events.jsonl');
      // Claude Sonnet: 3000 input + 15000 output per 1M tokens
      // 100K input = $0.30, 50K output = $0.75 → total $1.05
      const lines = [
        JSON.stringify({ model: 'claude-3.5-sonnet', usage: { input_tokens: 100000, output_tokens: 50000 }, timestamp: new Date().toISOString() }),
      ];
      fs.writeFileSync(sessionFile, lines.join('\n'));

      const snapshot = getCostSnapshot(tmpDir, {
        hourlyLimitUsd: 1.20,
        circuitBreakerEnabled: true,
      });
      expect(snapshot.breaker).toBe('warning');
    });

    it('returns zero for empty directory', async () => {
      const { getCostSnapshot } = await import('../../src/daemon/cost-monitor.js');
      const emptyDir = path.join(tmpDir, 'empty');
      fs.mkdirSync(emptyDir);

      const snapshot = getCostSnapshot(emptyDir, {});
      expect(snapshot.hourly).toBe(0);
      expect(snapshot.daily).toBe(0);
      expect(snapshot.monthly).toBe(0);
    });

    it('handles nested JSONL files', async () => {
      const { getCostSnapshot } = await import('../../src/daemon/cost-monitor.js');

      const subDir = path.join(tmpDir, 'agent-1');
      fs.mkdirSync(subDir);
      fs.writeFileSync(
        path.join(subDir, 'session.jsonl'),
        JSON.stringify({ model: 'gpt-4o', usage: { input_tokens: 1000, output_tokens: 500 }, timestamp: new Date().toISOString() }),
      );

      const snapshot = getCostSnapshot(tmpDir, {});
      expect(snapshot.hourly).toBeGreaterThan(0);
    });
  });

  describe('getModelPricing', () => {
    it('returns pricing table', async () => {
      const { getModelPricing } = await import('../../src/daemon/cost-monitor.js');
      const pricing = getModelPricing();
      expect(pricing['gpt-4o']).toBeDefined();
      expect(pricing['gpt-4o'].inputPer1M).toBeGreaterThan(0);
      expect(pricing['claude-opus-4']).toBeDefined();
    });
  });
});
