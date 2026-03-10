import { describe, it, expect } from 'vitest';
import type { ReceivedEvent } from '../../src/daemon/event-receiver.js';
import type { CVEEntry } from '../../src/intelligence/cve-feed.js';
import type { IOCMatch } from '../../src/intelligence/ioc-database.js';

describe('Correlation Engine', () => {
  describe('correlateEvents', () => {
    it('detects confirmed injection vulnerability (CT-001)', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [{ id: 'AA-TS-001', severity: 'high', domain: 'tool-safety', name: 'Missing input validation' }],
        [],
        [{ source: 'g0-plugin', type: 'injection.detected', timestamp: new Date().toISOString(), data: {} }],
        [],
        [],
      );

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].id).toBe('CT-001');
      expect(threats[0].severity).toBe('critical');
      expect(threats[0].confidence).toBeGreaterThanOrEqual(90);
    });

    it('detects known CVE with exposed gateway (CT-002)', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [{ id: 'OC-H-001', severity: 'critical', domain: 'network', name: 'Gateway bind not loopback' }],
        [],
        [],
        [{ id: 'CVE-2026-28363', severity: 'critical', cvss: 9.9, description: 'safeBins bypass', affectedVersions: ['< 0.12.4'], references: [], source: 'openclaw-advisory' }],
        [],
      );

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].id).toBe('CT-002');
    });

    it('detects active compromise (CT-003)', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [],
        [],
        [{ source: 'g0-plugin', type: 'behavioral.anomaly', timestamp: new Date().toISOString(), data: {} }],
        [],
        [{ type: 'domain', indicator: 'webhook.site', matched: 'webhook.site', description: 'exfil', severity: 'high' }],
      );

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].id).toBe('CT-003');
    });

    it('detects confirmed exploit without sandbox (CT-004)', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [{ id: 'AA-TS-100', severity: 'high', domain: 'tool-safety', name: 'Missing sandboxing' }],
        [{ category: 'prompt-injection', passed: false }],
        [],
        [],
        [],
      );

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].id).toBe('CT-004');
    });

    it('detects cognitive poisoning (CT-005)', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [],
        [],
        [
          { source: 'g0-plugin', type: 'cognitive-file-modified', timestamp: new Date().toISOString(), data: {} },
          { source: 'g0-plugin', type: 'injection.detected', timestamp: new Date().toISOString(), data: {} },
        ],
        [],
        [],
      );

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].id).toBe('CT-005');
    });

    it('detects cost abuse (CT-006)', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [],
        [],
        [
          { source: 'g0-plugin', type: 'cost.warning', timestamp: new Date().toISOString(), data: {} },
          { source: 'g0-plugin', type: 'new-tool-first-seen', timestamp: new Date().toISOString(), data: {} },
        ],
        [],
        [],
      );

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].id).toBe('CT-006');
    });

    it('returns empty when no correlations match', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents([], [], [], [], []);
      expect(threats).toHaveLength(0);
    });

    it('returns multiple threats when multiple rules match', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [
          { id: 'AA-TS-001', severity: 'high', domain: 'tool-safety', name: 'Missing input validation' },
          { id: 'OC-H-001', severity: 'critical', domain: 'network', name: 'Gateway bind exposed' },
        ],
        [],
        [{ source: 'g0-plugin', type: 'injection.detected', timestamp: new Date().toISOString(), data: {} }],
        [{ id: 'CVE-2026-28363', severity: 'critical', cvss: 9.9, description: 'test', affectedVersions: [], references: [], source: 'openclaw-advisory' }],
        [],
      );

      expect(threats.length).toBeGreaterThanOrEqual(2);
      // Should be sorted by severity
      expect(threats[0].severity).toBe('critical');
    });

    it('sorts threats by severity then confidence', async () => {
      const { correlateEvents } = await import('../../src/daemon/correlation-engine.js');

      const threats = correlateEvents(
        [
          { id: 'AA-TS-001', severity: 'high', domain: 'tool-safety', name: 'Missing input validation' },
          { id: 'AA-TS-100', severity: 'high', domain: 'tool-safety', name: 'Missing sandboxing' },
        ],
        [{ category: 'test', passed: false }],
        [{ source: 'g0-plugin', type: 'injection.detected', timestamp: new Date().toISOString(), data: {} }],
        [],
        [],
      );

      if (threats.length >= 2) {
        const severityOrder = { critical: 0, high: 1, medium: 2 };
        for (let i = 1; i < threats.length; i++) {
          const prev = severityOrder[threats[i - 1].severity] ?? 3;
          const curr = severityOrder[threats[i].severity] ?? 3;
          expect(curr).toBeGreaterThanOrEqual(prev);
        }
      }
    });
  });

  describe('getCorrelationRules', () => {
    it('returns all rule definitions', async () => {
      const { getCorrelationRules } = await import('../../src/daemon/correlation-engine.js');
      const rules = getCorrelationRules();
      expect(rules.length).toBeGreaterThanOrEqual(6);
      expect(rules[0]).toHaveProperty('id');
      expect(rules[0]).toHaveProperty('name');
      expect(rules[0]).toHaveProperty('severity');
    });
  });
});
