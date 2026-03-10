import { describe, it, expect } from 'vitest';
import * as os from 'node:os';

describe('Host Hardening', () => {
  describe('auditHostHardening', () => {
    it('returns valid result shape', async () => {
      const { auditHostHardening } = await import('../../src/endpoint/host-hardening.js');
      const result = auditHostHardening();

      expect(result).toHaveProperty('checks');
      expect(result).toHaveProperty('platform');
      expect(result).toHaveProperty('summary');
      expect(result.summary).toHaveProperty('total');
      expect(result.summary).toHaveProperty('passed');
      expect(result.summary).toHaveProperty('failed');
      expect(result.summary).toHaveProperty('skipped');
      expect(result.summary).toHaveProperty('errors');
    });

    it('includes platform-relevant check IDs', async () => {
      const { auditHostHardening } = await import('../../src/endpoint/host-hardening.js');
      const os = await import('node:os');
      const result = auditHostHardening();

      const checkIds = result.checks.map(c => c.id);
      const macIds = ['OC-H-040', 'OC-H-041', 'OC-H-042', 'OC-H-043', 'OC-H-044', 'OC-H-045', 'OC-H-046', 'OC-H-047'];
      const linuxIds = ['OC-H-048', 'OC-H-049', 'OC-H-050', 'OC-H-051', 'OC-H-052'];

      const expectedIds = os.platform() === 'darwin' ? macIds : os.platform() === 'linux' ? linuxIds : [];
      for (const id of expectedIds) {
        expect(checkIds).toContain(id);
      }
      // Skipped checks should be filtered out
      expect(result.checks.every(c => c.status !== 'skip')).toBe(true);
    });

    it('checks have valid severity and status values', async () => {
      const { auditHostHardening } = await import('../../src/endpoint/host-hardening.js');
      const result = auditHostHardening();

      const validSeverities = ['critical', 'high', 'medium', 'low'];
      const validStatuses = ['pass', 'fail', 'error', 'skip'];

      for (const check of result.checks) {
        expect(validSeverities).toContain(check.severity);
        expect(validStatuses).toContain(check.status);
        expect(check.name).toBeTruthy();
        expect(check.detail).toBeTruthy();
      }
    });

    it('summary counts match check statuses', async () => {
      const { auditHostHardening } = await import('../../src/endpoint/host-hardening.js');
      const result = auditHostHardening();

      const passed = result.checks.filter(c => c.status === 'pass').length;
      const failed = result.checks.filter(c => c.status === 'fail').length;
      const skipped = result.checks.filter(c => c.status === 'skip').length;
      const errors = result.checks.filter(c => c.status === 'error').length;

      expect(result.summary.passed).toBe(passed);
      expect(result.summary.failed).toBe(failed);
      expect(result.summary.skipped).toBe(skipped);
      expect(result.summary.errors).toBe(errors);
      expect(result.summary.total).toBe(result.checks.length);
    });

    it('skips platform-inappropriate checks', async () => {
      const { auditHostHardening } = await import('../../src/endpoint/host-hardening.js');
      const result = auditHostHardening();
      const platform = os.platform();

      if (platform === 'darwin') {
        // Linux checks should be skipped
        const linuxChecks = result.checks.filter(c =>
          ['OC-H-048', 'OC-H-049', 'OC-H-050', 'OC-H-051', 'OC-H-052'].includes(c.id)
        );
        expect(linuxChecks.every(c => c.status === 'skip')).toBe(true);
      } else if (platform === 'linux') {
        // macOS checks should be skipped
        const macChecks = result.checks.filter(c =>
          ['OC-H-040', 'OC-H-041', 'OC-H-042', 'OC-H-043', 'OC-H-044', 'OC-H-045', 'OC-H-046', 'OC-H-047'].includes(c.id)
        );
        expect(macChecks.every(c => c.status === 'skip')).toBe(true);
      }
    });

    it('reports correct platform', async () => {
      const { auditHostHardening } = await import('../../src/endpoint/host-hardening.js');
      const result = auditHostHardening();
      expect(result.platform).toBe(os.platform());
    });
  });
});
