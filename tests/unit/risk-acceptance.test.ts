import { describe, it, expect } from 'vitest';
import {
  isAcceptanceActive,
  buildAcceptanceSet,
  applyRiskAcceptance,
  isCheckAccepted,
} from '../../src/config/risk-acceptance.js';
import type { Finding } from '../../src/types/finding.js';
import type { RiskAcceptance } from '../../src/types/config.js';

const makeFinding = (ruleId: string): Finding => ({
  id: `${ruleId}-0`,
  ruleId,
  title: 'Test finding',
  description: 'Test',
  severity: 'high',
  confidence: 'high',
  domain: 'code-execution',
  location: { file: 'test.py', line: 1 },
  remediation: 'Fix it',
  standards: { owaspAgentic: ['ASI01'] },
});

describe('risk-acceptance', () => {
  describe('isAcceptanceActive', () => {
    it('returns true when no expiry', () => {
      expect(isAcceptanceActive({ rule: 'OC-H-001', reason: 'test' })).toBe(true);
    });

    it('returns true when expiry is in the future', () => {
      const future = new Date(Date.now() + 86400000).toISOString();
      expect(isAcceptanceActive({ rule: 'OC-H-001', reason: 'test', expires: future })).toBe(true);
    });

    it('returns false when expiry is in the past', () => {
      expect(isAcceptanceActive({ rule: 'OC-H-001', reason: 'test', expires: '2020-01-01' })).toBe(false);
    });

    it('returns false for invalid date format (NaN comparison)', () => {
      expect(isAcceptanceActive({ rule: 'OC-H-001', reason: 'test', expires: 'not-a-date' })).toBe(false);
    });
  });

  describe('buildAcceptanceSet', () => {
    it('builds map of active acceptances', () => {
      const acceptances: RiskAcceptance[] = [
        { rule: 'OC-H-001', reason: 'Tailscale' },
        { rule: 'OC-H-003', reason: 'Behind VPN' },
        { rule: 'OC-H-009', reason: 'Expired', expires: '2020-01-01' },
      ];

      const map = buildAcceptanceSet(acceptances);
      expect(map.size).toBe(2);
      expect(map.has('OC-H-001')).toBe(true);
      expect(map.has('OC-H-003')).toBe(true);
      expect(map.has('OC-H-009')).toBe(false);
    });
  });

  describe('applyRiskAcceptance', () => {
    it('marks matching findings as accepted', () => {
      const findings = [makeFinding('AA-CE-012'), makeFinding('AA-TS-065')];
      const acceptances: RiskAcceptance[] = [
        { rule: 'AA-CE-012', reason: 'Not real SQL' },
      ];

      const { acceptedCount } = applyRiskAcceptance(findings, acceptances);

      expect(acceptedCount).toBe(1);
      expect(findings[0].accepted).toBe(true);
      expect(findings[0].acceptedReason).toBe('Not real SQL');
      expect(findings[1].accepted).toBeUndefined();
    });

    it('returns 0 when no acceptances', () => {
      const findings = [makeFinding('AA-CE-012')];
      const { acceptedCount } = applyRiskAcceptance(findings, []);
      expect(acceptedCount).toBe(0);
    });

    it('strips instance suffix when matching', () => {
      const finding = makeFinding('AA-CE-012');
      finding.id = 'AA-CE-012-3'; // instance suffix
      const findings = [finding];
      const acceptances: RiskAcceptance[] = [
        { rule: 'AA-CE-012', reason: 'Accepted' },
      ];

      const { acceptedCount } = applyRiskAcceptance(findings, acceptances);
      expect(acceptedCount).toBe(1);
    });

    it('ignores expired acceptances', () => {
      const findings = [makeFinding('AA-CE-012')];
      const acceptances: RiskAcceptance[] = [
        { rule: 'AA-CE-012', reason: 'Old', expires: '2020-01-01' },
      ];

      const { acceptedCount } = applyRiskAcceptance(findings, acceptances);
      expect(acceptedCount).toBe(0);
    });
  });

  describe('isCheckAccepted', () => {
    it('returns acceptance for matching check', () => {
      const acceptances: RiskAcceptance[] = [
        { rule: 'OC-H-003', reason: 'Tailscale' },
      ];

      const result = isCheckAccepted('OC-H-003', acceptances);
      expect(result).not.toBeNull();
      expect(result!.reason).toBe('Tailscale');
    });

    it('returns null for non-matching check', () => {
      const acceptances: RiskAcceptance[] = [
        { rule: 'OC-H-003', reason: 'Tailscale' },
      ];

      expect(isCheckAccepted('OC-H-001', acceptances)).toBeNull();
    });

    it('returns null for expired acceptance', () => {
      const acceptances: RiskAcceptance[] = [
        { rule: 'OC-H-003', reason: 'Old', expires: '2020-01-01' },
      ];

      expect(isCheckAccepted('OC-H-003', acceptances)).toBeNull();
    });
  });
});
