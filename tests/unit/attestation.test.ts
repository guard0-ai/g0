import { describe, it, expect } from 'vitest';
import {
  buildStandardsCoverage,
  buildAttestationPack,
  computeAttestationHash,
  ATTESTATION_SCHEMA,
} from '../../src/governance/attestation.js';
import { generateKeyPair, signBomHash, verifyBomSignature } from '../../src/inventory/sign.js';
import type { Finding } from '../../src/types/finding.js';
import type { ScanScore } from '../../src/types/score.js';

function finding(id: string, severity: Finding['severity'], standards: Partial<Finding['standards']>): Finding {
  return {
    id, ruleId: id, title: id, description: '', severity, confidence: 'high',
    domain: 'tool-safety', location: { file: 'a.py', line: 1 }, remediation: '',
    standards: { owaspAgentic: [], ...standards },
  } as Finding;
}

const score: ScanScore = {
  overall: 55, grade: 'F', capReason: '3 exploitable critical findings', domains: [],
};

describe('buildStandardsCoverage', () => {
  it('aggregates controls per standard from findings', () => {
    const findings = [
      finding('a', 'critical', { owaspAgentic: ['ASI01', 'ASI02'], nistAiRmf: ['MEASURE-1.1'] }),
      finding('b', 'high', { owaspAgentic: ['ASI01'] }),
    ];
    const coverage = buildStandardsCoverage(findings);
    const owasp = coverage.find(c => c.key === 'owaspAgentic')!;
    expect(owasp.findingCount).toBe(2);
    const asi01 = owasp.controls.find(c => c.control === 'ASI01')!;
    expect(asi01.findingCount).toBe(2);
    expect(asi01.severities.critical).toBe(1);
    expect(asi01.severities.high).toBe(1);
    expect(coverage.some(c => c.key === 'nistAiRmf')).toBe(true);
  });

  it('omits standards with no findings', () => {
    const coverage = buildStandardsCoverage([finding('a', 'low', { owaspAgentic: ['ASI01'] })]);
    expect(coverage.every(c => c.findingCount > 0)).toBe(true);
    expect(coverage.some(c => c.key === 'euAiAct')).toBe(false);
  });
});

describe('buildAttestationPack', () => {
  const findings = [finding('a', 'critical', { owaspAgentic: ['ASI01'], euAiAct: ['Art.15'] })];
  const params = {
    project: 'demo', score, findings, toolVersion: '2.0.0',
    hostname: 'host', generatedAt: '2026-01-01T00:00:00Z',
  };

  it('produces a schema-tagged pack with a content hash', () => {
    const pack = buildAttestationPack(params);
    expect(pack.schema).toBe(ATTESTATION_SCHEMA);
    expect(pack.scan.grade).toBe('F');
    expect(pack.scan.capReason).toContain('critical');
    expect(pack.contentHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('content hash is independent of generatedAt', () => {
    const a = buildAttestationPack(params);
    const b = buildAttestationPack({ ...params, generatedAt: '2030-06-06T06:06:06Z' });
    expect(a.contentHash).toBe(b.contentHash);
  });

  it('is signable and verifiable', () => {
    const { privateKeyPem } = generateKeyPair();
    const pack = buildAttestationPack(params);
    const sig = signBomHash(pack.contentHash, privateKeyPem, params.generatedAt);
    expect(sig.bomHash).toBe(pack.contentHash);
    expect(verifyBomSignature(sig)).toBe(true);
  });

  it('detects tampering with the scan result', () => {
    const pack = buildAttestationPack(params);
    // Recompute hash after mutating the score — must differ.
    const mutated = { ...pack, scan: { ...pack.scan, score: 95, grade: 'A' } };
    const rehash = computeAttestationHash(mutated);
    expect(rehash).not.toBe(pack.contentHash);
  });
});
