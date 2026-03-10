import { describe, it, expect } from 'vitest';
import { DOMAIN_STANDARDS, applyDomainDefaults, STANDARDS_INFO } from '../../src/standards/mapping.js';
import type { StandardsMapping } from '../../src/types/finding.js';
import type { SecurityDomain } from '../../src/types/common.js';

const ALL_DOMAINS: SecurityDomain[] = [
  'goal-integrity', 'tool-safety', 'identity-access', 'supply-chain',
  'code-execution', 'memory-context', 'data-leakage', 'cascading-failures',
  'human-oversight', 'inter-agent', 'reliability-bounds', 'rogue-agent',
];

const ALL_STANDARD_KEYS: (keyof StandardsMapping)[] = [
  'owaspAgentic', 'nistAiRmf', 'iso42001', 'iso23894',
  'owaspAivss', 'owaspAgenticTop10', 'aiuc1', 'euAiAct',
  'mitreAtlas', 'owaspLlmTop10',
];

describe('DOMAIN_STANDARDS', () => {
  it('covers all 12 security domains', () => {
    for (const domain of ALL_DOMAINS) {
      expect(DOMAIN_STANDARDS[domain]).toBeDefined();
    }
  });

  it('maps every domain to all 10 standards', () => {
    for (const domain of ALL_DOMAINS) {
      const mapping = DOMAIN_STANDARDS[domain];
      for (const key of ALL_STANDARD_KEYS) {
        expect(mapping[key], `${domain} missing ${key}`).toBeDefined();
        expect(Array.isArray(mapping[key]), `${domain}.${key} should be array`).toBe(true);
        expect((mapping[key] as string[]).length, `${domain}.${key} should not be empty`).toBeGreaterThan(0);
      }
    }
  });

  it('all owaspAgentic values are valid ASI codes', () => {
    const validCodes = ['ASI01', 'ASI02', 'ASI03', 'ASI04', 'ASI05', 'ASI06', 'ASI07', 'ASI08', 'ASI09', 'ASI10'];
    for (const domain of ALL_DOMAINS) {
      for (const code of DOMAIN_STANDARDS[domain].owaspAgentic) {
        expect(validCodes, `${domain}: invalid ASI code ${code}`).toContain(code);
      }
    }
  });

  it('all nistAiRmf values follow NIST pattern', () => {
    const pattern = /^(GOVERN|MAP|MEASURE|MANAGE)-\d+\.\d+$/;
    for (const domain of ALL_DOMAINS) {
      for (const code of DOMAIN_STANDARDS[domain].nistAiRmf!) {
        expect(pattern.test(code), `${domain}: invalid NIST code ${code}`).toBe(true);
      }
    }
  });

  it('all mitreAtlas values follow MITRE pattern', () => {
    const pattern = /^AML\.T\d{4}$/;
    for (const domain of ALL_DOMAINS) {
      for (const code of DOMAIN_STANDARDS[domain].mitreAtlas!) {
        expect(pattern.test(code), `${domain}: invalid ATLAS code ${code}`).toBe(true);
      }
    }
  });

  it('all owaspLlmTop10 values follow LLM pattern', () => {
    const pattern = /^LLM\d{2}$/;
    for (const domain of ALL_DOMAINS) {
      for (const code of DOMAIN_STANDARDS[domain].owaspLlmTop10!) {
        expect(pattern.test(code), `${domain}: invalid LLM code ${code}`).toBe(true);
      }
    }
  });
});

describe('applyDomainDefaults', () => {
  it('fills all missing fields from domain defaults', () => {
    const empty: StandardsMapping = { owaspAgentic: [] };
    const result = applyDomainDefaults(empty, 'goal-integrity');

    expect(result.owaspAgentic).toEqual(['ASI01']);
    expect(result.nistAiRmf).toEqual(['MAP-1.5', 'GOVERN-1.1']);
    expect(result.iso42001).toEqual(['A.4', 'A.7']);
    expect(result.euAiAct).toEqual(['Article-15']);
    expect(result.mitreAtlas).toEqual(['AML.T0051', 'AML.T0054']);
    expect(result.owaspLlmTop10).toEqual(['LLM01']);
  });

  it('does not overwrite existing values', () => {
    const existing: StandardsMapping = {
      owaspAgentic: ['ASI99'],
      nistAiRmf: ['CUSTOM-1.0'],
      iso42001: ['A.99'],
    };
    const result = applyDomainDefaults(existing, 'tool-safety');

    expect(result.owaspAgentic).toEqual(['ASI99']);
    expect(result.nistAiRmf).toEqual(['CUSTOM-1.0']);
    expect(result.iso42001).toEqual(['A.99']);
    // Unfilled fields get defaults
    expect(result.euAiAct).toEqual(['Article-14', 'Article-15']);
    expect(result.mitreAtlas).toEqual(['AML.T0040', 'AML.T0043']);
  });

  it('works for all 12 domains', () => {
    for (const domain of ALL_DOMAINS) {
      const result = applyDomainDefaults({ owaspAgentic: [] }, domain);
      for (const key of ALL_STANDARD_KEYS) {
        expect((result[key] as string[])?.length, `${domain}.${key}`).toBeGreaterThan(0);
      }
    }
  });
});

describe('STANDARDS_INFO', () => {
  it('covers all 10 standard keys', () => {
    for (const key of ALL_STANDARD_KEYS) {
      expect(STANDARDS_INFO[key], `missing info for ${key}`).toBeDefined();
      expect(STANDARDS_INFO[key].name).toBeTruthy();
      expect(STANDARDS_INFO[key].url).toMatch(/^https?:\/\//);
    }
  });
});
