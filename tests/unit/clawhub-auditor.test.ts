import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'node:path';
import { auditSkill, auditSkillsFromDirectory, auditSkillsFromList } from '../../src/mcp/clawhub-auditor.js';

const FIXTURE_DIR = path.resolve(__dirname, '../fixtures/openclaw-agent');

// Mock fetch for registry calls
const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function mockRegistryResponse(data: Record<string, unknown>, status = 200): void {
  mockFetch.mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => data,
    headers: { get: () => null },
  });
}

function mockRegistryNotFound(): void {
  mockFetch.mockResolvedValue({
    ok: false,
    status: 404,
    json: async () => ({}),
    headers: { get: () => null },
  });
}

describe('ClawHub Auditor — Trust Scoring', () => {
  describe('auditSkill — trust score calculation', () => {
    it('returns trusted (≥80) for verified publisher with many downloads', async () => {
      mockRegistryResponse({
        publisher: 'openclaw',
        verified: true,
        downloads: 50000,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('openclaw/web-search');
      expect(result.trustLevel).toBe('trusted');
      expect(result.trustScore).toBeGreaterThanOrEqual(80);
      expect(result.risks.length).toBe(0);
    });

    it('deducts 20 points for unverified publisher', async () => {
      mockRegistryResponse({
        publisher: 'unknown-dev',
        verified: false,
        downloads: 50000,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('unknown-dev/some-skill');
      expect(result.trustScore).toBeLessThanOrEqual(80);
      expect(result.risks.some(r => r.includes('Unverified publisher'))).toBe(true);
    });

    it('deducts 15 points for downloads < 100', async () => {
      mockRegistryResponse({
        publisher: 'new-dev',
        verified: true,
        downloads: 5,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('new-dev/rare-skill');
      expect(result.risks.some(r => r.includes('Low download count'))).toBe(true);
    });

    it('deducts 20 points for skill published < 30 days ago', async () => {
      mockRegistryResponse({
        publisher: 'test-dev',
        verified: true,
        downloads: 500,
        publishedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test-dev/new-skill');
      expect(result.risks.some(r => r.includes('days old'))).toBe(true);
    });

    it('returns malicious (score=0) for ClawHavoc IOC in content', async () => {
      mockRegistryResponse({ publisher: 'attacker', verified: false, downloads: 100 });
      const result = await auditSkill('attacker/malware-skill', 'fetch clawback7.onion/beacon');
      expect(result.trustLevel).toBe('malicious');
      expect(result.trustScore).toBe(0);
      expect(result.risks.some(r => r.includes('ClawHavoc'))).toBe(true);
    });

    it('returns caution when registry returns 404 (not found deducts 25)', async () => {
      mockRegistryNotFound();
      const result = await auditSkill('nobody/unknown-skill');
      // 100 - 20 (unverified) - 25 (not found) = 55 → caution
      expect(result.trustLevel).toBe('caution');
      expect(result.trustScore).toBe(55);
      expect(result.risks.some(r => r.includes('not found'))).toBe(true);
    });

    it('returns caution (50–79) for partially trusted skill', async () => {
      mockRegistryResponse({
        publisher: 'mid-dev',
        verified: false,  // -20
        downloads: 50,    // -15 (< 100)
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('mid-dev/mid-skill');
      expect(result.trustScore).toBeGreaterThanOrEqual(50);
      expect(result.trustScore).toBeLessThan(80);
      expect(result.trustLevel).toBe('caution');
    });
  });

  describe('auditSkillsFromDirectory', () => {
    it('audits skills from fixture directory', async () => {
      // fetch won't be called for directory-based audit (no registry lookup)
      const result = await auditSkillsFromDirectory(FIXTURE_DIR);
      expect(result.skills.length).toBeGreaterThan(0);
      expect(result.summary.total).toBeGreaterThan(0);
    });

    it('summary counts are consistent', async () => {
      const result = await auditSkillsFromDirectory(FIXTURE_DIR);
      const s = result.summary;
      expect(s.trusted + s.caution + s.untrusted + s.malicious).toBe(s.total);
    });

    it('detects critical findings in fixture', async () => {
      const result = await auditSkillsFromDirectory(FIXTURE_DIR);
      expect(result.summary.findingsBySeverity.critical).toBeGreaterThan(0);
    });

    it('flags malicious skills from openclaw.json with safeBins:false', async () => {
      const result = await auditSkillsFromDirectory(FIXTURE_DIR);
      const configSkill = result.skills.find(s => s.skillName === 'openclaw.json');
      expect(configSkill).toBeDefined();
      expect(configSkill!.trustLevel).toBe('malicious');
    });
  });

  describe('auditSkillsFromList', () => {
    it('audits multiple named skills', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ publisher: 'openclaw', verified: true, downloads: 1000, publishedAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString() }),
        headers: { get: () => null },
      });
      const result = await auditSkillsFromList(['openclaw/web-search', 'openclaw/code-runner']);
      expect(result.skills).toHaveLength(2);
      expect(result.summary.total).toBe(2);
    });
  });
});
