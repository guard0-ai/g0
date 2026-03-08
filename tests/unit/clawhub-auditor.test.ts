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
    it('returns trusted (>=80) for verified publisher with many downloads', async () => {
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
      expect(result.trustScore).toBe(80);
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
      expect(result.trustScore).toBe(85);
      expect(result.risks.some(r => r.includes('Low download count'))).toBe(true);
    });

    it('does not deduct for downloads exactly 100', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 100,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test/exact-100');
      expect(result.trustScore).toBe(100);
      expect(result.risks.some(r => r.includes('download'))).toBe(false);
    });

    it('deducts for downloads 99', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 99,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test/downloads-99');
      expect(result.trustScore).toBe(85);
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
      expect(result.trustScore).toBe(80);
      expect(result.risks.some(r => r.includes('days old'))).toBe(true);
    });

    it('returns malicious (score=0) for ClawHavoc IOC in content', async () => {
      mockRegistryResponse({ publisher: 'attacker', verified: false, downloads: 100 });
      const result = await auditSkill('attacker/malware-skill', 'fetch clawback7.onion/beacon');
      expect(result.trustLevel).toBe('malicious');
      expect(result.trustScore).toBe(0);
      expect(result.risks.some(r => r.includes('ClawHavoc'))).toBe(true);
    });

    it('returns malicious for .claw_exec hook', async () => {
      mockRegistryResponse({ publisher: 'attacker', verified: false, downloads: 100 });
      const result = await auditSkill('attacker/hook-skill', '.claw_exec("payload")');
      expect(result.trustLevel).toBe('malicious');
      expect(result.trustScore).toBe(0);
    });

    it('does not flag content without IOC patterns', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 500,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test/clean-skill', 'This is a safe skill with no malicious content.');
      expect(result.trustLevel).toBe('trusted');
      expect(result.staticFindings).toHaveLength(0);
    });

    it('returns caution when registry returns 404 (not found deducts 25)', async () => {
      mockRegistryNotFound();
      const result = await auditSkill('nobody/unknown-skill');
      expect(result.trustLevel).toBe('caution');
      expect(result.trustScore).toBe(55);
      expect(result.risks.some(r => r.includes('not found'))).toBe(true);
    });

    it('combined deductions: unverified + low downloads + recent', async () => {
      mockRegistryResponse({
        publisher: 'mid-dev',
        verified: false,  // -20
        downloads: 50,    // -15
        publishedAt: new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(), // -20
      });
      const result = await auditSkill('mid-dev/risky-skill');
      // 100 - 20 - 15 - 20 = 45
      expect(result.trustScore).toBe(45);
      expect(result.trustLevel).toBe('untrusted');
      expect(result.risks).toHaveLength(3);
    });
  });

  // ── Boundary tests ────────────────────────────────────────────────────

  describe('trust score boundaries', () => {
    it('score exactly 80 is trusted', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: false,  // -20, total = 80
        downloads: 500,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test/boundary-80');
      expect(result.trustScore).toBe(80);
      expect(result.trustLevel).toBe('trusted');
    });

    it('score floors at 0 (never negative)', async () => {
      mockRegistryNotFound();
      const result = await auditSkill('test/floor-zero', '.claw_update("x")');
      expect(result.trustScore).toBe(0);
      expect(result.trustLevel).toBe('malicious');
    });
  });

  // ── Registry response validation ────────────────────────────────────────

  describe('registry response validation', () => {
    it('handles missing verified field (defaults to false)', async () => {
      mockRegistryResponse({ publisher: 'test', downloads: 500 });
      const result = await auditSkill('test/no-verified');
      expect(result.registryInfo?.verified).toBe(false);
      expect(result.risks.some(r => r.includes('Unverified'))).toBe(true);
    });

    it('handles missing downloads field', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test/no-downloads');
      expect(result.risks.some(r => r.includes('download'))).toBe(false);
    });

    it('handles invalid downloads type (string instead of number)', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 'many',
        publishedAt: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
      });
      const result = await auditSkill('test/bad-downloads');
      expect(result.registryInfo?.downloads).toBeUndefined();
    });

    it('handles missing publishedAt field', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 500,
      });
      const result = await auditSkill('test/no-date');
      expect(result.registryInfo?.ageInDays).toBeUndefined();
      expect(result.risks.some(r => r.includes('days old'))).toBe(false);
    });

    it('handles invalid publishedAt date', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 500,
        publishedAt: 'not-a-date',
      });
      const result = await auditSkill('test/bad-date');
      expect(result.registryInfo?.ageInDays).toBeUndefined();
    });

    it('handles future publishedAt date', async () => {
      mockRegistryResponse({
        publisher: 'test',
        verified: true,
        downloads: 500,
        publishedAt: new Date(Date.now() + 30 * 86400000).toISOString(),
      });
      const result = await auditSkill('test/future-date');
      expect(result.registryInfo?.ageInDays).toBeUndefined();
    });

    it('handles network error gracefully', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'));
      const result = await auditSkill('test/network-error');
      expect(result.registryInfo?.found).toBe(false);
      expect(result.risks.some(r => r.includes('not found'))).toBe(true);
    });
  });

  // ── Directory audit ─────────────────────────────────────────────────────

  describe('auditSkillsFromDirectory', () => {
    it('audits skills from fixture directory', async () => {
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

  // ── List audit ──────────────────────────────────────────────────────────

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

    it('deduplicates skill names', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ publisher: 'openclaw', verified: true, downloads: 1000, publishedAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString() }),
        headers: { get: () => null },
      });
      const result = await auditSkillsFromList(['openclaw/web-search', 'openclaw/web-search', 'openclaw/web-search']);
      expect(result.skills).toHaveLength(1);
    });
  });
});
