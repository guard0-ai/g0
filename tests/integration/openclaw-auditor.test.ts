import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { auditSkill, auditSkillsFromList } from '../../src/mcp/clawhub-auditor.js';
import { startRegistryServer } from '../helpers/openclaw-registry-server.js';

describe('OpenClaw Auditor — Integration (real HTTP registry)', () => {
  let registryUrl: string;
  let close: () => Promise<void>;

  beforeAll(async () => {
    const server = await startRegistryServer();
    registryUrl = server.url;
    close = server.close;
  });

  afterAll(async () => { await close(); });

  it('trusted skill: verified publisher, high downloads, old publish', async () => {
    const result = await auditSkill('web-search', undefined, { registryUrl });
    expect(result.trustScore).toBeGreaterThanOrEqual(80);
    expect(result.trustLevel).toBe('trusted');
    expect(result.registryInfo?.verified).toBe(true);
    expect(result.registryInfo?.found).toBe(true);
    expect(result.risks).toHaveLength(0);
  });

  it('caution skill: unverified, low downloads, recently published', async () => {
    const result = await auditSkill('sketchy-tool', undefined, { registryUrl });
    expect(result.trustScore).toBeLessThan(80);
    expect(result.trustScore).toBeGreaterThanOrEqual(20);
    expect(result.trustLevel).toMatch(/caution|untrusted/);
    expect(result.registryInfo?.verified).toBe(false);
    expect(result.risks.length).toBeGreaterThan(0);
    expect(result.risks.some(r => r.includes('Unverified'))).toBe(true);
    expect(result.risks.some(r => r.includes('Low download'))).toBe(true);
    expect(result.risks.some(r => r.includes('Recently published'))).toBe(true);
  });

  it('unknown skill: not found in registry', async () => {
    const result = await auditSkill('nonexistent-skill-xyz', undefined, { registryUrl });
    expect(result.registryInfo?.found).toBe(false);
    expect(result.trustScore).toBeLessThan(80);
    expect(result.risks.some(r => r.includes('not found'))).toBe(true);
  });

  it('malicious content: ClawHavoc IOC triggers score 0', async () => {
    const maliciousContent = 'This skill calls .claw_update() to phone home to clawback42.onion';
    const result = await auditSkill('web-search', maliciousContent, { registryUrl });
    expect(result.trustScore).toBe(0);
    expect(result.trustLevel).toBe('malicious');
    expect(result.risks.some(r => r.includes('ClawHavoc'))).toBe(true);
  });

  it('bulk audit: returns correct summary counts', async () => {
    const result = await auditSkillsFromList(
      ['web-search', 'sketchy-tool', 'nonexistent-skill-xyz'],
      { registryUrl },
    );
    expect(result.skills).toHaveLength(3);
    expect(result.summary.total).toBe(3);

    // web-search should be trusted
    const webSearch = result.skills.find(s => s.skillName === 'web-search')!;
    expect(webSearch.trustLevel).toBe('trusted');

    // sketchy-tool should not be trusted
    const sketchy = result.skills.find(s => s.skillName === 'sketchy-tool')!;
    expect(sketchy.trustLevel).not.toBe('trusted');

    // summary categories should add up
    const { trusted, caution, untrusted, malicious } = result.summary;
    expect(trusted + caution + untrusted + malicious).toBe(3);
  });

  it('bulk audit: parallelized (faster than sequential)', async () => {
    const start = Date.now();
    const result = await auditSkillsFromList(
      ['web-search', 'code-runner', 'sketchy-tool'],
      { registryUrl },
    );
    const elapsed = Date.now() - start;
    expect(result.skills).toHaveLength(3);
    // Parallel should complete in well under 1 second for local server
    expect(elapsed).toBeLessThan(2000);
  });

  it('registry info includes correct metadata fields', async () => {
    const result = await auditSkill('code-runner', undefined, { registryUrl });
    const info = result.registryInfo!;
    expect(info.name).toBe('code-runner');
    expect(info.publisher).toBe('clawhub-official');
    expect(info.verified).toBe(true);
    expect(info.downloads).toBe(25_000);
    expect(info.ageInDays).toBeGreaterThan(200); // published 2025-06-01
    expect(info.found).toBe(true);
    expect(info.registry).toBe(registryUrl);
  });
});
