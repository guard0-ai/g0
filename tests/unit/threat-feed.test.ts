import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  resolveFeedSources,
  checkPackageVulnerable,
  checkVersionVulnerable,
  getCVESummary,
  type CVEEntry,
} from '../../src/intelligence/cve-feed.js';

describe('resolveFeedSources', () => {
  it('returns built-in sources by default', () => {
    const sources = resolveFeedSources({ configPath: '/does/not/exist.json', env: {} });
    const ids = sources.map(s => s.id);
    expect(ids).toContain('openclaw-advisory');
    expect(ids).toContain('g0-threat-feed');
  });

  it('adds a source from the G0_THREAT_FEED_URL env override', () => {
    const sources = resolveFeedSources({
      configPath: '/does/not/exist.json',
      env: { G0_THREAT_FEED_URL: 'https://example.com/feed.json' } as NodeJS.ProcessEnv,
    });
    expect(sources.some(s => s.url === 'https://example.com/feed.json')).toBe(true);
  });

  it('merges user-configured sources from a config file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-feeds-'));
    const cfg = path.join(dir, 'feeds.json');
    fs.writeFileSync(cfg, JSON.stringify({
      sources: [{ id: 'my-mcp-feed', ecosystem: 'mcp', url: 'https://mcp.example/feed.json' }],
    }));
    const sources = resolveFeedSources({ configPath: cfg, env: {} });
    const mine = sources.find(s => s.id === 'my-mcp-feed');
    expect(mine).toBeDefined();
    expect(mine!.ecosystem).toBe('mcp');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});

describe('checkPackageVulnerable', () => {
  const entries: CVEEntry[] = [
    {
      id: 'GHSA-mcp-xxxx', severity: 'high', cvss: 7.5, description: 'MCP server RCE',
      affectedVersions: ['< 1.2.0'], references: [], source: 'ghsa', status: 'confirmed',
      ecosystem: 'mcp', package: 'server-postgres', kind: 'advisory',
    },
    {
      id: 'CVE-2026-28363', severity: 'critical', cvss: 9.9, description: 'openclaw',
      affectedVersions: ['< 0.12.4'], references: [], source: 'openclaw-advisory', status: 'confirmed',
      ecosystem: 'openclaw', kind: 'cve',
    },
  ];

  it('matches a vulnerable package version within its ecosystem', () => {
    const hits = checkPackageVulnerable('mcp', 'server-postgres', '1.1.0', entries);
    expect(hits.map(h => h.id)).toEqual(['GHSA-mcp-xxxx']);
  });

  it('does not match a patched version', () => {
    expect(checkPackageVulnerable('mcp', 'server-postgres', '1.2.0', entries)).toHaveLength(0);
  });

  it('does not cross ecosystems or package names', () => {
    expect(checkPackageVulnerable('npm', 'server-postgres', '1.1.0', entries)).toHaveLength(0);
    expect(checkPackageVulnerable('mcp', 'server-slack', '1.1.0', entries)).toHaveLength(0);
  });
});

describe('getCVESummary still works with ecosystem-tagged entries', () => {
  it('counts by severity', () => {
    const entries: CVEEntry[] = [
      { id: 'a', severity: 'critical', cvss: 9, description: '', affectedVersions: [], references: [], source: 'g0-feed', status: 'confirmed', ecosystem: 'mcp' },
      { id: 'b', severity: 'high', cvss: 8, description: '', affectedVersions: [], references: [], source: 'g0-feed', status: 'confirmed', ecosystem: 'langchain' },
    ];
    const summary = getCVESummary(entries);
    expect(summary.total).toBe(2);
    expect(summary.bySeverity.critical).toBe(1);
    expect(summary.critical).toHaveLength(1);
  });
});
