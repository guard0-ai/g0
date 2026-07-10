import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as path from 'node:path';

// Spy on the real runScan while preserving its behavior — lets us assert
// "did a rescan happen?" (call count) without faking the scan pipeline.
vi.mock('../../src/pipeline.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/pipeline.js')>();
  return { ...actual, runScan: vi.fn(actual.runScan) };
});

import { runScan } from '../../src/pipeline.js';
import { getAllRules } from '../../src/analyzers/rules/index.js';
import { scanMCPPath } from '../../src/mcp/scan-path.js';
import { scanProject } from '../../src/mcp/server/tools/scan-project.js';
import { getScore } from '../../src/mcp/server/tools/get-score.js';
import { scanMcpServer } from '../../src/mcp/server/tools/scan-mcp-server.js';
import { inventory } from '../../src/mcp/server/tools/inventory.js';
import { explainFinding } from '../../src/mcp/server/tools/explain-finding.js';
import { mapRiskToRecommendation, verifyMcpPackage } from '../../src/mcp/server/tools/verify-mcp-package.js';
import { resetSessionForTests } from '../../src/mcp/server/session.js';
import { resolveConfinedPath, PathEscapeError } from '../../src/mcp/server/tools/util.js';

const FIXTURES = path.resolve(__dirname, '../fixtures');
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

describe('resolveConfinedPath', () => {
  it('allows a path inside the confined root', () => {
    const root = path.join(FIXTURES, 'vulnerable-agent');
    expect(() => resolveConfinedPath('.', root)).not.toThrow();
    expect(resolveConfinedPath('.', root)).toBe(path.resolve(root));
  });

  it('rejects a path that escapes the confined root via ..', () => {
    const root = path.join(FIXTURES, 'vulnerable-agent');
    expect(() => resolveConfinedPath('../mcp-server', root)).toThrow(PathEscapeError);
  });

  it('rejects an absolute path outside the confined root', () => {
    const root = path.join(FIXTURES, 'vulnerable-agent');
    expect(() => resolveConfinedPath(path.join(FIXTURES, 'mcp-server'), root)).toThrow(PathEscapeError);
  });

  it('allows any resolved path when projectRoot is undefined', () => {
    expect(() => resolveConfinedPath(path.join(FIXTURES, 'mcp-server'))).not.toThrow();
  });
});

describe('scanMCPPath (post-refactor)', () => {
  it('produces an MCPScanResult for the mcp-server fixture', async () => {
    const result = await scanMCPPath(path.join(FIXTURES, 'mcp-server'));
    expect(result.summary).toBeDefined();
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.tools)).toBe(true);
    expect(result.summary.totalFindings).toBe(result.findings.length);
  });
});

describe('scan_project tool', () => {
  beforeEach(() => {
    resetSessionForTests();
    vi.mocked(runScan).mockClear();
  });

  it('scans a fixture project and returns structured, severity-sorted findings', async () => {
    const target = path.join(FIXTURES, 'vulnerable-agent');
    const result = await scanProject({ path: target }, { projectRoot: target });

    expect(result.isError).toBeUndefined();
    const structured = result.structuredContent as any;
    expect(structured.totalFindings).toBeGreaterThan(0);
    expect(structured.grade).toMatch(/^[A-F]$/);

    const severities = structured.topFindings.map((f: any) => f.severity);
    for (let i = 1; i < severities.length; i++) {
      expect(SEVERITY_ORDER.indexOf(severities[i - 1])).toBeLessThanOrEqual(SEVERITY_ORDER.indexOf(severities[i]));
    }
  });

  it('rejects a path that escapes the confined project root', async () => {
    const root = path.join(FIXTURES, 'vulnerable-agent');
    const result = await scanProject({ path: '../mcp-server' }, { projectRoot: root });

    expect(result.isError).toBe(true);
    expect(result.content[0].text).toMatch(/outside the confined project root/i);
    expect(runScan).not.toHaveBeenCalled();
  });

  it('rejects a path that does not exist', async () => {
    const root = path.join(FIXTURES, 'vulnerable-agent');
    const result = await scanProject({ path: 'does-not-exist' }, { projectRoot: root });
    expect(result.isError).toBe(true);
  });

  it('allows any local path when projectRoot is not set', async () => {
    const target = path.join(FIXTURES, 'langchain-basic');
    const result = await scanProject({ path: target }, {});
    expect(result.isError).toBeUndefined();
  });
});

describe('get_score reuses the scan_project session cache', () => {
  beforeEach(() => {
    resetSessionForTests();
    vi.mocked(runScan).mockClear();
  });

  it('does not rescan when a cached scan_project result exists for the path', async () => {
    const target = path.join(FIXTURES, 'langchain-basic');

    const scanResult = await scanProject({ path: target }, { projectRoot: target });
    expect(runScan).toHaveBeenCalledTimes(1);

    const scoreResult = await getScore({ path: target }, { projectRoot: target });
    expect(runScan).toHaveBeenCalledTimes(1); // cache hit — no second scan

    const scanStructured = scanResult.structuredContent as any;
    const scoreStructured = scoreResult.structuredContent as any;
    expect(scoreStructured.score).toBe(scanStructured.score);
    expect(scoreStructured.grade).toBe(scanStructured.grade);
  });

  it('runs a scan when nothing is cached for the path', async () => {
    const target = path.join(FIXTURES, 'crewai-crew');
    const result = await getScore({ path: target }, { projectRoot: target });

    expect(runScan).toHaveBeenCalledTimes(1);
    expect(result.isError).toBeUndefined();
    const structured = result.structuredContent as any;
    expect(structured.grade).toMatch(/^[A-F]$/);
    expect(Array.isArray(structured.domains)).toBe(true);
  });

  it('rejects a path escaping the confined root', async () => {
    const root = path.join(FIXTURES, 'langchain-basic');
    const result = await getScore({ path: '../crewai-crew' }, { projectRoot: root });
    expect(result.isError).toBe(true);
    expect(runScan).not.toHaveBeenCalled();
  });
});

describe('scan_mcp_server tool', () => {
  it('scans an MCP server fixture and reports a status + findings', async () => {
    const target = path.join(FIXTURES, 'mcp-server');
    const result = await scanMcpServer({ path: target }, { projectRoot: target });

    expect(result.isError).toBeUndefined();
    const structured = result.structuredContent as any;
    expect(['ok', 'warn', 'critical']).toContain(structured.status);
    expect(Array.isArray(structured.findings)).toBe(true);
  });

  it('rejects a path escaping the confined root', async () => {
    const root = path.join(FIXTURES, 'mcp-server');
    const result = await scanMcpServer({ path: path.join(FIXTURES, 'vulnerable-agent') }, { projectRoot: root });
    expect(result.isError).toBe(true);
  });
});

describe('inventory tool', () => {
  it('returns a summary by default', async () => {
    const target = path.join(FIXTURES, 'inventory-agent');
    const result = await inventory({ path: target }, { projectRoot: target });

    expect(result.isError).toBeUndefined();
    const structured = result.structuredContent as any;
    expect(structured.summary).toBeDefined();
  });

  it('returns an unsigned CycloneDX AI-BOM with format=cyclonedx', async () => {
    const target = path.join(FIXTURES, 'inventory-agent');
    const result = await inventory({ path: target, format: 'cyclonedx' }, { projectRoot: target });

    expect(result.isError).toBeUndefined();
    const structured = result.structuredContent as any;
    expect(structured.bom.bomFormat).toBe('CycloneDX');
    expect(structured.bom.signature).toBeUndefined();
    expect(result.content[0].text).toMatch(/unsigned/i);
  });

  it('rejects a path escaping the confined root', async () => {
    const root = path.join(FIXTURES, 'inventory-agent');
    const result = await inventory({ path: '../mcp-server' }, { projectRoot: root });
    expect(result.isError).toBe(true);
  });
});

describe('explain_finding tool', () => {
  beforeEach(() => {
    resetSessionForTests();
  });

  it('explains a known rule by rule_id', async () => {
    const anyRule = getAllRules()[0];
    const result = await explainFinding({ rule_id: anyRule.id });

    expect(result.isError).toBeUndefined();
    const structured = result.structuredContent as any;
    expect(structured.rule.id).toBe(anyRule.id);
    expect(structured.rule.description).toBeTruthy();
  });

  it('resolves a finding_id from a cached scan_project result', async () => {
    const target = path.join(FIXTURES, 'vulnerable-agent');
    const scanResult = await scanProject({ path: target }, { projectRoot: target });
    const scanStructured = scanResult.structuredContent as any;
    const findingId = scanStructured.topFindings[0]?.id;
    expect(findingId).toBeTruthy();

    const explainResult = await explainFinding({ finding_id: findingId, path: target }, { projectRoot: target });
    expect(explainResult.isError).toBeUndefined();
    const explainStructured = explainResult.structuredContent as any;
    expect(explainStructured.finding.id).toBe(findingId);
  });

  it('returns a helpful error when neither rule_id nor finding_id resolves', async () => {
    const result = await explainFinding(
      { finding_id: 'nonexistent-finding', path: path.join(FIXTURES, 'langchain-basic') },
      {},
    );
    expect(result.isError).toBe(true);
  });

  it('errors when called with neither rule_id nor finding_id', async () => {
    const result = await explainFinding({});
    expect(result.isError).toBe(true);
  });
});

describe('verify_mcp_package', () => {
  describe('mapRiskToRecommendation (pure)', () => {
    it('maps low risk to safe-to-install', () => {
      expect(mapRiskToRecommendation('low')).toBe('safe-to-install');
    });
    it('maps medium risk to review', () => {
      expect(mapRiskToRecommendation('medium')).toBe('review');
    });
    it('maps high and critical risk to do-not-install', () => {
      expect(mapRiskToRecommendation('high')).toBe('do-not-install');
      expect(mapRiskToRecommendation('critical')).toBe('do-not-install');
    });
  });

  describe('tool handler with stubbed fetch (no real network call)', () => {
    beforeEach(() => {
      vi.stubGlobal('fetch', vi.fn());
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it('returns found + a recommendation for a resolvable package', async () => {
      (fetch as any)
        .mockResolvedValueOnce({
          status: 200,
          ok: true,
          json: async () => ({
            name: 'safe-pkg',
            license: 'MIT',
            repository: { url: 'https://github.com/example/safe-pkg' },
            maintainers: [{ name: 'alice' }, { name: 'bob' }],
            time: {
              created: new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(),
              '1.0.0': new Date().toISOString(),
            },
            'dist-tags': { latest: '1.0.0' },
            versions: { '1.0.0': { dependencies: {} } },
          }),
        })
        .mockResolvedValueOnce({ ok: true, json: async () => ({ downloads: 5000 }) });

      const result = await verifyMcpPackage({ package: 'safe-pkg' });
      expect(result.isError).toBeUndefined();
      const structured = result.structuredContent as any;
      expect(structured.found).toBe(true);
      expect(['safe-to-install', 'review', 'do-not-install']).toContain(structured.recommendation);
    });

    it('recommends do-not-install for a package not found on the registry', async () => {
      (fetch as any).mockResolvedValueOnce({ status: 404, ok: false });

      const result = await verifyMcpPackage({ package: 'nonexistent-package-xyz' });
      const structured = result.structuredContent as any;
      expect(structured.found).toBe(false);
      expect(structured.recommendation).toBe('do-not-install');
    });
  });
});
