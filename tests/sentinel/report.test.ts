import { describe, it, expect } from 'vitest';
import { summarizeOrg, renderOrgReportHtml } from '../../src/sentinel/report.js';
import type { MachineSnapshot } from '../../src/sentinel/snapshot.js';

function snap(overrides: Partial<MachineSnapshot>): MachineSnapshot {
  return {
    schemaVersion: 2,
    generatedAtMs: 1_700_000_000_000,
    sentinelVersion: '0.0.0',
    host: { hostname: 'host', platform: 'darwin', arch: 'arm64' },
    tools: [],
    exposures: [],
    piiSummary: {},
    ...overrides,
  };
}

const mac1 = snap({
  host: { hostname: 'mac-1', platform: 'darwin', arch: 'arm64' },
  endpointScore: 82,
  tools: [
    { name: 'Claude Code', installed: true, running: true, mcpServerCount: 2 },
    { name: 'Cursor', installed: true, running: false, mcpServerCount: 0 },
  ],
  exposures: [
    {
      tool: 'Claude Code',
      category: 'coding-agent',
      reach: { mcpServers: ['github', 'postgres'], network: true },
      evidenced: { email: 3, credit_card: 1 },
      locators: [{ path: '/Users/alice/.claude/history.jsonl', counts: { email: 3, credit_card: 1 } }],
      riskScore: 41,
    },
    {
      tool: 'Cursor',
      category: 'coding-agent',
      reach: { mcpServers: [], network: false },
      evidenced: { email: 2 },
      locators: [],
      riskScore: 6,
    },
  ],
  piiSummary: { email: 5, credit_card: 1 },
});

const win1 = snap({
  host: { hostname: 'win-1', platform: 'win32', arch: 'x64' },
  endpointScore: 60,
  tools: [{ name: 'Claude Code', installed: true, running: false, mcpServerCount: 1 }],
  exposures: [
    {
      tool: 'Claude Code',
      category: 'coding-agent',
      reach: { mcpServers: ['slack'], network: true },
      evidenced: { api_token: 2 },
      locators: [],
      riskScore: 44,
    },
  ],
  piiSummary: { api_token: 2 },
  governance: {
    policyName: 'baseline',
    verdicts: [{ tool: 'Claude Code', verdict: 'deny', rule: 'no-secrets' }],
    compliant: false,
  },
});

const linux1 = snap({
  host: { hostname: 'linux-1', platform: 'linux', arch: 'x64' },
  endpointScore: 95,
  tools: [{ name: 'Codex', installed: true, running: true, mcpServerCount: 0 }],
  exposures: [],
  piiSummary: {},
  governance: {
    policyName: 'baseline',
    verdicts: [{ tool: 'Codex', verdict: 'allow' }],
    compliant: true,
  },
});

describe('summarizeOrg', () => {
  it('computes fleet-wide numbers', () => {
    const s = summarizeOrg([mac1, win1, linux1]);
    expect(s.machines).toBe(3);
    // distinct installed tool names: Claude Code, Cursor, Codex
    expect(s.totalTools).toBe(3);
    // pii sums: mac-1 (5+1) + win-1 (2) + linux-1 (0) = 8
    expect(s.totalPii).toBe(8);
    // only win-1 is non-compliant
    expect(s.nonCompliant).toBe(1);
  });

  it('orders topTools by machine count descending', () => {
    const s = summarizeOrg([mac1, win1, linux1]);
    // Claude Code installed on mac-1 and win-1 => 2; Cursor and Codex => 1 each
    expect(s.topTools[0]).toEqual({ name: 'Claude Code', machines: 2 });
    expect(s.topTools[0].machines).toBeGreaterThanOrEqual(s.topTools[1].machines);
    const names = s.topTools.map((t) => t.name);
    expect(names).toContain('Cursor');
    expect(names).toContain('Codex');
  });

  it('is resilient to snapshots missing optional fields', () => {
    const bare = {
      schemaVersion: 2,
      generatedAtMs: 1,
      sentinelVersion: '0.0.0',
      host: { hostname: 'bare', platform: 'linux', arch: 'x64' },
      tools: [{ name: 'Aider', installed: true, running: false, mcpServerCount: 0 }],
    } as unknown as MachineSnapshot;
    const s = summarizeOrg([bare]);
    expect(s.machines).toBe(1);
    expect(s.totalTools).toBe(1);
    expect(s.totalPii).toBe(0);
    expect(s.nonCompliant).toBe(0);
  });
});

describe('renderOrgReportHtml', () => {
  const html = renderOrgReportHtml([mac1, win1, linux1]);

  it('returns a complete self-contained HTML document', () => {
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).toContain('<style>');
    expect(html).not.toContain('http://');
    expect(html).not.toContain('https://');
  });

  it('includes every hostname', () => {
    expect(html).toContain('mac-1');
    expect(html).toContain('win-1');
    expect(html).toContain('linux-1');
  });

  it('shows PII class labels and counts (classes+counts only)', () => {
    expect(html).toContain('credit_card');
    expect(html).toContain('email');
    expect(html).toContain('api_token');
    // per-tool inline class:count formatting present (real evidenced values)
    expect(html).toContain('credit_card:1');
    expect(html).toContain('email:3');
    expect(html).toContain('api_token:2');
    // fleet PII table aggregates counts: email 3+2=5 across mac-1's tools
    expect(html).toContain('<td>email</td><td class="num">5</td>');
  });

  it('flags the non-compliant machine', () => {
    expect(html).toContain('NON-COMPLIANT');
    expect(html).toContain('deny');
  });

  it('escapes hostnames to prevent HTML/script injection', () => {
    const evil = snap({
      host: { hostname: '<script>alert(1)</script>', platform: 'darwin', arch: 'arm64' },
      tools: [{ name: 'Cursor', installed: true, running: false, mcpServerCount: 0 }],
    });
    const out = renderOrgReportHtml([evil]);
    // the raw, dangerous form must NOT appear
    expect(out).not.toContain('<script>alert(1)</script>');
    // its escaped form must appear instead
    expect(out).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('escapes tool names and locator paths', () => {
    const evil = snap({
      host: { hostname: 'h', platform: 'darwin', arch: 'arm64' },
      tools: [{ name: '<b>Cursor</b>', installed: true, running: false, mcpServerCount: 0 }],
      exposures: [
        {
          tool: '<b>Cursor</b>',
          category: 'coding-agent',
          reach: { mcpServers: [], network: false },
          evidenced: { email: 1 },
          locators: [{ path: '/Users/<img>/x.log', counts: { email: 1 } }],
          riskScore: 3,
        },
      ],
      piiSummary: { email: 1 },
    });
    const out = renderOrgReportHtml([evil]);
    expect(out).not.toContain('<b>Cursor</b>');
    expect(out).toContain('&lt;b&gt;Cursor&lt;/b&gt;');
    expect(out).not.toContain('/Users/<img>/x.log');
    expect(out).toContain('/Users/&lt;img&gt;/x.log');
  });
});
