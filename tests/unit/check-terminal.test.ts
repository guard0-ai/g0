import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { reportCheckTerminal } from '../../src/reporters/check-terminal.js';
import type { CheckResult } from '../../src/check/runner.js';

let logSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  logSpy.mockRestore();
});

function output(): string {
  return logSpy.mock.calls.map(args => args.join(' ')).join('\n');
}

function makeResult(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    skills: {
      skills: [],
      summary: {
        total: 0,
        trusted: 0,
        caution: 0,
        untrusted: 0,
        malicious: 0,
        totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      },
    },
    infostealerIOCs: [],
    maliciousServers: [],
    verdict: { score: 95, grade: 'A', capped: false, headline: 'No known-malicious components found' },
    ...overrides,
  };
}

function makeEndpoint(overrides: Record<string, unknown> = {}): CheckResult['endpoint'] {
  return {
    tools: [{ name: 'Claude Code' }, { name: 'Cursor' }],
    mcp: { servers: [{}, {}, {}] },
    score: {
      total: 95,
      grade: 'A',
      categories: {
        configuration: { score: 30, max: 30, deductions: [] },
        credentials: { score: 30, max: 30, deductions: [] },
        network: { score: 25, max: 25, deductions: [] },
        discovery: { score: 10, max: 15, deductions: [] },
      },
    },
    ...overrides,
  } as unknown as CheckResult['endpoint'];
}

describe('reportCheckTerminal', () => {
  it('prints the grade and headline', () => {
    reportCheckTerminal(makeResult());
    const out = output();
    expect(out).toContain('A');
    expect(out).toContain('95');
    expect(out).toContain('No known-malicious components found');
  });

  it('lists malicious skills with a ~-shortened path, a skill-removal fix, and no deduction section', () => {
    vi.stubEnv('HOME', '/home/u');
    const result = makeResult({
      skills: {
        skills: [
          {
            skillName: 'evil-helper/SKILL',
            filePath: '/home/u/.openclaw/skills/evil-helper/SKILL.md',
            staticFindings: [
              {
                severity: 'critical',
                type: 'openclaw-clawhavoc-c2-ioc',
                title: 'ClawHavoc C2 IOC in skill content',
                description: 'Skill content contains a ClawHavoc malware campaign indicator.',
                file: 'SKILL.md',
              },
            ],
            trustScore: 0,
            trustLevel: 'malicious',
            risks: ['ClawHavoc malware IOC detected — skill is malicious'],
          },
        ],
        summary: {
          total: 3,
          trusted: 2,
          caution: 0,
          untrusted: 0,
          malicious: 1,
          totalFindings: 1,
          findingsBySeverity: { critical: 1, high: 0, medium: 0, low: 0 },
        },
      },
      verdict: {
        score: 35,
        grade: 'F',
        capped: true,
        headline: '1 of 3 installed skills is known-malicious',
      },
    });

    result.endpoint = makeEndpoint({
      score: {
        total: 35,
        grade: 'F',
        categories: {
          configuration: {
            score: 15, max: 30,
            deductions: [{ finding: 'ClawHavoc C2 IOC', severity: 'critical', points: 15 }],
          },
          credentials: { score: 30, max: 30, deductions: [] },
          network: { score: 25, max: 25, deductions: [] },
          discovery: { score: 0, max: 15, deductions: [] },
        },
      },
    });

    reportCheckTerminal(result);
    const out = output();
    vi.unstubAllEnvs();
    expect(out).toContain('MALICIOUS');
    expect(out).toContain('evil-helper');
    expect(out).toContain('~/.openclaw/skills/evil-helper/SKILL.md');
    expect(out).toContain('1 of 3 installed skills is known-malicious');
    expect(out).toContain('Grade capped');
    expect(out).toContain('Remove the skill directory');
    // Quarantine only handles MCP server configs — must not be suggested for skills.
    expect(out).not.toContain('quarantine');
    // The cap IS the explanation — deduction breakdown would be noise here.
    expect(out).not.toContain('Why not an A');
  });

  it('lists known-malicious MCP servers with the quarantine fix', () => {
    const result = makeResult({
      maliciousServers: [{
        client: 'Cursor',
        configPath: '/home/u/.cursor/mcp.json',
        mcpKey: 'mcpServers',
        serverName: 'evil-mcp',
        matches: [{
          type: 'name',
          indicator: 'evil-mcp',
          matched: 'evil-mcp',
          description: 'Known-malicious MCP server (ClawHavoc campaign)',
          severity: 'critical',
        }],
      }],
      verdict: {
        score: 35,
        grade: 'F',
        capped: true,
        headline: '1 known-malicious MCP server in your IDE configs',
      },
    });

    reportCheckTerminal(result);
    const out = output();
    expect(out).toContain('MALICIOUS');
    expect(out).toContain('evil-mcp');
    expect(out).toContain('Cursor');
    expect(out).toContain('Known-malicious MCP server (ClawHavoc campaign)');
    expect(out).toContain('g0 endpoint quarantine --apply');
  });

  it('summarizes the endpoint estate with tool names when the endpoint scan ran', () => {
    const result = makeResult();
    result.endpoint = makeEndpoint();

    reportCheckTerminal(result);
    const out = output();
    expect(out).toContain('2 AI tools');
    expect(out).toContain('3 MCP servers');
    expect(out).toContain('Claude Code');
    expect(out).toContain('Cursor');
    expect(out).toContain('g0 endpoint');
  });

  it('justifies a non-A grade with the top endpoint deductions', () => {
    const result = makeResult({
      verdict: { score: 55, grade: 'D', capped: false, headline: 'No known-malicious components found' },
    });
    result.endpoint = makeEndpoint({
      score: {
        total: 55,
        grade: 'D',
        categories: {
          configuration: {
            score: 20, max: 30,
            deductions: [{ finding: 'MCP server running with --dangerously-skip-permissions', severity: 'high', points: 10 }],
          },
          credentials: {
            score: 10, max: 30,
            deductions: [
              { finding: 'OpenAI API key in plaintext MCP config', severity: 'critical', points: 15 },
              { finding: 'GitHub token in shell history', severity: 'low', points: 5 },
            ],
          },
          network: { score: 25, max: 25, deductions: [] },
          discovery: { score: 0, max: 15, deductions: [] },
        },
      },
    });

    reportCheckTerminal(result);
    const out = output();
    expect(out).toContain('Why not an A');
    expect(out).toContain('OpenAI API key in plaintext MCP config');
    expect(out).toContain('MCP server running with --dangerously-skip-permissions');
    expect(out).toContain('-15');
  });

  it('does not print the deduction section for a clean A', () => {
    const result = makeResult();
    result.endpoint = makeEndpoint();

    reportCheckTerminal(result);
    expect(output()).not.toContain('Why not an A');
  });
});
