import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getAllRules, getRuleById } from '../../src/analyzers/rules/index.js';

describe('rules command', () => {
  describe('getAllRules', () => {
    it('returns a non-empty array of rules', () => {
      expect(getAllRules().length).toBeGreaterThan(0);
    });

    it('every rule has required fields', () => {
      for (const rule of getAllRules()) {
        expect(rule.id).toBeTruthy();
        expect(rule.name).toBeTruthy();
        expect(rule.domain).toBeTruthy();
        expect(rule.severity).toBeTruthy();
        expect(rule.description).toBeTruthy();
        expect(typeof rule.check).toBe('function');
      }
    });

    it('every rule has a valid severity', () => {
      const valid = ['critical', 'high', 'medium', 'low', 'info'];
      for (const rule of getAllRules()) expect(valid).toContain(rule.severity);
    });
  });

  describe('getRuleById', () => {
    it('finds a known rule', () => {
      const rule = getRuleById('AA-GI-001');
      expect(rule).toBeDefined();
      expect(rule!.id).toBe('AA-GI-001');
    });

    it('returns undefined for unknown rule', () => {
      expect(getRuleById('NONEXISTENT-999')).toBeUndefined();
    });
  });

  describe('filtering', () => {
    it('filters by domain', () => {
      const rules = getAllRules().filter(r => r.domain === 'goal-integrity');
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.every(r => r.domain === 'goal-integrity')).toBe(true);
    });

    it('filters by severity', () => {
      const rules = getAllRules().filter(r => r.severity === 'critical');
      expect(rules.length).toBeGreaterThan(0);
      expect(rules.every(r => r.severity === 'critical')).toBe(true);
    });

    it('searches by text', () => {
      const rules = getAllRules().filter(r =>
        r.name.toLowerCase().includes('injection') || r.description.toLowerCase().includes('injection')
      );
      expect(rules.length).toBeGreaterThan(0);
    });

    it('returns empty for non-matching domain', () => {
      expect(getAllRules().filter(r => r.domain === 'nonexistent').length).toBe(0);
    });
  });

  describe('standards', () => {
    it('some rules have standards mapping', () => {
      expect(getAllRules().filter(r => r.standards && Object.keys(r.standards).length > 0).length).toBeGreaterThan(0);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────
// `g0 rules list` / `g0 rules describe` — driven through the REAL CLI tree
// via `createCli()`, not by calling the rules.ts internals directly. This
// is the part the underlying-library tests above can't cover: that `rules`
// is actually registered on the top-level program (src/cli/index.ts) and
// that `--json`/`--rules-dir`, declared directly on the `list`/`describe`
// leaf commands, are read correctly by Commander when parsed through the
// full `rules -> list|describe` subcommand chain (the same class of
// parent/child option-shadowing bug covered for `endpoint`/`proxy`
// elsewhere in this suite).
// ─────────────────────────────────────────────────────────────────────────
describe('g0 rules CLI wiring (via the real createCli() tree)', () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  async function run(argv: string[]) {
    const { createCli } = await import('../../src/cli/index.js');
    const program = createCli();
    program.exitOverride();
    await program.parseAsync(argv, { from: 'user' });
  }

  it('g0 rules list --json emits parseable JSON for every rule', async () => {
    await run(['rules', 'list', '--json']);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(logSpy.mock.calls[0][0] as string);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(getAllRules().length);
    expect(parsed[0]).toHaveProperty('id');
  });

  it('g0 rules list --json --domain <domain> filters correctly through the CLI', async () => {
    await run(['rules', 'list', '--json', '--domain', 'goal-integrity']);

    const parsed = JSON.parse(logSpy.mock.calls[0][0] as string);
    expect(parsed.length).toBeGreaterThan(0);
    expect(parsed.every((r: { domain: string }) => r.domain === 'goal-integrity')).toBe(true);
  });

  it('g0 rules describe <id> --json emits the matching rule', async () => {
    await run(['rules', 'describe', 'AA-GI-001', '--json']);

    expect(logSpy).toHaveBeenCalledTimes(1);
    const parsed = JSON.parse(logSpy.mock.calls[0][0] as string);
    expect(parsed.id).toBe('AA-GI-001');
    expect(parsed.name).toBe(getRuleById('AA-GI-001')!.name);
  });
});
