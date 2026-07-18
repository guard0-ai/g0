import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import {
  maybeShowCta,
  maybeGetCta,
  recordScan,
  buildCtaUrl,
  ctaStateFilePath,
  CTA_TRIGGERS,
  __resetCtaLatchForTests,
  type CtaTrigger,
} from '../../src/platform/cta.js';
import { saveTokens } from '../../src/platform/auth.js';
import { entitlementsFilePath } from '../../src/platform/entitlements.js';

const ALL_TRIGGERS = Object.keys(CTA_TRIGGERS) as CtaTrigger[];

describe('CTA module', () => {
  let tmpDir: string;
  let originalCI: string | undefined;
  let originalNoCta: string | undefined;
  let originalIsTTY: boolean | undefined;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-cta-test-'));

    originalCI = process.env.CI;
    originalNoCta = process.env.G0_NO_CTA;
    delete process.env.CI;
    delete process.env.G0_NO_CTA;

    originalIsTTY = process.stdout.isTTY;
    Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });

    __resetCtaLatchForTests();

    logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });

    if (originalCI === undefined) delete process.env.CI;
    else process.env.CI = originalCI;

    if (originalNoCta === undefined) delete process.env.G0_NO_CTA;
    else process.env.G0_NO_CTA = originalNoCta;

    Object.defineProperty(process.stdout, 'isTTY', { value: originalIsTTY, configurable: true });

    logSpy.mockRestore();
  });

  function writePaidUser(): void {
    saveTokens(
      {
        tokenType: 'oauth',
        accessToken: 'tok',
        refreshToken: 'refresh',
        expiresAt: Date.now() + 60 * 60 * 1000,
        email: 'paid@example.com',
      },
      tmpDir,
    );
    fs.writeFileSync(
      entitlementsFilePath(tmpDir),
      JSON.stringify({ plan: 'pro', features: [], fetchedAt: new Date().toISOString() }),
      { mode: 0o600 },
    );
  }

  function allOutput(): string {
    return logSpy.mock.calls.map(call => call.join(' ')).join('\n');
  }

  describe('buildCtaUrl', () => {
    it('produces the exact UTM URL for every trigger, defaulting medium to cli', () => {
      for (const trigger of ALL_TRIGGERS) {
        const url = buildCtaUrl(trigger);
        expect(url).toBe(
          `https://guard0.ai/signup?utm_source=g0&utm_medium=cli&utm_campaign=${CTA_TRIGGERS[trigger].utmCampaign}`,
        );
      }
    });

    it('honors a custom medium', () => {
      expect(buildCtaUrl('criticals-found', 'mcp')).toBe(
        'https://guard0.ai/signup?utm_source=g0&utm_medium=mcp&utm_campaign=criticals-found',
      );
      expect(buildCtaUrl('gate-failed', 'github')).toBe(
        'https://guard0.ai/signup?utm_source=g0&utm_medium=github&utm_campaign=gate-failed',
      );
    });
  });

  describe('maybeShowCta — fires on fresh state', () => {
    it('prints the CTA block with the correct UTM URL', () => {
      maybeShowCta('criticals-found', { dir: tmpDir });

      const output = allOutput();
      expect(output).toContain(buildCtaUrl('criticals-found'));
      expect(output).toContain(CTA_TRIGGERS['criticals-found'].headline);
      expect(logSpy).toHaveBeenCalled();
    });

    it('includes the optional detail line', () => {
      maybeShowCta('criticals-found', { dir: tmpDir, detail: '3 critical findings' });
      expect(allOutput()).toContain('3 critical findings');
    });

    it('appends the G0_NO_CTA hint only on the first-ever CTA', () => {
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(allOutput()).toContain('Set G0_NO_CTA=1 to hide these.');
    });
  });

  describe('suppression — env vars', () => {
    it('suppresses when G0_NO_CTA=1', () => {
      process.env.G0_NO_CTA = '1';
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('suppresses when G0_NO_CTA=true', () => {
      process.env.G0_NO_CTA = 'true';
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('maybeGetCta also honors G0_NO_CTA', () => {
      process.env.G0_NO_CTA = '1';
      const result = maybeGetCta('criticals-found', { dir: tmpDir });
      expect(result).toBeNull();
    });
  });

  describe('suppression — CI / TTY (maybeShowCta only)', () => {
    it('suppresses maybeShowCta when CI is set', () => {
      process.env.CI = '1';
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('suppresses maybeShowCta when stdout is not a TTY', () => {
      Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('does NOT apply the TTY/CI guard to maybeGetCta', () => {
      Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
      process.env.CI = '1';
      const result = maybeGetCta('criticals-found', { dir: tmpDir });
      expect(result).not.toBeNull();
      expect(result).toContain(buildCtaUrl('criticals-found'));
    });
  });

  describe('suppression — configCta', () => {
    it('suppresses maybeShowCta when configCta is false', () => {
      maybeShowCta('criticals-found', { dir: tmpDir, configCta: false });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('does not suppress when configCta is undefined', () => {
      maybeShowCta('criticals-found', { dir: tmpDir, configCta: undefined });
      expect(logSpy).toHaveBeenCalled();
    });
  });

  describe('suppression — logged-in paid plan', () => {
    it('suppresses marketing triggers for a logged-in paid user', () => {
      writePaidUser();
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('still shows gated-flag-used for a logged-in paid user, with an adapted message', () => {
      writePaidUser();
      maybeShowCta('gated-flag-used', { dir: tmpDir, detail: '--html' });
      const output = allOutput();
      expect(output).toContain('--html is available on a higher plan');
    });

    it('shows the sign-up message for a logged-out user hitting a gated flag', () => {
      maybeShowCta('gated-flag-used', { dir: tmpDir, detail: '--upload' });
      const output = allOutput();
      expect(output).toContain('--upload is a Guard0 Platform feature');
    });
  });

  describe('frequency caps — per-trigger cooldown', () => {
    it('suppresses a repeat of the SAME trigger within its cooldown window', () => {
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockClear();

      // Isolate the cooldown check from the one-per-process latch, which is
      // covered by its own test below.
      __resetCtaLatchForTests();

      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('does NOT suppress gated-flag-used on repeat (cooldownDays: 0)', () => {
      maybeShowCta('gated-flag-used', { dir: tmpDir, detail: '--html' });
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockClear();

      __resetCtaLatchForTests();

      maybeShowCta('gated-flag-used', { dir: tmpDir, detail: '--html' });
      expect(logSpy).toHaveBeenCalled();
    });
  });

  describe('frequency caps — global 24h gap', () => {
    it('suppresses a DIFFERENT marketing trigger within 24h of the last shown CTA', () => {
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockClear();

      __resetCtaLatchForTests();

      maybeShowCta('drift-detected', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('does not apply the 24h gap to gated-flag-used', () => {
      // A marketing CTA was shown "now" — well within 24h.
      maybeShowCta('scan-complete', { dir: tmpDir });
      expect(logSpy).toHaveBeenCalled();
      logSpy.mockClear();

      __resetCtaLatchForTests();

      maybeShowCta('gated-flag-used', { dir: tmpDir, detail: '--report' });
      expect(logSpy).toHaveBeenCalled();
    });

    it('allows a different trigger once 24h have passed', () => {
      const past = new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString();
      fs.writeFileSync(
        ctaStateFilePath(tmpDir),
        JSON.stringify({ scanCount: 0, lastShownAt: { 'criticals-found': past }, lastAnyShownAt: past }),
        { mode: 0o600 },
      );

      maybeShowCta('drift-detected', { dir: tmpDir });
      expect(logSpy).toHaveBeenCalled();
    });
  });

  describe('frequency caps — one-per-process latch', () => {
    it('only shows the first of two calls within the same process', () => {
      maybeShowCta('criticals-found', { dir: tmpDir });
      expect(logSpy).toHaveBeenCalled();
      const callsAfterFirst = logSpy.mock.calls.length;

      // No latch reset here — this is the behavior under test.
      maybeShowCta('scan-complete', { dir: tmpDir });
      expect(logSpy.mock.calls.length).toBe(callsAfterFirst);
    });
  });

  describe('recordScan', () => {
    it('increments and persists the scan count', () => {
      expect(recordScan(tmpDir)).toBe(1);
      expect(recordScan(tmpDir)).toBe(2);
      expect(recordScan(tmpDir)).toBe(3);

      const persisted = JSON.parse(fs.readFileSync(ctaStateFilePath(tmpDir), 'utf-8'));
      expect(persisted.scanCount).toBe(3);
    });
  });

  describe('maybeGetCta', () => {
    it('returns a plain string with the trigger headline and URL', () => {
      const result = maybeGetCta('drift-detected', { dir: tmpDir, medium: 'mcp' });
      expect(result).not.toBeNull();
      expect(result).toContain(CTA_TRIGGERS['drift-detected'].headline);
      expect(result).toContain(buildCtaUrl('drift-detected', 'mcp'));
    });

    it('adapts the gated-flag-used message for a logged-in paid user missing the feature', () => {
      writePaidUser();
      const result = maybeGetCta('gated-flag-used', { dir: tmpDir, detail: '--adaptive' });
      expect(result).toContain('--adaptive is available on a higher plan');
    });

    it('adapts the gated-flag-used message for a logged-out user', () => {
      const result = maybeGetCta('gated-flag-used', { dir: tmpDir, detail: '--adaptive' });
      expect(result).toContain('--adaptive is a Guard0 Platform feature');
    });

    it('records state so a follow-up MCP call within cooldown is suppressed', () => {
      expect(maybeGetCta('drift-detected', { dir: tmpDir })).not.toBeNull();
      __resetCtaLatchForTests();
      expect(maybeGetCta('drift-detected', { dir: tmpDir })).toBeNull();
    });
  });

  describe('machine-output safety', () => {
    it('maybeShowCta writes NOTHING when stdout is not a TTY', () => {
      Object.defineProperty(process.stdout, 'isTTY', { value: false, configurable: true });
      maybeShowCta('scan-complete', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });

    it('maybeShowCta writes NOTHING in CI even on a TTY', () => {
      process.env.CI = 'true';
      maybeShowCta('scan-complete', { dir: tmpDir });
      expect(logSpy).not.toHaveBeenCalled();
    });
  });
});
