// Signup-funnel CTA module for the guard0.ai platform.
//
// A single, self-contained decision point for whether (and what) signup CTA
// to surface at high-intent moments — a critical finding, drift between
// scans, a gated flag, etc. Strict suppression + frequency capping so it
// never annoys a user or pollutes machine-readable output.
//
// Hard rules:
//   - `maybeShowCta` is the only entry point that touches the terminal
//     (chalk + console.log) and it refuses to run outside an interactive TTY
//     or in CI — never pollute machine output.
//   - `maybeGetCta` is for surfaces without a TTY concept (MCP tool
//     footers, GitHub Action / PR comments) — it returns a plain string (or
//     null) and does not apply the TTY/CI guard, since those surfaces
//     manage their own context.
//   - Both are synchronous, disk-only, and never throw.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import chalk from 'chalk';
import { getAuthState } from './auth.js';
import { getEntitlementsCached } from './entitlements.js';

const G0_DIR = path.join(os.homedir(), '.g0');

const DAY_MS = 24 * 60 * 60 * 1000;

export type CtaTrigger =
  | 'criticals-found' // scan/gate found >=1 critical
  | 'drift-detected' // fleet drift or new findings since last run
  | 'gated-flag-used' // user passed a platform-only flag (--html/--upload/--adaptive/--report)
  | 'endpoint-secrets' // endpoint scan found exposed secrets in MCP configs
  | 'scan-milestone' // Nth scan (5/25/100)
  | 'gate-failed' // gate threshold failed (local runs only)
  | 'scan-complete' // generic fallback after a clean scan
  | 'check-malicious'; // g0 check found known-malicious skills/components

interface CtaTriggerConfig {
  headline: string;
  utmCampaign: string;
  cooldownDays: number;
  showWhenLoggedIn: boolean;
}

/**
 * The trigger registry. Marketing triggers cap at once per 7 days and hide
 * for logged-in paid users. `gated-flag-used` is a direct response to a
 * user action (not marketing) — no cooldown, and it still shows for
 * logged-in users (its message just adapts to be informational).
 */
export const CTA_TRIGGERS: Record<CtaTrigger, CtaTriggerConfig> = {
  'criticals-found': {
    headline: 'Track remediation & prove it to auditors across every agent',
    utmCampaign: 'criticals-found',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
  'drift-detected': {
    headline: 'See what changed across your whole fleet over time',
    utmCampaign: 'drift-detected',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
  'gated-flag-used': {
    // Unused for the actual headline (see buildCtaMessage) — kept as a
    // reasonable fallback if a caller somehow bypasses the message builder.
    headline: 'This is a Guard0 Platform feature',
    utmCampaign: 'gated-flag-used',
    cooldownDays: 0,
    showWhenLoggedIn: true,
  },
  'endpoint-secrets': {
    headline: 'Continuously monitor every developer endpoint',
    utmCampaign: 'endpoint-secrets',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
  'scan-milestone': {
    headline: "You've run real scans — see trends across your whole team",
    utmCampaign: 'scan-milestone',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
  'gate-failed': {
    headline: 'Enforce this gate automatically, across every repo',
    utmCampaign: 'gate-failed',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
  'scan-complete': {
    headline: 'Get this visibility across your whole fleet, automatically',
    utmCampaign: 'scan-complete',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
  'check-malicious': {
    headline: 'Get the real-time threat feed — catch malicious skills the day they drop',
    utmCampaign: 'check-malicious',
    cooldownDays: 7,
    showWhenLoggedIn: false,
  },
};

export function ctaStateFilePath(dir: string = G0_DIR): string {
  return path.join(dir, 'cta-state.json');
}

interface CtaState {
  scanCount: number;
  lastShownAt: Record<string, string>;
  lastAnyShownAt?: string;
}

function defaultState(): CtaState {
  return { scanCount: 0, lastShownAt: {} };
}

/** Sync read. Returns default state on missing file, corrupt JSON, or any other error. */
function loadState(dir: string): CtaState {
  try {
    const raw = fs.readFileSync(ctaStateFilePath(dir), 'utf-8');
    const parsed = JSON.parse(raw) as Partial<CtaState>;
    return {
      scanCount: typeof parsed.scanCount === 'number' ? parsed.scanCount : 0,
      lastShownAt:
        parsed.lastShownAt && typeof parsed.lastShownAt === 'object' ? parsed.lastShownAt : {},
      lastAnyShownAt: typeof parsed.lastAnyShownAt === 'string' ? parsed.lastAnyShownAt : undefined,
    };
  } catch {
    return defaultState();
  }
}

/** Sync write. Best-effort — CTA state is not load-bearing, so failures are swallowed. */
function saveState(state: CtaState, dir: string): void {
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(ctaStateFilePath(dir), JSON.stringify(state, null, 2), { mode: 0o600 });
  } catch {
    // Non-fatal — never let CTA bookkeeping break a scan.
  }
}

/**
 * Increments and persists the lifetime scan count. Callers (e.g. the scan
 * command) fire the `scan-milestone` trigger on round numbers (5/25/100).
 */
export function recordScan(dir: string = G0_DIR): number {
  const state = loadState(dir);
  state.scanCount += 1;
  saveState(state, dir);
  return state.scanCount;
}

/**
 * Builds the guard0.ai signup URL with UTM parameters for a given trigger.
 * `medium` defaults to `'cli'`; MCP/Action surfaces pass `'mcp'`/`'github'`.
 */
export function buildCtaUrl(trigger: CtaTrigger, medium: string = 'cli'): string {
  const config = CTA_TRIGGERS[trigger];
  const params = new URLSearchParams({
    utm_source: 'g0',
    utm_medium: medium,
    utm_campaign: config.utmCampaign,
  });
  return `https://guard0.ai/signup?${params.toString()}`;
}

/** True when the caller is logged in AND on a paid (non-free) plan. */
function isLoggedInPaid(dir: string): boolean {
  const auth = getAuthState(dir);
  if (!auth.loggedIn) return false;
  const plan = getEntitlementsCached(dir)?.plan;
  return !!plan && plan !== 'free';
}

interface CtaMessage {
  headline: string;
  detail?: string;
}

/**
 * Builds the headline (and optional detail line) for a trigger. `gated-flag-used`
 * is special: its message adapts to login/plan state and the named feature
 * rather than using a static registry headline.
 */
function buildCtaMessage(trigger: CtaTrigger, detail: string | undefined, loggedInPaid: boolean): CtaMessage {
  if (trigger === 'gated-flag-used') {
    const feature = detail ?? 'This feature';
    const headline = loggedInPaid
      ? `${feature} is available on a higher plan`
      : `${feature} is a Guard0 Platform feature`;
    return { headline };
  }
  return { headline: CTA_TRIGGERS[trigger].headline, detail };
}

// One CTA per process, max — a boolean latch reset only when the process
// restarts (or via __resetCtaLatchForTests in tests).
let ctaShownThisProcess = false;

/** Test-only: resets the per-process latch. Not part of the public contract. */
export function __resetCtaLatchForTests(): void {
  ctaShownThisProcess = false;
}

interface ShouldSuppressOpts {
  configCta?: boolean;
  dir: string;
}

/**
 * Shared suppression logic for both entry points. Order matters — first
 * match wins:
 *   1. G0_NO_CTA env var
 *   2. .g0.yaml `cta: false` (passed through as opts.configCta)
 *   3. (NOT here — the TTY/CI guard lives in maybeShowCta only)
 *   4. logged-in + paid plan, for marketing triggers only
 *   5. frequency caps: process latch, per-trigger cooldown, global 24h gap
 */
function shouldSuppress(trigger: CtaTrigger, opts: ShouldSuppressOpts): boolean {
  if (process.env.G0_NO_CTA === '1' || process.env.G0_NO_CTA === 'true') return true;

  if (opts.configCta === false) return true;

  const config = CTA_TRIGGERS[trigger];

  if (!config.showWhenLoggedIn && isLoggedInPaid(opts.dir)) return true;

  if (ctaShownThisProcess) return true;

  const state = loadState(opts.dir);
  const now = Date.now();

  if (config.cooldownDays > 0) {
    const lastForTrigger = state.lastShownAt[trigger];
    if (lastForTrigger) {
      const elapsed = now - new Date(lastForTrigger).getTime();
      if (elapsed < config.cooldownDays * DAY_MS) return true;
    }

    // Global 24h gap between ANY two CTAs — skipped for triggers with no
    // cooldown (currently only `gated-flag-used`, which is user-initiated).
    if (state.lastAnyShownAt) {
      const elapsedAny = now - new Date(state.lastAnyShownAt).getTime();
      if (elapsedAny < DAY_MS) return true;
    }
  }

  return false;
}

function recordShown(trigger: CtaTrigger, dir: string): void {
  ctaShownThisProcess = true;
  const state = loadState(dir);
  const nowIso = new Date().toISOString();
  state.lastShownAt[trigger] = nowIso;
  state.lastAnyShownAt = nowIso;
  saveState(state, dir);
}

export interface MaybeShowCtaOpts {
  /** Extra context line, e.g. "3 critical findings" or a gated feature name. */
  detail?: string;
  medium?: string;
  /** The `.g0.yaml` `cta:` value, passed through by the caller. `false` suppresses. */
  configCta?: boolean;
  dir?: string;
}

/**
 * Terminal entry point. Prints a chalk CTA block matching the existing
 * hardcoded block in src/reporters/terminal.ts, or does nothing at all if
 * suppressed. Never writes anything outside an interactive TTY, and never
 * writes in CI — machine-readable output must stay clean.
 */
export function maybeShowCta(trigger: CtaTrigger, opts: MaybeShowCtaOpts = {}): void {
  if (process.env.CI || !process.stdout.isTTY) return;

  const dir = opts.dir ?? G0_DIR;
  if (shouldSuppress(trigger, { configCta: opts.configCta, dir })) return;

  const loggedInPaid = isLoggedInPaid(dir);
  const { headline, detail } = buildCtaMessage(trigger, opts.detail, loggedInPaid);
  const url = buildCtaUrl(trigger, opts.medium ?? 'cli');
  const isFirstEver = !loadState(dir).lastAnyShownAt;

  console.log(chalk.dim('\n  ' + '─'.repeat(60)));
  console.log(chalk.dim(`  ${headline}`));
  if (detail) console.log(chalk.dim(`  ${detail}`));
  console.log(chalk.bold(`  → ${url}`));
  if (isFirstEver) {
    console.log(chalk.dim('  Set G0_NO_CTA=1 to hide these.'));
  }
  console.log(chalk.dim('  ' + '─'.repeat(60)));

  recordShown(trigger, dir);
}

export interface MaybeGetCtaOpts {
  /** Extra context, e.g. a gated feature name for `gated-flag-used`. */
  detail?: string;
  medium?: string;
  dir?: string;
}

/**
 * String-returning entry point for MCP-tool footers / PR comments. Same
 * suppression as maybeShowCta EXCEPT it does not apply the TTY/CI guard
 * (those surfaces have no TTY and manage their own context) and never uses
 * chalk. Returns null when suppressed.
 */
export function maybeGetCta(trigger: CtaTrigger, opts: MaybeGetCtaOpts = {}): string | null {
  const dir = opts.dir ?? G0_DIR;
  if (shouldSuppress(trigger, { dir })) return null;

  const loggedInPaid = isLoggedInPaid(dir);
  const { headline, detail } = buildCtaMessage(trigger, opts.detail, loggedInPaid);
  const url = buildCtaUrl(trigger, opts.medium ?? 'cli');

  recordShown(trigger, dir);

  return detail ? `${headline} — ${detail} → ${url}` : `${headline} → ${url}`;
}
