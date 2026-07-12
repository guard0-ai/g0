// Fires the `gated-flag-used` CTA when the user passes a Guard0 Platform
// feature flag that the OSS CLI doesn't implement (--html/--upload/--report
// on `scan`, --adaptive on `test`). Extracted into one shared, pure-ish
// helper so every call site is forced to compute and pass a `machineOutput`
// guard — `maybeShowCta` itself only checks CI/non-TTY, it has no idea
// whether the caller is mid-way through emitting --json/--sarif output, so
// callers MUST suppress the nudge themselves on any machine-output path.
import { maybeShowCta, type MaybeShowCtaOpts, type CtaTrigger } from './cta.js';

export interface GatedFlags {
  /** scan --html [file] */
  html?: string | boolean;
  /** scan --upload */
  upload?: boolean;
  /** scan --report <std> */
  report?: string | boolean;
  /** test --adaptive */
  adaptive?: boolean;
}

export type ShowCtaFn = (trigger: CtaTrigger, opts: MaybeShowCtaOpts) => void;

export interface NudgeGatedFlagsOpts {
  /**
   * True when the caller is on any machine-readable output path (--json,
   * --sarif, --output, --quiet, ...). Required — there is no default,
   * because silently defaulting to `false` is exactly the bug this helper
   * exists to prevent. When true, this function is a no-op.
   */
  machineOutput: boolean;
  /** The `.g0.yaml` `cta:` value, passed through to maybeShowCta. */
  configCta?: boolean;
  /** Injectable for tests; defaults to the real `maybeShowCta`. */
  showCta?: ShowCtaFn;
}

const GATED_FLAG_DETAILS: ReadonlyArray<{
  key: keyof GatedFlags;
  detail: string;
  isActive: (value: GatedFlags[keyof GatedFlags]) => boolean;
}> = [
  { key: 'html', detail: 'HTML reports', isActive: (v) => v !== undefined },
  { key: 'upload', detail: 'Cloud upload', isActive: (v) => !!v },
  { key: 'report', detail: 'Compliance reports', isActive: (v) => v !== undefined },
  { key: 'adaptive', detail: 'Adaptive red teaming', isActive: (v) => !!v },
];

/**
 * Surfaces a `gated-flag-used` CTA for each active gated flag — but ONLY on
 * the human-output path. Callers MUST compute `machineOutput` from their own
 * --json/--sarif/--output/--quiet options before calling this; there is no
 * safe default here.
 *
 * Mirrors prior behavior: one call per active flag (maybeShowCta's
 * per-process latch means only the first one actually prints).
 */
export function nudgeGatedFlags(flags: GatedFlags, opts: NudgeGatedFlagsOpts): void {
  if (opts.machineOutput) return;

  const showCta = opts.showCta ?? maybeShowCta;
  for (const { key, detail, isActive } of GATED_FLAG_DETAILS) {
    if (isActive(flags[key])) {
      showCta('gated-flag-used', { detail, configCta: opts.configCta });
    }
  }
}
