// Subtle, capped signup-funnel footer for MCP tool results.
//
// Reuses the existing `platform/cta.js` decision engine (Task 2) — the same
// suppression rules (G0_NO_CTA, .g0.yaml `cta: false`, logged-in+paid,
// frequency caps) apply here. On top of that, this module applies a
// per-server-session latch (see session.ts) so at most one MCP tool result
// per session carries a footer, even across multiple qualifying tool calls.
import type { CtaTrigger } from '../../platform/cta.js';
import { hasCtaBeenShown, markCtaShown } from './session.js';

/**
 * Appends a subtle signup CTA line to `markdown` when eligible, otherwise
 * returns `markdown` unchanged. Never throws — any failure to load the CTA
 * module (or a suppressed/null result) is a no-op.
 */
export async function appendCta(markdown: string, trigger: CtaTrigger): Promise<string> {
  if (hasCtaBeenShown()) return markdown;

  try {
    const { maybeGetCta } = await import('../../platform/cta.js');
    const line = maybeGetCta(trigger, { medium: 'mcp' });
    if (!line) return markdown;
    markCtaShown();
    return markdown + '\n\n' + line;
  } catch {
    return markdown;
  }
}
