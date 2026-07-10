// In-memory, per-process session state for the `g0 mcp serve` MCP server.
//
// Not persisted to disk and not shared across server processes — this is
// intentionally scoped to a single running `g0 mcp serve` session so tools
// like `get_score` / `explain_finding` can reuse the last `scan_project`
// result for a given path without rescanning, and so the CTA footer only
// appears once per session rather than on every tool call.
import type { ScanResult } from '../../types/score.js';

const scanCache = new Map<string, ScanResult>();

/** Cache a scan result for `resolvedPath` (absolute path is the key). */
export function cacheScanResult(resolvedPath: string, result: ScanResult): void {
  scanCache.set(resolvedPath, result);
}

/** Returns the last cached scan result for `resolvedPath`, if any. */
export function getCachedScanResult(resolvedPath: string): ScanResult | undefined {
  return scanCache.get(resolvedPath);
}

/** Test/debug helper: clears all cached scan results. */
export function clearScanCache(): void {
  scanCache.clear();
}

// One CTA footer per server session, max.
let ctaShownThisSession = false;

export function hasCtaBeenShown(): boolean {
  return ctaShownThisSession;
}

export function markCtaShown(): void {
  ctaShownThisSession = true;
}

/** Test-only: resets all session state (scan cache + CTA latch). */
export function resetSessionForTests(): void {
  scanCache.clear();
  ctaShownThisSession = false;
}
