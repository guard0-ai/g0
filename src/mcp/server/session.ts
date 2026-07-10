// In-memory, per-process session state for the `g0 mcp serve` MCP server.
//
// Not persisted to disk and not shared across server processes — this is
// intentionally scoped to a single running `g0 mcp serve` session so tools
// like `get_score` / `explain_finding` can reuse the last `scan_project`
// result for a given path without rescanning, and so the CTA footer only
// appears once per session rather than on every tool call.
import type { ScanResult } from '../../types/score.js';

// Cap on the number of distinct project paths cached per server session, so
// a long-lived `g0 mcp serve` process pointed at many different paths over
// time (or repeatedly re-scanning a churn of paths) can't grow this Map
// without bound. Small and simple by design: insertion order in a `Map` is
// preserved, so evicting the first key is an O(1) approximation of LRU that
// only kicks in once we're over the cap.
const SCAN_CACHE_MAX_ENTRIES = 20;

const scanCache = new Map<string, ScanResult>();

/** Cache a scan result for `resolvedPath` (absolute path is the key). */
export function cacheScanResult(resolvedPath: string, result: ScanResult): void {
  // Re-inserting an existing key should refresh its recency (move it to the
  // end of iteration order) rather than leaving it in its old position.
  scanCache.delete(resolvedPath);
  scanCache.set(resolvedPath, result);

  while (scanCache.size > SCAN_CACHE_MAX_ENTRIES) {
    const oldestKey = scanCache.keys().next().value;
    if (oldestKey === undefined) break;
    scanCache.delete(oldestKey);
  }
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
