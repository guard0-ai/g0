// Offline-first entitlements cache for the guard0.ai platform.
//
// Hard rule: `getEntitlementsCached` and `hasFeature` are synchronous,
// disk-only, and never throw — they're safe to call from any scan path.
// Only `refreshEntitlements` touches the network, and it degrades to the
// existing cache (stale-forever) on any network failure rather than throwing.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { getValidAccessToken } from './auth.js';
import { fetchEntitlements } from './client.js';

const G0_DIR = path.join(os.homedir(), '.g0');

/** TTL used by callers that want to decide whether to trigger a background refresh. */
export const ENTITLEMENTS_TTL_MS = 24 * 60 * 60 * 1000;

export interface Entitlements {
  plan: string;
  features: string[];
  feedToken?: string;
  fetchedAt: string;
}

export function entitlementsFilePath(dir: string = G0_DIR): string {
  return path.join(dir, 'entitlements.json');
}

/** Sync read. Returns null on missing file, corrupt JSON, or any other error. Does not check TTL. */
export function getEntitlementsCached(dir: string = G0_DIR): Entitlements | null {
  try {
    const raw = fs.readFileSync(entitlementsFilePath(dir), 'utf-8');
    const parsed = JSON.parse(raw) as Entitlements;
    if (!parsed || !Array.isArray(parsed.features)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function saveEntitlements(entitlements: Entitlements, dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(entitlementsFilePath(dir), JSON.stringify(entitlements, null, 2), { mode: 0o600 });
}

/**
 * Async: fetches fresh entitlements from the platform and caches them.
 * Never throws. Returns null when there's no valid access token (not logged
 * in). On network failure, returns the existing cache (stale-forever offline
 * grace) rather than failing the caller.
 */
export async function refreshEntitlements(dir: string = G0_DIR): Promise<Entitlements | null> {
  try {
    const token = await getValidAccessToken(dir);
    if (!token) return null;

    const resp = await fetchEntitlements(token);
    const entitlements: Entitlements = {
      plan: resp.plan,
      features: resp.features,
      feedToken: resp.feed_token,
      fetchedAt: new Date().toISOString(),
    };
    saveEntitlements(entitlements, dir);
    return entitlements;
  } catch {
    return getEntitlementsCached(dir);
  }
}

/** Removes entitlements.json. Never throws. */
export function clearEntitlements(dir: string = G0_DIR): void {
  try {
    fs.unlinkSync(entitlementsFilePath(dir));
  } catch {
    // Already gone, or never existed — fine.
  }
}

/** Sync, disk-only, never throws. */
export function hasFeature(name: string, dir: string = G0_DIR): boolean {
  return getEntitlementsCached(dir)?.features.includes(name) ?? false;
}

/** Sync helper: true if there's no cache, or the cache is older than ENTITLEMENTS_TTL_MS. */
export function isEntitlementsStale(dir: string = G0_DIR): boolean {
  const cached = getEntitlementsCached(dir);
  if (!cached) return true;
  const age = Date.now() - new Date(cached.fetchedAt).getTime();
  return age > ENTITLEMENTS_TTL_MS;
}
