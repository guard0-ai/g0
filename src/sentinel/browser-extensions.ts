// Browser-extension inventory + permission-risk engine.
//
// Enumerate installed extensions across Chrome / Edge / Brave (Chromium) and
// Firefox from LOCAL on-disk artifacts only, read their declared permissions,
// flag AI-related ones against a small catalog/heuristic, and score how much a
// given permission set can reach (CRXcavator / crx-analyzer-style weighting).
//
// Everything is best-effort and defensive: a missing profile, a locked file, or
// a malformed manifest never throws — we return whatever was successfully read.

import * as fs from 'node:fs';
import * as path from 'node:path';

export interface BrowserExtension {
  browser: string;          // 'Chrome' | 'Edge' | 'Brave' | 'Firefox'
  id: string;               // extension id (32-char for Chromium; addon id for Firefox)
  name: string;             // best-effort display name; fall back to id
  permissions: string[];    // manifest 'permissions' + 'host_permissions' merged, deduped
  isAI: boolean;            // matches the AI-extension heuristic
  riskScore: number;        // 0-100 from permission risk
}

// ─── Chromium extension locations ───────────────────────────────────────────
//
// `bases` are HOME-relative "user data" roots whose direct children are profile
// directories (Default, Profile 1, ...), each of which may contain an
// `Extensions/<id>/<version>/manifest.json` tree. We probe every OS layout so a
// sandbox HOME is testable regardless of the host platform.
interface ChromiumBrowserDef {
  name: string;
  bases: string[];
}

const CHROMIUM_BROWSERS: ChromiumBrowserDef[] = [
  {
    name: 'Chrome',
    bases: [
      'Library/Application Support/Google/Chrome',      // macOS
      '.config/google-chrome',                          // Linux
      'AppData/Local/Google/Chrome/User Data',          // Windows
    ],
  },
  {
    name: 'Edge',
    bases: [
      'Library/Application Support/Microsoft Edge',      // macOS
      '.config/microsoft-edge',                          // Linux
      'AppData/Local/Microsoft/Edge/User Data',          // Windows
    ],
  },
  {
    name: 'Brave',
    bases: [
      'Library/Application Support/BraveSoftware/Brave-Browser',   // macOS
      '.config/BraveSoftware/Brave-Browser',                       // Linux
      'AppData/Local/BraveSoftware/Brave-Browser/User Data',       // Windows
    ],
  },
];

// Firefox keeps a per-profile `extensions.json`; profiles live one level below.
const FIREFOX_BASES: string[] = [
  'Library/Application Support/Firefox/Profiles',  // macOS
  '.mozilla/firefox',                              // Linux
  'AppData/Roaming/Mozilla/Firefox/Profiles',      // Windows
];

// ─── AI-extension catalog / heuristic ───────────────────────────────────────
//
// Case-insensitive substrings matched against an extension's name (and id).
// Clearly listed so it is trivial to extend as new AI tools ship.
const AI_NAME_CATALOG: string[] = [
  'chatgpt',
  'openai',
  'claude',
  'anthropic',
  'copilot',
  'gemini',
  'bard',
  'perplexity',
  'monica',
  'sider',
  'merlin',
  'jasper',
  'writesonic',
  'grammarly',   // AI writing assistant
  'notion ai',
  'poe',
  'you.com',
  'phind',
];

// A name is also treated as AI if it contains the standalone word "ai"
// (e.g. "AI Assistant", "AI-powered") — the \b boundaries keep it from matching
// substrings inside other words like "email", "captain", or "aid".
const AI_TOKEN = /\bai\b/i;

/** True when an extension's name or id looks like an AI tool. */
export function isAIExtension(name: string, id: string): boolean {
  const hay = `${name} ${id}`.toLowerCase();
  if (AI_NAME_CATALOG.some((needle) => hay.includes(needle))) return true;
  return AI_TOKEN.test(name);
}

// ─── Permission risk weighting ──────────────────────────────────────────────
//
// CRXcavator / crx-analyzer-style tiers. Weights: CRITICAL=10, HIGH=7,
// MEDIUM=4, LOW=1. Anything unlisted contributes 0 (treated as negligible).
const CRITICAL = 10;
const HIGH = 7;
const MEDIUM = 4;
const LOW = 1;

const PERMISSION_WEIGHTS: Record<string, number> = {
  // CRITICAL — full page access, code injection into other pages, native reach
  '<all_urls>': CRITICAL,
  '*://*/*': CRITICAL,
  'http://*/*': CRITICAL,
  'https://*/*': CRITICAL,
  debugger: CRITICAL,
  nativeMessaging: CRITICAL,
  proxy: CRITICAL,
  management: CRITICAL,
  // HIGH — reads/modifies sensitive data or network traffic broadly
  tabs: HIGH,
  cookies: HIGH,
  webRequest: HIGH,
  webRequestBlocking: HIGH,
  history: HIGH,
  clipboardRead: HIGH,
  contentSettings: HIGH,
  downloads: HIGH,
  // MEDIUM — meaningful but narrower reach
  bookmarks: MEDIUM,
  webNavigation: MEDIUM,
  privacy: MEDIUM,
  geolocation: MEDIUM,
  clipboardWrite: MEDIUM,
  declarativeNetRequest: MEDIUM,
  scripting: MEDIUM,
  // LOW — commonplace, low sensitivity
  storage: LOW,
  activeTab: LOW,
  alarms: LOW,
  notifications: LOW,
  contextMenus: LOW,
};

// Multiplier applied to the summed permission weight before clamping to 0-100,
// so realistic high-risk combinations saturate toward the top of the range
// while a single benign permission stays low.
const RISK_SCALE = 3;

/** Weight of a single permission or host-permission pattern. */
export function weightForPermission(perm: string): number {
  const named = PERMISSION_WEIGHTS[perm];
  if (named !== undefined) return named;
  // Host-permission patterns not covered by the named table:
  //   broad wildcard hosts -> critical; a specific host -> low.
  if (perm === '<all_urls>' || /^\*:\/\//.test(perm)) return CRITICAL;
  if (/:\/\/\*\//.test(perm) || /:\/\/\*$/.test(perm)) return CRITICAL; // e.g. https://*/*
  if (perm.includes('://')) return LOW; // e.g. https://mail.google.com/*
  return 0;
}

/** Sum permission weights and normalize/clamp to a 0-100 risk score. */
export function scorePermissions(permissions: string[]): number {
  let sum = 0;
  for (const perm of permissions) sum += weightForPermission(perm);
  return Math.max(0, Math.min(100, Math.round(sum * RISK_SCALE)));
}

// ─── Defensive filesystem helpers ───────────────────────────────────────────

const MAX_EXTENSIONS = 2000; // hard cap so a pathological tree can't run away

function safeReaddir(p: string): fs.Dirent[] {
  try {
    return fs.readdirSync(p, { withFileTypes: true });
  } catch {
    return [];
  }
}

function safeReadJson(p: string): unknown {
  try {
    return JSON.parse(fs.readFileSync(p, 'utf-8'));
  } catch {
    return null;
  }
}

/** Compare two Chromium version dir names ("1.2.3_0") — newest first. */
function compareVersionDesc(a: string, b: string): number {
  const parse = (s: string) => s.split('_')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const av = parse(a);
  const bv = parse(b);
  const len = Math.max(av.length, bv.length);
  for (let i = 0; i < len; i++) {
    const d = (bv[i] ?? 0) - (av[i] ?? 0);
    if (d !== 0) return d;
  }
  return b.localeCompare(a);
}

/** Merge + dedupe manifest `permissions` and `host_permissions` (strings only). */
function mergePermissions(manifest: Record<string, unknown>): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const key of ['permissions', 'host_permissions']) {
    const arr = manifest[key];
    if (!Array.isArray(arr)) continue;
    for (const v of arr) {
      if (typeof v !== 'string') continue; // some entries are objects; skip
      if (seen.has(v)) continue;
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

/** Resolve a best-effort display name; fall back to id for __MSG_*__ / missing. */
function resolveName(manifest: Record<string, unknown>, id: string): string {
  const raw = manifest['name'];
  if (typeof raw !== 'string' || raw.length === 0) return id;
  if (raw.startsWith('__MSG_')) return id; // localized placeholder — fall back to id
  return raw;
}

// ─── Chromium enumeration ───────────────────────────────────────────────────

function scanChromiumExtensions(home: string, out: BrowserExtension[]): void {
  for (const browser of CHROMIUM_BROWSERS) {
    const seen = new Set<string>(); // dedupe same id across this browser's profiles
    for (const base of browser.bases) {
      const baseDir = path.join(home, base);
      // Direct children of the user-data root are profile dirs (Default, ...).
      for (const profile of safeReaddir(baseDir)) {
        if (!profile.isDirectory()) continue;
        const extRoot = path.join(baseDir, profile.name, 'Extensions');
        for (const ext of safeReaddir(extRoot)) {
          if (!ext.isDirectory()) continue;
          if (out.length >= MAX_EXTENSIONS) return;
          const id = ext.name;
          if (seen.has(id)) continue;
          const record = readChromiumExtension(browser.name, id, path.join(extRoot, id));
          if (record) {
            seen.add(id);
            out.push(record);
          }
        }
      }
    }
  }
}

function readChromiumExtension(
  browser: string,
  id: string,
  extDir: string,
): BrowserExtension | null {
  // Version subdirs — try newest first until one yields a readable manifest.
  const versions = safeReaddir(extDir)
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort(compareVersionDesc);

  for (const version of versions) {
    const manifest = safeReadJson(path.join(extDir, version, 'manifest.json'));
    if (!manifest || typeof manifest !== 'object') continue;
    const m = manifest as Record<string, unknown>;
    const name = resolveName(m, id);
    const permissions = mergePermissions(m);
    return {
      browser,
      id,
      name,
      permissions,
      isAI: isAIExtension(name, id),
      riskScore: scorePermissions(permissions),
    };
  }
  return null;
}

// ─── Firefox enumeration ────────────────────────────────────────────────────
//
// Best-effort parse of each profile's `extensions.json`. Shape (Firefox 57+):
//   { addons: [ { id, type, defaultLocale: { name }, userPermissions: {
//       permissions: string[], origins: string[] } }, ... ] }
// We keep only user-installed extensions (skip themes, langpacks, dictionaries,
// and built-ins). userPermissions may be null for older/legacy add-ons.
function scanFirefoxExtensions(home: string, out: BrowserExtension[]): void {
  const seen = new Set<string>();
  for (const base of FIREFOX_BASES) {
    const baseDir = path.join(home, base);
    for (const profile of safeReaddir(baseDir)) {
      if (!profile.isDirectory()) continue;
      const data = safeReadJson(path.join(baseDir, profile.name, 'extensions.json'));
      if (!data || typeof data !== 'object') continue;
      const addons = (data as Record<string, unknown>)['addons'];
      if (!Array.isArray(addons)) continue;

      for (const addon of addons) {
        if (out.length >= MAX_EXTENSIONS) return;
        if (!addon || typeof addon !== 'object') continue;
        const a = addon as Record<string, unknown>;

        const type = typeof a['type'] === 'string' ? (a['type'] as string) : 'extension';
        if (type !== 'extension') continue; // skip themes / langpacks / dictionaries

        const location = typeof a['location'] === 'string' ? (a['location'] as string) : '';
        if (location.startsWith('app-builtin') || location.startsWith('app-system')) continue;

        const id = typeof a['id'] === 'string' ? (a['id'] as string) : '';
        if (!id || seen.has(id)) continue;

        const name = firefoxName(a, id);
        const permissions = firefoxPermissions(a);
        seen.add(id);
        out.push({
          browser: 'Firefox',
          id,
          name,
          permissions,
          isAI: isAIExtension(name, id),
          riskScore: scorePermissions(permissions),
        });
      }
    }
  }
}

function firefoxName(addon: Record<string, unknown>, id: string): string {
  const locale = addon['defaultLocale'];
  if (locale && typeof locale === 'object') {
    const n = (locale as Record<string, unknown>)['name'];
    if (typeof n === 'string' && n.length > 0) return n;
  }
  return id;
}

function firefoxPermissions(addon: Record<string, unknown>): string[] {
  const up = addon['userPermissions'];
  if (!up || typeof up !== 'object') return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const key of ['permissions', 'origins']) {
    const arr = (up as Record<string, unknown>)[key];
    if (!Array.isArray(arr)) continue;
    for (const v of arr) {
      if (typeof v !== 'string' || seen.has(v)) continue;
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

// ─── Public entrypoint ──────────────────────────────────────────────────────

/** Enumerate all extensions found under the given HOME (testable via sandbox). */
export function scanBrowserExtensions(home: string): BrowserExtension[] {
  const out: BrowserExtension[] = [];
  scanChromiumExtensions(home, out);
  scanFirefoxExtensions(home, out);
  return out;
}
