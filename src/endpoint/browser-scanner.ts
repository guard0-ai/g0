import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execFileSync } from 'node:child_process';
import type { AIBrowsingEntry, BrowserScanResult } from '../types/endpoint.js';

const HOME = os.homedir();
const PLATFORM = os.platform();

// ─── AI Service URL Patterns ────────────────────────────────────────────────

interface AIServicePattern {
  service: string;
  patterns: RegExp[];
}

const AI_SERVICE_PATTERNS: AIServicePattern[] = [
  {
    service: 'chatgpt',
    patterns: [/chat\.openai\.com/, /chatgpt\.com/],
  },
  {
    service: 'claude',
    patterns: [/claude\.ai/, /console\.anthropic\.com/],
  },
  {
    service: 'gemini',
    patterns: [/gemini\.google\.com/, /aistudio\.google\.com/, /makersuite\.google\.com/],
  },
  {
    service: 'copilot',
    patterns: [/copilot\.microsoft\.com/, /github\.com\/copilot/],
  },
  {
    service: 'perplexity',
    patterns: [/perplexity\.ai/],
  },
  {
    service: 'huggingface',
    patterns: [/huggingface\.co\/chat/],
  },
  {
    service: 'poe',
    patterns: [/poe\.com/],
  },
  {
    service: 'deepseek',
    patterns: [/chat\.deepseek\.com/],
  },
  {
    service: 'mistral',
    patterns: [/chat\.mistral\.ai/],
  },
  {
    service: 'groq',
    patterns: [/groq\.com/],
  },
  {
    service: 'together',
    patterns: [/api\.together\.xyz/, /together\.ai/],
  },
  {
    service: 'replicate',
    patterns: [/replicate\.com/],
  },
];

function matchAIService(url: string): string | null {
  for (const svc of AI_SERVICE_PATTERNS) {
    if (svc.patterns.some(p => p.test(url))) return svc.service;
  }
  return null;
}

// ─── Browser History Locations ──────────────────────────────────────────────

interface BrowserDef {
  name: string;
  paths: Record<string, string[]>;
  type: 'sqlite' | 'json';
}

const BROWSERS: BrowserDef[] = [
  {
    name: 'Chrome',
    paths: {
      darwin: [
        path.join(HOME, 'Library/Application Support/Google/Chrome/Default/History'),
        path.join(HOME, 'Library/Application Support/Google/Chrome/Profile 1/History'),
      ],
      linux: [
        path.join(HOME, '.config/google-chrome/Default/History'),
        path.join(HOME, '.config/google-chrome/Profile 1/History'),
      ],
      win32: [
        path.join(HOME, 'AppData/Local/Google/Chrome/User Data/Default/History'),
        path.join(HOME, 'AppData/Local/Google/Chrome/User Data/Profile 1/History'),
      ],
    },
    type: 'sqlite',
  },
  {
    name: 'Arc',
    paths: {
      darwin: [
        path.join(HOME, 'Library/Application Support/Arc/User Data/Default/History'),
        path.join(HOME, 'Library/Application Support/Arc/User Data/Profile 1/History'),
      ],
      linux: [],
      win32: [
        path.join(HOME, 'AppData/Local/Arc/User Data/Default/History'),
      ],
    },
    type: 'sqlite',
  },
  {
    name: 'Edge',
    paths: {
      darwin: [
        path.join(HOME, 'Library/Application Support/Microsoft Edge/Default/History'),
      ],
      linux: [
        path.join(HOME, '.config/microsoft-edge/Default/History'),
      ],
      win32: [
        path.join(HOME, 'AppData/Local/Microsoft/Edge/User Data/Default/History'),
      ],
    },
    type: 'sqlite',
  },
  {
    name: 'Brave',
    paths: {
      darwin: [
        path.join(HOME, 'Library/Application Support/BraveSoftware/Brave-Browser/Default/History'),
      ],
      linux: [
        path.join(HOME, '.config/BraveSoftware/Brave-Browser/Default/History'),
      ],
      win32: [
        path.join(HOME, 'AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/History'),
      ],
    },
    type: 'sqlite',
  },
  {
    name: 'Firefox',
    paths: {
      darwin: [
        path.join(HOME, 'Library/Application Support/Firefox/Profiles'),
      ],
      linux: [
        path.join(HOME, '.mozilla/firefox'),
      ],
      win32: [
        path.join(HOME, 'AppData/Roaming/Mozilla/Firefox/Profiles'),
      ],
    },
    type: 'sqlite',
  },
];

// Safari uses a binary plist format — we'll handle it specially on macOS
const SAFARI_HISTORY = path.join(HOME, 'Library/Safari/History.db');

// ─── SQLite History Extraction ──────────────────────────────────────────────

/**
 * Extract AI-related browsing history from a Chromium-based browser's History DB.
 * We copy the DB to a temp file since browsers lock the original.
 */
function extractChromiumHistory(browserName: string, dbPath: string): AIBrowsingEntry[] {
  if (!fs.existsSync(dbPath)) return [];

  const entries: AIBrowsingEntry[] = [];
  const tmpPath = path.join(os.tmpdir(), `g0-browser-${Date.now()}.db`);

  try {
    // Copy to avoid lock conflicts with running browser
    fs.copyFileSync(dbPath, tmpPath);

    // Query: last 90 days of AI-related URLs
    const query = `
      SELECT url, title, visit_count, last_visit_time
      FROM urls
      WHERE last_visit_time > (strftime('%s', 'now', '-90 days') * 1000000 + 11644473600000000)
      ORDER BY last_visit_time DESC
      LIMIT 500;
    `;

    const output = execFileSync('sqlite3', ['-separator', '|', tmpPath, query], {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();

    if (!output) return entries;

    for (const line of output.split('\n')) {
      if (!line.trim()) continue;
      const parts = line.split('|');
      if (parts.length < 4) continue;

      const url = parts[0];
      const service = matchAIService(url);
      if (!service) continue;

      const title = parts[1] || '';
      const visitCount = parseInt(parts[2], 10) || 1;
      // Chromium stores time as microseconds since Windows epoch (1601-01-01)
      const chromiumTime = parseInt(parts[3], 10) || 0;
      const lastVisit = chromiumTimeToISO(chromiumTime);

      entries.push({
        browser: browserName,
        url,
        title,
        visitCount,
        lastVisit,
        service,
      });
    }
  } catch {
    // DB locked, sqlite3 not available, or query failed
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }

  return entries;
}

function extractFirefoxHistory(profilesDir: string): AIBrowsingEntry[] {
  if (!fs.existsSync(profilesDir)) return [];

  const entries: AIBrowsingEntry[] = [];

  try {
    const profiles = fs.readdirSync(profilesDir, { withFileTypes: true });
    for (const profile of profiles) {
      if (!profile.isDirectory()) continue;
      const placesDb = path.join(profilesDir, profile.name, 'places.sqlite');
      if (!fs.existsSync(placesDb)) continue;

      const tmpPath = path.join(os.tmpdir(), `g0-firefox-${Date.now()}.db`);
      try {
        fs.copyFileSync(placesDb, tmpPath);

        const query = `
          SELECT p.url, p.title, p.visit_count, v.visit_date
          FROM moz_places p
          JOIN moz_historyvisits v ON p.id = v.place_id
          WHERE v.visit_date > (strftime('%s', 'now', '-90 days') * 1000000)
          ORDER BY v.visit_date DESC
          LIMIT 500;
        `;

        const output = execFileSync('sqlite3', ['-separator', '|', tmpPath, query], {
          encoding: 'utf-8',
          timeout: 5000,
          stdio: ['pipe', 'pipe', 'pipe'],
        }).trim();

        if (output) {
          for (const line of output.split('\n')) {
            const parts = line.split('|');
            if (parts.length < 4) continue;

            const url = parts[0];
            const service = matchAIService(url);
            if (!service) continue;

            entries.push({
              browser: 'Firefox',
              url,
              title: parts[1] || '',
              visitCount: parseInt(parts[2], 10) || 1,
              lastVisit: firefoxTimeToISO(parseInt(parts[3], 10) || 0),
              service,
            });
          }
        }
      } catch {
        // Skip this profile
      } finally {
        try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
      }
    }
  } catch {
    // Can't read profiles dir
  }

  return entries;
}

function extractSafariHistory(): AIBrowsingEntry[] {
  if (PLATFORM !== 'darwin' || !fs.existsSync(SAFARI_HISTORY)) return [];

  const entries: AIBrowsingEntry[] = [];
  const tmpPath = path.join(os.tmpdir(), `g0-safari-${Date.now()}.db`);

  try {
    fs.copyFileSync(SAFARI_HISTORY, tmpPath);

    const query = `
      SELECT i.url, v.title, i.visit_count,
             CAST((v.visit_time + 978307200) AS INTEGER) as unix_time
      FROM history_items i
      JOIN history_visits v ON i.id = v.history_item
      WHERE v.visit_time > (strftime('%s', 'now', '-90 days') - 978307200)
      ORDER BY v.visit_time DESC
      LIMIT 500;
    `;

    const output = execFileSync('sqlite3', ['-separator', '|', tmpPath, query], {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();

    if (output) {
      for (const line of output.split('\n')) {
        const parts = line.split('|');
        if (parts.length < 4) continue;

        const url = parts[0];
        const service = matchAIService(url);
        if (!service) continue;

        const unixTime = parseInt(parts[3], 10) || 0;

        entries.push({
          browser: 'Safari',
          url,
          title: parts[1] || '',
          visitCount: parseInt(parts[2], 10) || 1,
          lastVisit: new Date(unixTime * 1000).toISOString(),
          service,
        });
      }
    }
  } catch {
    // Safari history locked or sqlite3 not available
  } finally {
    try { fs.unlinkSync(tmpPath); } catch { /* ignore */ }
  }

  return entries;
}

// ─── Time Conversions ───────────────────────────────────────────────────────

function chromiumTimeToISO(microseconds: number): string {
  // Chromium epoch: Jan 1, 1601 in microseconds
  const unixMicro = microseconds - 11644473600000000;
  return new Date(unixMicro / 1000).toISOString();
}

function firefoxTimeToISO(microseconds: number): string {
  return new Date(microseconds / 1000).toISOString();
}

// ─── Main Scanner ───────────────────────────────────────────────────────────

export function scanBrowserHistory(): BrowserScanResult {
  const allEntries: AIBrowsingEntry[] = [];
  const platform = PLATFORM as string;

  for (const browser of BROWSERS) {
    const paths = browser.paths[platform] || [];

    if (browser.name === 'Firefox') {
      // Firefox has profiles directory — handle separately
      for (const profilesDir of paths) {
        allEntries.push(...extractFirefoxHistory(profilesDir));
      }
    } else {
      // Chromium-based browsers
      for (const dbPath of paths) {
        allEntries.push(...extractChromiumHistory(browser.name, dbPath));
      }
    }
  }

  // Safari (macOS only)
  if (platform === 'darwin') {
    allEntries.push(...extractSafariHistory());
  }

  // Deduplicate by URL + browser (keep highest visit count)
  const deduped = deduplicateEntries(allEntries);

  // Build summary
  const browsers = [...new Set(deduped.map(e => e.browser))];
  const services: Record<string, number> = {};
  let oldest: string | null = null;
  let newest: string | null = null;

  for (const entry of deduped) {
    services[entry.service] = (services[entry.service] || 0) + entry.visitCount;
    if (!oldest || entry.lastVisit < oldest) oldest = entry.lastVisit;
    if (!newest || entry.lastVisit > newest) newest = entry.lastVisit;
  }

  return {
    entries: deduped,
    summary: {
      totalEntries: deduped.length,
      browsers,
      services,
      dateRange: { oldest, newest },
    },
  };
}

function deduplicateEntries(entries: AIBrowsingEntry[]): AIBrowsingEntry[] {
  const map = new Map<string, AIBrowsingEntry>();
  for (const entry of entries) {
    const key = `${entry.browser}:${entry.url}`;
    const existing = map.get(key);
    if (!existing || entry.visitCount > existing.visitCount) {
      map.set(key, entry);
    }
  }
  return [...map.values()];
}

// Exported for testing
export { AI_SERVICE_PATTERNS, BROWSERS, matchAIService, chromiumTimeToISO, firefoxTimeToISO };
