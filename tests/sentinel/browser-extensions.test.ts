import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  scanBrowserExtensions,
  isAIExtension,
  scorePermissions,
} from '../../src/sentinel/browser-extensions.js';

// Plant a Chromium extension manifest at
//   <home>/<base>/<profile>/Extensions/<id>/<version>/manifest.json
function plantChromeExtension(
  home: string,
  id: string,
  version: string,
  manifest: Record<string, unknown>,
): void {
  const dir = path.join(
    home,
    'Library/Application Support/Google/Chrome',
    'Default',
    'Extensions',
    id,
    version,
  );
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify(manifest));
}

describe('sentinel browser-extensions', () => {
  let home: string;
  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-bext-'));
  });
  afterEach(() => fs.rmSync(home, { recursive: true, force: true }));

  it('enumerates a Chrome AI extension and a benign one with merged perms + risk', () => {
    // AI extension: name "ChatGPT Sidebar", tabs + <all_urls>
    plantChromeExtension(home, 'a'.repeat(32), '1.4.0_0', {
      name: 'ChatGPT Sidebar',
      permissions: ['tabs', 'storage'],
      host_permissions: ['<all_urls>'],
    });
    // Benign extension: uBlock Origin, storage only
    plantChromeExtension(home, 'b'.repeat(32), '1.0.0_0', {
      name: 'uBlock Origin',
      permissions: ['storage'],
    });

    const exts = scanBrowserExtensions(home);
    expect(exts).toHaveLength(2);

    const ai = exts.find((e) => e.name === 'ChatGPT Sidebar');
    const benign = exts.find((e) => e.name === 'uBlock Origin');
    expect(ai).toBeDefined();
    expect(benign).toBeDefined();
    if (!ai || !benign) return;

    // AI flagged; benign not
    expect(ai.isAI).toBe(true);
    expect(benign.isAI).toBe(false);

    // Merged permissions (permissions + host_permissions), deduped
    expect(ai.permissions).toContain('tabs');
    expect(ai.permissions).toContain('storage');
    expect(ai.permissions).toContain('<all_urls>');
    expect(benign.permissions).toEqual(['storage']);

    // Risk: AI (tabs + <all_urls>) strictly higher than benign (storage)
    expect(ai.riskScore).toBeGreaterThan(benign.riskScore);
    expect(ai.riskScore).toBeLessThanOrEqual(100);
    expect(benign.riskScore).toBeGreaterThanOrEqual(0);

    // Browser + id carried through
    expect(ai.browser).toBe('Chrome');
    expect(ai.id).toHaveLength(32);
  });

  it('picks the newest version subdir', () => {
    const id = 'c'.repeat(32);
    plantChromeExtension(home, id, '1.0.0_0', { name: 'Old', permissions: ['storage'] });
    plantChromeExtension(home, id, '1.10.0_0', { name: 'New', permissions: ['tabs'] });
    const exts = scanBrowserExtensions(home);
    expect(exts).toHaveLength(1);
    expect(exts[0].name).toBe('New');
  });

  it('returns [] for a clean/empty HOME without throwing', () => {
    expect(() => scanBrowserExtensions(home)).not.toThrow();
    expect(scanBrowserExtensions(home)).toEqual([]);
  });

  it('AI heuristic: catalog substrings and standalone "ai" token, not substrings', () => {
    expect(isAIExtension('ChatGPT Sidebar', 'x')).toBe(true);
    expect(isAIExtension('Claude for Chrome', 'x')).toBe(true);
    expect(isAIExtension('AI Assistant', 'x')).toBe(true);
    expect(isAIExtension('Grammarly', 'x')).toBe(true);
    // "ai" must not match inside other words
    expect(isAIExtension('Email Tracker', 'x')).toBe(false);
    expect(isAIExtension('Captain Screenshot', 'x')).toBe(false);
    expect(isAIExtension('uBlock Origin', 'x')).toBe(false);
  });

  it('risk score: broad host + high-risk perms outweigh a lone storage perm', () => {
    const high = scorePermissions(['<all_urls>', 'tabs', 'cookies', 'webRequest']);
    const low = scorePermissions(['storage']);
    expect(high).toBeGreaterThan(low);
    expect(high).toBeLessThanOrEqual(100);
    expect(low).toBeGreaterThanOrEqual(0);
  });
});
