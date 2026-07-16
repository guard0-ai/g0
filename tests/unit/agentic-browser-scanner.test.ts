import { describe, it, expect } from 'vitest';
import type { AgenticBrowserIOContext } from '../../src/endpoint/agentic-browser-scanner.js';
import { detectAgenticBrowsers, scanRiskyExtensions } from '../../src/endpoint/agentic-browser-scanner.js';

// ─── Helper: build a mock IO context backed by an in-memory fixture tree ────

interface FixtureFS {
  files?: Record<string, string>;
  dirs?: Record<string, string[]>;
  processOutput?: string;
}

function mockIO(
  platform: NodeJS.Platform,
  fixture: FixtureFS = {},
  homedir = '/Users/test',
): AgenticBrowserIOContext {
  const files = fixture.files ?? {};
  const dirs = fixture.dirs ?? {};

  return {
    platform: () => platform,
    homedir: () => homedir,
    existsSync: (p: string) => p in files || p in dirs,
    readFileSync: (p: string) => (p in files ? files[p] : null),
    readdirSync: (p: string) => dirs[p] ?? [],
    processOutput: () => fixture.processOutput ?? '',
  };
}

// Build the Chrome-family extension fixture tree for a single manifest.
function chromeExtensionFixture(
  homedir: string,
  manifestJson: string,
  opts: { vendor?: string; profile?: string; extensionId?: string; version?: string } = {},
): FixtureFS {
  const vendor = opts.vendor ?? 'Google/Chrome';
  const profile = opts.profile ?? 'Default';
  const extensionId = opts.extensionId ?? 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const version = opts.version ?? '1.0.0';

  const baseDir = `${homedir}/Library/Application Support/${vendor}`;
  const extDir = `${baseDir}/${profile}/Extensions`;
  const extIdDir = `${extDir}/${extensionId}`;
  const versionDir = `${extIdDir}/${version}`;
  const manifestPath = `${versionDir}/manifest.json`;

  return {
    dirs: {
      [baseDir]: [profile],
      [extDir]: [extensionId],
      [extIdDir]: [version],
    },
    files: {
      [manifestPath]: manifestJson,
    },
  };
}

describe('agentic-browser-scanner', () => {
  describe('detectAgenticBrowsers', () => {
    it('detects an installed-but-not-running Atlas with an info finding', () => {
      const io = mockIO('darwin', {
        dirs: {},
        files: {},
      });
      // existsSync needs to report the app bundle path as present.
      const patched: AgenticBrowserIOContext = {
        ...io,
        existsSync: (p: string) => p === '/Applications/ChatGPT Atlas.app',
      };

      const result = detectAgenticBrowsers(patched);
      const atlas = result.browsers.find((b) => b.name === 'ChatGPT Atlas');

      expect(atlas).toBeDefined();
      expect(atlas?.installed).toBe(true);
      expect(atlas?.running).toBe(false);
      expect(atlas?.capability).toBe('full-agent');
      expect(atlas?.findings.some((f) => f.severity === 'info')).toBe(true);
      expect(atlas?.findings.some((f) => f.severity === 'high')).toBe(false);
    });

    it('detects a running Comet with an escalated finding', () => {
      const patched: AgenticBrowserIOContext = {
        platform: () => 'darwin',
        homedir: () => '/Users/test',
        existsSync: (p: string) => p === '/Applications/Comet.app',
        readFileSync: () => null,
        readdirSync: () => [],
        processOutput: () =>
          'user  1234  0.0  0.1  123456  7890 ??  S  10:00AM  0:00.10 /Applications/Comet.app/Contents/MacOS/Comet',
      };

      const result = detectAgenticBrowsers(patched);
      const comet = result.browsers.find((b) => b.name === 'Perplexity Comet');

      expect(comet).toBeDefined();
      expect(comet?.installed).toBe(true);
      expect(comet?.running).toBe(true);
      expect(comet?.findings.some((f) => f.severity === 'high')).toBe(true);
    });

    it('returns empty browsers with no throw when nothing is installed', () => {
      const io = mockIO('darwin');
      expect(() => detectAgenticBrowsers(io)).not.toThrow();

      const result = detectAgenticBrowsers(io);
      expect(result.browsers).toEqual([]);
      expect(result.riskyExtensions).toEqual([]);
      expect(result.summary).toEqual({ installed: 0, running: 0, riskyExtensions: 0, findings: 0 });
    });

    it('returns an empty result on non-macOS platforms', () => {
      const linuxIO = mockIO('linux', {
        files: { '/Applications/ChatGPT Atlas.app': 'irrelevant' },
      });
      const result = detectAgenticBrowsers(linuxIO);

      expect(result.browsers).toEqual([]);
      expect(result.riskyExtensions).toEqual([]);

      const winIO = mockIO('win32' as NodeJS.Platform);
      expect(detectAgenticBrowsers(winIO).browsers).toEqual([]);
    });
  });

  describe('scanRiskyExtensions', () => {
    it('flags a critical extension: debugger + <all_urls> + AI-sounding name', () => {
      const manifest = JSON.stringify({
        name: 'AI Autopilot',
        description: 'Automate your browsing with an AI agent.',
        permissions: ['debugger', '<all_urls>', 'tabs'],
      });
      const fixture = chromeExtensionFixture('/Users/test', manifest, { extensionId: 'riskyext01' });
      const io = mockIO('darwin', fixture);

      const results = scanRiskyExtensions(io);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe('critical');
      expect(results[0].name).toBe('AI Autopilot');
      expect(results[0].browser).toBe('Chrome');
      expect(results[0].extensionId).toBe('riskyext01');
      expect(results[0].permissions).toEqual(expect.arrayContaining(['debugger', '<all_urls>']));
      expect(results[0].aiSignals.length).toBeGreaterThan(0);
    });

    it('flags a high-severity extension: scripting + broad host + AI signal, no debugger', () => {
      const manifest = JSON.stringify({
        name: 'Copilot Web Agent',
        description: 'An AI copilot that reads and fills forms for you.',
        permissions: ['scripting', 'tabs'],
        host_permissions: ['*://*/*'],
      });
      const fixture = chromeExtensionFixture('/Users/test', manifest, { extensionId: 'riskyext02' });
      const io = mockIO('darwin', fixture);

      const results = scanRiskyExtensions(io);
      expect(results).toHaveLength(1);
      expect(results[0].severity).toBe('high');
    });

    it('does not flag a broad-host extension with no AI signal', () => {
      const manifest = JSON.stringify({
        name: 'Ad Blocker Pro',
        description: 'Blocks ads and trackers everywhere.',
        permissions: ['<all_urls>', 'webNavigation', 'debugger'],
      });
      const fixture = chromeExtensionFixture('/Users/test', manifest, { extensionId: 'benign01' });
      const io = mockIO('darwin', fixture);

      expect(scanRiskyExtensions(io)).toEqual([]);
    });

    it('does not flag an AI-named extension with no dangerous permissions', () => {
      const manifest = JSON.stringify({
        name: 'AI Notes Assistant',
        description: 'Summarizes notes using AI.',
        permissions: ['storage'],
      });
      const fixture = chromeExtensionFixture('/Users/test', manifest, { extensionId: 'benign02' });
      const io = mockIO('darwin', fixture);

      expect(scanRiskyExtensions(io)).toEqual([]);
    });

    it('skips a malformed manifest.json without throwing', () => {
      const fixture = chromeExtensionFixture('/Users/test', '{ this is not valid json', {
        extensionId: 'malformed01',
      });
      const io = mockIO('darwin', fixture);

      expect(() => scanRiskyExtensions(io)).not.toThrow();
      expect(scanRiskyExtensions(io)).toEqual([]);
    });

    it('returns an empty array on non-macOS platforms', () => {
      const manifest = JSON.stringify({
        name: 'AI Autopilot',
        permissions: ['debugger', '<all_urls>'],
      });
      const fixture = chromeExtensionFixture('/Users/test', manifest);
      const io = mockIO('linux', fixture);

      expect(scanRiskyExtensions(io)).toEqual([]);
    });

    it('does not hang when a directory tree contains an unbounded number of entries', () => {
      const manyIds = Array.from({ length: 20_000 }, (_, i) => `ext-${i}`);
      const baseDir = '/Users/test/Library/Application Support/Google/Chrome';
      const extDir = `${baseDir}/Default/Extensions`;

      const io: AgenticBrowserIOContext = {
        platform: () => 'darwin',
        homedir: () => '/Users/test',
        existsSync: (p: string) => p === baseDir || p === extDir,
        readFileSync: () => null,
        readdirSync: (p: string) => {
          if (p === baseDir) return ['Default'];
          if (p === extDir) return manyIds;
          return [];
        },
        processOutput: () => '',
      };

      const start = Date.now();
      const results = scanRiskyExtensions(io);
      expect(Date.now() - start).toBeLessThan(2000);
      expect(results).toEqual([]);
    });
  });

  describe('combined summary', () => {
    it('computes correct summary counts across browsers and extensions', () => {
      const riskyManifest = JSON.stringify({
        name: 'AI Autopilot',
        permissions: ['debugger', '<all_urls>'],
      });
      const extFixture = chromeExtensionFixture('/Users/test', riskyManifest, { extensionId: 'summary01' });

      const io: AgenticBrowserIOContext = {
        platform: () => 'darwin',
        homedir: () => '/Users/test',
        existsSync: (p: string) =>
          p === '/Applications/ChatGPT Atlas.app' ||
          p === '/Applications/Comet.app' ||
          p in (extFixture.files ?? {}) ||
          p in (extFixture.dirs ?? {}),
        readFileSync: (p: string) => (extFixture.files && p in extFixture.files ? extFixture.files[p] : null),
        readdirSync: (p: string) => (extFixture.dirs && p in extFixture.dirs ? extFixture.dirs[p] : []),
        processOutput: () =>
          'user  1  0.0  0.1  1  1 ??  S  10:00AM  0:00.10 /Applications/Comet.app/Contents/MacOS/Comet',
      };

      const result = detectAgenticBrowsers(io);

      expect(result.summary.installed).toBe(2); // Atlas + Comet
      expect(result.summary.running).toBe(1); // Comet
      expect(result.summary.riskyExtensions).toBe(1);
      expect(result.summary.findings).toBe(result.browsers.reduce((sum, b) => sum + b.findings.length, 0));
      expect(result.summary.findings).toBeGreaterThan(0);
    });
  });
});
