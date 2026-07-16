import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { execSync } from 'node:child_process';
import type {
  AgenticBrowserCapability,
  AgenticBrowserDetection,
  AgenticBrowserFinding,
  AgenticBrowserScanResult,
  RiskyExtensionDetection,
} from '../types/endpoint.js';

// ─── Injectable I/O (mirrors MDMIOContext in mdm-detect.ts) ─────────────────
//
// Every filesystem/process access goes through this interface so the scanner
// is fully testable against in-memory fixture trees with zero real FS/process
// access. All methods must degrade gracefully (never throw).

export interface AgenticBrowserIOContext {
  platform(): NodeJS.Platform;
  homedir(): string;
  existsSync(p: string): boolean;
  /** Returns file contents as utf-8, or null if missing/unreadable. */
  readFileSync(p: string): string | null;
  /** Returns child entry names, or [] if missing/unreadable. */
  readdirSync(p: string): string[];
  /** Returns `ps aux`-style process listing, or '' if unavailable. */
  processOutput(): string;
}

const defaultIO: AgenticBrowserIOContext = {
  platform: () => os.platform(),
  homedir: () => os.homedir(),

  existsSync(p: string): boolean {
    try {
      return fs.existsSync(p);
    } catch {
      return false;
    }
  },

  readFileSync(p: string): string | null {
    try {
      return fs.readFileSync(p, 'utf-8');
    } catch {
      return null;
    }
  },

  readdirSync(p: string): string[] {
    try {
      return fs.readdirSync(p);
    } catch {
      return [];
    }
  },

  processOutput(): string {
    try {
      return execSync('ps aux', { encoding: 'utf-8', timeout: 5_000, stdio: ['pipe', 'pipe', 'pipe'] });
    } catch {
      return '';
    }
  },
};

// ─── Browser registry ────────────────────────────────────────────────────────
//
// Bundle IDs below are best-effort — none of these vendors publish a stable
// bundle-id reference, and the IDs can change across releases. Treat this as
// a starting point: adding a new agentic browser is a one-object change to
// AGENTIC_BROWSER_DEFS below.

interface AssessContext {
  installed: boolean;
  running: boolean;
  appPath?: string;
  io: AgenticBrowserIOContext;
  homedir: string;
}

interface AgenticBrowserDef {
  name: string;
  /** Best-effort bundle identifiers; also matched as process-output substrings. */
  bundleIds: string[];
  /** Candidate `.app` names under /Applications and ~/Applications. */
  appNames: string[];
  /** Substrings matched against `ps aux` output to detect a running instance. */
  processPatterns: string[];
  capability: AgenticBrowserCapability;
  /** Directory names under ~/Library/Application Support that indicate profile/session data. */
  configDirs: string[];
  assess(ctx: AssessContext): AgenticBrowserFinding[];
}

type AgenticBrowserDefBase = Omit<AgenticBrowserDef, 'assess'>;

const AGENTIC_BROWSER_BASES: AgenticBrowserDefBase[] = [
  {
    // Best-effort — OpenAI has not published a stable bundle ID; extend/adjust as observed.
    name: 'ChatGPT Atlas',
    bundleIds: ['com.openai.atlas', 'com.openai.atlas-browser'],
    appNames: ['ChatGPT Atlas', 'Atlas'],
    processPatterns: ['ChatGPT Atlas.app', 'ChatGPT Atlas Helper'],
    capability: 'full-agent',
    configDirs: ['ChatGPT Atlas', 'Atlas'],
  },
  {
    // Best-effort — Perplexity has used both `ai.perplexity.*` and `com.perplexity.*`.
    name: 'Perplexity Comet',
    bundleIds: ['ai.perplexity.comet', 'com.perplexity.comet'],
    appNames: ['Comet'],
    processPatterns: ['Comet.app', 'Comet Helper'],
    capability: 'full-agent',
    configDirs: ['Comet'],
  },
  {
    // Made by The Browser Company (also makers of Arc).
    name: 'Dia',
    bundleIds: ['company.thebrowser.dia'],
    appNames: ['Dia'],
    processPatterns: ['Dia.app', 'Dia Helper'],
    capability: 'agent-mode',
    configDirs: ['Dia'],
  },
  {
    name: 'Arc',
    bundleIds: ['company.thebrowser.Browser'],
    appNames: ['Arc'],
    processPatterns: ['Arc.app', 'Arc Helper'],
    capability: 'ai-assistant',
    configDirs: ['Arc'],
  },
];

function sessionDataFindings(def: AgenticBrowserDefBase, ctx: AssessContext): AgenticBrowserFinding[] {
  const found = def.configDirs.filter((dir) =>
    ctx.io.existsSync(path.join(ctx.homedir, 'Library', 'Application Support', dir)),
  );
  if (found.length === 0) return [];

  return [
    {
      severity: ctx.running ? 'medium' : 'low',
      title: `${def.name} profile/session data present`,
      detail: `Found local profile data for ${def.name} (${found.join(', ')}), suggesting an active or previously active browser session that may retain logged-in credentials.`,
      remediation: `Review and, if unused, clear ${def.name}'s stored profile/session data.`,
    },
  ];
}

function capabilityFindings(def: AgenticBrowserDefBase, ctx: AssessContext): AgenticBrowserFinding[] {
  if (def.capability === 'full-agent') {
    if (ctx.running) {
      return [
        {
          severity: 'high',
          title: `${def.name} is running with autonomous agent capability`,
          detail: `${def.name} can navigate, click, and submit forms on the web autonomously while using the signed-in user's session cookies. A running instance with an active session is a high-value target for prompt-injection-driven data exfiltration.`,
          remediation: `Restrict ${def.name}'s agent/autopilot mode to trusted sites; avoid leaving it signed into sensitive accounts while agent mode is enabled.`,
        },
      ];
    }
    return [
      {
        severity: 'info',
        title: `${def.name} installed — can autonomously act on logged-in sessions`,
        detail: `${def.name} is installed and includes an autonomous "agent" mode capable of navigating and acting on the web using the user's logged-in sessions.`,
        remediation: `Confirm ${def.name}'s agent mode is disabled or scoped to trusted sites before use.`,
      },
    ];
  }

  if (def.capability === 'agent-mode') {
    return [
      {
        severity: ctx.running ? 'medium' : 'info',
        title: `${def.name} installed with agent-mode features`,
        detail: `${def.name} ships agent-mode capabilities that can act on the user's behalf within the browser.`,
      },
    ];
  }

  // ai-assistant
  return [
    {
      severity: 'info',
      title: `${def.name} installed with AI-assistant features`,
      detail: `${def.name} includes AI-assistant features that can read and summarize the page content the user is browsing.`,
    },
  ];
}

function defaultAssess(def: AgenticBrowserDefBase, ctx: AssessContext): AgenticBrowserFinding[] {
  if (!ctx.installed) return [];
  return [...capabilityFindings(def, ctx), ...sessionDataFindings(def, ctx)];
}

const AGENTIC_BROWSER_DEFS: AgenticBrowserDef[] = AGENTIC_BROWSER_BASES.map((def) => ({
  ...def,
  assess: (ctx: AssessContext) => defaultAssess(def, ctx),
}));

// ─── Installed / running detection ──────────────────────────────────────────

function getAppVersion(io: AgenticBrowserIOContext, appPath: string): string | undefined {
  const infoPlistPath = path.join(appPath, 'Contents', 'Info.plist');
  if (!io.existsSync(infoPlistPath)) return undefined;
  const content = io.readFileSync(infoPlistPath);
  if (!content) return undefined;
  // Best-effort text match; compiled/binary plists won't match and version is
  // simply omitted (never throws).
  const match = content.match(/<key>CFBundleShortVersionString<\/key>\s*<string>([^<]*)<\/string>/);
  return match ? match[1] : undefined;
}

function findInstalled(
  io: AgenticBrowserIOContext,
  homedir: string,
  def: AgenticBrowserDefBase,
): { installed: boolean; appPath?: string; version?: string } {
  const candidates: string[] = [];
  for (const appName of def.appNames) {
    candidates.push(path.join('/Applications', `${appName}.app`));
    candidates.push(path.join(homedir, 'Applications', `${appName}.app`));
  }

  for (const candidate of candidates) {
    if (io.existsSync(candidate)) {
      return { installed: true, appPath: candidate, version: getAppVersion(io, candidate) };
    }
  }

  return { installed: false };
}

function isRunning(processOutput: string, def: AgenticBrowserDefBase): boolean {
  if (!processOutput) return false;
  const patterns = [...def.processPatterns, ...def.bundleIds];
  return patterns.some((pattern) => processOutput.includes(pattern));
}

function emptyResult(): AgenticBrowserScanResult {
  return {
    browsers: [],
    riskyExtensions: [],
    summary: { installed: 0, running: 0, riskyExtensions: 0, findings: 0 },
  };
}

// ─── Public API: detectAgenticBrowsers ──────────────────────────────────────

export function detectAgenticBrowsers(io: AgenticBrowserIOContext = defaultIO): AgenticBrowserScanResult {
  try {
    let platform: NodeJS.Platform;
    try {
      platform = io.platform();
    } catch {
      return emptyResult();
    }

    // macOS-first: these browsers ship on macOS today. Empty result elsewhere.
    if (platform !== 'darwin') {
      return emptyResult();
    }

    let homedir: string;
    try {
      homedir = io.homedir();
    } catch {
      return emptyResult();
    }

    let processOutput = '';
    try {
      processOutput = io.processOutput() || '';
    } catch {
      processOutput = '';
    }

    const browsers: AgenticBrowserDetection[] = [];

    for (const def of AGENTIC_BROWSER_DEFS) {
      try {
        const { installed, appPath, version } = findInstalled(io, homedir, def);
        const running = isRunning(processOutput, def);

        if (!installed && !running) continue;

        const findings = def.assess({ installed, running, appPath, io, homedir });

        browsers.push({
          name: def.name,
          installed,
          running,
          capability: def.capability,
          ...(appPath ? { appPath } : {}),
          ...(version ? { version } : {}),
          findings,
        });
      } catch {
        // Skip this browser on unexpected error — never throw.
        continue;
      }
    }

    let riskyExtensions: RiskyExtensionDetection[] = [];
    try {
      riskyExtensions = scanRiskyExtensions(io);
    } catch {
      riskyExtensions = [];
    }

    const summary = {
      installed: browsers.filter((b) => b.installed).length,
      running: browsers.filter((b) => b.running).length,
      riskyExtensions: riskyExtensions.length,
      findings: browsers.reduce((sum, b) => sum + b.findings.length, 0),
    };

    return { browsers, riskyExtensions, summary };
  } catch {
    return emptyResult();
  }
}

// ─── Chromium extension sweep ───────────────────────────────────────────────

interface ExtensionBaseDir {
  browser: string;
  /** Path segments under ~/Library/Application Support. */
  segments: string[];
}

const EXTENSION_BASE_DIRS: ExtensionBaseDir[] = [
  { browser: 'Chrome', segments: ['Google', 'Chrome'] },
  { browser: 'Chrome Beta', segments: ['Google', 'Chrome Beta'] },
  { browser: 'Chrome Canary', segments: ['Google', 'Chrome Canary'] },
  { browser: 'Edge', segments: ['Microsoft Edge'] },
  { browser: 'Brave', segments: ['BraveSoftware', 'Brave-Browser'] },
  { browser: 'Arc', segments: ['Arc', 'User Data'] },
];

const BROAD_HOST_PATTERNS: RegExp[] = [
  /^<all_urls>$/,
  /^\*:\/\/\*\/\*$/,
  /^https?:\/\/\*\/\*$/,
  /^http\*:\/\/\*\/\*$/,
];

const POWERFUL_CAPABILITIES = ['debugger', 'scripting', 'tabs', 'webNavigation', 'nativeMessaging', 'cookies'];

const AI_SIGNAL_RE = /\b(ai|agent|autopilot|copilot|assistant|gpt|claude|llm|automat)/i;

function truncate(s: string, max = 80): string {
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

interface ManifestMeta {
  browser: string;
  extensionId: string;
  path: string;
}

function assessExtensionManifest(manifest: unknown, meta: ManifestMeta): RiskyExtensionDetection | null {
  if (!manifest || typeof manifest !== 'object') return null;
  const m = manifest as Record<string, unknown>;

  const name = typeof m.name === 'string' ? m.name : '';
  const description = typeof m.description === 'string' ? m.description : '';
  const shortName = typeof m.short_name === 'string' ? m.short_name : '';

  const permissions = Array.isArray(m.permissions)
    ? m.permissions.filter((p): p is string => typeof p === 'string')
    : [];
  const hostPermissions = Array.isArray(m.host_permissions)
    ? m.host_permissions.filter((p): p is string => typeof p === 'string')
    : [];
  const allHostSources = [...permissions, ...hostPermissions];

  const matchedBroadHost = allHostSources.filter((p) => BROAD_HOST_PATTERNS.some((re) => re.test(p)));
  const matchedCapabilities = permissions.filter((p) => POWERFUL_CAPABILITIES.includes(p));

  const aiSignals: string[] = [];
  if (AI_SIGNAL_RE.test(name)) aiSignals.push(`name:"${name}"`);
  if (AI_SIGNAL_RE.test(description)) aiSignals.push(`description:"${truncate(description)}"`);
  if (shortName && AI_SIGNAL_RE.test(shortName)) aiSignals.push(`short_name:"${shortName}"`);

  // Flag only when all three signals co-occur: broad host access, a powerful
  // capability, and something that looks AI/agent-related.
  if (matchedBroadHost.length === 0 || matchedCapabilities.length === 0 || aiSignals.length === 0) {
    return null;
  }

  let severity: RiskyExtensionDetection['severity'];
  if (matchedCapabilities.includes('debugger')) {
    severity = 'critical';
  } else if (matchedCapabilities.includes('scripting') || matchedCapabilities.includes('nativeMessaging')) {
    severity = 'high';
  } else {
    severity = 'medium';
  }

  return {
    name: name || meta.extensionId,
    extensionId: meta.extensionId,
    browser: meta.browser,
    path: meta.path,
    permissions: [...new Set([...matchedCapabilities, ...matchedBroadHost])],
    aiSignals,
    severity,
  };
}

// Bounds so a pathological/huge directory tree can never hang the scan.
const MAX_PROFILES_PER_BASE = 30;
const MAX_EXTENSIONS_PER_PROFILE = 500;
const MAX_VERSIONS_PER_EXTENSION = 10;
const MAX_MANIFESTS_SCANNED = 3_000;

export function scanRiskyExtensions(io: AgenticBrowserIOContext = defaultIO): RiskyExtensionDetection[] {
  try {
    let platform: NodeJS.Platform;
    try {
      platform = io.platform();
    } catch {
      return [];
    }

    if (platform !== 'darwin') return [];

    let homedir: string;
    try {
      homedir = io.homedir();
    } catch {
      return [];
    }

    const results: RiskyExtensionDetection[] = [];
    let manifestsScanned = 0;

    for (const base of EXTENSION_BASE_DIRS) {
      if (manifestsScanned >= MAX_MANIFESTS_SCANNED) break;

      const baseDir = path.join(homedir, 'Library', 'Application Support', ...base.segments);
      let profiles: string[];
      try {
        if (!io.existsSync(baseDir)) continue;
        profiles = io.readdirSync(baseDir).slice(0, MAX_PROFILES_PER_BASE);
      } catch {
        continue;
      }

      for (const profile of profiles) {
        if (manifestsScanned >= MAX_MANIFESTS_SCANNED) break;

        const extDir = path.join(baseDir, profile, 'Extensions');
        let extensionIds: string[];
        try {
          if (!io.existsSync(extDir)) continue;
          extensionIds = io.readdirSync(extDir).slice(0, MAX_EXTENSIONS_PER_PROFILE);
        } catch {
          continue;
        }

        for (const extensionId of extensionIds) {
          if (manifestsScanned >= MAX_MANIFESTS_SCANNED) break;

          const extIdDir = path.join(extDir, extensionId);
          let versions: string[];
          try {
            versions = io.readdirSync(extIdDir).slice(0, MAX_VERSIONS_PER_EXTENSION);
          } catch {
            continue;
          }

          for (const version of versions) {
            if (manifestsScanned >= MAX_MANIFESTS_SCANNED) break;
            manifestsScanned++;

            const manifestPath = path.join(extIdDir, version, 'manifest.json');
            try {
              if (!io.existsSync(manifestPath)) continue;
              const raw = io.readFileSync(manifestPath);
              if (raw === null) continue;

              const parsed: unknown = JSON.parse(raw);
              const detection = assessExtensionManifest(parsed, {
                browser: base.browser,
                extensionId,
                path: manifestPath,
              });
              if (detection) results.push(detection);
            } catch {
              // Malformed manifest — skip, never throw.
              continue;
            }
          }
        }
      }
    }

    return results;
  } catch {
    return [];
  }
}
