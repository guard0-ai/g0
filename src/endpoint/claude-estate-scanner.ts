/**
 * Claude-native supply-chain scanner (spec §6.2): enumerates the components
 * that PROGRAM a Claude agent — skills, plugins, subagents, settings hooks,
 * Desktop extensions — and content-scans each for injected instructions,
 * known-malicious infrastructure, and shell-execution droppers.
 *
 * Report-only in this phase: findings feed `g0 check` grading (criticals cap
 * at F); file-level quarantine of flagged components arrives with the
 * watcher phase. Everything is best-effort and bounded — a scanner error
 * skips that component, never throws.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { PROMPT_INJECTION_PATTERNS, UNICODE_TRICKS } from '../enforcement/injection-patterns.js';
import { extractHosts } from '../enforcement/response-inspector.js';
import { checkAgainstIOCs } from '../intelligence/ioc-database.js';

export type ClaudeComponentKind = 'skill' | 'plugin' | 'agent' | 'hook' | 'desktop-extension';

export interface EstateFinding {
  severity: 'critical' | 'high' | 'medium' | 'low';
  rule: string;
  detail: string;
}

export interface ClaudeEstateComponent {
  kind: ClaudeComponentKind;
  name: string;
  path: string;
  findings: EstateFinding[];
}

export interface ClaudeEstateResult {
  components: ClaudeEstateComponent[];
  summary: { total: number; flagged: number; critical: number };
}

const MAX_FILES = 500;
const MAX_FILE_BYTES = 256 * 1024;

const SHELL_HEURISTICS: Array<{ pattern: RegExp; rule: string; severity: EstateFinding['severity'] }> = [
  { pattern: /curl[^|\n]{0,200}\|\s*(ba)?sh/i, rule: 'shell:curl-pipe-sh', severity: 'critical' },
  { pattern: /wget[^|\n]{0,200}\|\s*(ba)?sh/i, rule: 'shell:wget-pipe-sh', severity: 'critical' },
  { pattern: /base64\s+(-d|--decode)[^|\n]{0,100}\|\s*(ba)?sh/i, rule: 'shell:base64-pipe-sh', severity: 'critical' },
  { pattern: /\beval\s*\(\s*atob\s*\(/i, rule: 'shell:eval-atob', severity: 'high' },
];

/** Content checks shared by every component kind. Never throws. */
function scanText(text: string): EstateFinding[] {
  const findings: EstateFinding[] = [];
  try {
    for (const { pattern, rule, severity } of SHELL_HEURISTICS) {
      const match = text.match(pattern);
      if (match) findings.push({ severity, rule, detail: match[0].slice(0, 120) });
    }
    for (const { pattern, name } of PROMPT_INJECTION_PATTERNS) {
      const match = text.match(pattern);
      if (match) findings.push({ severity: 'high', rule: `injection:${name}`, detail: match[0].slice(0, 120) });
    }
    for (const { pattern, name } of UNICODE_TRICKS) {
      const match = text.match(pattern);
      if (match) findings.push({ severity: 'medium', rule: `injection:${name}`, detail: match[0].slice(0, 120) });
    }
    for (const host of extractHosts(text)) {
      for (const ioc of checkAgainstIOCs(host, 'domain')) {
        findings.push({ severity: 'critical', rule: `ioc:${ioc.indicator}`, detail: host });
      }
    }
  } catch {
    // best effort — partial findings are fine
  }
  return findings;
}

function readBounded(filePath: string): string | null {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

/** Recursively list files under dir (bounded), best effort. */
function listFiles(dir: string, budget: { remaining: number }): string[] {
  const out: string[] = [];
  try {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (budget.remaining <= 0) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) out.push(...listFiles(full, budget));
      else if (entry.isFile()) {
        out.push(full);
        budget.remaining--;
      }
    }
  } catch {
    // unreadable dir — skip
  }
  return out;
}

function scanFileComponent(kind: ClaudeComponentKind, name: string, files: string[]): ClaudeEstateComponent {
  const findings: EstateFinding[] = [];
  for (const file of files) {
    const text = readBounded(file);
    if (text !== null) findings.push(...scanText(text));
  }
  return { kind, name, path: files[0] ?? '', findings };
}

/** One component per immediate subdirectory of `root` (skills, plugins). */
function scanDirOfComponents(kind: ClaudeComponentKind, root: string, budget: { remaining: number }): ClaudeEstateComponent[] {
  const components: ClaudeEstateComponent[] = [];
  try {
    for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = path.join(root, entry.name);
      const files = listFiles(dir, budget).filter((f) => /\.(md|json|js|mjs|cjs|sh|yaml|yml|toml)$/i.test(f));
      components.push({ ...scanFileComponent(kind, entry.name, files), path: dir });
    }
  } catch {
    // missing root — none
  }
  return components;
}

function scanSettingsHooks(settingsPath: string): ClaudeEstateComponent[] {
  const components: ClaudeEstateComponent[] = [];
  const text = readBounded(settingsPath);
  if (text === null) return components;
  try {
    const settings = JSON.parse(text) as { hooks?: Record<string, Array<{ hooks?: Array<{ command?: string }> }>> };
    for (const [event, entries] of Object.entries(settings.hooks ?? {})) {
      if (!Array.isArray(entries)) continue;
      for (const entry of entries) {
        for (const hook of entry?.hooks ?? []) {
          if (typeof hook?.command !== 'string') continue;
          components.push({ kind: 'hook', name: event, path: settingsPath, findings: scanText(hook.command) });
        }
      }
    }
  } catch {
    // unparseable settings — nothing to scan
  }
  return components;
}

export function scanClaudeEstate(opts?: { homeDir?: string }): ClaudeEstateResult {
  const home = opts?.homeDir ?? os.homedir();
  const claudeDir = path.join(home, '.claude');
  const budget = { remaining: MAX_FILES };
  const components: ClaudeEstateComponent[] = [];

  try {
    components.push(...scanDirOfComponents('skill', path.join(claudeDir, 'skills'), budget));

    // Plugins: the marketplace cache nests two levels deeper
    // (plugins/cache/<marketplace>/<plugin>) — group per plugin so a REVIEW
    // badge points at the actual plugin, not one blob named "cache".
    const pluginsRoot = path.join(claudeDir, 'plugins');
    try {
      for (const entry of fs.readdirSync(pluginsRoot, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        if (entry.name === 'cache') {
          const cacheRoot = path.join(pluginsRoot, 'cache');
          for (const marketplace of fs.readdirSync(cacheRoot, { withFileTypes: true })) {
            if (!marketplace.isDirectory()) continue;
            const marketplaceRoot = path.join(cacheRoot, marketplace.name);
            for (const component of scanDirOfComponents('plugin', marketplaceRoot, budget)) {
              components.push({ ...component, name: `${marketplace.name}/${component.name}` });
            }
          }
        } else {
          const dir = path.join(pluginsRoot, entry.name);
          const files = listFiles(dir, budget).filter((f) => /\.(md|json|js|mjs|cjs|sh|yaml|yml|toml)$/i.test(f));
          components.push({ ...scanFileComponent('plugin', entry.name, files), path: dir });
        }
      }
    } catch { /* no plugins dir */ }

    // Subagents: one component per markdown file.
    try {
      for (const entry of fs.readdirSync(path.join(claudeDir, 'agents'), { withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith('.md')) {
          const full = path.join(claudeDir, 'agents', entry.name);
          components.push(scanFileComponent('agent', entry.name.replace(/\.md$/, ''), [full]));
        }
      }
    } catch { /* no agents dir */ }

    // Settings hooks: every configured hook command (user + local scope).
    components.push(...scanSettingsHooks(path.join(claudeDir, 'settings.json')));
    components.push(...scanSettingsHooks(path.join(claudeDir, 'settings.local.json')));

    // Claude Desktop extensions (macOS layout; missing dir elsewhere = none).
    components.push(...scanDirOfComponents(
      'desktop-extension',
      path.join(home, 'Library', 'Application Support', 'Claude', 'Claude Extensions'),
      budget,
    ));
  } catch {
    // estate scanning is always best-effort
  }

  const flagged = components.filter((c) => c.findings.length > 0);
  return {
    components,
    summary: {
      total: components.length,
      flagged: flagged.length,
      critical: flagged.filter((c) => c.findings.some((f) => f.severity === 'critical')).length,
    },
  };
}
