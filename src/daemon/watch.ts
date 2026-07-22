/**
 * Watch core for the resident daemon (spec §8): which paths to watch, a
 * debounced fs.watch fan-in, and a targeted re-check that reports only what
 * is NEW since the last check (state snapshot on disk), so each finding
 * notifies exactly once. Point-in-time coverage becomes a state.
 *
 * Never-throw discipline throughout: a watcher that cannot attach or a
 * corrupt state file degrades to the periodic sweep, never to a crash.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanClaudeEstate } from '../endpoint/claude-estate-scanner.js';
import type { ClaudeEstateComponent } from '../endpoint/claude-estate-scanner.js';
import { planQuarantine } from '../endpoint/quarantine.js';
import type { QuarantineCandidate } from '../endpoint/quarantine.js';
import { resolveClientPaths } from '../mcp/well-known-paths.js';
import { hookConfigDir } from '../protect/hooks/paths.js';

export interface WatchDelta {
  newCriticalComponents: ClaudeEstateComponent[];
  newMaliciousServers: QuarantineCandidate[];
  hookErrorSpike?: { errors: number; total: number };
}

/** Existing paths worth watching: MCP client configs + the Claude estate. */
export function buildWatchPaths(homeDir?: string): string[] {
  const home = homeDir ?? os.homedir();
  const paths = new Set<string>();
  try {
    for (const client of resolveClientPaths()) paths.add(path.dirname(client.configPath));
  } catch { /* discovery is best-effort */ }
  for (const p of [
    path.join(home, '.claude', 'settings.json'),
    path.join(home, '.claude', 'settings.local.json'),
    path.join(home, '.claude', 'skills'),
    path.join(home, '.claude', 'plugins'),
    path.join(home, '.claude', 'agents'),
    path.join(home, '.openclaw', 'skills'),
  ]) {
    paths.add(p);
  }
  return [...paths].filter((p) => {
    try { return fs.existsSync(p); } catch { return false; }
  });
}

interface WatchState {
  v: 1;
  seenComponents: string[]; // `${path}|${sorted finding rules}`
  seenServers: string[];    // `${client}/${serverName}`
  hookSpikeNotified: boolean;
}

function componentKey(component: ClaudeEstateComponent): string {
  return `${component.path}|${component.findings.map((f) => f.rule).sort().join(',')}`;
}

function loadState(stateFile: string): WatchState {
  try {
    const parsed = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as WatchState;
    if (parsed?.v === 1) return { ...parsed, hookSpikeNotified: parsed.hookSpikeNotified ?? false };
  } catch { /* fresh */ }
  return { v: 1, seenComponents: [], seenServers: [], hookSpikeNotified: false };
}

function hookErrorStats(configDir: string): { errors: number; total: number } {
  try {
    const lines = fs.readFileSync(path.join(configDir, 'audit.jsonl'), 'utf8').trim().split('\n').slice(-100);
    let errors = 0; let total = 0;
    for (const line of lines) {
      try {
        const record = JSON.parse(line) as { action?: string };
        total++;
        if (record.action === 'error') errors++;
      } catch { /* skip */ }
    }
    return { errors, total };
  } catch {
    return { errors: 0, total: 0 };
  }
}

export function runTargetedCheck(opts?: { homeDir?: string; stateFile?: string; hookConfigDir?: string }): WatchDelta {
  const stateFile = opts?.stateFile ?? path.join(process.env.G0_STATE_DIR ?? path.join(os.homedir(), '.g0'), 'watch', 'state.json');
  const state = loadState(stateFile);

  const estate = scanClaudeEstate({ homeDir: opts?.homeDir });
  const criticals = estate.components.filter((c) => c.findings.some((f) => f.severity === 'critical'));
  const newCriticalComponents = criticals.filter((c) => !state.seenComponents.includes(componentKey(c)));

  let newMaliciousServers: QuarantineCandidate[] = [];
  try {
    const candidates = planQuarantine().candidates;
    newMaliciousServers = candidates.filter((c) => !state.seenServers.includes(`${c.client}/${c.serverName}`));
    state.seenServers = candidates.map((c) => `${c.client}/${c.serverName}`);
  } catch { /* quarantine planning is best-effort */ }

  const stats = hookErrorStats(hookConfigDir(opts?.hookConfigDir));
  const spiking = stats.total >= 5 && stats.errors / Math.max(1, stats.total) > 0.2 && stats.errors >= 5;
  const hookErrorSpike = spiking && !state.hookSpikeNotified ? stats : undefined;

  state.seenComponents = criticals.map(componentKey);
  state.hookSpikeNotified = spiking;
  try {
    fs.mkdirSync(path.dirname(stateFile), { recursive: true, mode: 0o700 });
    fs.writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
  } catch { /* state loss = re-notify next time, acceptable */ }

  return { newCriticalComponents, newMaliciousServers, hookErrorSpike };
}

/** Trailing-edge debounce: a burst of trigger() calls collapses to one fn() call. */
export function makeDebounced(fn: () => void, debounceMs: number): { trigger: () => void; cancel: () => void } {
  let timer: NodeJS.Timeout | undefined;
  return {
    trigger(): void {
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        timer = undefined;
        try { fn(); } catch { /* handler errors never kill watchers */ }
      }, debounceMs);
      timer.unref?.();
    },
    cancel(): void {
      if (timer) clearTimeout(timer);
      timer = undefined;
    },
  };
}

/** Attach fs.watch to each path with one shared debounce. Returns stop(). */
export function startWatchers(
  paths: string[],
  onChange: () => void,
  opts?: { debounceMs?: number },
): () => void {
  const watchers: fs.FSWatcher[] = [];
  const { trigger, cancel } = makeDebounced(onChange, opts?.debounceMs ?? 2000);
  for (const watchPath of paths) {
    try {
      watchers.push(fs.watch(watchPath, { recursive: true }, trigger));
    } catch {
      try { watchers.push(fs.watch(watchPath, trigger)); } catch { /* skip unwatchable */ }
    }
  }
  return () => {
    cancel();
    for (const watcher of watchers) {
      try { watcher.close(); } catch { /* already closed */ }
    }
  };
}
