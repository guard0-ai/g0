/**
 * g0 v2 Daemon Runner — focused on OpenClaw/MCP monitoring.
 */
import { loadDaemonConfig, type DaemonConfig } from './config.js';
import { DaemonLogger } from './logger.js';
import { removePid } from './process.js';
import { getMachineId } from '../platform/machine-id.js';
import { detectCognitiveDrift, loadCognitiveBaseline } from './openclaw-drift.js';
import { detectRunningAgents, getAgentSummary, type AgentWatchResult } from './agent-watchers/index.js';
import { buildWatchPaths, runTargetedCheck, startWatchers, type WatchDelta } from './watch.js';
import { notifyOS } from './os-notify.js';
import { appendJsonlLine } from '../enforcement/audit.js';
import { applyQuarantine } from '../endpoint/quarantine.js';
import { applyEstateQuarantine } from '../endpoint/estate-quarantine.js';
import * as os from 'node:os';
import * as path from 'node:path';

export interface DeltaDeps {
  notify: (title: string, body: string) => void;
  quarantineServers: () => unknown;
  quarantineEstate: (delta: WatchDelta) => unknown;
  log: (message: string) => void;
  audit: (record: Record<string, unknown>) => void;
}

/**
 * React to a watch delta: notify once per new finding (observe), and when
 * `enforce` is on, auto-quarantine known-malicious servers + flagged-critical
 * estate components. Never throws.
 */
export function handleDelta(delta: WatchDelta, enforce: boolean, deps: DeltaDeps): void {
  try {
    for (const component of delta.newCriticalComponents) {
      deps.log(`watch: critical ${component.kind} "${component.name}" (${component.findings[0]?.rule})`);
      deps.notify('g0: critical Claude component', `${component.kind} "${component.name}" — ${component.findings[0]?.rule ?? 'flagged'}`);
      deps.audit({ ts: new Date().toISOString(), kind: 'estate-critical', component: component.name, path: component.path });
    }
    for (const server of delta.newMaliciousServers) {
      deps.log(`watch: known-malicious MCP server "${server.serverName}" (${server.client})`);
      deps.notify('g0: known-malicious MCP server', `"${server.serverName}" in ${server.client}`);
      deps.audit({ ts: new Date().toISOString(), kind: 'malicious-server', server: server.serverName, client: server.client });
    }
    if (delta.hookErrorSpike) {
      deps.notify('g0: hook error spike', `${delta.hookErrorSpike.errors}/${delta.hookErrorSpike.total} recent hook invocations errored — possible bypass attempt`);
      deps.audit({ ts: new Date().toISOString(), kind: 'hook-error-spike', ...delta.hookErrorSpike });
    }
    if (enforce && (delta.newMaliciousServers.length > 0 || delta.newCriticalComponents.length > 0)) {
      if (delta.newMaliciousServers.length > 0) deps.quarantineServers();
      if (delta.newCriticalComponents.length > 0) deps.quarantineEstate(delta);
      deps.notify('g0: auto-quarantine applied', 'known-malicious findings were quarantined — undo: g0 protect off / g0 endpoint quarantine --undo');
    }
  } catch {
    // watcher reactions are best-effort
  }
}


let running = true;
let config: DaemonConfig;
let logger: DaemonLogger;

export async function startDaemon(): Promise<void> {
  config = loadDaemonConfig();
  logger = new DaemonLogger(config.logFile);

  process.on('SIGTERM', () => { logger.info('Received SIGTERM'); running = false; removePid(config.pidFile); process.exit(0); });
  process.on('SIGINT', () => { logger.info('Received SIGINT'); running = false; removePid(config.pidFile); process.exit(0); });

  if (process.send) process.send({ type: 'daemon-ready' });

  logger.info('g0 daemon starting (v2 — OpenClaw/MCP focused)');
  logger.info(`Interval: ${config.intervalMinutes} minutes`);
  logger.info(`Machine ID: ${getMachineId()}`);

  const watchAudit = path.join(process.env.G0_STATE_DIR ?? path.join(os.homedir(), '.g0'), 'watch', 'audit.jsonl');
  const deps: DeltaDeps = {
    notify: notifyOS,
    quarantineServers: () => applyQuarantine(),
    quarantineEstate: (delta) => applyEstateQuarantine({ candidates: delta.newCriticalComponents }),
    log: (message) => logger.info(message),
    audit: (record) => appendJsonlLine(watchAudit, record),
  };
  const sweep = (): void => {
    try { handleDelta(runTargetedCheck(), config.enforce, deps); }
    catch (err) { logger.error(`watch sweep failed: ${err}`); }
  };
  const stopWatchers = startWatchers(buildWatchPaths(), sweep);
  process.on('exit', stopWatchers);

  while (running) {
    try {
      const tickStart = Date.now();

      // 1. Detect running AI agents
      try {
        const agentResult: AgentWatchResult = detectRunningAgents();
        const summary = getAgentSummary(agentResult);
        logger.info(`Agents: ${summary}`);
      } catch (err) { logger.error(`Agent detection failed: ${err}`); }

      // 2. OpenClaw cognitive drift
      if (config.watchPaths?.length) {
        for (const watchPath of config.watchPaths) {
          try {
            const drift = detectCognitiveDrift(watchPath);
            if (drift.events.length > 0) {
              for (const event of drift.events) {
                logger.warn(`OpenClaw drift: ${event.type} in ${event.file} — ${event.detail}`);
              }
            }
          } catch (err) { logger.error(`Cognitive drift check failed for ${watchPath}: ${err}`); }
        }
      }

      sweep();

      logger.info(`Tick complete in ${Date.now() - tickStart}ms`);
      await sleep(config.intervalMinutes * 60_000);
    } catch (err) {
      logger.error(`Tick error: ${err}`);
      await sleep(60_000);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => { const timer = setTimeout(resolve, ms); if (timer.unref) timer.unref(); });
}

// Run if this is the daemon process
if (process.env.G0_DAEMON === '1') {
  process.on('uncaughtException', (err) => {
    console.error('Daemon uncaught exception:', err);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('Daemon unhandled rejection:', reason);
    process.exit(1);
  });

  startDaemon().catch(err => {
    console.error('Daemon fatal error:', err);
    process.exit(1);
  });
}

export { startDaemon as runDaemon };
