/**
 * g0 v2 Daemon Runner — focused on OpenClaw/MCP monitoring.
 */
import { loadDaemonConfig, type DaemonConfig } from './config.js';
import { DaemonLogger } from './logger.js';
import { removePid } from './process.js';
import { getMachineId } from '../platform/machine-id.js';
import { detectCognitiveDrift, loadCognitiveBaseline } from './openclaw-drift.js';
import { detectRunningAgents, getAgentSummary, type AgentWatchResult } from './agent-watchers/index.js';

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
