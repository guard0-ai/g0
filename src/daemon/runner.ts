import { loadDaemonConfig, type DaemonConfig } from './config.js';
import { DaemonLogger } from './logger.js';
import { removePid } from './process.js';
import { isAuthenticated } from '../platform/auth.js';
import { PlatformClient } from '../platform/client.js';
import { getMachineId } from '../platform/machine-id.js';
import { collectMachineMeta } from '../platform/upload.js';
import * as os from 'node:os';
import type { HeartbeatPayload } from '../platform/types.js';

let running = true;
let config: DaemonConfig;
let logger: DaemonLogger;
let endpointId: string | undefined;

async function main(): Promise<void> {
  config = loadDaemonConfig();
  logger = new DaemonLogger(config.logFile);

  logger.info('Daemon starting');
  logger.info(`Interval: ${config.intervalMinutes} minutes`);
  logger.info(`Machine ID: ${getMachineId()}`);

  // Handle signals for graceful shutdown
  process.on('SIGTERM', () => {
    logger.info('Received SIGTERM, shutting down');
    running = false;
    removePid(config.pidFile);
    process.exit(0);
  });

  process.on('SIGINT', () => {
    logger.info('Received SIGINT, shutting down');
    running = false;
    removePid(config.pidFile);
    process.exit(0);
  });

  // Register endpoint if authenticated
  if (config.upload && isAuthenticated()) {
    await registerEndpoint();
  }

  // Run initial tick immediately
  await tick();

  // Schedule recurring ticks
  const intervalMs = config.intervalMinutes * 60 * 1000;
  while (running) {
    await sleep(intervalMs);
    if (!running) break;
    await tick();
  }
}

async function tick(): Promise<void> {
  logger.info('Tick started');
  const startTime = Date.now();

  try {
    // 1. MCP config scan
    if (config.mcpScan) {
      await runMCPScan();
    }

    // 2. MCP pin check
    if (config.mcpPinCheck) {
      await runPinCheck();
    }

    // 3. Inventory diff on watch paths
    if (config.inventoryDiff && config.watchPaths.length > 0) {
      await runInventoryDiff();
    }

    // 4. Heartbeat
    if (config.upload && isAuthenticated() && endpointId) {
      await sendHeartbeat('healthy');
    }

    const elapsed = Date.now() - startTime;
    logger.info(`Tick completed in ${elapsed}ms`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Tick failed: ${msg}`);

    if (config.upload && isAuthenticated() && endpointId) {
      await sendHeartbeat('degraded', [msg]);
    }
  }
}

async function runMCPScan(): Promise<void> {
  try {
    const { scanAllMCPConfigs } = await import('../mcp/analyzer.js');
    const result = scanAllMCPConfigs();
    logger.info(`MCP scan: ${result.summary.totalServers} servers, ${result.summary.totalFindings} findings`);

    if (config.upload && isAuthenticated()) {
      const client = new PlatformClient();
      const meta = collectMachineMeta();
      await client.upload({
        type: 'mcp',
        machine: meta,
        result,
      });
      logger.info('MCP scan results uploaded');
    }
  } catch (err) {
    logger.error(`MCP scan failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function runPinCheck(): Promise<void> {
  try {
    const { loadPinFile, checkPins } = await import('../mcp/hash-pinning.js');
    const { scanAllMCPConfigs } = await import('../mcp/analyzer.js');

    const pinFile = loadPinFile('.g0-pins.json');
    if (!pinFile) {
      logger.info('No pin file found, skipping pin check');
      return;
    }

    const result = scanAllMCPConfigs();
    if (result.tools.length === 0) return;

    const check = checkPins(result.tools, pinFile);
    if (check.mismatches.length > 0) {
      logger.warn(`Pin check: ${check.mismatches.length} mismatches detected!`);
      for (const m of check.mismatches) {
        logger.warn(`  MISMATCH: ${m.toolName} — description changed`);
      }
    } else {
      logger.info(`Pin check: ${check.matches} tools verified`);
    }
  } catch (err) {
    logger.error(`Pin check failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function runInventoryDiff(): Promise<void> {
  for (const watchPath of config.watchPaths) {
    try {
      const { runDiscovery, runGraphBuild } = await import('../pipeline.js');
      const { buildInventory } = await import('../inventory/builder.js');

      const discovery = await runDiscovery(watchPath);
      const graph = runGraphBuild(watchPath, discovery);
      const inventory = buildInventory(graph);

      logger.info(`Inventory for ${watchPath}: ${inventory.summary.totalModels} models, ${inventory.summary.totalTools} tools`);

      if (config.upload && isAuthenticated()) {
        const client = new PlatformClient();
        const meta = collectMachineMeta();
        await client.upload({
          type: 'inventory',
          project: { name: watchPath.split('/').pop() || watchPath, path: watchPath },
          machine: meta,
          result: inventory,
        });
        logger.info(`Inventory for ${watchPath} uploaded`);
      }
    } catch (err) {
      logger.error(`Inventory diff for ${watchPath} failed: ${err instanceof Error ? err.message : err}`);
    }
  }
}

async function registerEndpoint(): Promise<void> {
  try {
    const client = new PlatformClient();
    const response = await client.registerEndpoint({
      machineId: getMachineId(),
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      g0Version: '1.0.0',
      watchPaths: config.watchPaths,
    });
    endpointId = response.endpointId;
    logger.info(`Registered as endpoint ${endpointId}`);
  } catch (err) {
    logger.warn(`Endpoint registration failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function sendHeartbeat(
  status: 'healthy' | 'degraded' | 'error',
  issues?: string[],
): Promise<void> {
  try {
    const client = new PlatformClient();
    const payload: HeartbeatPayload = {
      endpointId: endpointId!,
      machineId: getMachineId(),
      timestamp: new Date().toISOString(),
      status,
      issues,
    };
    await client.heartbeat(payload);
  } catch (err) {
    logger.warn(`Heartbeat failed: ${err instanceof Error ? err.message : err}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Run if this is the daemon process
if (process.env.G0_DAEMON === '1') {
  main().catch(err => {
    console.error('Daemon fatal error:', err);
    process.exit(1);
  });
}

export { main as runDaemon, tick };
