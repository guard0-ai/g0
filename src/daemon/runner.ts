import { loadDaemonConfig, type DaemonConfig } from './config.js';
import { DaemonLogger } from './logger.js';
import { removePid } from './process.js';
import { isAuthenticated } from '../platform/auth.js';
import { PlatformClient } from '../platform/client.js';
import { getMachineId } from '../platform/machine-id.js';
import { collectMachineMeta } from '../platform/upload.js';
import { EventReceiver } from './event-receiver.js';
import { BaselineManager } from './behavioral-baseline.js';
import { correlateEvents } from './correlation-engine.js';
import { getCostSnapshot } from './cost-monitor.js';
import * as os from 'node:os';
import type { HeartbeatPayload } from '../platform/types.js';

let running = true;
let config: DaemonConfig;
let logger: DaemonLogger;
let endpointId: string | undefined;
let eventReceiver: EventReceiver | null = null;
let killSwitchMonitor: import('./kill-switch.js').KillSwitchMonitor | null = null;
let baselineManager: BaselineManager | null = null;

// Track OpenClaw audit state across ticks for heartbeat reporting
let lastOpenClawStatus: 'secure' | 'warn' | 'critical' | undefined;
let lastOpenClawFailedChecks = 0;
let lastOpenClawDriftEvents = 0;

async function main(): Promise<void> {
  config = loadDaemonConfig();
  logger = new DaemonLogger(config.logFile);

  // Handle signals for graceful shutdown — register early so that a SIGTERM
  // arriving during the rest of initialization triggers a clean exit instead
  // of an abrupt process termination.
  process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM, shutting down');
    running = false;
    stopFastEgressLoop();
    if (eventReceiver) await eventReceiver.stop();
    removePid(config.pidFile);
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.info('Received SIGINT, shutting down');
    running = false;
    stopFastEgressLoop();
    if (eventReceiver) await eventReceiver.stop();
    removePid(config.pidFile);
    process.exit(0);
  });

  // Signal to the parent process that we survived initialization.
  // The parent holds an IPC channel open and waits for this message
  // before reporting the PID and exiting.
  if (process.send) {
    process.send({ type: 'daemon-ready' });
  }

  logger.info('Daemon starting');
  logger.info(`Interval: ${config.intervalMinutes} minutes`);
  logger.info(`Machine ID: ${getMachineId()}`);

  if (config.alerting?.webhookUrl) {
    logger.info(`Alerting: webhook configured (${config.alerting.format ?? 'generic'} format)`);
  }
  if (config.enforcement?.stopContainersOnCritical) {
    logger.info(`Enforcement: container stop enabled (threshold: ${config.enforcement.criticalThreshold ?? 2} ticks)`);
  }
  if (config.enforcement?.applyEgressRules) {
    logger.info('Enforcement: iptables egress rules enabled');
  }

  // Start fast egress loop if configured
  const egressInterval = config.openclaw?.egressIntervalSeconds;
  if (config.openclaw?.enabled && config.openclaw?.egressAllowlist?.length && egressInterval !== 0) {
    const intervalSec = egressInterval ?? 60;
    logger.info(`Fast egress loop: every ${intervalSec}s`);
    startFastEgressLoop(intervalSec);
  }

  // Initialize kill switch monitor
  if (config.killSwitch?.autoEnabled !== false) {
    try {
      const { createKillSwitchMonitor } = await import('./kill-switch.js');
      killSwitchMonitor = createKillSwitchMonitor(config.killSwitch?.rules);
      logger.info('Kill switch monitor initialized');
    } catch (err) {
      logger.error(`Kill switch monitor init failed: ${err instanceof Error ? err.message : err}`);
    }
  }

  // Initialize behavioral baseline manager
  try {
    baselineManager = new BaselineManager();
    logger.info(`Behavioral baseline initialized (learning=${baselineManager.getBaseline().learningMode})`);
  } catch (err) {
    logger.error(`Behavioral baseline init failed: ${err instanceof Error ? err.message : err}`);
  }

  // Start event receiver if configured
  if (config.eventReceiver?.enabled) {
    eventReceiver = new EventReceiver({
      port: config.eventReceiver.port,
      bind: config.eventReceiver.bind,
      authToken: config.eventReceiver.authToken,
      logFile: config.eventReceiver.logFile,
      logger,
      onEvent: (event) => {
        // Log high-severity events as warnings
        if (event.type.includes('injection') || event.type.includes('blocked')) {
          logger.warn(`Security event: ${event.source}/${event.type}`);
        }
        // Feed into behavioral baseline
        if (baselineManager && event.type.includes('tool_call')) {
          const toolName = (event.data?.toolName as string) ?? event.type;
          const anomalies = baselineManager.recordToolCall(toolName, event.timestamp);
          for (const anomaly of anomalies) {
            logger.warn(`Behavioral anomaly: ${anomaly.type} — ${anomaly.toolName} (expected=${anomaly.expected}, actual=${anomaly.actual})`);
            // Alert on behavioral anomalies
            if (config.alerting?.webhookUrl) {
              import('./alerter.js').then(({ sendUrgentAlert }) =>
                sendUrgentAlert(config.alerting!, `Behavioral anomaly: ${anomaly.type}`,
                  `Tool: ${anomaly.toolName}, expected=${anomaly.expected}, actual=${anomaly.actual}`, 'high')
              ).catch(() => {});
            }
          }
        }
        // Feed into kill switch monitor
        if (killSwitchMonitor) {
          const triggered = killSwitchMonitor.recordEvent(event.type, event.timestamp);
          if (triggered) {
            logger.warn(`KILL SWITCH AUTO-ACTIVATED: ${triggered.reason}`);
            // Alert on kill switch activation
            if (config.alerting?.webhookUrl) {
              import('./alerter.js').then(({ sendUrgentAlert }) =>
                sendUrgentAlert(config.alerting!, 'KILL SWITCH ACTIVATED', triggered.reason, 'critical')
              ).catch(() => {});
            }
          }
        }
      },
    });
    try {
      await eventReceiver.start();
    } catch (err) {
      logger.error(`Failed to start event receiver: ${err instanceof Error ? err.message : err}`);
      eventReceiver = null;
    }
  }

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
  const tickIssues: string[] = [];

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

    // 4. Full endpoint scan (network + artifacts + drift)
    if (config.networkScan || config.artifactScan) {
      await runEndpointScan();
    }

    // 5. Host hardening audit
    await runHostHardening();

    // 6. OpenClaw deployment audit (with drift, alerting, enforcement)
    if (config.openclaw?.enabled) {
      await runOpenClawAudit();
    }

    // 7. Agent watcher (detect running AI agents)
    if (config.fleet?.reportAgents !== false) {
      await runAgentWatch();
    }

    // 8. Fleet registration
    if (config.fleet?.enabled) {
      await runFleetRegistration();
    }

    // 9. Correlation engine — cross-source attack chain detection
    if (eventReceiver) {
      const { recentEvents } = eventReceiver.getStats();
      if (recentEvents.length > 0) {
        try {
          const threats = correlateEvents([], [], recentEvents, [], []);
          if (threats.length > 0) {
            for (const threat of threats) {
              logger.warn(`Correlated threat: [${threat.id}] ${threat.name} (severity=${threat.severity}, confidence=${threat.confidence})`);
              tickIssues.push(`${threat.id}: ${threat.name}`);
            }
          }
        } catch (err) {
          logger.error(`Correlation engine failed: ${err instanceof Error ? err.message : err}`);
        }
      }
    }

    // 10. Cost monitoring — budget warnings and circuit breaker
    if (config.costMonitor?.enabled) {
      try {
        const eventsDir = config.costMonitor.eventsDir ?? config.eventReceiver?.logFile?.replace(/[^/]+$/, '') ?? '';
        if (eventsDir) {
          const snapshot = getCostSnapshot(eventsDir, {
            hourlyLimitUsd: config.costMonitor.hourlyLimitUsd,
            dailyLimitUsd: config.costMonitor.dailyLimitUsd,
            monthlyLimitUsd: config.costMonitor.monthlyLimitUsd,
            circuitBreakerEnabled: config.costMonitor.circuitBreakerEnabled,
          });

          logger.info(`Cost monitor: hourly=$${snapshot.hourly} daily=$${snapshot.daily} monthly=$${snapshot.monthly} breaker=${snapshot.breaker}`);

          if (snapshot.breaker === 'warning') {
            logger.warn('Cost monitor: approaching budget limit');
            tickIssues.push('Cost approaching budget limit');
            if (config.alerting?.webhookUrl) {
              try {
                const { sendUrgentAlert } = await import('./alerter.js');
                await sendUrgentAlert(config.alerting, 'Cost approaching budget limit',
                  `Hourly: $${snapshot.hourly}, Daily: $${snapshot.daily}, Monthly: $${snapshot.monthly}`, 'high');
              } catch {}
            }
          } else if (snapshot.breaker === 'tripped') {
            logger.warn('Cost monitor: budget limit EXCEEDED — circuit breaker tripped');
            tickIssues.push('Cost budget exceeded');
            if (config.alerting?.webhookUrl) {
              try {
                const { sendUrgentAlert } = await import('./alerter.js');
                await sendUrgentAlert(config.alerting, 'Cost budget EXCEEDED — circuit breaker tripped',
                  `Hourly: $${snapshot.hourly}, Daily: $${snapshot.daily}, Monthly: $${snapshot.monthly}`, 'critical');
              } catch {}
            }
            // Auto-activate kill switch if configured
            if (killSwitchMonitor && config.costMonitor.circuitBreakerEnabled) {
              const triggered = killSwitchMonitor.recordEvent('cost-breaker-tripped', new Date().toISOString());
              if (triggered) {
                logger.warn(`KILL SWITCH AUTO-ACTIVATED: ${triggered.reason}`);
              }
            }
          }
        }
      } catch (err) {
        logger.error(`Cost monitor failed: ${err instanceof Error ? err.message : err}`);
      }
    }

    // 11. Heartbeat — derive status from actual audit results
    if (config.upload && isAuthenticated() && endpointId) {
      const heartbeatStatus = deriveHeartbeatStatus(tickIssues);
      await sendHeartbeat(heartbeatStatus, tickIssues.length > 0 ? tickIssues : undefined);
    }

    const elapsed = Date.now() - startTime;
    logger.info(`Tick completed in ${elapsed}ms`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`Tick failed: ${msg}`);

    if (config.upload && isAuthenticated() && endpointId) {
      await sendHeartbeat('error', [msg]);
    }
  }
}

/** Derive heartbeat status from OpenClaw audit + tick issues */
function deriveHeartbeatStatus(issues: string[]): 'healthy' | 'degraded' | 'error' {
  if (issues.length > 0) return 'degraded';
  if (lastOpenClawStatus === 'critical') return 'error';
  if (lastOpenClawStatus === 'warn') return 'degraded';
  return 'healthy';
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
      const inventory = buildInventory(graph, discovery);

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

async function runOpenClawAudit(): Promise<void> {
  try {
    const { auditOpenClawDeployment } = await import('../mcp/openclaw-deployment.js');
    const { detectOpenClawDrift, saveLastAudit } = await import('./openclaw-drift.js');
    const ocConfig = config.openclaw!;

    // ── Run the audit ─────────────────────────────────────────────────
    const result = await auditOpenClawDeployment({
      agentDataPath: ocConfig.agentDataPath,
      composePath: ocConfig.composePath,
      dockerDaemonConfigPath: ocConfig.dockerDaemonConfigPath,
      egressAllowlist: ocConfig.egressAllowlist,
    });

    const { summary } = result;
    logger.info(
      `OpenClaw audit: ${summary.passed} passed, ${summary.failed} failed, ` +
      `${summary.errors} errors, ${summary.skipped} skipped — status: ${summary.overallStatus}`,
    );

    // Log failed checks at warn level
    for (const check of result.checks) {
      if (check.status === 'fail') {
        const level = check.severity === 'critical' || check.severity === 'high' ? 'warn' : 'info';
        logger[level](`  [${check.id}] ${check.name}: ${check.detail}`);
      }
    }

    // Update module-level state for heartbeat
    lastOpenClawStatus = summary.overallStatus;
    lastOpenClawFailedChecks = summary.failed;

    // ── Drift detection ───────────────────────────────────────────────
    const drift = detectOpenClawDrift(result);
    lastOpenClawDriftEvents = drift.events.length;

    if (drift.events.length > 0) {
      const newFailures = drift.events.filter(e => e.type === 'new-failure' || e.type === 'regression');
      const resolved = drift.events.filter(e => e.type === 'resolved');

      if (newFailures.length > 0) {
        logger.warn(`Drift: ${newFailures.length} new/regressed failures`);
        for (const event of newFailures) {
          logger.warn(`  [${event.type}] ${event.title}`);
        }
      }

      if (resolved.length > 0) {
        logger.info(`Drift: ${resolved.length} issues resolved`);
        for (const event of resolved) {
          logger.info(`  [resolved] ${event.title}`);
        }
      }

      // Status change
      const statusChange = drift.events.find(e => e.type === 'status-change');
      if (statusChange) {
        logger.warn(`Drift: ${statusChange.title}`);
      }
    }

    // Save for next drift comparison
    saveLastAudit(result);

    // ── Cognitive file integrity monitoring ────────────────────────────
    if (ocConfig.agentDataPath) {
      try {
        const { detectCognitiveDrift } = await import('./openclaw-drift.js');
        const openclawDir = ocConfig.agentDataPath.replace(/\/agents\/?$/, '');
        const cogDrift = detectCognitiveDrift(openclawDir);

        if (cogDrift.events.length > 0) {
          for (const event of cogDrift.events) {
            const level = event.severity === 'critical' ? 'warn' : 'info';
            logger[level](`Cognitive drift: [${event.type}] ${event.detail}`);
          }
        }
      } catch (err) {
        logger.error(`Cognitive drift check failed: ${err instanceof Error ? err.message : err}`);
      }
    }

    // ── Webhook alerting ──────────────────────────────────────────────
    if (config.alerting?.webhookUrl) {
      const onChangeOnly = config.alerting.onChangeOnly ?? true;
      const shouldAlert = onChangeOnly
        ? drift.events.some(e => e.type !== 'resolved') // Alert on new/regression/status-change
        : summary.overallStatus !== 'secure'; // Alert whenever not secure

      if (shouldAlert) {
        try {
          const { sendWebhookAlert } = await import('./alerter.js');
          const failedChecks = result.checks.filter(c => c.status === 'fail');
          const alertResult = await sendWebhookAlert(
            config.alerting,
            failedChecks,
            drift.events,
            summary.overallStatus,
          );

          if (alertResult.sent) {
            logger.info(`Webhook alert sent (status: ${alertResult.statusCode})`);
          } else if (alertResult.error) {
            logger.warn(`Webhook alert skipped: ${alertResult.error}`);
          }
        } catch (err) {
          logger.error(`Webhook alert failed: ${err instanceof Error ? err.message : err}`);
        }
      }
    }

    // ── Enforcement ───────────────────────────────────────────────────
    if (config.enforcement) {
      try {
        const { enforceOnCritical } = await import('./enforcement.js');
        const enforcement = await enforceOnCritical(result, config.enforcement, logger);
        if (enforcement.actioned) {
          logger.warn(`Enforcement actions taken: ${enforcement.actions.join(', ')}`);
        }
      } catch (err) {
        logger.error(`Enforcement failed: ${err instanceof Error ? err.message : err}`);
      }

      // Apply auditd rules if observability checks failed
      if (config.enforcement.applyAuditdRules) {
        const obsCheckIds = ['OC-H-031', 'OC-H-032', 'OC-H-033'];
        const obsFailed = result.checks.some(c => obsCheckIds.includes(c.id) && c.status === 'fail');
        if (obsFailed) {
          try {
            const { generateAuditdRules, applyAuditdRules } = await import('../endpoint/auditd-rules.js');
            const ruleSet = generateAuditdRules({
              agentDataPath: ocConfig.agentDataPath,
            });
            const auditdResult = applyAuditdRules(ruleSet, logger);
            if (auditdResult.applied) {
              logger.info(`auditd enforcement: ${auditdResult.rulesLoaded} rules installed`);
            }
          } catch (err) {
            logger.error(`auditd enforcement failed: ${err instanceof Error ? err.message : err}`);
          }
        }
      }
    }

    // ── Upload (proper typed payload) ─────────────────────────────────
    if (config.upload && isAuthenticated()) {
      try {
        const client = new PlatformClient();
        const meta = collectMachineMeta();
        await client.upload({
          type: 'openclaw-audit',
          machine: meta,
          result,
        });
        logger.info('OpenClaw audit results uploaded');
      } catch (err) {
        logger.warn(`OpenClaw audit upload failed: ${err instanceof Error ? err.message : err}`);
      }
    }
  } catch (err) {
    logger.error(`OpenClaw audit failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function runAgentWatch(): Promise<void> {
  try {
    const { detectRunningAgents } = await import('./agent-watchers/index.js');
    const result = detectRunningAgents();
    const running = result.agents.filter(a => a.status === 'running');
    if (running.length > 0) {
      logger.info(`Agent watcher: ${running.length} active agents detected (${running.map(a => a.type).join(', ')})`);
    }
  } catch (err) {
    logger.error(`Agent watcher failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function runFleetRegistration(): Promise<void> {
  try {
    const { registerMember, pruneStaleMembers } = await import('./fleet.js');
    registerMember(getMachineId(), {
      endpointScore: undefined,
      openclawStatus: lastOpenClawStatus,
      openclawFailedChecks: lastOpenClawFailedChecks,
    }, {
      group: config.fleet?.group,
      tags: config.fleet?.tags,
    });

    // Prune stale members every tick
    pruneStaleMembers(72);
  } catch (err) {
    logger.error(`Fleet registration failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function runHostHardening(): Promise<void> {
  try {
    const { auditHostHardening } = await import('../endpoint/host-hardening.js');
    const result = await auditHostHardening();
    const passed = result.checks.filter(c => c.status === 'pass').length;
    const failed = result.checks.filter(c => c.status === 'fail').length;
    const skipped = result.checks.filter(c => c.status === 'skip').length;
    logger.info(`Host hardening: ${passed} passed, ${failed} failed, ${skipped} skipped (${result.platform})`);

    for (const check of result.checks) {
      if (check.status === 'fail') {
        const level = check.severity === 'critical' || check.severity === 'high' ? 'warn' : 'info';
        logger[level](`  [${check.id}] ${check.name}: ${check.detail}`);
      }
    }

    // Alert on host hardening failures
    const hostFailedChecks = result.checks.filter(c => c.status === 'fail');
    if (hostFailedChecks.length > 0 && config.alerting?.webhookUrl) {
      try {
        const { sendWebhookAlert } = await import('./alerter.js');
        const hostStatus = hostFailedChecks.some(c => c.severity === 'critical') ? 'critical' as const
          : hostFailedChecks.some(c => c.severity === 'high') ? 'warn' as const : 'secure' as const;
        if (hostStatus !== 'secure') {
          await sendWebhookAlert(config.alerting, hostFailedChecks, [], hostStatus);
          logger.info('Host hardening alert sent');
        }
      } catch (err) {
        logger.warn(`Host hardening alert failed: ${err instanceof Error ? err.message : err}`);
      }
    }

    if (config.upload && isAuthenticated()) {
      try {
        const client = new PlatformClient();
        const meta = collectMachineMeta();
        await client.upload({ type: 'host-hardening', machine: meta, result });
        logger.info('Host hardening results uploaded');
      } catch (err) {
        logger.warn(`Host hardening upload failed: ${err instanceof Error ? err.message : err}`);
      }
    }
  } catch (err) {
    logger.error(`Host hardening failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function runEndpointScan(): Promise<void> {
  try {
    const { scanEndpoint } = await import('../endpoint/scanner.js');
    const { detectDrift, saveLastScan, loadLastScan } = await import('../endpoint/drift.js');

    const result = await scanEndpoint({
      network: config.networkScan,
      artifacts: config.artifactScan,
    });

    logger.info(`Endpoint scan: score=${result.score.total} (${result.score.grade}), findings=${result.summary.totalFindings}, network=${result.summary.networkServices} services, credentials=${result.summary.credentialExposures}`);

    // Drift detection
    if (config.driftDetection) {
      const previous = loadLastScan();
      if (previous) {
        const drift = detectDrift(previous, result);
        if (drift.events.length > 0) {
          logger.warn(`Drift detected: ${drift.events.length} events, score delta=${drift.scoreDelta}`);
          for (const event of drift.events) {
            const level = event.severity === 'critical' || event.severity === 'high' ? 'warn' : 'info';
            logger[level](`  [${event.type}] ${event.title}`);
          }
        }
      }
    }

    // Save for next drift comparison
    saveLastScan(result);

    // Upload full endpoint result
    if (config.upload && isAuthenticated()) {
      const client = new PlatformClient();
      const meta = collectMachineMeta();
      await client.upload({
        type: 'endpoint',
        machine: meta,
        result,
      });
      logger.info('Endpoint scan results uploaded');
    }
  } catch (err) {
    logger.error(`Endpoint scan failed: ${err instanceof Error ? err.message : err}`);
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
      endpointId: endpointId ?? '',
      machineId: getMachineId(),
      timestamp: new Date().toISOString(),
      status,
      issues,
      // Include OpenClaw audit state in heartbeat
      openclawStatus: lastOpenClawStatus,
      openclawFailedChecks: lastOpenClawFailedChecks,
      openclawDriftEvents: lastOpenClawDriftEvents,
    };
    await client.heartbeat(payload);
  } catch (err) {
    logger.warn(`Heartbeat failed: ${err instanceof Error ? err.message : err}`);
  }
}

// ── Fast Egress Loop ──────────────────────────────────────────────────────

let egressLoopTimer: ReturnType<typeof setInterval> | undefined;

function startFastEgressLoop(intervalSeconds: number): void {
  // Run immediately, then on interval
  runFastEgressCheck();
  egressLoopTimer = setInterval(runFastEgressCheck, intervalSeconds * 1000);
}

async function runFastEgressCheck(): Promise<void> {
  if (!running || !config.openclaw?.egressAllowlist?.length) return;

  try {
    const { scanEgress } = await import('../endpoint/egress-monitor.js');

    const result = await scanEgress({
      allowlist: config.openclaw.egressAllowlist,
      perContainer: true,
    });

    if (result.violations.length === 0) return;

    logger.warn(
      `Fast egress: ${result.violations.length} violations detected (${result.totalConnections} connections)`,
    );

    for (const v of result.violations.slice(0, 5)) {
      const dest = v.connection.remoteHost || v.connection.remote;
      const container = v.connection.container ? ` (${v.connection.container})` : '';
      logger.warn(`  ${dest}${container} — ${v.reason}`);
    }
    if (result.violations.length > 5) {
      logger.warn(`  ... and ${result.violations.length - 5} more`);
    }

    // Immediate webhook alert on egress violations
    if (config.alerting?.webhookUrl) {
      try {
        const { sendWebhookAlert } = await import('./alerter.js');
        const egressFindings = result.violations.map(v => ({
          id: 'OC-H-019' as const,
          name: 'Egress violation',
          severity: 'critical' as const,
          status: 'fail' as const,
          detail: v.reason,
        }));
        await sendWebhookAlert(config.alerting, egressFindings, [], 'critical');
      } catch (err) {
        logger.error(`Fast egress webhook failed: ${err instanceof Error ? err.message : err}`);
      }
    }

    // Apply iptables rules if enforcement configured
    if (config.enforcement?.applyEgressRules) {
      await applyEgressEnforcement();
    }
  } catch (err) {
    logger.error(`Fast egress check failed: ${err instanceof Error ? err.message : err}`);
  }
}

async function applyEgressEnforcement(): Promise<void> {
  const allowlist = config.openclaw?.egressAllowlist;
  if (!allowlist?.length) return;

  try {
    const { generateIptablesRules, applyIptablesRules } = await import('../endpoint/egress-rules.js');

    const ruleSet = await generateIptablesRules(allowlist);

    if (ruleSet.unresolved.length > 0) {
      logger.warn(`Egress rules: ${ruleSet.unresolved.length} allowlist entries could not be resolved`);
    }

    const result = applyIptablesRules(ruleSet, logger);
    if (result.applied) {
      logger.info(`Egress enforcement: ${result.rulesApplied} iptables rules applied`);
    }
    if (result.errors.length > 0) {
      logger.warn(`Egress enforcement: ${result.errors.length} rules failed to apply`);
    }
  } catch (err) {
    logger.error(`Egress enforcement failed: ${err instanceof Error ? err.message : err}`);
  }
}

export function stopFastEgressLoop(): void {
  if (egressLoopTimer) {
    clearInterval(egressLoopTimer);
    egressLoopTimer = undefined;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Run if this is the daemon process
if (process.env.G0_DAEMON === '1') {
  // Install global error handlers early — before any async work — so that
  // crashes during module loading or config parsing are captured to the
  // startup log (stdout/stderr are redirected to a file by forkDaemon).
  process.on('uncaughtException', (err) => {
    console.error('Daemon uncaught exception:', err);
    process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('Daemon unhandled rejection:', reason);
    process.exit(1);
  });

  main().catch(err => {
    console.error('Daemon fatal error:', err);
    process.exit(1);
  });
}

export { main as runDaemon, tick };
