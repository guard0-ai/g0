import { execFileSync } from 'node:child_process';
import type { DaemonConfig } from './config.js';
import type { DeploymentAuditResult } from '../mcp/openclaw-deployment.js';
import type { DaemonLogger } from './logger.js';

// ── Consecutive Critical Tracker ──────────────────────────────────────────

let consecutiveCriticalTicks = 0;

export function resetCriticalCounter(): void {
  consecutiveCriticalTicks = 0;
}

export function getConsecutiveCriticalTicks(): number {
  return consecutiveCriticalTicks;
}

// ── Main Enforcement Entry Point ──────────────────────────────────────────

export async function enforceOnCritical(
  result: DeploymentAuditResult,
  config: NonNullable<DaemonConfig['enforcement']>,
  logger: DaemonLogger,
): Promise<{ actioned: boolean; actions: string[] }> {
  const actions: string[] = [];
  const threshold = config.criticalThreshold ?? 2;

  if (result.summary.overallStatus === 'critical') {
    consecutiveCriticalTicks++;
  } else {
    consecutiveCriticalTicks = 0;
    return { actioned: false, actions: [] };
  }

  if (consecutiveCriticalTicks < threshold) {
    logger.warn(
      `Critical status detected (${consecutiveCriticalTicks}/${threshold} ticks before enforcement)`,
    );
    return { actioned: false, actions: [] };
  }

  logger.warn(
    `Critical threshold reached (${consecutiveCriticalTicks} consecutive ticks). Executing enforcement actions.`,
  );

  // ── Action 1: Stop non-protected containers ─────────────────────────

  if (config.stopContainersOnCritical) {
    const stopped = stopVulnerableContainers(
      result,
      config.protectedContainers ?? [],
      logger,
    );
    actions.push(...stopped);
  }

  // ── Action 2: Run custom command ────────────────────────────────────

  if (config.onCriticalCommand) {
    const cmdResult = runCustomCommand(config.onCriticalCommand, result, logger);
    if (cmdResult) actions.push(cmdResult);
  }

  return { actioned: actions.length > 0, actions };
}

// ── Container Stop Logic ──────────────────────────────────────────────────

function stopVulnerableContainers(
  result: DeploymentAuditResult,
  protectedPatterns: string[],
  logger: DaemonLogger,
): string[] {
  const actions: string[] = [];

  // Find containers flagged by Docker-related checks
  const dockerCheckIds = ['OC-H-021', 'OC-H-025', 'OC-H-027'];
  const failedDockerChecks = result.checks.filter(
    c => dockerCheckIds.includes(c.id) && c.status === 'fail' && c.severity === 'critical',
  );

  if (failedDockerChecks.length === 0) return actions;

  // Get running containers
  let containers: string[];
  try {
    const output = execFileSync('docker', ['ps', '--format', '{{.Names}}'], {
      encoding: 'utf-8',
      timeout: 10_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    containers = output.trim().split('\n').filter(Boolean);
  } catch {
    logger.error('Enforcement: Could not list Docker containers');
    return actions;
  }

  for (const container of containers) {
    // Check protection list
    const isProtected = protectedPatterns.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        return regex.test(container);
      }
      return container === pattern;
    });

    if (isProtected) {
      logger.info(`Enforcement: Skipping protected container "${container}"`);
      continue;
    }

    try {
      execFileSync('docker', ['stop', container], {
        encoding: 'utf-8',
        timeout: 30_000,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      logger.warn(`Enforcement: Stopped container "${container}"`);
      actions.push(`docker stop ${container}`);
    } catch (err) {
      logger.error(
        `Enforcement: Failed to stop container "${container}": ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  return actions;
}

// ── Custom Command Execution ──────────────────────────────────────────────

function runCustomCommand(
  command: string,
  result: DeploymentAuditResult,
  logger: DaemonLogger,
): string | null {
  // Split the command into executable and arguments.
  // We use execFileSync (no shell) to prevent injection.
  const parts = command.split(/\s+/).filter(Boolean);
  if (parts.length === 0) {
    logger.error('Enforcement: onCriticalCommand is empty');
    return null;
  }

  const [executable, ...args] = parts;

  try {
    const summaryJson = JSON.stringify({
      overallStatus: result.summary.overallStatus,
      failed: result.summary.failed,
      checks: result.checks
        .filter(c => c.status === 'fail')
        .map(c => ({ id: c.id, name: c.name, severity: c.severity, detail: c.detail })),
    });

    execFileSync(executable, args, {
      encoding: 'utf-8',
      timeout: 30_000,
      stdio: ['pipe', 'pipe', 'pipe'],
      input: summaryJson,
      env: {
        ...process.env,
        G0_AUDIT_STATUS: result.summary.overallStatus,
        G0_AUDIT_FAILED: String(result.summary.failed),
        G0_AUDIT_PASSED: String(result.summary.passed),
      },
    });

    logger.info(`Enforcement: Custom command executed: "${command}"`);
    return `exec: ${command}`;
  } catch (err) {
    logger.error(
      `Enforcement: Custom command failed: ${err instanceof Error ? err.message : err}`,
    );
    return null;
  }
}
