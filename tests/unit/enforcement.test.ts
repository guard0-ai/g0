import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock child_process before importing the module
vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
}));

import { execFileSync } from 'node:child_process';
import {
  enforceOnCritical,
  resetCriticalCounter,
  getConsecutiveCriticalTicks,
} from '../../src/daemon/enforcement.js';
import type { DeploymentAuditResult } from '../../src/mcp/openclaw-deployment.js';
import type { DaemonConfig } from '../../src/daemon/config.js';

const mockExecFileSync = vi.mocked(execFileSync);

function makeLogger() {
  return {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  } as any;
}

function makeResult(
  overallStatus: 'secure' | 'warn' | 'critical',
  checks: DeploymentAuditResult['checks'] = [],
): DeploymentAuditResult {
  const failed = checks.filter(c => c.status === 'fail').length;
  return {
    checks,
    summary: {
      total: checks.length,
      passed: checks.length - failed,
      failed,
      errors: 0,
      skipped: 0,
      overallStatus,
    },
  };
}

function makeConfig(
  overrides: Partial<NonNullable<DaemonConfig['enforcement']>> = {},
): NonNullable<DaemonConfig['enforcement']> {
  return {
    criticalThreshold: 2,
    stopContainersOnCritical: false,
    ...overrides,
  };
}

describe('enforcement', () => {
  beforeEach(() => {
    resetCriticalCounter();
    vi.clearAllMocks();
  });

  it('resets critical counter', () => {
    expect(getConsecutiveCriticalTicks()).toBe(0);
  });

  it('returns no action when status is not critical', async () => {
    const result = makeResult('secure');
    const config = makeConfig();
    const logger = makeLogger();

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(false);
    expect(res.actions).toHaveLength(0);
    expect(getConsecutiveCriticalTicks()).toBe(0);
  });

  it('increments critical counter but does not enforce below threshold', async () => {
    const result = makeResult('critical');
    const config = makeConfig({ criticalThreshold: 3 });
    const logger = makeLogger();

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(false);
    expect(getConsecutiveCriticalTicks()).toBe(1);
    expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('1/3'));
  });

  it('resets counter when status returns to non-critical', async () => {
    const logger = makeLogger();
    const config = makeConfig();

    // Push counter up
    await enforceOnCritical(makeResult('critical'), config, logger);
    expect(getConsecutiveCriticalTicks()).toBe(1);

    // Non-critical resets
    await enforceOnCritical(makeResult('warn'), config, logger);
    expect(getConsecutiveCriticalTicks()).toBe(0);
  });

  it('enforces container stop when threshold reached and docker checks fail', async () => {
    const logger = makeLogger();
    const checks = [
      { id: 'OC-H-021', name: 'Docker socket', severity: 'critical' as const, status: 'fail' as const, detail: 'exposed' },
    ];
    const result = makeResult('critical', checks);
    const config = makeConfig({
      criticalThreshold: 2,
      stopContainersOnCritical: true,
      protectedContainers: ['db-*'],
    });

    // First tick
    await enforceOnCritical(result, config, logger);

    // Second tick triggers enforcement
    mockExecFileSync
      .mockReturnValueOnce('web-app\ndb-primary\nworker\n') // docker ps
      .mockReturnValueOnce('') // docker stop web-app
      .mockReturnValueOnce(''); // docker stop worker

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(true);
    expect(res.actions).toContain('docker stop web-app');
    expect(res.actions).toContain('docker stop worker');
    // db-primary should be protected by db-* pattern
    expect(res.actions).not.toContain('docker stop db-primary');
  });

  it('skips containers matching exact protected name', async () => {
    const logger = makeLogger();
    const checks = [
      { id: 'OC-H-025', name: 'test', severity: 'critical' as const, status: 'fail' as const, detail: 'fail' },
    ];
    const result = makeResult('critical', checks);
    const config = makeConfig({
      criticalThreshold: 1,
      stopContainersOnCritical: true,
      protectedContainers: ['critical-svc'],
    });

    mockExecFileSync
      .mockReturnValueOnce('critical-svc\nother-svc\n')
      .mockReturnValueOnce('');

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actions).toEqual(['docker stop other-svc']);
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('Skipping protected'));
  });

  it('handles docker ps failure gracefully', async () => {
    const logger = makeLogger();
    const checks = [
      { id: 'OC-H-021', name: 'test', severity: 'critical' as const, status: 'fail' as const, detail: 'fail' },
    ];
    const result = makeResult('critical', checks);
    const config = makeConfig({
      criticalThreshold: 1,
      stopContainersOnCritical: true,
    });

    mockExecFileSync.mockImplementationOnce(() => { throw new Error('docker not found'); });

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(false);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Could not list Docker'));
  });

  it('handles docker stop failure gracefully', async () => {
    const logger = makeLogger();
    const checks = [
      { id: 'OC-H-027', name: 'test', severity: 'critical' as const, status: 'fail' as const, detail: 'fail' },
    ];
    const result = makeResult('critical', checks);
    const config = makeConfig({
      criticalThreshold: 1,
      stopContainersOnCritical: true,
    });

    mockExecFileSync
      .mockReturnValueOnce('my-container\n')
      .mockImplementationOnce(() => { throw new Error('permission denied'); });

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(false);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Failed to stop'));
  });

  it('executes custom command with audit data on stdin', async () => {
    const logger = makeLogger();
    const checks = [
      { id: 'OC-H-021', name: 'Socket check', severity: 'critical' as const, status: 'fail' as const, detail: 'exposed socket' },
    ];
    const result = makeResult('critical', checks);
    const config = makeConfig({
      criticalThreshold: 1,
      onCriticalCommand: '/usr/bin/notify --alert',
    });

    mockExecFileSync.mockReturnValueOnce('');

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(true);
    expect(res.actions).toContain('exec: /usr/bin/notify --alert');

    // Verify execFileSync was called with correct args
    expect(mockExecFileSync).toHaveBeenCalledWith(
      '/usr/bin/notify',
      ['--alert'],
      expect.objectContaining({
        input: expect.stringContaining('"overallStatus":"critical"'),
        env: expect.objectContaining({
          G0_AUDIT_STATUS: 'critical',
          G0_AUDIT_FAILED: '1',
        }),
      }),
    );
  });

  it('handles empty custom command', async () => {
    const logger = makeLogger();
    const result = makeResult('critical');
    const config = makeConfig({
      criticalThreshold: 1,
      onCriticalCommand: '   ',
    });

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(false);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('onCriticalCommand is empty'));
  });

  it('handles custom command failure', async () => {
    const logger = makeLogger();
    const result = makeResult('critical');
    const config = makeConfig({
      criticalThreshold: 1,
      onCriticalCommand: '/bin/false',
    });

    mockExecFileSync.mockImplementationOnce(() => { throw new Error('exit code 1'); });

    const res = await enforceOnCritical(result, config, logger);
    expect(res.actioned).toBe(false);
    expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Custom command failed'));
  });

  it('does not stop containers when no docker checks fail', async () => {
    const logger = makeLogger();
    const checks = [
      { id: 'OC-H-040', name: 'Non-docker', severity: 'critical' as const, status: 'fail' as const, detail: 'fail' },
    ];
    const result = makeResult('critical', checks);
    const config = makeConfig({
      criticalThreshold: 1,
      stopContainersOnCritical: true,
    });

    const res = await enforceOnCritical(result, config, logger);
    // No docker ps call should have been made
    expect(mockExecFileSync).not.toHaveBeenCalled();
    expect(res.actioned).toBe(false);
  });
});
