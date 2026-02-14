import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// ─── Daemon Config ───────────────────────────────────────────────────────────

describe('daemon config', () => {
  it('DEFAULT_DAEMON_CONFIG has correct defaults', async () => {
    const { DEFAULT_DAEMON_CONFIG } = await import('../../src/daemon/config.js');
    expect(DEFAULT_DAEMON_CONFIG.intervalMinutes).toBe(30);
    expect(DEFAULT_DAEMON_CONFIG.upload).toBe(true);
    expect(DEFAULT_DAEMON_CONFIG.mcpScan).toBe(true);
    expect(DEFAULT_DAEMON_CONFIG.mcpPinCheck).toBe(true);
    expect(DEFAULT_DAEMON_CONFIG.inventoryDiff).toBe(true);
    expect(DEFAULT_DAEMON_CONFIG.watchPaths).toEqual([]);
  });

  it('loadDaemonConfig returns defaults when no file exists', async () => {
    const { loadDaemonConfig } = await import('../../src/daemon/config.js');
    const config = loadDaemonConfig();
    expect(config.intervalMinutes).toBe(30);
    expect(config.upload).toBe(true);
  });
});

// ─── Daemon Logger ───────────────────────────────────────────────────────────

describe('daemon logger', () => {
  const testDir = path.join(os.tmpdir(), `g0-logger-test-${Date.now()}`);
  const logPath = path.join(testDir, 'test.log');

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('writes log entries with timestamps', async () => {
    const { DaemonLogger } = await import('../../src/daemon/logger.js');
    const logger = new DaemonLogger(logPath);

    logger.info('Test info message');
    logger.warn('Test warning');
    logger.error('Test error');

    const content = fs.readFileSync(logPath, 'utf-8');
    expect(content).toContain('[INFO] Test info message');
    expect(content).toContain('[WARN] Test warning');
    expect(content).toContain('[ERROR] Test error');
  });

  it('tail returns last N lines', async () => {
    const { DaemonLogger } = await import('../../src/daemon/logger.js');
    const logger = new DaemonLogger(logPath);

    for (let i = 0; i < 10; i++) {
      logger.info(`Line ${i}`);
    }

    const lines = logger.tail(3);
    expect(lines).toHaveLength(3);
    expect(lines[2]).toContain('Line 9');
  });

  it('tail returns empty array for missing file', async () => {
    const { DaemonLogger } = await import('../../src/daemon/logger.js');
    const logger = new DaemonLogger(path.join(testDir, 'nonexistent.log'));
    expect(logger.tail()).toEqual([]);
  });
});

// ─── Daemon Process ──────────────────────────────────────────────────────────

describe('daemon process', () => {
  const testDir = path.join(os.tmpdir(), `g0-process-test-${Date.now()}`);
  const pidFile = path.join(testDir, 'test.pid');

  beforeEach(() => {
    fs.mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('readPid returns null for missing file', async () => {
    const { readPid } = await import('../../src/daemon/process.js');
    expect(readPid(pidFile)).toBeNull();
  });

  it('writePid and readPid round-trip for current process', async () => {
    const { writePid, readPid, removePid } = await import('../../src/daemon/process.js');
    writePid(pidFile, process.pid);
    expect(readPid(pidFile)).toBe(process.pid);
    removePid(pidFile);
    expect(fs.existsSync(pidFile)).toBe(false);
  });

  it('readPid cleans up stale PID files', async () => {
    const { readPid } = await import('../../src/daemon/process.js');
    // Write a PID that doesn't exist
    fs.writeFileSync(pidFile, '999999999\n');
    expect(readPid(pidFile)).toBeNull();
    // PID file should be cleaned up
    expect(fs.existsSync(pidFile)).toBe(false);
  });

  it('stopDaemon returns false for non-running daemon', async () => {
    const { stopDaemon } = await import('../../src/daemon/process.js');
    expect(stopDaemon(pidFile)).toBe(false);
  });

  it('forkDaemon throws if already running', async () => {
    const { writePid, forkDaemon, removePid } = await import('../../src/daemon/process.js');
    // Simulate running daemon using our own PID
    writePid(pidFile, process.pid);

    expect(() => forkDaemon(pidFile)).toThrow('already running');

    removePid(pidFile);
  });
});

// ─── Daemon Runner ───────────────────────────────────────────────────────────

describe('daemon runner', () => {
  it('exports tick function', async () => {
    const { tick } = await import('../../src/daemon/runner.js');
    expect(typeof tick).toBe('function');
  });
});
