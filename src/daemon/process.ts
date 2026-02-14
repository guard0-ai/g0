import * as fs from 'node:fs';
import * as path from 'node:path';
import * as childProcess from 'node:child_process';

/**
 * Read PID from PID file. Returns null if file doesn't exist or PID is stale.
 */
export function readPid(pidFile: string): number | null {
  try {
    const pid = parseInt(fs.readFileSync(pidFile, 'utf-8').trim(), 10);
    if (isNaN(pid)) return null;

    // Check if process is actually running
    try {
      process.kill(pid, 0); // Signal 0 = just check existence
      return pid;
    } catch {
      // Process not running, clean up stale PID file
      fs.unlinkSync(pidFile);
      return null;
    }
  } catch {
    return null;
  }
}

/**
 * Write PID to PID file.
 */
export function writePid(pidFile: string, pid: number): void {
  fs.mkdirSync(path.dirname(pidFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(pidFile, String(pid) + '\n', { mode: 0o600 });
}

/**
 * Remove PID file.
 */
export function removePid(pidFile: string): void {
  try {
    fs.unlinkSync(pidFile);
  } catch {
    // Already gone
  }
}

/**
 * Fork and detach the daemon process.
 * Returns the child PID, or null if we ARE the child (should start running).
 */
export function forkDaemon(pidFile: string): number | null {
  // Check if already running
  const existing = readPid(pidFile);
  if (existing !== null) {
    throw new Error(`Daemon already running (PID ${existing})`);
  }

  // Resolve path to the daemon runner entry point
  // In development: tsx src/daemon/runner.ts
  // In production: node dist/src/daemon/runner.js
  const runnerPath = resolveRunnerPath();

  const child = childProcess.fork(runnerPath, [], {
    detached: true,
    stdio: 'ignore',
    env: { ...process.env, G0_DAEMON: '1' },
  });

  if (child.pid) {
    writePid(pidFile, child.pid);
    child.unref();
    return child.pid;
  }

  throw new Error('Failed to fork daemon process');
}

/**
 * Stop the daemon by sending SIGTERM.
 */
export function stopDaemon(pidFile: string): boolean {
  const pid = readPid(pidFile);
  if (pid === null) return false;

  try {
    process.kill(pid, 'SIGTERM');
    removePid(pidFile);
    return true;
  } catch {
    removePid(pidFile);
    return false;
  }
}

function resolveRunnerPath(): string {
  // Check for compiled version first
  const compiledPath = path.resolve(
    import.meta.url.replace('file://', '').replace('/daemon/process.js', ''),
    '../daemon/runner.js',
  );

  // In dist/ context
  try {
    const distPath = path.resolve(__dirname, '../daemon/runner.js');
    if (fs.existsSync(distPath)) return distPath;
  } catch {
    // __dirname not available in ESM
  }

  // Resolve relative to this file's URL
  const thisDir = new URL('.', import.meta.url).pathname;
  const candidate = path.join(thisDir, 'runner.js');
  if (fs.existsSync(candidate)) return candidate;

  // Fallback: assume we're in src/ or dist/
  return compiledPath;
}
