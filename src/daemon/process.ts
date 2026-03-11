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
 * Returns the child PID on success. Throws if the child exits immediately.
 *
 * The child's stdout/stderr are redirected to a startup log file so that
 * errors during module loading or early initialization (before the daemon
 * logger is ready) are captured instead of being silently swallowed.
 *
 * An IPC channel is kept open briefly so the child can signal "ready"
 * once its logger is initialized. If the child exits before signalling,
 * the startup log is included in the thrown error.
 */
export async function forkDaemon(pidFile: string): Promise<number> {
  // Check if already running
  const existing = readPid(pidFile);
  if (existing !== null) {
    throw new Error(`Daemon already running (PID ${existing})`);
  }

  const runnerPath = resolveRunnerPath();

  // Capture early stdout/stderr to a file so errors before logger init are not lost
  const startupLogPath = path.join(path.dirname(pidFile), 'daemon-startup.log');
  const startupLogFd = fs.openSync(startupLogPath, 'a');

  const child = childProcess.fork(runnerPath, [], {
    detached: true,
    stdio: ['ignore', startupLogFd, startupLogFd, 'ipc'],
    env: { ...process.env, G0_DAEMON: '1', G0_DAEMON_STARTUP_LOG: startupLogPath },
  });

  if (!child.pid) {
    fs.closeSync(startupLogFd);
    throw new Error('Failed to fork daemon process');
  }

  writePid(pidFile, child.pid);

  // Wait for the child to signal readiness or exit
  const pid = await new Promise<number>((resolve, reject) => {
    let settled = false;

    const cleanup = () => {
      child.removeAllListeners('message');
      child.removeAllListeners('exit');
    };

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      // Timeout — check if process is still alive
      try {
        process.kill(child.pid!, 0);
        // Still running (slow init) — detach and report success
        child.unref();
        child.disconnect?.();
        fs.closeSync(startupLogFd);
        resolve(child.pid!);
      } catch {
        // Child already exited during the wait window
        fs.closeSync(startupLogFd);
        const log = readStartupLog(startupLogPath);
        removePid(pidFile);
        reject(new Error(
          `Daemon process exited immediately after fork.` +
          (log ? `\nStartup log:\n${log}` : '\nNo startup log captured — check the runner path and Node.js version.'),
        ));
      }
    }, 3000);

    child.on('message', (msg: unknown) => {
      if (settled) return;
      if (msg && typeof msg === 'object' && (msg as Record<string, unknown>).type === 'daemon-ready') {
        settled = true;
        clearTimeout(timer);
        cleanup();
        child.unref();
        child.disconnect?.();
        fs.closeSync(startupLogFd);
        resolve(child.pid!);
      }
    });

    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cleanup();
      fs.closeSync(startupLogFd);
      const log = readStartupLog(startupLogPath);
      removePid(pidFile);
      reject(new Error(
        `Daemon process exited with code ${code ?? 'unknown'}.` +
        (log ? `\nStartup log:\n${log}` : '\nNo startup log captured.'),
      ));
    });
  });

  return pid;
}

function readStartupLog(logPath: string): string {
  try {
    const content = fs.readFileSync(logPath, 'utf-8').trim();
    // Return last 20 lines to keep error messages manageable
    const lines = content.split('\n');
    return lines.slice(-20).join('\n');
  } catch {
    return '';
  }
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
