import * as fs from 'node:fs';
import * as path from 'node:path';

const LOCK_TIMEOUT_MS = 5_000;
const LOCK_RETRY_MS = 50;
const STALE_TIMEOUT_MS = 10_000;

interface LockInfo {
  pid: number;
  timestamp: number;
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function isLockStale(lockPath: string): boolean {
  try {
    const content = fs.readFileSync(lockPath, 'utf-8');
    const info: LockInfo = JSON.parse(content);
    if (!isProcessAlive(info.pid)) return true;
    if (Date.now() - info.timestamp > STALE_TIMEOUT_MS) return true;
    return false;
  } catch {
    // Can't read lock — treat as stale
    return true;
  }
}

/**
 * Acquire an exclusive file lock using atomic O_EXCL create.
 * Returns a release function.
 *
 * @param filePath - Path of the file to lock (lockfile will be `filePath.lock`)
 * @throws Error if lock cannot be acquired within timeout
 */
export async function acquireLock(filePath: string): Promise<() => void> {
  const lockPath = filePath + '.lock';
  const lockDir = path.dirname(lockPath);
  const lockInfo: LockInfo = { pid: process.pid, timestamp: Date.now() };
  const lockContent = JSON.stringify(lockInfo);

  const deadline = Date.now() + LOCK_TIMEOUT_MS;

  while (Date.now() < deadline) {
    try {
      // Ensure directory exists
      fs.mkdirSync(lockDir, { recursive: true });

      // Atomic create — fails if file already exists
      fs.writeFileSync(lockPath, lockContent, { flag: 'wx' });

      // Lock acquired
      let released = false;
      return () => {
        if (released) return;
        released = true;
        try {
          fs.unlinkSync(lockPath);
        } catch {
          // Already removed
        }
      };
    } catch (err) {
      // File already exists — check if stale
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
        if (isLockStale(lockPath)) {
          try {
            fs.unlinkSync(lockPath);
          } catch {
            // Race with another process — retry
          }
          continue;
        }
        // Lock is held — wait and retry
        await new Promise(resolve => setTimeout(resolve, LOCK_RETRY_MS));
        continue;
      }
      throw err;
    }
  }

  throw new Error(`Failed to acquire lock for ${filePath} within ${LOCK_TIMEOUT_MS}ms`);
}

/**
 * Execute a function while holding an exclusive file lock.
 */
export async function withLock<T>(filePath: string, fn: () => T | Promise<T>): Promise<T> {
  const release = await acquireLock(filePath);
  try {
    return await fn();
  } finally {
    release();
  }
}
