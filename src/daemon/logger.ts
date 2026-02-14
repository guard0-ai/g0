import * as fs from 'node:fs';
import * as path from 'node:path';

const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_ROTATED = 3;

export class DaemonLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
  }

  info(message: string): void {
    this.write('INFO', message);
  }

  warn(message: string): void {
    this.write('WARN', message);
  }

  error(message: string): void {
    this.write('ERROR', message);
  }

  private write(level: string, message: string): void {
    this.rotateIfNeeded();
    const timestamp = new Date().toISOString();
    const line = `[${timestamp}] [${level}] ${message}\n`;
    fs.appendFileSync(this.logPath, line);
  }

  private rotateIfNeeded(): void {
    try {
      const stat = fs.statSync(this.logPath);
      if (stat.size < MAX_LOG_SIZE) return;
    } catch {
      return; // File doesn't exist yet
    }

    // Rotate: daemon.log.3 → delete, .2 → .3, .1 → .2, current → .1
    for (let i = MAX_ROTATED; i >= 1; i--) {
      const from = i === 1 ? this.logPath : `${this.logPath}.${i - 1}`;
      const to = `${this.logPath}.${i}`;
      try {
        if (i === MAX_ROTATED) {
          fs.unlinkSync(to);
        }
        fs.renameSync(from, to);
      } catch {
        // File may not exist
      }
    }
  }

  /** Read last N lines of the log file. */
  tail(lines: number = 50): string[] {
    try {
      const content = fs.readFileSync(this.logPath, 'utf-8');
      const allLines = content.split('\n').filter(l => l.length > 0);
      return allLines.slice(-lines);
    } catch {
      return [];
    }
  }
}
