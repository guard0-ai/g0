/**
 * Lightweight structured logger for g0.
 *
 * - TTY: human-readable colored output
 * - Non-TTY (CI/pipes): JSON lines for machine parsing
 * - Respects G0_LOG_LEVEL env var (error/warn/info/debug)
 */

const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 } as const;
type LogLevel = keyof typeof LEVELS;

const currentLevel: LogLevel = (process.env.G0_LOG_LEVEL as LogLevel) ?? 'warn';
const isTTY = process.stderr.isTTY ?? false;

function shouldLog(level: LogLevel): boolean {
  return LEVELS[level] <= LEVELS[currentLevel];
}

function formatTTY(level: LogLevel, message: string, data?: Record<string, unknown>): string {
  const prefix = level === 'error' ? '\x1b[31m[ERROR]\x1b[0m'
    : level === 'warn' ? '\x1b[33m[WARN]\x1b[0m'
    : level === 'info' ? '\x1b[36m[INFO]\x1b[0m'
    : '\x1b[90m[DEBUG]\x1b[0m';
  const extra = data ? ` ${JSON.stringify(data)}` : '';
  return `${prefix} ${message}${extra}`;
}

function formatJSON(level: LogLevel, message: string, data?: Record<string, unknown>): string {
  return JSON.stringify({ level, message, ...data, ts: new Date().toISOString() });
}

function log(level: LogLevel, message: string, data?: Record<string, unknown>): void {
  if (!shouldLog(level)) return;
  const formatted = isTTY ? formatTTY(level, message, data) : formatJSON(level, message, data);
  process.stderr.write(formatted + '\n');
}

export const logger = {
  error: (message: string, data?: Record<string, unknown>) => log('error', message, data),
  warn: (message: string, data?: Record<string, unknown>) => log('warn', message, data),
  info: (message: string, data?: Record<string, unknown>) => log('info', message, data),
  debug: (message: string, data?: Record<string, unknown>) => log('debug', message, data),
};
