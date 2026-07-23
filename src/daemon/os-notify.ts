/**
 * Best-effort native OS notifications for the watcher. Fire-and-forget:
 * a missing binary or display session must never affect the daemon loop.
 * Arguments are always passed as argv ARRAYS — finding text (which can be
 * attacker-influenced) is never interpolated into a shell string.
 */

import { execFile } from 'node:child_process';

export type ExecLike = (cmd: string, args: string[], cb: (err: Error | null) => void) => unknown;

const swallow = (): void => { /* notification delivery is best-effort */ };

/**
 * Argv-flag-smuggling guard: notification text can be attacker-influenced
 * (finding details from scanned skill content). A value starting with `-`
 * would be parsed as a FLAG by notify-send/osascript/msg — strip leading
 * dashes/whitespace and bound the length.
 */
function safeText(text: string): string {
  const stripped = text.replace(/^[\s-]+/, '').slice(0, 400);
  return stripped.length > 0 ? stripped : 'g0';
}

export function notifyOS(rawTitle: string, rawBody: string, execFn?: ExecLike, platform?: NodeJS.Platform): void {
  const run: ExecLike = execFn ?? ((cmd, args, cb) => execFile(cmd, args, cb));
  const os = platform ?? process.platform;
  const title = safeText(rawTitle);
  const body = safeText(rawBody);
  try {
    if (os === 'darwin') {
      // osascript with the payload as a separate argv element via `on run argv`
      // — quotes/backslashes in findings cannot escape into the script.
      run('osascript', [
        '-e', 'on run argv',
        '-e', 'display notification (item 2 of argv) with title (item 1 of argv)',
        '-e', 'end run',
        title, body,
      ], swallow);
    } else if (os === 'linux') {
      run('notify-send', ['--app-name=g0', '--', title, body], swallow);
    } else if (os === 'win32') {
      run('msg', ['*', `${title}: ${body}`], swallow);
    }
  } catch {
    // spawn itself failed — nothing more to do
  }
}
