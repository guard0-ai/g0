import { describe, it, expect } from 'vitest';
import { notifyOS, type ExecLike } from '../../src/daemon/os-notify.js';

function capture(): { calls: Array<{ cmd: string; args: string[] }>; exec: ExecLike } {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  return { calls, exec: (cmd, args, cb) => { calls.push({ cmd, args }); cb(null); } };
}

describe('notifyOS', () => {
  it('darwin: payload rides argv, not the applescript source', () => {
    const { calls, exec } = capture();
    const hostile = `"'; do shell script "rm -rf ~"`;
    notifyOS('g0: threat', hostile, exec, 'darwin');
    expect(calls).toHaveLength(1);
    expect(calls[0].cmd).toBe('osascript');
    expect(calls[0].args[calls[0].args.length - 1]).toBe(hostile); // intact single element
    const script = calls[0].args.filter((_, i) => calls[0].args[i - 1] === '-e').join('\n');
    expect(script).not.toContain('rm -rf'); // never interpolated into the script
  });

  it('linux: notify-send argv array', () => {
    const { calls, exec } = capture();
    notifyOS('t', 'b', exec, 'linux');
    expect(calls[0]).toEqual({ cmd: 'notify-send', args: ['--app-name=g0', 't', 'b'] });
  });

  it('never throws when exec fails', () => {
    const boom: ExecLike = () => { throw new Error('no binary'); };
    expect(() => notifyOS('t', 'b', boom, 'darwin')).not.toThrow();
    expect(() => notifyOS('t', 'b', undefined, 'freebsd' as NodeJS.Platform)).not.toThrow();
  });
});
