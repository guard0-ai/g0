import { describe, it, expect } from 'vitest';
import { mapHookInput } from '../../src/protect/hooks/mapping.js';

const pre = {
  session_id: 's1', transcript_path: '/t', cwd: '/w',
  hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'rm -rf /' },
};

describe('mapHookInput', () => {
  it('maps PreToolUse to a request event', () => {
    const m = mapHookInput(pre)!;
    expect(m.sessionId).toBe('s1');
    expect(m.hookEventName).toBe('PreToolUse');
    expect(m.event).toMatchObject({
      transport: 'claude-hook', direction: 'request', serverName: 'claude-code',
      toolName: 'Bash', args: { command: 'rm -rf /' },
    });
  });

  it('maps PostToolUse string and object responses', () => {
    const m1 = mapHookInput({ ...pre, hook_event_name: 'PostToolUse', tool_response: 'plain text out' })!;
    expect(m1.event.direction).toBe('response');
    expect(m1.event.responseText).toBe('plain text out');
    const m2 = mapHookInput({ ...pre, hook_event_name: 'PostToolUse', tool_response: { content: [{ type: 'text', text: 'mcp out' }] } })!;
    expect(m2.event.responseText).toBe('mcp out');
    const m3 = mapHookInput({ ...pre, hook_event_name: 'PostToolUse', tool_response: { stdout: 'raw', exit: 0 } })!;
    expect(m3.event.responseText).toContain('raw');
  });

  it('defaults missing session_id to unknown', () => {
    const { session_id: _drop, ...rest } = pre;
    expect(mapHookInput(rest)!.sessionId).toBe('unknown');
  });

  it('returns null on garbage', () => {
    expect(mapHookInput(null)).toBeNull();
    expect(mapHookInput({ hook_event_name: 'PreToolUse' })).toBeNull(); // no tool_name
    expect(mapHookInput('nonsense')).toBeNull();
    expect(mapHookInput({ ...pre, hook_event_name: 'SessionStart' })).toBeNull();
  });
});
