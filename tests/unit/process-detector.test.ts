import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('node:child_process', () => ({
  execSync: vi.fn(),
}));

import { execSync } from 'node:child_process';
import { detectRunningTools } from '../../src/endpoint/process-detector.js';

const mockExecSync = vi.mocked(execSync);

describe('process-detector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns empty set when ps fails', () => {
    mockExecSync.mockImplementation(() => { throw new Error('command not found'); });
    const result = detectRunningTools();
    expect(result.size).toBe(0);
  });

  it('detects Claude Desktop from process list', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Claude.app/Contents/MacOS/Claude\n' +
      'user  5678  0.0  0.1  /usr/bin/bash\n',
    );
    const result = detectRunningTools();
    expect(result.has('Claude Desktop')).toBe(true);
    expect(result.size).toBe(1);
  });

  it('detects Claude Code from /claude process', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /usr/local/bin/claude --chat\n',
    );
    const result = detectRunningTools();
    expect(result.has('Claude Code')).toBe(true);
  });

  it('detects Cursor from process list', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Cursor.app/Contents/MacOS/Cursor\n',
    );
    const result = detectRunningTools();
    expect(result.has('Cursor')).toBe(true);
  });

  it('detects multiple tools simultaneously', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Claude.app/Contents/MacOS/Claude\n' +
      'user  2345  0.0  0.1  /Applications/Cursor.app/Contents/Frameworks/Cursor Helper\n' +
      'user  3456  0.0  0.1  /usr/bin/openclaw-gateway --port 18789\n' +
      'user  4567  0.0  0.1  /usr/local/bin/code --status\n',
    );
    const result = detectRunningTools();
    expect(result.has('Claude Desktop')).toBe(true);
    expect(result.has('Cursor')).toBe(true);
    expect(result.has('OpenClaw')).toBe(true);
    expect(result.has('VS Code')).toBe(true);
    expect(result.size).toBe(4);
  });

  it('detects JetBrains IDEs', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /opt/idea/bin/idea run\n',
    );
    const result = detectRunningTools();
    expect(result.has('JetBrains (Junie)')).toBe(true);
  });

  it('detects Windsurf', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Windsurf.app/Contents/MacOS/Windsurf\n',
    );
    const result = detectRunningTools();
    expect(result.has('Windsurf')).toBe(true);
  });

  it('detects OpenClaw agent and gateway', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  openclaw-agent --config /etc/openclaw.json\n' +
      'user  2345  0.0  0.1  openclaw-gateway --port 18789\n',
    );
    const result = detectRunningTools();
    expect(result.has('OpenClaw')).toBe(true);
    // Should only appear once despite multiple pattern matches
    expect(result.size).toBe(1);
  });

  it('does not false-positive on unrelated processes', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /usr/bin/bash\n' +
      'user  2345  0.0  0.1  /usr/bin/python3 script.py\n' +
      'user  3456  0.0  0.1  /usr/bin/node server.js\n',
    );
    const result = detectRunningTools();
    expect(result.size).toBe(0);
  });

  it('detects Gemini CLI', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /usr/local/bin/gemini chat\n',
    );
    const result = detectRunningTools();
    expect(result.has('Gemini CLI')).toBe(true);
  });

  it('detects Kiro', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Kiro.app/Contents/MacOS/Kiro\n',
    );
    const result = detectRunningTools();
    expect(result.has('Kiro')).toBe(true);
  });

  it('calls ps aux with correct options', () => {
    mockExecSync.mockReturnValue('');
    detectRunningTools();
    expect(mockExecSync).toHaveBeenCalledWith('ps aux', { encoding: 'utf-8', timeout: 5000 });
  });
});
