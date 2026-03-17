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

  it('detects Claude Code on Linux via .claude/ path', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  node /home/user/.nvm/versions/node/v20/bin/claude --chat\n' +
      'user  2345  0.0  0.1  node /home/user/.claude/local/bin/claude-code\n',
    );
    const result = detectRunningTools();
    expect(result.has('Claude Code')).toBe(true);
  });

  it('detects Claude Code via @anthropic-ai/claude-code npm path', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  node /home/user/.nvm/versions/node/v20/lib/node_modules/@anthropic-ai/claude-code/cli.js\n',
    );
    const result = detectRunningTools();
    expect(result.has('Claude Code')).toBe(true);
  });

  it('detects Ollama process', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /usr/local/bin/ollama serve\n',
    );
    const result = detectRunningTools();
    expect(result.has('Ollama')).toBe(true);
  });

  it('detects LM Studio process', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/LM Studio.app/Contents/MacOS/lm-studio\n',
    );
    const result = detectRunningTools();
    expect(result.has('LM Studio')).toBe(true);
  });

  it('detects Aider process', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /usr/local/bin/aider --model claude-3.5-sonnet\n',
    );
    const result = detectRunningTools();
    expect(result.has('Aider')).toBe(true);
  });

  it('detects ChatGPT desktop app', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/ChatGPT.app/Contents/MacOS/ChatGPT\n',
    );
    const result = detectRunningTools();
    expect(result.has('ChatGPT')).toBe(true);
  });

  it('detects Microsoft Copilot (AI-specific, not general Office)', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Microsoft Copilot.app/Contents/MacOS/Microsoft Copilot\n',
    );
    const result = detectRunningTools();
    expect(result.has('Microsoft Copilot')).toBe(true);
  });

  it('detects Superhuman email client', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Superhuman.app/Contents/MacOS/Superhuman\n',
    );
    const result = detectRunningTools();
    expect(result.has('Superhuman')).toBe(true);
  });

  it('detects Grammarly', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Grammarly.app/Contents/MacOS/Grammarly\n',
    );
    const result = detectRunningTools();
    expect(result.has('Grammarly')).toBe(true);
  });

  it('detects GPT4All local runtime', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /usr/local/bin/gpt4all chat\n',
    );
    const result = detectRunningTools();
    expect(result.has('GPT4All')).toBe(true);
  });

  it('detects Warp terminal', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Warp.app/Contents/MacOS/stable\n',
    );
    const result = detectRunningTools();
    expect(result.has('Warp')).toBe(true);
  });

  it('detects Otter.ai transcription', () => {
    mockExecSync.mockReturnValue(
      'user  1234  0.0  0.1  /Applications/Otter.app/Contents/MacOS/Otter\n',
    );
    const result = detectRunningTools();
    expect(result.has('Otter.ai')).toBe(true);
  });
});

// Separate describe block that re-imports with os mocked for Windows
describe('process-detector (Windows)', () => {
  it('handles Windows tasklist CSV output', async () => {
    vi.resetModules();

    vi.doMock('node:os', () => ({
      default: { platform: () => 'win32' },
      platform: () => 'win32',
      homedir: () => 'C:\\Users\\test',
      hostname: () => 'test-host',
    }));
    vi.doMock('node:child_process', () => ({
      execSync: vi.fn(() =>
        '"claude.exe","1234","Console","1","50,000 K"\n' +
        '"cursor.exe","2345","Console","1","100,000 K"\n' +
        '"notepad.exe","3456","Console","1","10,000 K"\n',
      ),
    }));

    const { detectRunningTools: detectWin } = await import('../../src/endpoint/process-detector.js');
    const result = detectWin();

    expect(result.has('Claude Code')).toBe(true);
    expect(result.has('Cursor')).toBe(true);
    // Claude Desktop also matches claude.exe
    expect(result.has('Claude Desktop')).toBe(true);
    expect(result.size).toBe(3);

    vi.doUnmock('node:os');
    vi.doUnmock('node:child_process');
  });
});
