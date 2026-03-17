import { execSync } from 'node:child_process';
import * as os from 'node:os';

interface ProcessSignature {
  tool: string;
  patterns: string[];
  winPatterns?: string[];
}

const SIGNATURES: ProcessSignature[] = [
  // ── AI Code Editors & Agents ──────────────────────────────────────────────
  // These tools exist solely for AI-assisted coding — process = AI usage.
  { tool: 'Claude Desktop', patterns: ['Claude.app', 'Claude Helper', 'claude-desktop'], winPatterns: ['claude.exe'] },
  { tool: 'Claude Code', patterns: ['/claude', '.claude/', 'claude-code', '@anthropic-ai/claude-code'], winPatterns: ['claude.exe'] },
  { tool: 'ChatGPT', patterns: ['ChatGPT.app', 'ChatGPT Helper', 'com.openai.chat'], winPatterns: ['chatgpt.exe'] },
  { tool: 'Cursor', patterns: ['Cursor.app', 'Cursor Helper', 'cursor'], winPatterns: ['cursor.exe'] },
  { tool: 'Windsurf', patterns: ['Windsurf.app', 'Windsurf Helper', 'windsurf'], winPatterns: ['windsurf.exe'] },
  { tool: 'VS Code', patterns: ['Code.app', 'Code Helper', '/code'], winPatterns: ['code.exe'] },
  { tool: 'Zed', patterns: ['Zed.app', '/zed'], winPatterns: ['zed.exe'] },
  { tool: 'JetBrains (Junie)', patterns: ['/idea', '/webstorm', '/pycharm', '/goland', '/rider', '/clion', '/phpstorm', '/rubymine'], winPatterns: ['idea64.exe', 'webstorm64.exe', 'pycharm64.exe', 'goland64.exe', 'rider64.exe', 'clion64.exe', 'phpstorm64.exe', 'rubymine64.exe'] },
  { tool: 'Gemini CLI', patterns: ['/gemini', 'gemini'], winPatterns: ['gemini.exe'] },
  { tool: 'Gemini Desktop', patterns: ['Google Gemini', 'Gemini.app'], winPatterns: ['gemini desktop.exe'] },
  { tool: 'Amazon Q Developer', patterns: ['amazon-q', 'Amazon Q'], winPatterns: ['amazon-q.exe'] },
  { tool: 'Cline', patterns: ['cline'], winPatterns: ['cline.exe'] },
  { tool: 'Roo Code', patterns: ['roo-code'], winPatterns: ['roo-code.exe'] },
  { tool: 'Copilot CLI', patterns: ['github-copilot'], winPatterns: ['github-copilot.exe'] },
  { tool: 'Kiro', patterns: ['Kiro.app', '/kiro', 'kiro'], winPatterns: ['kiro.exe'] },
  { tool: 'Continue', patterns: ['continue'], winPatterns: ['continue.exe'] },
  { tool: 'Augment Code', patterns: ['augment'], winPatterns: ['augment.exe'] },
  { tool: 'BoltAI', patterns: ['BoltAI.app'] },
  { tool: 'Tabnine', patterns: ['TabNine', 'tabnine'], winPatterns: ['tabnine.exe'] },
  { tool: 'Warp', patterns: ['Warp.app', 'warp-terminal'], winPatterns: ['warp.exe'] },
  { tool: 'OpenClaw', patterns: ['openclaw', 'openclaw-gateway', 'openclaw-agent'], winPatterns: ['openclaw.exe'] },

  // ── Local AI Runtimes ─────────────────────────────────────────────────────
  // Running = actively serving/hosting AI models on this machine.
  { tool: 'Ollama', patterns: ['ollama'], winPatterns: ['ollama.exe'] },
  { tool: 'LM Studio', patterns: ['lm-studio', 'LM Studio', 'lmstudio'], winPatterns: ['lm studio.exe', 'lmstudio.exe'] },
  { tool: 'Jan', patterns: ['jan'], winPatterns: ['jan.exe'] },
  { tool: 'GPT4All', patterns: ['gpt4all', 'GPT4All'], winPatterns: ['gpt4all.exe'] },
  { tool: 'Aider', patterns: ['aider'], winPatterns: ['aider.exe'] },
  { tool: 'Msty', patterns: ['Msty.app', 'msty'], winPatterns: ['msty.exe'] },

  // ── AI-First Desktop Apps ─────────────────────────────────────────────────
  // These apps are purpose-built around AI — the app IS the AI feature.
  { tool: 'Microsoft Copilot', patterns: ['Microsoft Copilot', 'ms-copilot'], winPatterns: ['microsoft.copilot.exe'] },
  { tool: 'Superhuman', patterns: ['Superhuman.app', 'Superhuman Helper'], winPatterns: ['superhuman.exe'] },
  { tool: 'Grammarly', patterns: ['Grammarly.app', 'Grammarly Helper', 'grammarly'], winPatterns: ['grammarly.exe'] },
  { tool: 'Raycast', patterns: ['Raycast.app', 'raycast'] },
  { tool: 'Perplexity', patterns: ['Perplexity.app'], winPatterns: ['perplexity.exe'] },
  { tool: 'Pieces', patterns: ['Pieces.app', 'pieces-os', 'Pieces OS'], winPatterns: ['pieces os.exe', 'pieces.exe'] },

  // ── AI Meeting & Transcription ────────────────────────────────────────────
  // These apps exist solely for AI transcription/note-taking.
  { tool: 'Otter.ai', patterns: ['Otter.app', 'otter'], winPatterns: ['otter.exe'] },
  { tool: 'Fireflies.ai', patterns: ['Fireflies.app'], winPatterns: ['fireflies.exe'] },
  { tool: 'Krisp', patterns: ['Krisp.app', 'krisp'], winPatterns: ['krisp.exe'] },
  { tool: 'Granola', patterns: ['Granola.app', 'granola'] },

  // ── AI Plugins / Copilot Helpers in General-Purpose Apps ────────────────
  // We don't flag Word/Slack/Zoom themselves — we flag the AI helper
  // processes they spawn, which proves active AI feature usage.
  { tool: 'Microsoft 365 Copilot', patterns: ['Microsoft.Copilot', 'CopilotRuntime', 'ai-plugin-host'], winPatterns: ['microsoft.copilot.exe', 'copilotruntime.exe'] },
  { tool: 'Slack AI', patterns: ['slack-ai-', 'SlackAI'], winPatterns: ['slackai.exe'] },
  { tool: 'Zoom AI Companion', patterns: ['ZoomAICompanion', 'zoom-ai-'], winPatterns: ['zoomaicompanion.exe'] },
  { tool: 'Notion AI', patterns: ['notion-ai-', 'NotionAI'], winPatterns: ['notionai.exe'] },
  { tool: 'Figma AI', patterns: ['figma-ai-', 'FigmaAI'] },
];

function getProcessOutput(): string {
  const platform = os.platform();

  if (platform === 'win32') {
    try {
      return execSync('tasklist /FO CSV /NH', { encoding: 'utf-8', timeout: 5000 });
    } catch {
      return '';
    }
  }

  try {
    return execSync('ps aux', { encoding: 'utf-8', timeout: 5000 });
  } catch {
    return '';
  }
}

function matchWindows(output: string, signatures: ProcessSignature[]): Set<string> {
  const running = new Set<string>();

  // tasklist CSV format: "Image Name","PID","Session Name","Session#","Mem Usage"
  const imageNames = new Set<string>();
  for (const line of output.split('\n')) {
    const match = line.match(/^"([^"]+)"/);
    if (match) {
      imageNames.add(match[1].toLowerCase());
    }
  }

  for (const sig of signatures) {
    if (!sig.winPatterns) continue;
    for (const pattern of sig.winPatterns) {
      if (imageNames.has(pattern.toLowerCase())) {
        running.add(sig.tool);
        break;
      }
    }
  }

  return running;
}

export function detectRunningTools(): Set<string> {
  const output = getProcessOutput();
  if (!output) return new Set<string>();

  if (os.platform() === 'win32') {
    return matchWindows(output, SIGNATURES);
  }

  const running = new Set<string>();
  for (const sig of SIGNATURES) {
    for (const pattern of sig.patterns) {
      if (output.includes(pattern)) {
        running.add(sig.tool);
        break;
      }
    }
  }

  return running;
}
