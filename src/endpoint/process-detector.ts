import { execSync } from 'node:child_process';

interface ProcessSignature {
  tool: string;
  patterns: string[];
}

const SIGNATURES: ProcessSignature[] = [
  { tool: 'Claude Desktop', patterns: ['Claude.app', 'Claude Helper'] },
  { tool: 'Claude Code', patterns: ['/claude'] },
  { tool: 'Cursor', patterns: ['Cursor.app', 'Cursor Helper'] },
  { tool: 'Windsurf', patterns: ['Windsurf.app', 'Windsurf Helper'] },
  { tool: 'VS Code', patterns: ['Code.app', 'Code Helper', '/code'] },
  { tool: 'Zed', patterns: ['Zed.app', '/zed'] },
  { tool: 'JetBrains (Junie)', patterns: ['/idea', '/webstorm', '/pycharm', '/goland', '/rider', '/clion', '/phpstorm', '/rubymine'] },
  { tool: 'Gemini CLI', patterns: ['/gemini'] },
  { tool: 'Amazon Q Developer', patterns: ['amazon-q', 'Amazon Q'] },
  { tool: 'Cline', patterns: ['cline'] },
  { tool: 'Roo Code', patterns: ['roo-code'] },
  { tool: 'Copilot CLI', patterns: ['github-copilot'] },
  { tool: 'Kiro', patterns: ['Kiro.app', '/kiro'] },
  { tool: 'Continue', patterns: ['continue'] },
  { tool: 'Augment Code', patterns: ['augment'] },
  { tool: 'BoltAI', patterns: ['BoltAI.app'] },
];

export function detectRunningTools(): Set<string> {
  const running = new Set<string>();

  let psOutput: string;
  try {
    psOutput = execSync('ps aux', { encoding: 'utf-8', timeout: 5000 });
  } catch {
    return running;
  }

  for (const sig of SIGNATURES) {
    for (const pattern of sig.patterns) {
      if (psOutput.includes(pattern)) {
        running.add(sig.tool);
        break;
      }
    }
  }

  return running;
}
