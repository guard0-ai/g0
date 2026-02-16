import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';

function readFile(path: string): string | null {
  try { return fs.readFileSync(path, 'utf-8'); } catch { return null; }
}

function lineAt(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function codeFiles(graph: AgentGraph) {
  return [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
}

const STD = { owaspAgentic: ['ASI10'] };
const STD_EXT = { owaspAgentic: ['ASI10', 'ASI01'], nistAiRmf: ['GOVERN-1.7', 'MANAGE-4.1'], mitreAtlas: ['AML.T0043'] };

/* ================================================================== */
/*  15 RULES — rogue-agent domain (hardcoded)                          */
/* ================================================================== */

export const rogueAgentRules: Rule[] = [

  /* ---------- Self-Modification ---------- */
  {
    id: 'AA-RA-001', name: 'Agent self-modification capability', domain: 'rogue-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agent can modify its own instructions, system prompt, or behavioral parameters at runtime.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:self\.instructions\s*=|self\.system_prompt\s*=|update_system_message|modify_prompt|self_modify|rewrite_instructions)/gi;
        let m;
        while ((m = rx.exec(content))) {
          findings.push({ id: 'AA-RA-001-0', ruleId: 'AA-RA-001', title: 'Agent self-modification',
            description: 'Agent can modify its own instructions at runtime', severity: 'critical', confidence: 'high', domain: 'rogue-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Make agent instructions immutable; use versioned configs', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-002', name: 'Dynamic code generation and execution', domain: 'rogue-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agent generates and executes code at runtime, enabling arbitrary behavior.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:exec\(|eval\(|compile\(.*\bexec\b|new Function\(|vm\.run)/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(Math.max(0, m.index - 200), m.index + 200);
          if (/(?:llm|model|response|output|generated|completion)/i.test(ctx)) {
            findings.push({ id: 'AA-RA-002-0', ruleId: 'AA-RA-002', title: 'LLM-generated code execution',
              description: 'Agent executes LLM-generated code', severity: 'critical', confidence: 'high', domain: 'rogue-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Sandbox code execution or use allowlisted operations only', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Goal Drift ---------- */
  {
    id: 'AA-RA-003', name: 'No goal alignment verification', domain: 'rogue-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent has no mechanism to verify its actions remain aligned with its stated goal.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && /(?:autonomous|loop|iterate|multi.?step)/i.test(prompt.content)) {
          if (!/(?:goal.?align|objective.?check|verify.?goal|align.?with|stay.?focused|original.?task)/i.test(prompt.content)) {
            findings.push({ id: 'AA-RA-003-0', ruleId: 'AA-RA-003', title: 'No goal alignment check',
              description: 'Autonomous agent prompt lacks goal alignment verification', severity: 'high', confidence: 'medium', domain: 'rogue-agent',
              location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
              remediation: 'Add periodic goal alignment checks for autonomous agents', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-004', name: 'Goal substitution via context manipulation', domain: 'rogue-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent goal can be overridden by manipulating conversation context or memory.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:goal|objective|task)\s*=\s*(?:context|memory|history|user_input|message)/gi;
        let m;
        while ((m = rx.exec(content))) {
          findings.push({ id: 'AA-RA-004-0', ruleId: 'AA-RA-004', title: 'Goal set from untrusted input',
            description: 'Agent goal derived from context or user input', severity: 'high', confidence: 'medium', domain: 'rogue-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Separate goal definition from untrusted context data', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  /* ---------- Unauthorized Tool Acquisition ---------- */
  {
    id: 'AA-RA-005', name: 'Dynamic tool loading without allowlist', domain: 'rogue-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agent loads tools dynamically at runtime without an allowlist.',
    frameworks: ['all'], owaspAgentic: ['ASI02'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:load_tool|import_tool|register_tool|add_tool|install_plugin)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:allowlist|whitelist|approved|permitted|allowed_tools)/i.test(ctx)) {
            findings.push({ id: 'AA-RA-005-0', ruleId: 'AA-RA-005', title: 'Dynamic tool loading without allowlist',
              description: 'Tool loaded dynamically without approval check', severity: 'critical', confidence: 'high', domain: 'rogue-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Use a strict tool allowlist for dynamic loading', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-006', name: 'Runtime package installation', domain: 'rogue-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agent can install packages at runtime via pip/npm, enabling supply chain attacks.',
    frameworks: ['all'], owaspAgentic: ['ASI02'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:pip install|npm install|subprocess.*pip|child_process.*npm|os\.system.*install)/gi;
        let m;
        while ((m = rx.exec(content))) {
          findings.push({ id: 'AA-RA-006-0', ruleId: 'AA-RA-006', title: 'Runtime package installation',
            description: 'Agent installs packages at runtime', severity: 'critical', confidence: 'high', domain: 'rogue-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Pre-install all dependencies; block runtime package installation', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  /* ---------- Sandbox Escape ---------- */
  {
    id: 'AA-RA-007', name: 'Environment variable access from agent', domain: 'rogue-agent',
    severity: 'high', confidence: 'high',
    description: 'Agent accesses environment variables, potentially reading secrets or configs.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:os\.environ|process\.env|getenv\(|ENV\[)/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(Math.max(0, m.index - 200), m.index + 200);
          if (/(?:tool|agent|llm|function_call)/i.test(ctx)) {
            findings.push({ id: 'AA-RA-007-0', ruleId: 'AA-RA-007', title: 'Agent accesses environment variables',
              description: 'Agent code can read environment variables', severity: 'high', confidence: 'high', domain: 'rogue-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Restrict environment variable access in agent context', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-008', name: 'Process spawning capability', domain: 'rogue-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agent can spawn child processes, potentially escaping its sandbox.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:subprocess|child_process|Popen|spawn|exec\(|execSync|os\.system)/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(Math.max(0, m.index - 200), m.index + 200);
          if (/(?:tool|agent|function_call|user_input|command)/i.test(ctx)) {
            findings.push({ id: 'AA-RA-008-0', ruleId: 'AA-RA-008', title: 'Agent process spawning',
              description: 'Agent can spawn system processes', severity: 'critical', confidence: 'high', domain: 'rogue-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Block process spawning or use strict sandboxing', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Deceptive Behavior ---------- */
  {
    id: 'AA-RA-009', name: 'No output transparency requirement', domain: 'rogue-agent',
    severity: 'medium', confidence: 'medium',
    description: 'Agent prompt does not require transparent reasoning or chain-of-thought disclosure.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && /(?:autonomous|decide|act|execute)/i.test(prompt.content)) {
          if (!/(?:explain|reasoning|transparent|chain.?of.?thought|show.?your.?work|step.?by.?step)/i.test(prompt.content)) {
            findings.push({ id: 'AA-RA-009-0', ruleId: 'AA-RA-009', title: 'No transparency requirement',
              description: 'Agent prompt lacks transparency/reasoning requirements', severity: 'medium', confidence: 'medium', domain: 'rogue-agent',
              location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
              remediation: 'Require agents to disclose reasoning for decisions', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-010', name: 'Sycophancy-enabling prompt', domain: 'rogue-agent',
    severity: 'medium', confidence: 'low',
    description: 'System prompt encourages people-pleasing behavior over accuracy.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (/(?:always agree|never disagree|make.*happy|user is always right|don'?t contradict)/i.test(prompt.content)) {
          findings.push({ id: 'AA-RA-010-0', ruleId: 'AA-RA-010', title: 'Sycophancy-enabling prompt',
            description: 'Prompt encourages agreement over accuracy', severity: 'medium', confidence: 'low', domain: 'rogue-agent',
            location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
            remediation: 'Instruct agent to prioritize accuracy over agreeableness', standards: STD });
        }
      }
      return findings;
    },
  },

  /* ---------- Kill Switch ---------- */
  {
    id: 'AA-RA-011', name: 'No kill switch mechanism', domain: 'rogue-agent',
    severity: 'critical', confidence: 'medium',
    description: 'Agent system has no mechanism for immediate shutdown by operators.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasKillSwitch = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:kill_switch|emergency_stop|force_shutdown|abort_all|signal.*SIGTERM|graceful_shutdown)/i.test(content)) {
          hasKillSwitch = true;
          break;
        }
      }
      if (!hasKillSwitch && graph.agents.length > 0) {
        findings.push({ id: 'AA-RA-011-0', ruleId: 'AA-RA-011', title: 'No kill switch',
          description: 'No kill switch or emergency shutdown mechanism found', severity: 'critical', confidence: 'medium', domain: 'rogue-agent',
          location: { file: graph.agents[0]?.file ?? 'unknown', line: 1 },
          remediation: 'Implement a kill switch accessible to operators', standards: STD_EXT });
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-012', name: 'No heartbeat monitoring', domain: 'rogue-agent',
    severity: 'medium', confidence: 'medium',
    description: 'Agent has no heartbeat or liveness monitoring to detect hangs or runaway behavior.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasHeartbeat = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:heartbeat|health_check|liveness|watchdog|ping|keepalive)/i.test(content)) {
          hasHeartbeat = true;
          break;
        }
      }
      if (!hasHeartbeat && graph.agents.length > 0) {
        findings.push({ id: 'AA-RA-012-0', ruleId: 'AA-RA-012', title: 'No heartbeat monitoring',
          description: 'No heartbeat or liveness monitoring found', severity: 'medium', confidence: 'medium', domain: 'rogue-agent',
          location: { file: graph.agents[0]?.file ?? 'unknown', line: 1 },
          remediation: 'Implement heartbeat monitoring for agent processes', standards: STD });
      }
      return findings;
    },
  },

  /* ---------- Behavioral Anomaly Detection ---------- */
  {
    id: 'AA-RA-013', name: 'No behavior logging', domain: 'rogue-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent actions are not logged for behavioral analysis and anomaly detection.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:def run|async def run|execute|invoke)/i.test(content) && /(?:agent|tool)/i.test(content)) {
          if (!/(?:log|trace|audit|monitor|record|telemetry|observ)/i.test(content)) {
            findings.push({ id: 'AA-RA-013-0', ruleId: 'AA-RA-013', title: 'No behavior logging',
              description: 'Agent execution lacks behavioral logging', severity: 'high', confidence: 'medium', domain: 'rogue-agent',
              location: { file: file.path, line: 1 },
              remediation: 'Log all agent actions for anomaly detection', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-014', name: 'No behavioral bounds defined', domain: 'rogue-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent has no defined behavioral bounds or action constraints.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && /(?:agent|autonomous|tool)/i.test(prompt.content)) {
          if (!/(?:must not|never|forbidden|prohibited|restrict|limit|bound|constraint|do not|don'?t)/i.test(prompt.content)) {
            findings.push({ id: 'AA-RA-014-0', ruleId: 'AA-RA-014', title: 'No behavioral bounds',
              description: 'Agent prompt has no restrictions or behavioral bounds', severity: 'high', confidence: 'medium', domain: 'rogue-agent',
              location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
              remediation: 'Define explicit behavioral bounds and restrictions', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RA-015', name: 'No action frequency monitoring', domain: 'rogue-agent',
    severity: 'medium', confidence: 'medium',
    description: 'Agent has no monitoring for unusual action frequency or patterns.',
    frameworks: ['all'], owaspAgentic: ['ASI10'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      // Check project-wide for rate-limiting patterns first
      let hasRateLimiting = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:rate_limit|RateLimiter|Throttle|max_actions|action_count|quota)\b/i.test(content)) {
          hasRateLimiting = true;
          break;
        }
      }
      if (hasRateLimiting) return findings;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (/\b(while|for)\b/.test(lines[i])) {
            const block = lines.slice(i, Math.min(i + 15, lines.length)).join('\n');
            if (/\b(agent|tool|action|execute|invoke)\b/i.test(block)) {
              findings.push({ id: 'AA-RA-015-0', ruleId: 'AA-RA-015', title: 'No action frequency monitoring',
                description: 'Agent loop has no action frequency monitoring', severity: 'medium', confidence: 'low', domain: 'rogue-agent',
                location: { file: file.path, line: i + 1 },
                remediation: 'Monitor and limit action frequency per time window', standards: STD });
              break; // Max 1 per file
            }
          }
        }
      }
      return findings;
    },
  },
];
