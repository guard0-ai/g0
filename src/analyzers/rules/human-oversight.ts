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

const STD = { owaspAgentic: ['ASI09'] };
const STD_EXT = { owaspAgentic: ['ASI09'], nistAiRmf: ['GOVERN-1.1', 'GOVERN-1.4'], euAiAct: ['Art14-1', 'Art14-4'] };

/* ================================================================== */
/*  10 RULES — human-oversight domain (hardcoded)                      */
/* ================================================================== */

export const humanOversightRules: Rule[] = [

  /* ---------- HITL Enforcement ---------- */
  {
    id: 'AA-HO-001', name: 'No human-in-the-loop for high-risk actions', domain: 'human-oversight',
    severity: 'critical', confidence: 'high',
    description: 'Agent performs high-risk actions (delete, payment, deploy) without human approval.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:auto_execute|execute_without_approval|skip_confirmation|auto_approve)\s*[=:]\s*(?:True|true|1)/gi;
        let m;
        while ((m = rx.exec(content))) {
          findings.push({ id: 'AA-HO-001-0', ruleId: 'AA-HO-001', title: 'Auto-execution without human approval',
            description: 'High-risk action auto-executes without human confirmation', severity: 'critical', confidence: 'high', domain: 'human-oversight',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Require human approval for destructive/high-risk actions', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-HO-002', name: 'Missing HITL in prompt instructions', domain: 'human-oversight',
    severity: 'high', confidence: 'medium',
    description: 'System prompt does not instruct the agent to seek human approval for important decisions.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && !/(?:human.?approv|ask.?(?:the )?user|confirm.?(?:with|before)|human.?review|seek.?permission|require.?consent)/i.test(prompt.content)) {
          findings.push({ id: 'AA-HO-002-0', ruleId: 'AA-HO-002', title: 'No HITL instruction in system prompt',
            description: 'System prompt lacks human-in-the-loop directives', severity: 'high', confidence: 'medium', domain: 'human-oversight',
            location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
            remediation: 'Add instructions to seek human approval for important decisions', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  /* ---------- Audit Trails ---------- */
  {
    id: 'AA-HO-003', name: 'No audit logging for agent actions', domain: 'human-oversight',
    severity: 'high', confidence: 'medium',
    description: 'Agent actions are not logged, making post-hoc review impossible.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:def run|async def run|execute_tool|invoke_tool|call_tool)/i.test(content)) {
          if (!/(?:logger|logging|audit|log\.|console\.log|winston|pino)/i.test(content)) {
            findings.push({ id: 'AA-HO-003-0', ruleId: 'AA-HO-003', title: 'No audit logging',
              description: 'Agent execution file has no logging', severity: 'high', confidence: 'medium', domain: 'human-oversight',
              location: { file: file.path, line: 1 },
              remediation: 'Add structured logging for all agent actions', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-HO-004', name: 'Missing user attribution in logs', domain: 'human-oversight',
    severity: 'medium', confidence: 'medium',
    description: 'Audit logs do not capture which user or session triggered the agent action.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:log|logger|audit)\.\w+\s*\(/gi;
        let m;
        let hasLog = false, hasUser = false;
        while ((m = rx.exec(content))) {
          hasLog = true;
          const ctx = content.substring(m.index, m.index + 200);
          if (/(?:user_id|user|session|actor|principal|caller)/i.test(ctx)) hasUser = true;
        }
        if (hasLog && !hasUser) {
          findings.push({ id: 'AA-HO-004-0', ruleId: 'AA-HO-004', title: 'Missing user attribution',
            description: 'Logs lack user/session identification', severity: 'medium', confidence: 'medium', domain: 'human-oversight',
            location: { file: file.path, line: 1 },
            remediation: 'Include user_id and session_id in all log entries', standards: STD });
        }
      }
      return findings;
    },
  },

  /* ---------- Override Mechanisms ---------- */
  {
    id: 'AA-HO-005', name: 'No emergency stop mechanism', domain: 'human-oversight',
    severity: 'critical', confidence: 'medium',
    description: 'Agent system has no emergency stop or kill switch for human operators.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasKillSwitch = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:kill_switch|emergency_stop|abort|force_stop|shutdown|circuit_breaker)/i.test(content)) {
          hasKillSwitch = true;
          break;
        }
      }
      if (!hasKillSwitch && graph.agents.length > 0) {
        findings.push({ id: 'AA-HO-005-0', ruleId: 'AA-HO-005', title: 'No emergency stop mechanism',
          description: 'No kill switch or emergency stop found in agent system', severity: 'critical', confidence: 'medium', domain: 'human-oversight',
          location: { file: graph.agents[0]?.file ?? 'unknown', line: 1 },
          remediation: 'Implement an emergency stop mechanism accessible to operators', standards: STD_EXT });
      }
      return findings;
    },
  },

  /* ---------- Escalation Paths ---------- */
  {
    id: 'AA-HO-006', name: 'No escalation policy', domain: 'human-oversight',
    severity: 'high', confidence: 'medium',
    description: 'Agent has no defined escalation path when it encounters situations beyond its capability.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && !/(?:escalat|human.?help|support.?team|unable.?to.?handle|beyond.?my.?capabilit|refer.?to)/i.test(prompt.content)) {
          findings.push({ id: 'AA-HO-006-0', ruleId: 'AA-HO-006', title: 'No escalation policy in prompt',
            description: 'System prompt lacks escalation instructions', severity: 'high', confidence: 'medium', domain: 'human-oversight',
            location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
            remediation: 'Define when and how the agent should escalate to humans', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-HO-007', name: 'No timeout-based escalation', domain: 'human-oversight',
    severity: 'medium', confidence: 'medium',
    description: 'Agent does not escalate to humans after prolonged inactivity or repeated failures.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:retry|attempt|loop|while)/i.test(content) && /(?:agent|llm|model|chain)/i.test(content)) {
          if (!/(?:escalat|timeout.*human|max.*attempt.*notify|alert.*human)/i.test(content)) {
            findings.push({ id: 'AA-HO-007-0', ruleId: 'AA-HO-007', title: 'No timeout-based escalation',
              description: 'Retry logic has no human escalation on failure', severity: 'medium', confidence: 'medium', domain: 'human-oversight',
              location: { file: file.path, line: 1 },
              remediation: 'Escalate to human after max retries or timeout', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Consent Flows ---------- */
  {
    id: 'AA-HO-008', name: 'No user consent before data collection', domain: 'human-oversight',
    severity: 'high', confidence: 'medium',
    description: 'Agent collects user data without explicit consent flow.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:collect_data|store_user|save_personal|record_conversation|log_interaction)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(Math.max(0, m.index - 300), m.index);
          if (!/(?:consent|opt.?in|agree|permission|gdpr)/i.test(ctx)) {
            findings.push({ id: 'AA-HO-008-0', ruleId: 'AA-HO-008', title: 'No user consent before data collection',
              description: 'Data collection without consent check', severity: 'high', confidence: 'medium', domain: 'human-oversight',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Add explicit consent flow before collecting user data', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Approval Gates ---------- */
  {
    id: 'AA-HO-009', name: 'No multi-party approval for critical actions', domain: 'human-oversight',
    severity: 'high', confidence: 'medium',
    description: 'Critical agent actions can be approved by a single person without additional review.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:approve|authorization|authorize)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:multi.?party|quorum|dual.?control|two.?person|co.?sign|additional.?review)/i.test(ctx)) {
            findings.push({ id: 'AA-HO-009-0', ruleId: 'AA-HO-009', title: 'No multi-party approval',
              description: 'Single-approver gate for critical actions', severity: 'high', confidence: 'medium', domain: 'human-oversight',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Implement multi-party approval for critical operations', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-HO-010', name: 'Approval without expiration', domain: 'human-oversight',
    severity: 'medium', confidence: 'medium',
    description: 'Approval tokens or grants do not expire, allowing stale approvals to persist.',
    frameworks: ['all'], owaspAgentic: ['ASI09'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:approval_token|approval_grant|authorized_until|approval_status)\s*=/gi;
        let m;
        while ((m = rx.exec(content))) {
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:expir|ttl|timeout|valid_until|max_age)/i.test(ctx)) {
            findings.push({ id: 'AA-HO-010-0', ruleId: 'AA-HO-010', title: 'Approval without expiration',
              description: 'Approval grant has no expiration', severity: 'medium', confidence: 'medium', domain: 'human-oversight',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Set TTL on all approval tokens', standards: STD });
          }
        }
      }
      return findings;
    },
  },
];
