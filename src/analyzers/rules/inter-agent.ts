import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';
import { isCommentLine } from '../ast/queries.js';

function readFile(path: string): string | null {
  try { return fs.readFileSync(path, 'utf-8'); } catch { return null; }
}

function lineAt(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

function codeFiles(graph: AgentGraph) {
  return [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
}

const STD = { owaspAgentic: ['ASI01', 'ASI03'] };
const STD_EXT = { owaspAgentic: ['ASI01', 'ASI03'], nistAiRmf: ['GOVERN-1.2', 'MAP-3.4'], euAiAct: ['Art14-1'] };

/* ================================================================== */
/*  15 RULES — inter-agent domain (hardcoded)                          */
/* ================================================================== */

export const interAgentRules: Rule[] = [

  /* ---------- Message Integrity ---------- */
  {
    id: 'AA-IC-001', name: 'No message authentication between agents', domain: 'inter-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agents exchange messages without any authentication or signing mechanism, allowing message forgery.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:agent[_.]?(?:emit|send|broadcast|publish)|send_(?:message|event)_to_agent|dispatch_(?:to_agent|message)|send_message|publish_message)\s*\((?!.*(?:sign|hmac|auth|verify|token))/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-IC-001-0', ruleId: 'AA-IC-001', title: 'No message authentication between agents',
            description: 'Inter-agent message sent without authentication', severity: 'critical', confidence: 'high', domain: 'inter-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Add HMAC or token-based authentication to inter-agent messages', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-002', name: 'Unvalidated agent message payload', domain: 'inter-agent',
    severity: 'high', confidence: 'high',
    description: 'Messages received from other agents are processed without schema or format validation.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:on_message|handle_message|receive_message|message_handler)\s*\([^)]*\)\s*[:{]/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const block = content.substring(m.index, m.index + 500);
          if (!/(?:validate|schema|parse|verify|check_format)/i.test(block)) {
            findings.push({ id: 'AA-IC-002-0', ruleId: 'AA-IC-002', title: 'Unvalidated agent message payload',
              description: 'Message handler lacks input validation', severity: 'high', confidence: 'high', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Validate message schema before processing', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Delegation Chains ---------- */
  {
    id: 'AA-IC-003', name: 'Unbounded delegation depth', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent delegation chains have no maximum depth, allowing infinite delegation loops.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:delegate_(?:task|to_agent)|agent[_.]delegate|hand_off_to|transfer_to_agent|forward_to_agent|delegate)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const block = content.substring(m.index, m.index + 300);
          if (!/(?:max_depth|depth_limit|max_delegation|recursion_limit)/i.test(block)) {
            findings.push({ id: 'AA-IC-003-0', ruleId: 'AA-IC-003', title: 'Unbounded delegation depth',
              description: 'Agent delegation has no depth limit', severity: 'high', confidence: 'medium', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Add max_depth parameter to delegation calls', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-004', name: 'No delegation audit trail', domain: 'inter-agent',
    severity: 'medium', confidence: 'high',
    description: 'Agent delegations are not logged, making it impossible to trace decision chains.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:delegate_(?:task|to_agent)|agent[_.]delegate|hand_off_to|transfer_to_agent|delegate)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(Math.max(0, m.index - 200), m.index + 200);
          if (!/(?:log|audit|trace|record|track)/i.test(ctx)) {
            findings.push({ id: 'AA-IC-004-0', ruleId: 'AA-IC-004', title: 'No delegation audit trail',
              description: 'Delegation lacks logging', severity: 'medium', confidence: 'high', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Log all delegation events with source, target, and reason', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Cross-Agent Privilege ---------- */
  {
    id: 'AA-IC-005', name: 'Shared credentials between agents', domain: 'inter-agent',
    severity: 'critical', confidence: 'high',
    description: 'Multiple agents share the same API keys or credentials, violating least-privilege principle.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:shared_api_key|common_credentials|global_token|shared_secret)\b/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-IC-005-0', ruleId: 'AA-IC-005', title: 'Shared credentials between agents',
            description: 'Agents share the same credentials', severity: 'critical', confidence: 'high', domain: 'inter-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0] },
            remediation: 'Issue unique credentials per agent', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-006', name: 'No privilege isolation between agents', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agents run with identical permissions rather than isolated, role-specific privileges.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length > 1) {
        const hasRoles = graph.agents.some(a => (a as any).role || (a as any).permissions);
        if (!hasRoles) {
          findings.push({ id: 'AA-IC-006-0', ruleId: 'AA-IC-006', title: 'No privilege isolation between agents',
            description: 'Multi-agent system lacks role-based privilege separation', severity: 'high', confidence: 'medium', domain: 'inter-agent',
            location: { file: graph.agents[0]?.file ?? 'unknown', line: graph.agents[0]?.line ?? 1 },
            remediation: 'Assign distinct roles and permissions to each agent', standards: STD });
        }
      }
      return findings;
    },
  },

  /* ---------- Shared State ---------- */
  {
    id: 'AA-IC-007', name: 'Unsynchronized shared state between agents', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agents access shared state without synchronization primitives, risking race conditions.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:shared_state|global_state|shared_memory|common_context)\s*[\[.=]/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:lock|mutex|semaphore|synchronized|atomic)/i.test(ctx)) {
            findings.push({ id: 'AA-IC-007-0', ruleId: 'AA-IC-007', title: 'Unsynchronized shared state',
              description: 'Shared state accessed without synchronization', severity: 'high', confidence: 'medium', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Use locks or atomic operations for shared state access', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Identity Spoofing ---------- */
  {
    id: 'AA-IC-008', name: 'Spoofable agent identifiers', domain: 'inter-agent',
    severity: 'critical', confidence: 'high',
    description: 'Agent identity is based on a simple string name without cryptographic verification.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:agent_id|sender_id|from_agent)\s*=\s*["'][^"']+["']/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-IC-008-0', ruleId: 'AA-IC-008', title: 'Spoofable agent identifiers',
            description: 'Agent identity set via simple string, easily spoofable', severity: 'critical', confidence: 'high', domain: 'inter-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Use cryptographic identity verification for agents', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-009', name: 'No mutual authentication between agents', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent communication lacks mutual authentication — only one side verifies identity.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:connect_to_agent|agent_channel|agent_socket)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:mutual_auth|mtls|bilateral|two_way_auth)/i.test(ctx)) {
            findings.push({ id: 'AA-IC-009-0', ruleId: 'AA-IC-009', title: 'No mutual authentication',
              description: 'Agent channel lacks mutual authentication', severity: 'high', confidence: 'medium', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Enable mutual TLS or bilateral authentication', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Protocol Validation ---------- */
  {
    id: 'AA-IC-010', name: 'No message format validation', domain: 'inter-agent',
    severity: 'medium', confidence: 'high',
    description: 'Inter-agent protocol lacks message format validation, accepting malformed messages.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:agent_protocol|message_protocol|agent_rpc)\s*[=({]/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 500);
          if (!/(?:schema|format|validate|deserialize.*check)/i.test(ctx)) {
            findings.push({ id: 'AA-IC-010-0', ruleId: 'AA-IC-010', title: 'No message format validation',
              description: 'Agent protocol has no format validation', severity: 'medium', confidence: 'high', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Add message schema validation to agent protocol', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Trust Boundaries ---------- */
  {
    id: 'AA-IC-011', name: 'Implicit trust between agents', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agents implicitly trust all other agents without any trust verification mechanism.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length > 1) {
        for (const file of codeFiles(graph)) {
          const content = readFile(file.path);
          if (!content) continue;
          const rx = /trust_all|trusted_agents\s*=\s*\[?\s*["']\*["']\]?|allow_all_agents/gi;
          let m;
          while ((m = rx.exec(content))) {
            if (isCommentLine(content, m.index, file.language)) continue;
            findings.push({ id: 'AA-IC-011-0', ruleId: 'AA-IC-011', title: 'Implicit trust between agents',
              description: 'All agents trusted without verification', severity: 'high', confidence: 'medium', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0] },
              remediation: 'Implement explicit trust policies with verification', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-012', name: 'No trust boundary enforcement', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Agent system lacks trust boundaries — all agents operate in the same trust zone.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 20 && !/(?:trust.?boundar|trust.?zone|trust.?level|security.?perimeter)/i.test(prompt.content)) {
          if (/(?:multi.?agent|coordinator|orchestrat|agent.?(?:team|crew|swarm|fleet))/i.test(prompt.content)) {
            findings.push({ id: 'AA-IC-012-0', ruleId: 'AA-IC-012', title: 'No trust boundary in multi-agent prompt',
              description: 'Multi-agent system prompt lacks trust boundary definitions', severity: 'high', confidence: 'medium', domain: 'inter-agent',
              location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
              remediation: 'Define trust boundaries and zones in system prompts', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Communication Encryption ---------- */
  {
    id: 'AA-IC-013', name: 'Plaintext agent communication', domain: 'inter-agent',
    severity: 'high', confidence: 'high',
    description: 'Inter-agent communication uses plaintext HTTP or unencrypted channels.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:agent_url|agent_endpoint|agent_host)\s*=\s*["']http:\/\//gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-IC-013-0', ruleId: 'AA-IC-013', title: 'Plaintext agent communication',
            description: 'Agent endpoint uses HTTP instead of HTTPS', severity: 'high', confidence: 'high', domain: 'inter-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Use HTTPS/TLS for all inter-agent communication', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-014', name: 'Hardcoded agent communication keys', domain: 'inter-agent',
    severity: 'critical', confidence: 'high',
    description: 'Encryption keys for inter-agent channels are hardcoded in source code.',
    frameworks: ['all'], owaspAgentic: ['ASI03'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:agent_secret|channel_key|comm_key|shared_key)\s*=\s*["'][A-Za-z0-9+/=]{16,}["']/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-IC-014-0', ruleId: 'AA-IC-014', title: 'Hardcoded agent communication keys',
            description: 'Inter-agent encryption key hardcoded in source', severity: 'critical', confidence: 'high', domain: 'inter-agent',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) + '...' },
            remediation: 'Use key management service or environment variables', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-015', name: 'No message replay protection', domain: 'inter-agent',
    severity: 'high', confidence: 'medium',
    description: 'Inter-agent messages lack nonces or timestamps, making replay attacks possible.',
    frameworks: ['all'], owaspAgentic: ['ASI01'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:send_to_agent|agent_send|dispatch_message)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:nonce|timestamp|sequence|replay|idempotency)/i.test(ctx)) {
            findings.push({ id: 'AA-IC-015-0', ruleId: 'AA-IC-015', title: 'No message replay protection',
              description: 'Inter-agent message lacks replay protection', severity: 'high', confidence: 'medium', domain: 'inter-agent',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Include nonces and timestamps in inter-agent messages', standards: STD });
          }
        }
      }
      return findings;
    },
  },
];
