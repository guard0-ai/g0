import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';

export const enrichmentRules: Rule[] = [
  // ─── Data Leakage / PII ─────────────────────────────────────────

  {
    id: 'AA-DL-200',
    name: 'PII logged without masking',
    domain: 'data-leakage',
    severity: 'high',
    confidence: 'high',
    description: 'PII data is being logged without masking, risking exposure in log files.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const pii of graph.piiReferences) {
        if (pii.context === 'logging' && !pii.hasMasking) {
          findings.push({
            id: `AA-DL-200-${findings.length}`,
            ruleId: 'AA-DL-200',
            title: 'PII logged without masking',
            description: `PII field (${pii.type}) is logged without masking at ${pii.file}:${pii.line}.`,
            severity: 'high',
            confidence: 'high',
            domain: 'data-leakage',
            location: { file: pii.file, line: pii.line },
            remediation: 'Apply masking/redaction before logging PII data (e.g., mask(email) or redact(ssn)).',
            standards: { owaspAgentic: ['ASI07'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-DL-201',
    name: 'PII transmitted without encryption',
    domain: 'data-leakage',
    severity: 'high',
    confidence: 'medium',
    description: 'PII data is transmitted without encryption, risking interception.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const pii of graph.piiReferences) {
        if (pii.context === 'transmission' && !pii.hasEncryption) {
          findings.push({
            id: `AA-DL-201-${findings.length}`,
            ruleId: 'AA-DL-201',
            title: 'PII transmitted without encryption',
            description: `PII field (${pii.type}) is transmitted without encryption at ${pii.file}:${pii.line}.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'data-leakage',
            location: { file: pii.file, line: pii.line },
            remediation: 'Encrypt PII data before transmission or use HTTPS/TLS for transport.',
            standards: { owaspAgentic: ['ASI07'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-DL-202',
    name: 'PII stored without encryption',
    domain: 'data-leakage',
    severity: 'medium',
    confidence: 'medium',
    description: 'PII data is stored without encryption at rest.',
    frameworks: ['all'],
    owaspAgentic: ['ASI07'],
    standards: { owaspAgentic: ['ASI07'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const pii of graph.piiReferences) {
        if (pii.context === 'storage' && !pii.hasEncryption) {
          findings.push({
            id: `AA-DL-202-${findings.length}`,
            ruleId: 'AA-DL-202',
            title: 'PII stored without encryption',
            description: `PII field (${pii.type}) is stored without encryption at ${pii.file}:${pii.line}.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'data-leakage',
            location: { file: pii.file, line: pii.line },
            remediation: 'Encrypt PII data at rest using field-level encryption or an encrypted data store.',
            standards: { owaspAgentic: ['ASI07'], iso42001: ['A.8.2'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  // ─── Tool Safety / Database ─────────────────────────────────────

  {
    id: 'AA-TS-200',
    name: 'Unparameterized SQL query',
    domain: 'tool-safety',
    severity: 'high',
    confidence: 'high',
    description: 'SQL query without parameterized inputs is vulnerable to injection.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const db of graph.databaseAccesses) {
        if (db.type === 'sql' && !db.hasParameterizedQuery) {
          findings.push({
            id: `AA-TS-200-${findings.length}`,
            ruleId: 'AA-TS-200',
            title: 'Unparameterized SQL query',
            description: `SQL ${db.operation} query on table "${db.table || 'unknown'}" is not parameterized at ${db.file}:${db.line}.`,
            severity: 'high',
            confidence: 'high',
            domain: 'tool-safety',
            location: { file: db.file, line: db.line },
            remediation: 'Use parameterized queries (?, $1, :param) instead of string concatenation.',
            standards: { owaspAgentic: ['ASI04'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-TS-201',
    name: 'Admin database operation in agent code',
    domain: 'tool-safety',
    severity: 'medium',
    confidence: 'medium',
    description: 'Admin-level database operation (DROP, TRUNCATE, ALTER, CREATE) detected in agent code.',
    frameworks: ['all'],
    owaspAgentic: ['ASI04'],
    standards: { owaspAgentic: ['ASI04'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const db of graph.databaseAccesses) {
        if (db.operation === 'admin') {
          findings.push({
            id: `AA-TS-201-${findings.length}`,
            ruleId: 'AA-TS-201',
            title: 'Admin database operation in agent code',
            description: `Admin-level database operation on table "${db.table || 'unknown'}" at ${db.file}:${db.line}.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'tool-safety',
            location: { file: db.file, line: db.line },
            remediation: 'Restrict agent database access to read/write operations. Use migrations for schema changes.',
            standards: { owaspAgentic: ['ASI04'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  // ─── Identity & Access ──────────────────────────────────────────

  {
    id: 'AA-IA-200',
    name: 'Auth flow without token validation',
    domain: 'identity-access',
    severity: 'high',
    confidence: 'high',
    description: 'Authentication flow detected without token validation, allowing forged tokens.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const auth of graph.authFlows) {
        if (!auth.hasTokenValidation) {
          findings.push({
            id: `AA-IA-200-${findings.length}`,
            ruleId: 'AA-IA-200',
            title: 'Auth flow without token validation',
            description: `${auth.type} auth flow at ${auth.file}:${auth.line} lacks token validation.`,
            severity: 'high',
            confidence: 'high',
            domain: 'identity-access',
            location: { file: auth.file, line: auth.line },
            remediation: 'Add token verification (e.g., jwt.verify(), validate()) to all auth flows.',
            standards: { owaspAgentic: ['ASI03'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IA-201',
    name: 'Auth flow without token expiry',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'medium',
    description: 'Authentication flow without token expiry allows indefinite access.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const auth of graph.authFlows) {
        if (!auth.hasTokenExpiry) {
          findings.push({
            id: `AA-IA-201-${findings.length}`,
            ruleId: 'AA-IA-201',
            title: 'Auth flow without token expiry',
            description: `${auth.type} auth flow at ${auth.file}:${auth.line} has no token expiry configured.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'identity-access',
            location: { file: auth.file, line: auth.line },
            remediation: 'Set token expiry (expiresIn, exp, maxAge) on all authentication tokens.',
            standards: { owaspAgentic: ['ASI03'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IA-202',
    name: 'External API call without authentication',
    domain: 'identity-access',
    severity: 'medium',
    confidence: 'low',
    description: 'External API call detected in a file with no authentication flow nearby.',
    frameworks: ['all'],
    owaspAgentic: ['ASI03'],
    standards: { owaspAgentic: ['ASI03'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const authFiles = new Set(graph.authFlows.map(a => a.file));
      const seen = new Set<string>();
      for (const ep of graph.apiEndpoints) {
        if (ep.isExternal && !authFiles.has(ep.file)) {
          const key = `${ep.file}:${ep.line}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            id: `AA-IA-202-${findings.length}`,
            ruleId: 'AA-IA-202',
            title: 'External API call without authentication',
            description: `External API call to ${ep.url} at ${ep.file}:${ep.line} has no auth flow in the same file.`,
            severity: 'medium',
            confidence: 'low',
            domain: 'identity-access',
            location: { file: ep.file, line: ep.line },
            remediation: 'Add authentication (API key, Bearer token, OAuth) to external API calls.',
            standards: { owaspAgentic: ['ASI03'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  // ─── Inter-Agent / Message Queues ───────────────────────────────

  {
    id: 'AA-IC-200',
    name: 'Message queue without authentication',
    domain: 'inter-agent',
    severity: 'high',
    confidence: 'high',
    description: 'Message queue connection lacks authentication, allowing unauthorized access.',
    frameworks: ['all'],
    owaspAgentic: ['ASI10'],
    standards: { owaspAgentic: ['ASI10'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const mq of graph.messageQueues) {
        if (!mq.hasAuthentication) {
          findings.push({
            id: `AA-IC-200-${findings.length}`,
            ruleId: 'AA-IC-200',
            title: 'Message queue without authentication',
            description: `${mq.type} queue at ${mq.file}:${mq.line} lacks authentication (SASL, credentials).`,
            severity: 'high',
            confidence: 'high',
            domain: 'inter-agent',
            location: { file: mq.file, line: mq.line },
            remediation: 'Enable SASL authentication or credential-based access on message queue connections.',
            standards: { owaspAgentic: ['ASI10'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-IC-201',
    name: 'Message queue without encryption',
    domain: 'inter-agent',
    severity: 'medium',
    confidence: 'medium',
    description: 'Message queue connection lacks TLS/SSL encryption.',
    frameworks: ['all'],
    owaspAgentic: ['ASI10'],
    standards: { owaspAgentic: ['ASI10'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const mq of graph.messageQueues) {
        if (!mq.hasEncryption) {
          findings.push({
            id: `AA-IC-201-${findings.length}`,
            ruleId: 'AA-IC-201',
            title: 'Message queue without encryption',
            description: `${mq.type} queue at ${mq.file}:${mq.line} lacks TLS/SSL encryption.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'inter-agent',
            location: { file: mq.file, line: mq.line },
            remediation: 'Enable TLS/SSL on message queue connections to encrypt data in transit.',
            standards: { owaspAgentic: ['ASI10'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  // ─── Goal Integrity / Prompt Permissions ────────────────────────

  {
    id: 'AA-GI-200',
    name: 'Contradictory prompt permissions',
    domain: 'goal-integrity',
    severity: 'high',
    confidence: 'medium',
    description: 'Same prompt source has both allowed and forbidden permissions with overlapping actions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI01'],
    standards: { owaspAgentic: ['ASI01'], iso42001: ['A.8.2'], nistAiRmf: ['GOVERN-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      // Group permissions by source prompt
      const bySource = new Map<string, typeof graph.permissions>();
      for (const perm of graph.permissions) {
        const group = bySource.get(perm.source) ?? [];
        group.push(perm);
        bySource.set(perm.source, group);
      }

      for (const [source, perms] of bySource) {
        const allowed = perms.filter(p => p.type === 'allowed');
        const forbidden = perms.filter(p => p.type === 'forbidden');
        if (allowed.length === 0 || forbidden.length === 0) continue;

        // Check for keyword overlap
        for (const a of allowed) {
          const aWords = new Set(a.action.toLowerCase().split(/\s+/));
          for (const f of forbidden) {
            const fWords = f.action.toLowerCase().split(/\s+/);
            const overlap = fWords.filter(w => w.length > 3 && aWords.has(w));
            if (overlap.length > 0) {
              findings.push({
                id: `AA-GI-200-${findings.length}`,
                ruleId: 'AA-GI-200',
                title: 'Contradictory prompt permissions',
                description: `Prompt "${source}" allows "${a.action}" but forbids "${f.action}" (overlap: ${overlap.join(', ')}).`,
                severity: 'high',
                confidence: 'medium',
                domain: 'goal-integrity',
                location: { file: a.file, line: a.line },
                remediation: 'Resolve contradictory instructions in the system prompt to prevent ambiguous agent behavior.',
                standards: { owaspAgentic: ['ASI01'], iso42001: ['A.8.2'], nistAiRmf: ['GOVERN-1.1'] },
              });
              break; // one finding per allowed-forbidden pair is enough
            }
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-GI-201',
    name: 'No boundary constraints in system prompt',
    domain: 'goal-integrity',
    severity: 'medium',
    confidence: 'medium',
    description: 'System prompt has allowed actions but no boundary constraints (only, restricted to, limited to).',
    frameworks: ['all'],
    owaspAgentic: ['ASI01'],
    standards: { owaspAgentic: ['ASI01'], iso42001: ['A.8.2'], nistAiRmf: ['GOVERN-1.1'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const bySource = new Map<string, typeof graph.permissions>();
      for (const perm of graph.permissions) {
        const group = bySource.get(perm.source) ?? [];
        group.push(perm);
        bySource.set(perm.source, group);
      }

      for (const [source, perms] of bySource) {
        const hasAllowed = perms.some(p => p.type === 'allowed');
        const hasBoundary = perms.some(p => p.type === 'boundary');
        if (hasAllowed && !hasBoundary) {
          const firstAllowed = perms.find(p => p.type === 'allowed')!;
          findings.push({
            id: `AA-GI-201-${findings.length}`,
            ruleId: 'AA-GI-201',
            title: 'No boundary constraints in system prompt',
            description: `Prompt "${source}" grants permissions but has no boundary constraints (only, restricted to, limited to).`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'goal-integrity',
            location: { file: firstAllowed.file, line: firstAllowed.line },
            remediation: 'Add boundary constraints (e.g., "only access the X table", "restricted to read-only operations") to system prompts.',
            standards: { owaspAgentic: ['ASI01'], iso42001: ['A.8.2'], nistAiRmf: ['GOVERN-1.1'] },
          });
        }
      }
      return findings;
    },
  },

  // ─── Cascading Failures ─────────────────────────────────────────

  {
    id: 'AA-CF-200',
    name: 'External API without rate limiting',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'low',
    description: 'External API call detected in a file with no rate limiting configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: { owaspAgentic: ['ASI09'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const rateLimitFiles = new Set(graph.rateLimits.map(r => r.file));
      const seen = new Set<string>();
      for (const ep of graph.apiEndpoints) {
        if (ep.isExternal && !rateLimitFiles.has(ep.file)) {
          const key = `${ep.file}`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            id: `AA-CF-200-${findings.length}`,
            ruleId: 'AA-CF-200',
            title: 'External API without rate limiting',
            description: `External API call at ${ep.file}:${ep.line} has no rate limiting in the same file.`,
            severity: 'medium',
            confidence: 'low',
            domain: 'cascading-failures',
            location: { file: ep.file, line: ep.line },
            remediation: 'Add rate limiting to external API calls to prevent cascading failures and cost overruns.',
            standards: { owaspAgentic: ['ASI09'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
          });
        }
      }
      return findings;
    },
  },

  // ─── Reliability Bounds ─────────────────────────────────────────

  {
    id: 'AA-RB-200',
    name: 'No rate limiting for LLM calls',
    domain: 'reliability-bounds',
    severity: 'medium',
    confidence: 'medium',
    description: 'No LLM-specific rate limiting detected while models are in use.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: { owaspAgentic: ['ASI09'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
    check: (graph: AgentGraph): Finding[] => {
      if (graph.models.length === 0) return [];
      const hasLLMRateLimit = graph.rateLimits.some(r => r.type === 'llm');
      if (hasLLMRateLimit) return [];

      return [{
        id: 'AA-RB-200-0',
        ruleId: 'AA-RB-200',
        title: 'No rate limiting for LLM calls',
        description: `${graph.models.length} model(s) detected but no LLM-specific rate limiting (tokens_per_minute, max_requests_per_day) found.`,
        severity: 'medium',
        confidence: 'medium',
        domain: 'reliability-bounds',
        location: { file: graph.models[0].file, line: graph.models[0].line },
        remediation: 'Add LLM rate limiting (tokens_per_minute, max_requests_per_day) to prevent runaway costs.',
        standards: { owaspAgentic: ['ASI09'], iso42001: ['A.8.4'], nistAiRmf: ['MEASURE-2.6'] },
      }];
    },
  },
];
