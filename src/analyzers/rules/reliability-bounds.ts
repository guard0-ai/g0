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

const STD = { owaspAgentic: ['ASI07'] };
const STD_EXT = { owaspAgentic: ['ASI07', 'ASI05'], nistAiRmf: ['MEASURE-2.6', 'MANAGE-2.2'], owaspLlmTop10: ['LLM09'] };

/* ================================================================== */
/*  20 RULES — reliability-bounds domain (hardcoded)                   */
/* ================================================================== */

export const reliabilityBoundsRules: Rule[] = [

  /* ---------- Hallucination Guards ---------- */
  {
    id: 'AA-RB-001', name: 'No output validation on LLM response', domain: 'reliability-bounds',
    severity: 'high', confidence: 'high',
    description: 'LLM response is used directly without validation or parsing, risking hallucinated or malformed data downstream.',
    frameworks: ['all'], owaspAgentic: ['ASI07'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:response\.text|completion\.choices|result\.content|\.(?:ainvoke|invoke)\(|agent\s*\.\s*run\()\s*(?:\)|;|\n)/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const after = content.substring(m.index, m.index + 400);
          if (!/(?:validate|parse|check|verify|schema|assert|sanitize|JSON\.parse)/i.test(after.substring(0, 200))) {
            findings.push({ id: 'AA-RB-001-0', ruleId: 'AA-RB-001', title: 'Unvalidated LLM output',
              description: 'LLM response used without output validation', severity: 'high', confidence: 'high', domain: 'reliability-bounds',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Add output validation/parsing step after LLM calls', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-002', name: 'No grounding verification', domain: 'reliability-bounds',
    severity: 'high', confidence: 'medium',
    description: 'LLM outputs are not verified against a known source of truth, allowing hallucinations to propagate.',
    frameworks: ['all'], owaspAgentic: ['ASI07'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && /(?:answer|respond|provide|generate)/i.test(prompt.content)) {
          if (!/(?:ground|verify|fact.?check|source|cite|reference|evidence)/i.test(prompt.content)) {
            findings.push({ id: 'AA-RB-002-0', ruleId: 'AA-RB-002', title: 'No grounding instruction',
              description: 'System prompt lacks grounding/fact-checking instructions', severity: 'high', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
              remediation: 'Add instructions to verify outputs against authoritative sources', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Output Validation ---------- */
  {
    id: 'AA-RB-003', name: 'No JSON schema validation for structured output', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'high',
    description: 'Agent parses structured LLM output without schema validation.',
    frameworks: ['all'], owaspAgentic: ['ASI07'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /JSON\.parse\s*\(\s*(?:response|result|output|completion|generated|data\b)|json\.loads\s*\(\s*(?:response|result|output|completion|generated|data\b)/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const after = content.substring(m.index, m.index + 500);
          if (!/(?:schema|zod|ajv|pydantic|validate|joi|yup|TypeAdapter)/i.test(after.substring(0, 300))) {
            findings.push({ id: 'AA-RB-003-0', ruleId: 'AA-RB-003', title: 'JSON parsed without schema validation',
              description: 'Parsed JSON output without schema validation', severity: 'medium', confidence: 'high', domain: 'reliability-bounds',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Validate parsed JSON against a schema (zod, ajv, pydantic)', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Confidence Thresholds ---------- */
  {
    id: 'AA-RB-004', name: 'No confidence threshold enforcement', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Agent acts on LLM output regardless of confidence level, without abstention on low confidence.',
    frameworks: ['all'], owaspAgentic: ['ASI07'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const prompt of graph.prompts) {
        if (prompt.content.length > 50 && !/(?:confidence|certain|uncertain|unsure|don'?t know|abstain|decline|refuse)/i.test(prompt.content)) {
          if (/(?:tool|action|execute|decide|classify)/i.test(prompt.content)) {
            findings.push({ id: 'AA-RB-004-0', ruleId: 'AA-RB-004', title: 'No confidence guidance in prompt',
              description: 'System prompt lacks confidence/abstention instructions', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: prompt.file, line: prompt.line, snippet: prompt.content.substring(0, 80) },
              remediation: 'Instruct agent to express uncertainty and abstain when unsure', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Retry / Fallback ---------- */
  {
    id: 'AA-RB-005', name: 'No fallback model configured', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Agent uses a single LLM without a fallback, making it vulnerable to provider outages.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.models.length === 1) {
        findings.push({ id: 'AA-RB-005-0', ruleId: 'AA-RB-005', title: 'Single model without fallback',
          description: 'Only one model configured, no fallback for outages', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
          location: { file: graph.models[0]?.file ?? 'unknown', line: graph.models[0]?.line ?? 1 },
          remediation: 'Configure a fallback model for resilience', standards: STD });
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-006', name: 'No exponential backoff on retries', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'LLM API retries use fixed intervals instead of exponential backoff.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:retry|retries|max_retries|num_retries)\s*[=:]/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 500);
          if (!/(?:backoff|exponential|jitter|delay\s*\*|sleep\s*\*)/i.test(ctx)) {
            findings.push({ id: 'AA-RB-006-0', ruleId: 'AA-RB-006', title: 'No exponential backoff',
              description: 'Retry logic lacks exponential backoff', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Use exponential backoff with jitter for retries', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Token / Cost Limits ---------- */
  {
    id: 'AA-RB-007', name: 'No token budget enforcement', domain: 'reliability-bounds',
    severity: 'high', confidence: 'medium',
    description: 'Agent lacks token budget limits, risking unbounded API costs.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const model of graph.models) {
        // Check for runtime properties not on the ModelNode interface (set by some frameworks)
        if (!(model as unknown as Record<string, unknown>).maxTokens && !(model as unknown as Record<string, unknown>).max_tokens) {
          findings.push({ id: 'AA-RB-007-0', ruleId: 'AA-RB-007', title: 'No token budget on model',
            description: `Model "${model.name}" has no max_tokens limit`, severity: 'high', confidence: 'medium', domain: 'reliability-bounds',
            location: { file: model.file, line: model.line },
            remediation: 'Set max_tokens on all model configurations', standards: STD_EXT });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-008', name: 'No cost tracking mechanism', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Agent has no mechanism to track or limit API spending.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasCostTracking = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:cost_track|spending|budget|usage_limit|token_count|billing|metering)/i.test(content)) {
          hasCostTracking = true;
          break;
        }
      }
      if (!hasCostTracking && graph.models.length > 0) {
        findings.push({ id: 'AA-RB-008-0', ruleId: 'AA-RB-008', title: 'No cost tracking',
          description: 'No API cost tracking mechanism found', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
          location: { file: graph.models[0]?.file ?? 'unknown', line: 1 },
          remediation: 'Implement cost tracking and budget alerting', standards: STD });
      }
      return findings;
    },
  },

  /* ---------- Determinism ---------- */
  {
    id: 'AA-RB-009', name: 'Temperature not explicitly set', domain: 'reliability-bounds',
    severity: 'low', confidence: 'high',
    description: 'Model temperature is not explicitly set, leading to non-deterministic outputs.',
    frameworks: ['all'], owaspAgentic: ['ASI07'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const model of graph.models) {
        if ((model as unknown as Record<string, unknown>).temperature === undefined) {
          findings.push({ id: 'AA-RB-009-0', ruleId: 'AA-RB-009', title: 'Temperature not set',
            description: `Model "${model.name}" has no explicit temperature setting`, severity: 'low', confidence: 'high', domain: 'reliability-bounds',
            location: { file: model.file, line: model.line },
            remediation: 'Explicitly set temperature for reproducible outputs', standards: STD });
        }
      }
      return findings;
    },
  },

  /* ---------- Timeout Enforcement ---------- */
  {
    id: 'AA-RB-010', name: 'No request timeout for LLM calls', domain: 'reliability-bounds',
    severity: 'high', confidence: 'medium',
    description: 'LLM API calls have no timeout, potentially blocking indefinitely.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:openai|anthropic|llm|chat_model|completion_client)\.\w*(?:create|complete|generate|chat|invoke)\s*\(/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 500);
          if (!/(?:timeout|deadline|signal|abort|max_time)/i.test(ctx)) {
            findings.push({ id: 'AA-RB-010-0', ruleId: 'AA-RB-010', title: 'No timeout on LLM call',
              description: 'LLM API call has no timeout configured', severity: 'high', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Add timeout to all LLM API calls', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Rate Limiting ---------- */
  {
    id: 'AA-RB-011', name: 'No rate limiting on agent API', domain: 'reliability-bounds',
    severity: 'high', confidence: 'medium',
    description: 'Agent-exposed API has no rate limiting, vulnerable to abuse and cost explosion.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:app\.post|app\.get|router\.|@app\.route|FastAPI|Express)/i.test(content) && /(?:agent|llm|openai|anthropic|langchain|crewai|autogen|tool_call|ChatCompletion)/i.test(content)) {
          if (!/(?:rate_limit|rateLimit|throttle|limiter|slowDown)/i.test(content)) {
            findings.push({ id: 'AA-RB-011-0', ruleId: 'AA-RB-011', title: 'No rate limiting',
              description: 'API route has no rate limiting', severity: 'high', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: 1 },
              remediation: 'Add rate limiting middleware to API endpoints', standards: STD_EXT });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Graceful Degradation ---------- */
  {
    id: 'AA-RB-012', name: 'No graceful degradation strategy', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Agent has no fallback behavior when primary LLM is unavailable.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:except|catch)\s*[({]?/i.test(content) && /(?:openai|anthropic|llm|model)/i.test(content)) {
          if (!/(?:fallback|degrade|alternative|backup|cached_response|default_response)/i.test(content)) {
            findings.push({ id: 'AA-RB-012-0', ruleId: 'AA-RB-012', title: 'No graceful degradation',
              description: 'Error handling lacks graceful degradation strategy', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: 1 },
              remediation: 'Implement fallback responses when LLM is unavailable', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  /* ---------- Resource Bounds ---------- */
  {
    id: 'AA-RB-013', name: 'No concurrent request limit', domain: 'reliability-bounds',
    severity: 'high', confidence: 'medium',
    description: 'Agent processes unlimited concurrent requests, risking resource exhaustion.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:asyncio\.gather|Promise\.all|concurrent|parallel|ThreadPool|ProcessPool)/i.test(content)) {
          if (!/(?:semaphore|max_concurrent|concurrency_limit|max_workers|pool_size|limit)/i.test(content)) {
            findings.push({ id: 'AA-RB-013-0', ruleId: 'AA-RB-013', title: 'Unbounded concurrency',
              description: 'Parallel execution without concurrency limit', severity: 'high', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: 1 },
              remediation: 'Set max_concurrent or use a semaphore to bound concurrency', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-014', name: 'Unbounded batch size', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Agent processes input batches without size limits, risking OOM.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:batch_size|chunk_size)\s*=\s*(?:None|null|undefined|len\()/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-RB-014-0', ruleId: 'AA-RB-014', title: 'Unbounded batch size',
            description: 'Batch processing without size limit', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Set maximum batch size to prevent resource exhaustion', standards: STD });
        }
      }
      return findings;
    },
  },

  /* ---------- Additional ---------- */
  {
    id: 'AA-RB-015', name: 'No output length limit', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Agent does not limit LLM output length, risking excessive token usage.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:max_tokens|maxTokens|max_length|max_output)\s*[=:]\s*(?:None|null|undefined|\d{5,})/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          findings.push({ id: 'AA-RB-015-0', ruleId: 'AA-RB-015', title: 'Excessive output limit',
            description: 'Output token limit is missing or very high', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
            location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
            remediation: 'Set reasonable max_tokens limit on LLM calls', standards: STD });
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-016', name: 'No health check endpoint', domain: 'reliability-bounds',
    severity: 'low', confidence: 'medium',
    description: 'Agent service lacks a health check endpoint for monitoring.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasHealthCheck = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:\/health|\/healthz|\/ready|\/readiness|\/liveness|health_check)/i.test(content)) {
          hasHealthCheck = true;
          break;
        }
      }
      if (!hasHealthCheck && graph.agents.length > 0) {
        findings.push({ id: 'AA-RB-016-0', ruleId: 'AA-RB-016', title: 'No health check endpoint',
          description: 'No health check or readiness endpoint found', severity: 'low', confidence: 'medium', domain: 'reliability-bounds',
          location: { file: graph.agents[0]?.file ?? 'unknown', line: 1 },
          remediation: 'Add /health endpoint for monitoring', standards: STD });
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-017', name: 'No streaming timeout', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'medium',
    description: 'Streaming LLM responses have no inactivity timeout.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:stream\s*[=:]\s*True|stream\s*[=:]\s*true|\.stream\()/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 400);
          if (!/(?:timeout|deadline|max_time|abort|cancel)/i.test(ctx)) {
            findings.push({ id: 'AA-RB-017-0', ruleId: 'AA-RB-017', title: 'No streaming timeout',
              description: 'Streaming response has no timeout', severity: 'medium', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Add inactivity timeout for streaming responses', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-018', name: 'No circuit breaker for external services', domain: 'reliability-bounds',
    severity: 'high', confidence: 'medium',
    description: 'Agent calls external services without a circuit breaker pattern.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:fetch|axios|requests\.|httpx|urllib)/i.test(content) && /(?:agent|llm|tool)/i.test(content)) {
          if (!/(?:circuit.?breaker|circuitbreaker|breaker|opossum|cockatiel|polly)/i.test(content)) {
            findings.push({ id: 'AA-RB-018-0', ruleId: 'AA-RB-018', title: 'No circuit breaker',
              description: 'External service calls lack circuit breaker pattern', severity: 'high', confidence: 'medium', domain: 'reliability-bounds',
              location: { file: file.path, line: 1 },
              remediation: 'Implement circuit breaker pattern for external service calls', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-019', name: 'No input length validation', domain: 'reliability-bounds',
    severity: 'medium', confidence: 'high',
    description: 'User input is passed to LLM without length validation, risking context overflow.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        const rx = /(?:user_input|user_message|user_query|user_prompt)\s*=\s*(?:request\.(?:body|query|params|json)|req\.(?:body|query|params)|input\(|body\[)/gi;
        let m;
        while ((m = rx.exec(content))) {
          if (isCommentLine(content, m.index, file.language)) continue;
          const ctx = content.substring(m.index, m.index + 300);
          if (!/(?:max_length|truncate|limit|slice|substring|[:]\d)/i.test(ctx)) {
            findings.push({ id: 'AA-RB-019-0', ruleId: 'AA-RB-019', title: 'No input length validation',
              description: 'User input passed to LLM without length check', severity: 'medium', confidence: 'high', domain: 'reliability-bounds',
              location: { file: file.path, line: lineAt(content, m.index), snippet: m[0].substring(0, 80) },
              remediation: 'Validate and truncate user input before sending to LLM', standards: STD });
          }
        }
      }
      return findings;
    },
  },

  {
    id: 'AA-RB-020', name: 'No output caching for repeated queries', domain: 'reliability-bounds',
    severity: 'low', confidence: 'low',
    description: 'Agent has no output caching, repeating identical LLM calls unnecessarily.',
    frameworks: ['all'], owaspAgentic: ['ASI05'], standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasCache = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:cache|lru_cache|memoize|redis|memcached|Cache\()/i.test(content)) {
          hasCache = true;
          break;
        }
      }
      if (!hasCache && graph.models.length > 0) {
        findings.push({ id: 'AA-RB-020-0', ruleId: 'AA-RB-020', title: 'No output caching',
          description: 'No caching mechanism found for LLM responses', severity: 'low', confidence: 'low', domain: 'reliability-bounds',
          location: { file: graph.models[0]?.file ?? 'unknown', line: 1 },
          remediation: 'Consider caching identical LLM queries for cost efficiency', standards: STD });
      }
      return findings;
    },
  },
];
