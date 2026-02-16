import * as fs from 'node:fs';
import type { Rule } from '../../types/control.js';
import type { Finding } from '../../types/finding.js';
import type { AgentGraph } from '../../types/agent-graph.js';

/* ------------------------------------------------------------------ */
/* Helper: read a file safely                                         */
/* ------------------------------------------------------------------ */
function readFile(path: string): string | null {
  try {
    return fs.readFileSync(path, 'utf-8');
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/* Helper: get the line number at a given string index                */
/* ------------------------------------------------------------------ */
function lineAt(content: string, index: number): number {
  return content.substring(0, index).split('\n').length;
}

/* ------------------------------------------------------------------ */
/* Helper: collect code files (py + ts + js)                          */
/* ------------------------------------------------------------------ */
function codeFiles(graph: AgentGraph) {
  return [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript];
}

/* ------------------------------------------------------------------ */
/* Helper: collect ALL files including configs                        */
/* ------------------------------------------------------------------ */
function allFiles(graph: AgentGraph) {
  return [...graph.files.python, ...graph.files.typescript, ...graph.files.javascript, ...graph.files.yaml, ...graph.files.json];
}

/* ------------------------------------------------------------------ */
/* Shared standards mapping for all rules in this domain              */
/* ------------------------------------------------------------------ */
const STD = { owaspAgentic: ['ASI09'] };

/* ------------------------------------------------------------------ */
/* Extended standards for new rules                                   */
/* ------------------------------------------------------------------ */
const STD_EXT = {
  owaspAgentic: ['ASI09'],
  iso23894: ['R.5', 'R.6', 'R.8'],
  owaspAivss: ['AIVSS-RF'],
  a2asBasic: ['ISOL'],
};

/* ================================================================== */
/*  50 RULES — cascading-failures domain                              */
/* ================================================================== */

export const cascadingFailuresRules: Rule[] = [

  /* ================================================================ */
  /*  ERROR PROPAGATION (10 rules)                                    */
  /* ================================================================ */

  // 1. AA-CF-003 — Retry without max count
  {
    id: 'AA-CF-003',
    name: 'Retry without max count',
    domain: 'cascading-failures',
    severity: 'critical',
    confidence: 'medium',
    description: 'Retry loop or decorator lacks a maximum retry count, risking infinite retries.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;

        // Python: while True retry loops
        const whileTrue = /while\s+True\s*:/g;
        let m: RegExpExecArray | null;
        while ((m = whileTrue.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 500));
          if (/retry|attempt|try|except/i.test(region) && !/max_retries|max_attempts|retry_limit|break.*max/i.test(region)) {
            findings.push({
              id: `AA-CF-003-${findings.length}`,
              ruleId: 'AA-CF-003',
              title: 'Retry without max count',
              description: `Unbounded while-True retry loop in ${file.relativePath} at line ${lineAt(content, m.index)}.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
              remediation: 'Add a maximum retry count (e.g., max_retries) and break after exceeding it.',
              standards: STD,
            });
          }
        }

        // Python: @retry without max_retries / stop=
        const retryDec = /@retry\b[^)]*\)/g;
        while ((m = retryDec.exec(content)) !== null) {
          if (!/max_retries|stop=|stop_after_attempt|max_attempt/i.test(m[0])) {
            findings.push({
              id: `AA-CF-003-${findings.length}`,
              ruleId: 'AA-CF-003',
              title: 'Retry decorator without max count',
              description: `@retry decorator in ${file.relativePath} at line ${lineAt(content, m.index)} lacks a max retry setting.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Set stop=stop_after_attempt(N) or max_retries on the retry decorator.',
              standards: STD,
            });
          }
        }

        // JS/TS: while (true) with retry-like context
        const whileTrueJS = /while\s*\(\s*true\s*\)/g;
        while ((m = whileTrueJS.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 500));
          if (/retry|attempt|try\s*\{|catch/i.test(region) && !/maxRetries|maxAttempts|retryLimit|MAX_RETRIES/i.test(region)) {
            findings.push({
              id: `AA-CF-003-${findings.length}`,
              ruleId: 'AA-CF-003',
              title: 'Retry without max count',
              description: `Unbounded while(true) retry loop in ${file.relativePath} at line ${lineAt(content, m.index)}.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
              remediation: 'Add a maximum retry count and break after exceeding it.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 2. AA-CF-004 — Stack trace in error response
  {
    id: 'AA-CF-004',
    name: 'Stack trace in error response',
    domain: 'cascading-failures',
    severity: 'critical',
    confidence: 'medium',
    description: 'Stack trace or traceback is included in error responses, leaking internal details.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const patterns = [
        /traceback\.format_exc\s*\(/g,
        /traceback\.print_exc\s*\(/g,
        /err\.stack/g,
        /error\.stack/g,
        /exception\.stackTrace/g,
        /\.stack_info/g,
      ];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        for (const regex of patterns) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const region = content.substring(m.index, Math.min(content.length, m.index + 300));
            if (/return|response|res\.|send|json|body|output/i.test(region)) {
              findings.push({
                id: `AA-CF-004-${findings.length}`,
                ruleId: 'AA-CF-004',
                title: 'Stack trace in error response',
                description: `Stack trace leaked in response context in ${file.relativePath} at line ${lineAt(content, m.index)}.`,
                severity: 'critical',
                confidence: 'medium',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
                remediation: 'Never expose stack traces in API responses. Log internally and return generic error messages.',
                standards: STD,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // 3. AA-CF-005 — Unhandled exception propagates
  {
    id: 'AA-CF-005',
    name: 'Unhandled exception propagates',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'low',
    description: 'Async function or route handler lacks try/catch, allowing unhandled exceptions to propagate.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length === 0) return findings;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;

        // Python: async def without try/except in body
        const pyAsync = /async\s+def\s+(\w+)\s*\([^)]*\).*?:\s*\n([\s\S]*?)(?=\ndef\s|\nclass\s|\nasync\s+def\s|$)/g;
        let m: RegExpExecArray | null;
        while ((m = pyAsync.exec(content)) !== null) {
          const body = m[2];
          const bodyLines = body.split('\n').filter(l => l.trim().length > 0).length;
          // Skip small utility functions (< 5 non-empty lines)
          if (bodyLines < 5) continue;
          // Skip if body has try/except or framework decorators handle errors
          if (/try\s*:/.test(body)) continue;
          // Must have await (actual async work)
          if (!/await\s/.test(body)) continue;
          // Skip decorated functions where frameworks handle errors (FastAPI, Flask, Django, etc.)
          const beforeFunc = content.substring(Math.max(0, m.index - 200), m.index);
          if (/@(?:app\.(?:route|get|post|put|delete|patch|exception_handler|middleware)|router\.(?:get|post|put|delete|patch)|api_view|action|task|tool|error_handler|exception_handler|retry|celery)/.test(beforeFunc)) continue;
          // Skip test functions
          if (/^(?:test_|_test$)/.test(m[1]) || /(?:fixture|conftest|mock|spec)/.test(file.path)) continue;
          findings.push({
            id: `AA-CF-005-${findings.length}`,
            ruleId: 'AA-CF-005',
            title: 'Unhandled exception in async function',
            description: `Async function "${m[1]}" in ${file.relativePath} at line ${lineAt(content, m.index)} has no try/except.`,
            severity: 'medium',
            confidence: 'low',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: lineAt(content, m.index), snippet: `async def ${m[1]}` },
            remediation: 'Wrap async function body in try/except to handle errors gracefully.',
            standards: STD,
          });
        }

        // JS/TS: route handlers (app.get/post/etc) without try/catch
        const routeHandler = /app\.(?:get|post|put|delete|patch)\s*\([^,]+,\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)/g;
        while ((m = routeHandler.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 800));
          if (!/try\s*\{/.test(region)) {
            // Skip test/example files
            if (/(?:test|spec|example|fixture|__test__|\.test\.)/.test(file.path)) continue;
            findings.push({
              id: `AA-CF-005-${findings.length}`,
              ruleId: 'AA-CF-005',
              title: 'Route handler without error handling',
              description: `Route handler in ${file.relativePath} at line ${lineAt(content, m.index)} lacks try/catch.`,
              severity: 'medium',
              confidence: 'low',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Wrap route handler bodies in try/catch to prevent unhandled exceptions.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 4. AA-CF-008 — Error cascades through delegation
  {
    id: 'AA-CF-008',
    name: 'Error cascades through delegation',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Delegation calls between agents lack error handling, allowing failures to cascade.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const delegationPatterns = /(?:\.delegate|\.initiate_chat|\.invoke|\.run_agent|\.execute_agent|\.send_message)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        delegationPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = delegationPatterns.exec(content)) !== null) {
          const start = Math.max(0, m.index - 400);
          const end = Math.min(content.length, m.index + 400);
          const region = content.substring(start, end);
          if (!/try\s*[:{]|except|catch\s*[({]|\.catch\s*\(|on_error|error_handler/i.test(region)) {
            findings.push({
              id: `AA-CF-008-${findings.length}`,
              ruleId: 'AA-CF-008',
              title: 'Delegation call without error handling',
              description: `Delegation call in ${file.relativePath} at line ${lineAt(content, m.index)} lacks surrounding error handling.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Wrap delegation calls in try/catch and handle errors from downstream agents.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 5. AA-CF-010 — No timeout on inter-agent calls
  {
    id: 'AA-CF-010',
    name: 'No timeout on inter-agent calls',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Inter-agent or external service calls lack timeout configuration.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const callPatterns = /(?:requests\.(?:get|post|put|patch|delete)|fetch|axios\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|\.invoke|\.ainvoke)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        callPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = callPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 400));
          if (!/timeout\s*[=:]/i.test(region)) {
            findings.push({
              id: `AA-CF-010-${findings.length}`,
              ruleId: 'AA-CF-010',
              title: 'No timeout on call',
              description: `Call in ${file.relativePath} at line ${lineAt(content, m.index)} lacks a timeout parameter.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Add timeout parameter to all inter-agent and external service calls.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 6. AA-CF-013 — Bare except: pass (swallowed errors)
  {
    id: 'AA-CF-013',
    name: 'Bare except swallows error',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'high',
    description: 'Bare except clause with pass or empty catch block silently swallows errors.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;

        // Python: except: pass or except Exception: pass
        const pyBareExcept = /except(?:\s+\w+)?:\s*\n\s+pass\b/g;
        let m: RegExpExecArray | null;
        while ((m = pyBareExcept.exec(content)) !== null) {
          findings.push({
            id: `AA-CF-013-${findings.length}`,
            ruleId: 'AA-CF-013',
            title: 'Bare except swallows error',
            description: `Silent error swallowing (except: pass) in ${file.relativePath} at line ${lineAt(content, m.index)}.`,
            severity: 'high',
            confidence: 'high',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].trim().substring(0, 60) },
            remediation: 'Log or handle errors instead of silently swallowing them with pass.',
            standards: STD,
          });
        }

        // JS/TS: catch (e) {} or catch { }
        const jsEmptyCatch = /catch\s*(?:\([^)]*\))?\s*\{\s*\}/g;
        while ((m = jsEmptyCatch.exec(content)) !== null) {
          findings.push({
            id: `AA-CF-013-${findings.length}`,
            ruleId: 'AA-CF-013',
            title: 'Empty catch block swallows error',
            description: `Empty catch block in ${file.relativePath} at line ${lineAt(content, m.index)}.`,
            severity: 'high',
            confidence: 'high',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
            remediation: 'Log or handle errors inside catch blocks instead of silently swallowing them.',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 7. AA-CF-015 — JSON parsing without try/catch
  {
    id: 'AA-CF-015',
    name: 'JSON parsing without try/catch',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'JSON parsing is not wrapped in error handling, risking crashes on malformed input.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const patterns = [
        /json\.loads\s*\(/g,
        /JSON\.parse\s*\(/g,
        /json\.load\s*\(/g,
      ];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        for (const regex of patterns) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const start = Math.max(0, m.index - 300);
            const region = content.substring(start, m.index);
            if (!/try\s*[:{]|try\s*\{/.test(region)) {
              findings.push({
                id: `AA-CF-015-${findings.length}`,
                ruleId: 'AA-CF-015',
                title: 'JSON parsing without try/catch',
                description: `${m[0].replace(/\s*\($/, '')} in ${file.relativePath} at line ${lineAt(content, m.index)} is not inside a try/catch.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
                remediation: 'Wrap JSON parsing in try/catch to handle malformed input gracefully.',
                standards: STD,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // 8. AA-CF-017 — String formatting in error logs
  {
    id: 'AA-CF-017',
    name: 'String formatting in error logs',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Sensitive data may be interpolated into error log messages via f-strings or template literals.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      // Python: logger.error(f"...{secret/key/token/password}")
      const pyPattern = /(?:logger|logging)\.(?:error|exception|warning)\s*\(\s*f["']/g;
      // JS: console.error(`...${...}`) or logger.error(`...${...}`)
      const jsPattern = /(?:console|logger|log)\.(?:error|warn)\s*\(\s*`[^`]*\$\{/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;

        for (const regex of [pyPattern, jsPattern]) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const region = content.substring(m.index, Math.min(content.length, m.index + 200));
            if (/secret|password|token|key|credential|api_key|apiKey|auth/i.test(region)) {
              findings.push({
                id: `AA-CF-017-${findings.length}`,
                ruleId: 'AA-CF-017',
                title: 'Sensitive data in error log',
                description: `Error log in ${file.relativePath} at line ${lineAt(content, m.index)} may interpolate sensitive data.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
                remediation: 'Avoid interpolating secrets or credentials into log messages. Use structured logging with redaction.',
                standards: STD,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // 9. AA-CF-018 — No transient vs permanent error distinction
  {
    id: 'AA-CF-018',
    name: 'No transient vs permanent error distinction',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Retry logic does not distinguish between transient and permanent errors, wasting resources on non-retryable failures.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const retryPatterns = [
        /@retry\b/g,
        /tenacity\.retry/g,
        /retry_if_exception/g,
        /retryWhen|retryable|shouldRetry|isRetryable/g,
      ];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        for (const regex of retryPatterns) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const region = content.substring(m.index, Math.min(content.length, m.index + 500));
            if (!/retry_if_exception_type|retry_if_not_exception_type|isRetryable|retryable|shouldRetry|transient|permanent|non.?retryable|4\d\d|5\d\d|status.?code/i.test(region)) {
              findings.push({
                id: `AA-CF-018-${findings.length}`,
                ruleId: 'AA-CF-018',
                title: 'Retry without error classification',
                description: `Retry logic in ${file.relativePath} at line ${lineAt(content, m.index)} does not distinguish transient vs permanent errors.`,
                severity: 'medium',
                confidence: 'medium',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
                remediation: 'Only retry transient errors (e.g., 429, 503). Fail fast on permanent errors (e.g., 400, 401).',
                standards: STD,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // 10. AA-CF-020 — No error monitoring setup
  {
    id: 'AA-CF-020',
    name: 'No error monitoring setup',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Project lacks an error monitoring or observability integration (Sentry, Datadog, Prometheus, etc.).',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const monitoringPatterns = /sentry|datadog|prometheus|new.?relic|bugsnag|rollbar|honeybadger|airbrake|elastic.?apm|opentelemetry|grafana/i;
      let found = false;

      // Check dependency files
      for (const file of [...graph.files.json, ...graph.files.configs]) {
        const content = readFile(file.path);
        if (!content) continue;
        if (monitoringPatterns.test(content)) {
          found = true;
          break;
        }
      }

      // Also check code files for monitoring imports
      if (!found) {
        for (const file of codeFiles(graph)) {
          const content = readFile(file.path);
          if (!content) continue;
          if (monitoringPatterns.test(content)) {
            found = true;
            break;
          }
        }
      }

      if (!found && codeFiles(graph).length > 0) {
        findings.push({
          id: 'AA-CF-020-0',
          ruleId: 'AA-CF-020',
          title: 'No error monitoring setup',
          description: 'No error monitoring integration (Sentry, Datadog, Prometheus, etc.) detected in the project.',
          severity: 'medium',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Integrate an error monitoring service (e.g., Sentry, Datadog) for production observability.',
          standards: STD,
        });
      }
      return findings;
    },
  },

  /* ================================================================ */
  /*  CIRCUIT BREAKERS (8 rules)                                      */
  /* ================================================================ */

  // 11. AA-CF-021 — No circuit breaker between agents
  {
    id: 'AA-CF-021',
    name: 'No circuit breaker between agents',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multi-agent system lacks circuit breaker patterns, allowing cascading failures between agents.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;

      let hasCircuitBreaker = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/circuit.?breaker|CircuitBreaker|pybreaker|opossum|cockatiel|polly/i.test(content)) {
          hasCircuitBreaker = true;
          break;
        }
      }

      if (!hasCircuitBreaker) {
        findings.push({
          id: 'AA-CF-021-0',
          ruleId: 'AA-CF-021',
          title: 'No circuit breaker between agents',
          description: `Multi-agent system with ${graph.agents.length} agents lacks circuit breaker patterns.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Implement circuit breakers between agents to prevent cascading failures (e.g., pybreaker, opossum).',
          standards: STD,
        });
      }
      return findings;
    },
  },

  // 12. AA-CF-022 — No circuit breaker for external APIs
  {
    id: 'AA-CF-022',
    name: 'No circuit breaker for external APIs',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'External API calls lack circuit breaker wrapping, risking cascading failures from third-party outages.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const apiCallRegex = /(?:requests\.(?:get|post|put|delete)|fetch\s*\(|axios\.(?:get|post|put|delete)|httpx\.(?:get|post|put|delete))\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        apiCallRegex.lastIndex = 0;
        if (!apiCallRegex.test(content)) continue;
        if (!/circuit.?breaker|CircuitBreaker|pybreaker|opossum|cockatiel/i.test(content)) {
          findings.push({
            id: `AA-CF-022-${findings.length}`,
            ruleId: 'AA-CF-022',
            title: 'External API calls without circuit breaker',
            description: `${file.relativePath} makes external API calls without circuit breaker protection.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Wrap external API calls with a circuit breaker pattern to handle third-party outages gracefully.',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 13. AA-CF-023 — No circuit breaker for DB connections
  {
    id: 'AA-CF-023',
    name: 'No circuit breaker for DB connections',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Database connection code lacks circuit breaker, risking cascading failures from DB outages.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const dbPatterns = /(?:create_engine|connect|MongoClient|psycopg2\.connect|mysql\.connector|sqlite3\.connect|createConnection|createPool|PrismaClient|Sequelize)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        dbPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = dbPatterns.exec(content)) !== null) {
          if (!/circuit.?breaker|CircuitBreaker|pybreaker|opossum/i.test(content)) {
            findings.push({
              id: `AA-CF-023-${findings.length}`,
              ruleId: 'AA-CF-023',
              title: 'DB connection without circuit breaker',
              description: `Database connection in ${file.relativePath} at line ${lineAt(content, m.index)} lacks circuit breaker.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Wrap database connections with a circuit breaker to handle DB outages gracefully.',
              standards: STD,
            });
            break; // one finding per file is enough
          }
        }
      }
      return findings;
    },
  },

  // 14. AA-CF-025 — Circuit breaker no alerting
  {
    id: 'AA-CF-025',
    name: 'Circuit breaker without alerting',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Circuit breaker implementation exists but lacks alerting or logging on state transitions.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (!/circuit.?breaker|CircuitBreaker/i.test(content)) continue;
        if (!/(?:on_open|on_state_change|on_half_open|on_close|state_change|listeners|logger|log\.|alert|notify|emit)/i.test(content)) {
          findings.push({
            id: `AA-CF-025-${findings.length}`,
            ruleId: 'AA-CF-025',
            title: 'Circuit breaker without alerting',
            description: `Circuit breaker in ${file.relativePath} lacks alerting or logging on state changes.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Add logging or alerting callbacks when the circuit breaker changes state (open/half-open/closed).',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 15. AA-CF-026 — No fallback when circuit open
  {
    id: 'AA-CF-026',
    name: 'No fallback when circuit open',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Circuit breaker exists but has no fallback behavior when the circuit is open.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (!/circuit.?breaker|CircuitBreaker/i.test(content)) continue;
        if (!/fallback|fallbackAction|on_open|default_response|cached|graceful/i.test(content)) {
          findings.push({
            id: `AA-CF-026-${findings.length}`,
            ruleId: 'AA-CF-026',
            title: 'No fallback when circuit open',
            description: `Circuit breaker in ${file.relativePath} has no fallback behavior for when the circuit is open.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: 1 },
            remediation: 'Implement a fallback response (cached data, default value, graceful degradation) when the circuit breaker is open.',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 16. AA-CF-029 — No backoff policy for retries
  {
    id: 'AA-CF-029',
    name: 'No backoff policy for retries',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Retry logic lacks exponential backoff, risking thundering herd on failures.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const retryPatterns = /(?:@retry|retry\s*\(|max_retries|retries\s*[:=]|maxRetries|retryCount)/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        retryPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = retryPatterns.exec(content)) !== null) {
          const region = content.substring(Math.max(0, m.index - 300), Math.min(content.length, m.index + 500));
          if (!/backoff|exponential|wait_exponential|wait_random|jitter|delay\s*\*|delay\s*\*\*|Math\.pow|2\s*\*\*/i.test(region)) {
            findings.push({
              id: `AA-CF-029-${findings.length}`,
              ruleId: 'AA-CF-029',
              title: 'Retry without backoff',
              description: `Retry logic in ${file.relativePath} at line ${lineAt(content, m.index)} lacks exponential backoff.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0] },
              remediation: 'Add exponential backoff with jitter to retry logic to prevent thundering herd.',
              standards: STD,
            });
            break; // one per file
          }
        }
      }
      return findings;
    },
  },

  // 17. AA-CF-030 — No rate limit on agent actions
  {
    id: 'AA-CF-030',
    name: 'No rate limit on agent actions',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Agent tool invocations lack rate limiting, risking resource exhaustion.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length === 0) return findings;

      let hasRateLimit = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/rate.?limit|RateLimit|throttle|Throttle|token.?bucket|TokenBucket|leaky.?bucket|slowapi|bottleneck/i.test(content)) {
          hasRateLimit = true;
          break;
        }
      }

      if (!hasRateLimit) {
        for (const agent of graph.agents) {
          if (agent.tools.length > 0) {
            findings.push({
              id: `AA-CF-030-${findings.length}`,
              ruleId: 'AA-CF-030',
              title: 'No rate limit on agent actions',
              description: `Agent "${agent.name}" in ${agent.file} has ${agent.tools.length} tools but no rate limiting detected.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: agent.file, line: agent.line },
              remediation: 'Implement rate limiting on agent tool invocations to prevent resource exhaustion.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 18. AA-CF-032 — No global rate limit
  {
    id: 'AA-CF-032',
    name: 'No global rate limit',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Project has no rate limiting middleware or configuration for incoming requests.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasGlobalRateLimit = false;

      for (const file of allFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/rate.?limit|RateLimitMiddleware|slowapi|express-rate-limit|ratelimit|throttle.?middleware|Throttle|bottleneck/i.test(content)) {
          hasGlobalRateLimit = true;
          break;
        }
      }

      if (!hasGlobalRateLimit && codeFiles(graph).length > 0) {
        findings.push({
          id: 'AA-CF-032-0',
          ruleId: 'AA-CF-032',
          title: 'No global rate limit',
          description: 'No rate limiting middleware or configuration detected in the project.',
          severity: 'medium',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Add rate limiting middleware (e.g., express-rate-limit, slowapi) to protect against abuse.',
          standards: STD,
        });
      }
      return findings;
    },
  },

  /* ================================================================ */
  /*  RESOURCE EXHAUSTION (12 rules)                                  */
  /* ================================================================ */

  // 19. AA-CF-051 — No token/cost limit per request
  {
    id: 'AA-CF-051',
    name: 'No token/cost limit per request',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'LLM API calls lack max_tokens parameter, risking unbounded token usage per request.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const llmCallPatterns = /(?:ChatOpenAI|OpenAI|ChatAnthropic|Anthropic|ChatGoogleGenerativeAI|openai\.chat\.completions\.create|openai\.completions\.create|client\.chat|client\.messages\.create)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        llmCallPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = llmCallPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 500));
          if (!/max_tokens|maxTokens|max_output_tokens/i.test(region)) {
            findings.push({
              id: `AA-CF-051-${findings.length}`,
              ruleId: 'AA-CF-051',
              title: 'LLM call without max_tokens',
              description: `LLM call in ${file.relativePath} at line ${lineAt(content, m.index)} lacks max_tokens parameter.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Set max_tokens on all LLM API calls to cap per-request token usage.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 20. AA-CF-052 — No daily token/cost limit
  {
    id: 'AA-CF-052',
    name: 'No daily token/cost limit',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'No daily token or cost tracking/limiting mechanism detected in the codebase.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasDailyLimit = false;

      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/daily.?limit|daily.?budget|daily.?quota|cost.?limit|budget.?limit|spending.?limit|max.?daily|usage.?limit/i.test(content)) {
          hasDailyLimit = true;
          break;
        }
      }

      if (!hasDailyLimit && graph.models.length > 0) {
        findings.push({
          id: 'AA-CF-052-0',
          ruleId: 'AA-CF-052',
          title: 'No daily token/cost limit',
          description: `Project uses ${graph.models.length} LLM model(s) but has no daily token/cost limiting mechanism.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Implement daily token/cost limits to prevent runaway LLM spending.',
          standards: STD,
        });
      }
      return findings;
    },
  },

  // 21. AA-CF-053 — No context window limit
  {
    id: 'AA-CF-053',
    name: 'No context window limit',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Message history accumulates without bounds, risking context window overflow.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const appendPatterns = /(?:messages\.append|messages\.push|history\.append|history\.push|chat_history\.append|conversation\.append|add_message)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        appendPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = appendPatterns.exec(content)) !== null) {
          const region = content.substring(Math.max(0, m.index - 500), Math.min(content.length, m.index + 500));
          if (!/max.?length|max.?messages|max.?history|truncat|trim|slice|window.?size|context.?limit|pop\(0\)|shift\(\)|deque.*maxlen/i.test(region)) {
            findings.push({
              id: `AA-CF-053-${findings.length}`,
              ruleId: 'AA-CF-053',
              title: 'Unbounded message accumulation',
              description: `Message history grows without limit in ${file.relativePath} at line ${lineAt(content, m.index)}.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Implement a sliding window or maximum message count to cap context size.',
              standards: STD,
            });
            break; // one per file
          }
        }
      }
      return findings;
    },
  },

  // 22. AA-CF-054 — No max tool calls per request
  {
    id: 'AA-CF-054',
    name: 'No max tool calls per request',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent configuration lacks a maximum tool call limit per request, risking infinite tool loops.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const agent of graph.agents) {
        if (findings.length >= 3) break;
        if (!agent.maxIterations && (!agent.resourceLimits || !agent.resourceLimits.hasToolCallLimit)) {
          findings.push({
            id: `AA-CF-054-${findings.length}`,
            ruleId: 'AA-CF-054',
            title: 'No max tool calls per request',
            description: `Agent "${agent.name}" in ${agent.file} has no max_iterations or tool call limit configured.`,
            severity: 'low',
            confidence: 'low',
            domain: 'cascading-failures',
            location: { file: agent.file, line: agent.line },
            remediation: 'Set max_iterations or max_tool_calls to prevent infinite tool call loops.',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 23. AA-CF-055 — No max external API calls
  {
    id: 'AA-CF-055',
    name: 'No max external API calls',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Tools making external API calls lack a call count limit per invocation.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const tool of graph.tools) {
        if (tool.capabilities.includes('network') || tool.capabilities.includes('api')) {
          let content: string | null = null;
          try {
            const filePath = tool.file.startsWith('/') ? tool.file : `${graph.rootPath}/${tool.file}`;
            content = readFile(filePath);
          } catch { /* ignore */ }
          if (content && !/max.?calls|call.?limit|call.?count|rate.?limit|throttle/i.test(content)) {
            findings.push({
              id: `AA-CF-055-${findings.length}`,
              ruleId: 'AA-CF-055',
              title: 'No max external API calls',
              description: `Tool "${tool.name}" in ${tool.file} makes external calls without a call count limit.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: tool.file, line: tool.line },
              remediation: 'Implement a per-invocation call count limit for tools that make external API calls.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 24. AA-CF-056 — No compute time limit
  {
    id: 'AA-CF-056',
    name: 'No compute time limit',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Long-running agent tasks lack a timeout or compute time limit.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      for (const agent of graph.agents) {
        if (!agent.resourceLimits?.hasTimeoutLimit && !agent.errorHandling?.hasTimeout) {
          findings.push({
            id: `AA-CF-056-${findings.length}`,
            ruleId: 'AA-CF-056',
            title: 'No compute time limit',
            description: `Agent "${agent.name}" in ${agent.file} has no timeout or compute time limit configured.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: agent.file, line: agent.line },
            remediation: 'Set a timeout or max execution time for agent tasks to prevent runaway computation.',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 25. AA-CF-058 — No memory limit per agent
  {
    id: 'AA-CF-058',
    name: 'No memory limit per agent',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent processes lack memory limits, risking out-of-memory crashes.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasMemoryLimit = false;

      for (const file of allFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/memory.?limit|mem.?limit|max.?memory|--max.?old.?space|resource\.setrlimit|ulimit|MemoryLimit|memory_limit|cgroup/i.test(content)) {
          hasMemoryLimit = true;
          break;
        }
      }

      if (!hasMemoryLimit && graph.agents.length > 0) {
        findings.push({
          id: 'AA-CF-058-0',
          ruleId: 'AA-CF-058',
          title: 'No memory limit per agent',
          description: `Project with ${graph.agents.length} agent(s) lacks memory limit configuration.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Set memory limits per agent process (e.g., --max-old-space-size, resource.setrlimit, container memory limits).',
          standards: STD,
        });
      }
      return findings;
    },
  },

  // 26. AA-CF-059 — No file descriptor limit
  {
    id: 'AA-CF-059',
    name: 'No file descriptor limit',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'File operations lack limits on open handles, risking file descriptor exhaustion.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const openPatterns = /(?:open\s*\(|fs\.open|fs\.createReadStream|fs\.createWriteStream|fopen)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        openPatterns.lastIndex = 0;
        let count = 0;
        let m: RegExpExecArray | null;
        while ((m = openPatterns.exec(content)) !== null) {
          count++;
        }
        // Flag files with many open calls and no context manager / close
        if (count >= 3) {
          const hasCleanup = /with\s+open|\.close\(\)|\.end\(\)|using\s|finally/i.test(content);
          if (!hasCleanup) {
            findings.push({
              id: `AA-CF-059-${findings.length}`,
              ruleId: 'AA-CF-059',
              title: 'File handles without cleanup',
              description: `${file.relativePath} has ${count} file open calls without consistent cleanup (close/with/finally).`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: 1 },
              remediation: 'Use context managers (with open) or ensure all file handles are closed in finally blocks.',
              standards: STD,
            });
          }
        }
      }
      return findings;
    },
  },

  // 27. AA-CF-060 — No cost tracking
  {
    id: 'AA-CF-060',
    name: 'No cost tracking',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'LLM usage lacks cost tracking or logging, making it hard to detect runaway spending.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.models.length === 0) return findings;

      let hasCostTracking = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/cost.?track|usage.?track|token.?count|token.?usage|total.?tokens|prompt.?tokens|completion.?tokens|langsmith|langfuse|helicone|cost.?log|usage.?log|get_openai_callback/i.test(content)) {
          hasCostTracking = true;
          break;
        }
      }

      if (!hasCostTracking) {
        findings.push({
          id: 'AA-CF-060-0',
          ruleId: 'AA-CF-060',
          title: 'No cost tracking',
          description: `Project uses ${graph.models.length} LLM model(s) but has no cost/token tracking mechanism.`,
          severity: 'medium',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Add LLM cost/token tracking (e.g., LangSmith, Langfuse, Helicone, or manual token counting).',
          standards: STD,
        });
      }
      return findings;
    },
  },

  // 28. AA-CF-062 — Unbounded conversation history
  {
    id: 'AA-CF-062',
    name: 'Unbounded conversation history',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Conversation memory is used without a maximum length, risking context window overflow and cost explosion.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const memoryPatterns = /(?:ConversationBufferMemory|ChatMessageHistory|MessageHistory|InMemoryChatMessageHistory|BaseChatMessageHistory)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        memoryPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = memoryPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 400));
          if (!/max.?length|max.?messages|k=|window.?size|max_token_limit|ConversationBufferWindowMemory|ConversationSummaryMemory/i.test(region)) {
            findings.push({
              id: `AA-CF-062-${findings.length}`,
              ruleId: 'AA-CF-062',
              title: 'Unbounded conversation memory',
              description: `Conversation memory in ${file.relativePath} at line ${lineAt(content, m.index)} has no max length or window.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Use ConversationBufferWindowMemory with k= or set max_token_limit to bound conversation history.',
              standards: STD,
            });
          }
        }
      }

      // Also check agents with memory but no limit
      for (const agent of graph.agents) {
        if (agent.memoryType && !/window|summary|token_limit/i.test(agent.memoryType)) {
          findings.push({
            id: `AA-CF-062-${findings.length}`,
            ruleId: 'AA-CF-062',
            title: 'Agent with unbounded memory',
            description: `Agent "${agent.name}" uses "${agent.memoryType}" memory without a window or token limit.`,
            severity: 'medium',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: agent.file, line: agent.line },
            remediation: 'Switch to windowed or summary memory, or set a max_token_limit.',
            standards: STD,
          });
        }
      }
      return findings;
    },
  },

  // 29. AA-CF-064 — No log rotation
  {
    id: 'AA-CF-064',
    name: 'No log rotation',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Logging configuration lacks rotation settings, risking disk exhaustion from unbounded logs.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasLogging = false;
      let hasRotation = false;

      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/logging\.(?:basicConfig|FileHandler|getLogger)|winston|pino|bunyan|log4j|FileHandler/i.test(content)) {
          hasLogging = true;
          if (/RotatingFileHandler|TimedRotatingFileHandler|maxBytes|maxSize|maxFiles|rotate|logrotate|rotation|DailyRotateFile/i.test(content)) {
            hasRotation = true;
            break;
          }
        }
      }

      // Also check config files
      if (!hasRotation) {
        for (const file of [...graph.files.yaml, ...graph.files.json, ...graph.files.configs]) {
          const content = readFile(file.path);
          if (!content) continue;
          if (/logrotate|rotate|maxSize|maxFiles|RotatingFileHandler/i.test(content)) {
            hasRotation = true;
            break;
          }
        }
      }

      if (hasLogging && !hasRotation) {
        findings.push({
          id: 'AA-CF-064-0',
          ruleId: 'AA-CF-064',
          title: 'No log rotation',
          description: 'Logging is configured but no log rotation is set up, risking disk exhaustion.',
          severity: 'medium',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Add log rotation (e.g., RotatingFileHandler, winston maxSize/maxFiles, logrotate).',
          standards: STD,
        });
      }
      return findings;
    },
  },

  // 30. AA-CF-066 — No auto-scaling limit
  {
    id: 'AA-CF-066',
    name: 'No auto-scaling limit',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Deployment configuration lacks resource limits or auto-scaling caps.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      let hasDeployConfig = false;
      let hasResourceLimit = false;

      const deployFiles = allFiles(graph).filter(f =>
        /docker|compose|kubernetes|k8s|helm|terraform|cloudformation|serverless|Procfile|app\.yaml/i.test(f.relativePath)
      );

      for (const file of deployFiles) {
        hasDeployConfig = true;
        const content = readFile(file.path);
        if (!content) continue;
        if (/(?:resources:|limits:|maxReplicas|max_instances|max_scale|memory:|cpu:|max.?capacity|max.?concurrency|reserved.?concurrency)/i.test(content)) {
          hasResourceLimit = true;
          break;
        }
      }

      // Also check YAML/JSON config files for k8s-style resource limits
      if (!hasResourceLimit) {
        for (const file of [...graph.files.yaml, ...graph.files.json]) {
          const content = readFile(file.path);
          if (!content) continue;
          if (/(?:resources:\s*\n\s*limits:|maxReplicas|max_instances|memory_limit|cpu_limit)/i.test(content)) {
            hasResourceLimit = true;
            break;
          }
        }
      }

      if (hasDeployConfig && !hasResourceLimit) {
        findings.push({
          id: 'AA-CF-066-0',
          ruleId: 'AA-CF-066',
          title: 'No auto-scaling limit',
          description: 'Deployment configuration found but lacks resource limits or auto-scaling caps.',
          severity: 'medium',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: deployFiles[0]?.relativePath ?? graph.rootPath, line: 1 },
          remediation: 'Set resource limits (CPU, memory) and auto-scaling caps in deployment configuration.',
          standards: STD,
        });
      }
      return findings;
    },
  },

  /* ================================================================ */
  /*  GAP-FILL RULES (10 rules)                                       */
  /* ================================================================ */

  // 31. AA-CF-001 — Single agent failure crashes entire system
  {
    id: 'AA-CF-001',
    name: 'Single agent failure crashes entire system',
    domain: 'cascading-failures',
    severity: 'critical',
    confidence: 'medium',
    description: 'Agent invocation lacks try/catch — a single agent crash can take down the entire system.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const invokePatterns = /(?:(?:agent|executor|chain|crew|runner|pipeline)\.(?:run|invoke|ainvoke|call|execute)\(|agent\.run|crew\.kickoff|\.initiate_chat)\s*/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        invokePatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = invokePatterns.exec(content)) !== null) {
          const before = content.substring(Math.max(0, m.index - 400), m.index);
          const after = content.substring(m.index, Math.min(content.length, m.index + 400));
          if (!/try\s*[:{]|try\s*\{/.test(before) && !/\.catch\s*\(/.test(after)) {
            findings.push({
              id: `AA-CF-001-${findings.length}`,
              ruleId: 'AA-CF-001',
              title: 'Agent invocation without error boundary',
              description: `Agent invocation in ${file.relativePath} at line ${lineAt(content, m.index)} has no try/catch — failure crashes system.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].trim().substring(0, 60) },
              remediation: 'Wrap agent invocations in try/catch so a single agent failure does not crash the entire system.',
              standards: STD_EXT,
            });
          }
        }
      }
      return findings;
    },
  },

  // 32. AA-CF-002 — Tool error causes undefined agent state
  {
    id: 'AA-CF-002',
    name: 'Tool error causes undefined agent state',
    domain: 'cascading-failures',
    severity: 'critical',
    confidence: 'medium',
    description: 'Tool call lacks error-state handling — a tool failure leaves the agent in an undefined state.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const toolCallPatterns = /(?:tool\.run|tool\.invoke|tool_call|execute_tool|call_tool|\.use_tool)\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        toolCallPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = toolCallPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 500));
          if (!/(?:error_state|state\s*=\s*['"]error|status\s*=\s*['"]failed|on_tool_error|handle_tool_error|ToolError)/i.test(region)) {
            findings.push({
              id: `AA-CF-002-${findings.length}`,
              ruleId: 'AA-CF-002',
              title: 'No error-state handling after tool failure',
              description: `Tool call in ${file.relativePath} at line ${lineAt(content, m.index)} has no error-state transition on failure.`,
              severity: 'critical',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Set an explicit error state after tool failures so the agent does not continue in an undefined state.',
              standards: STD_EXT,
            });
          }
        }
      }
      return findings;
    },
  },

  // 33. AA-CF-006 — Tool error fails all tools for agent
  {
    id: 'AA-CF-006',
    name: 'Tool error disables other tools',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Tool execution in a shared loop means one tool error breaks the remaining tools for the agent.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const loopPatterns = /for\s+(?:\w+\s+in\s+tools|tool\s+(?:in|of)\s+|.*\btool_list\b)/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        loopPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = loopPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 600));
          if (!/try\s*[:{]|try\s*\{|individual.?error|per.?tool.?error/i.test(region)) {
            findings.push({
              id: `AA-CF-006-${findings.length}`,
              ruleId: 'AA-CF-006',
              title: 'Tool loop without per-tool error handling',
              description: `Tool iteration in ${file.relativePath} at line ${lineAt(content, m.index)} lacks per-tool try/catch.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Wrap each tool invocation inside the loop in its own try/catch so one tool failure does not block others.',
              standards: STD_EXT,
            });
          }
        }
      }
      return findings;
    },
  },

  // 34. AA-CF-007 — Corrupted state after partial failure
  {
    id: 'AA-CF-007',
    name: 'Corrupted state after partial failure',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multi-step operation lacks rollback on partial completion, risking inconsistent state.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const multiStepPatterns = /(?:step\s*\[|steps\s*=|pipeline\s*=|stage\s*\d|phase\s*\d|\.execute_step|run_steps)/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        multiStepPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = multiStepPatterns.exec(content)) !== null) {
          const region = content.substring(Math.max(0, m.index - 300), Math.min(content.length, m.index + 600));
          if (!/rollback|compensat|undo|revert|cleanup|transaction|atomic|savepoint/i.test(region)) {
            findings.push({
              id: `AA-CF-007-${findings.length}`,
              ruleId: 'AA-CF-007',
              title: 'No rollback on partial failure',
              description: `Multi-step operation in ${file.relativePath} at line ${lineAt(content, m.index)} lacks rollback or compensation logic.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Implement rollback or compensation logic so partial failures do not corrupt system state.',
              standards: STD_EXT,
            });
            break; // one per file
          }
        }
      }
      return findings;
    },
  },

  // 35. AA-CF-009 — Background task errors unhandled
  {
    id: 'AA-CF-009',
    name: 'Background task errors unhandled',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Async background tasks lack error handlers, causing silent failures.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const bgPatterns = [
        /asyncio\.create_task\s*\(/g,
        /asyncio\.ensure_future\s*\(/g,
        /loop\.run_in_executor\s*\(/g,
        /Promise\.all\s*\(/g,
        /setImmediate\s*\(/g,
        /process\.nextTick\s*\(/g,
        /new\s+Thread\s*\(/g,
        /threading\.Thread\s*\(/g,
      ];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        for (const regex of bgPatterns) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const region = content.substring(m.index, Math.min(content.length, m.index + 400));
            if (!/\.catch\s*\(|\.on\(\s*['"]error|add_done_callback|except|on_error|\.then\(.*,/i.test(region)) {
              findings.push({
                id: `AA-CF-009-${findings.length}`,
                ruleId: 'AA-CF-009',
                title: 'Background task without error handler',
                description: `Background task in ${file.relativePath} at line ${lineAt(content, m.index)} lacks an error handler.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
                remediation: 'Attach error handlers (.catch, add_done_callback, except) to all background/async tasks.',
                standards: STD_EXT,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  // 36. AA-CF-011 — Partial failures cause inconsistency
  {
    id: 'AA-CF-011',
    name: 'Partial failures cause inconsistency',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multiple side-effect operations lack transactional semantics — partial success leaves data inconsistent.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const writePatterns = /(?:\.save\(|\.update\(|\.insert\(|\.delete\(|\.put\(|\.write\(|\.send\()/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        writePatterns.lastIndex = 0;
        let count = 0;
        let firstIdx = 0;
        let m: RegExpExecArray | null;
        while ((m = writePatterns.exec(content)) !== null) {
          if (count === 0) firstIdx = m.index;
          count++;
        }
        if (count >= 3 && !/transaction|atomic|begin\(\)|commit\(\)|rollback|saga|compensat/i.test(content)) {
          findings.push({
            id: `AA-CF-011-${findings.length}`,
            ruleId: 'AA-CF-011',
            title: 'Multiple writes without transactional semantics',
            description: `${file.relativePath} has ${count} write operations with no transactional pattern.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: lineAt(content, firstIdx) },
            remediation: 'Use transactions, sagas, or compensation patterns to ensure atomicity across writes.',
            standards: STD_EXT,
          });
        }
      }
      return findings;
    },
  },

  // 37. AA-CF-012 — Behavioral drift after error recovery
  {
    id: 'AA-CF-012',
    name: 'Behavioral drift after error recovery',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Error recovery path does not verify state integrity, risking behavioral drift.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const recoveryPatterns = /(?:recover|on_error|handle_error|error_handler|fallback|on_failure)\s*(?:\(|=|:)/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        recoveryPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = recoveryPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 600));
          if (!/verify|validate|assert|check_state|health_check|integrity|consistent|invariant/i.test(region)) {
            findings.push({
              id: `AA-CF-012-${findings.length}`,
              ruleId: 'AA-CF-012',
              title: 'No state verification after recovery',
              description: `Error recovery in ${file.relativePath} at line ${lineAt(content, m.index)} does not verify state post-recovery.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'After error recovery, verify system state integrity before resuming normal operations.',
              standards: STD_EXT,
            });
          }
        }
      }
      return findings;
    },
  },

  // 38. AA-CF-014 — Retry amplification (retry storm)
  {
    id: 'AA-CF-014',
    name: 'Retry amplification (retry storm)',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Retry logic uses fixed delay without backoff or jitter, risking thundering-herd retry storms.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const fixedRetryPatterns = [
        /time\.sleep\s*\(\s*\d+\s*\)/g,
        /await\s+asyncio\.sleep\s*\(\s*\d+\s*\)/g,
        /setTimeout\s*\(\s*\w+\s*,\s*\d+\s*\)/g,
        /Thread\.sleep\s*\(\s*\d+\s*\)/g,
      ];
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        for (const regex of fixedRetryPatterns) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const region = content.substring(Math.max(0, m.index - 400), Math.min(content.length, m.index + 400));
            if (/retry|attempt|while|loop|max_retries|maxRetries/i.test(region) && !/jitter|random|exponential|backoff|\*\s*2|\*\*\s*attempt/i.test(region)) {
              findings.push({
                id: `AA-CF-014-${findings.length}`,
                ruleId: 'AA-CF-014',
                title: 'Fixed-delay retry without backoff/jitter',
                description: `Retry with fixed delay in ${file.relativePath} at line ${lineAt(content, m.index)} — no backoff or jitter.`,
                severity: 'high',
                confidence: 'medium',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
                remediation: 'Use exponential backoff with jitter (e.g., delay * 2^attempt + random) to prevent retry storms.',
                standards: STD_EXT,
              });
              break; // one per file per pattern
            }
          }
        }
      }
      return findings;
    },
  },

  // 39. AA-CF-016 — Concurrent error race conditions
  {
    id: 'AA-CF-016',
    name: 'Concurrent error race conditions',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Shared mutable state is accessed by concurrent agents or tasks without synchronization.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const sharedStatePatterns = /(?:global\s+\w+|shared_state|shared_memory|global_state|globalThis\.\w+)\s*/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        sharedStatePatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = sharedStatePatterns.exec(content)) !== null) {
          const region = content.substring(Math.max(0, m.index - 300), Math.min(content.length, m.index + 500));
          if (/async|thread|concurrent|parallel|worker|gather|Promise\.all/i.test(region) &&
              !/lock|mutex|semaphore|synchronized|atomic|Lock\(\)|RLock|threading\.Lock/i.test(region)) {
            findings.push({
              id: `AA-CF-016-${findings.length}`,
              ruleId: 'AA-CF-016',
              title: 'Shared state without synchronization',
              description: `Shared mutable state in ${file.relativePath} at line ${lineAt(content, m.index)} accessed concurrently without a lock.`,
              severity: 'medium',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].trim().substring(0, 60) },
              remediation: 'Use locks, mutexes, or atomic operations when accessing shared state from concurrent tasks.',
              standards: STD_EXT,
            });
            break; // one per file
          }
        }
      }
      return findings;
    },
  },

  // 40. AA-CF-019 — Error misinterpretation (generic catch swallows)
  {
    id: 'AA-CF-019',
    name: 'Error misinterpretation via generic catch',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'Generic catch blocks catch all exception types, masking the true cause of failures.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const pyBareExcept = /except\s*:/g;
      const pyBroadExcept = /except\s+(?:Exception|BaseException)\s*(?:as\s+\w+\s*)?:/g;
      const jsBroadCatch = /catch\s*\(\s*\w+\s*\)\s*\{\s*(?:\/\/[^\n]*\n?\s*\}|\})/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        for (const regex of [pyBareExcept, pyBroadExcept, jsBroadCatch]) {
          regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          while ((m = regex.exec(content)) !== null) {
            const region = content.substring(m.index, Math.min(content.length, m.index + 300));
            if (!/raise|throw|re-raise|log.*type|instanceof|error\.code|error\.name|error\.status/i.test(region)) {
              findings.push({
                id: `AA-CF-019-${findings.length}`,
                ruleId: 'AA-CF-019',
                title: 'Generic catch masks error type',
                description: `Generic catch in ${file.relativePath} at line ${lineAt(content, m.index)} swallows all errors without type inspection.`,
                severity: 'medium',
                confidence: 'low',
                domain: 'cascading-failures',
                location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
                remediation: 'Catch specific exception types, or inspect/re-raise so errors are not misinterpreted.',
                standards: STD_EXT,
              });
            }
          }
        }
      }
      return findings;
    },
  },

  /* ================================================================ */
  /*  BLAST RADIUS CONTROLS (10 rules)                                */
  /* ================================================================ */

  // 41. AA-CF-036 — Compromised agent accesses all resources
  {
    id: 'AA-CF-036',
    name: 'No per-agent resource boundaries',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Agents share the same resource access — a compromised agent can access all system resources.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;
      for (const agent of graph.agents) {
        if (!agent.isolationLevel || agent.isolationLevel === 'none') {
          findings.push({
            id: `AA-CF-036-${findings.length}`,
            ruleId: 'AA-CF-036',
            title: 'Agent has no resource boundary',
            description: `Agent "${agent.name}" in ${agent.file} has no isolation — shares all resources with other agents.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: agent.file, line: agent.line },
            remediation: 'Assign per-agent resource boundaries (separate credentials, namespaces, or containers).',
            standards: STD_EXT,
          });
        }
      }
      return findings;
    },
  },

  // 42. AA-CF-037 — No network segmentation between agents
  {
    id: 'AA-CF-037',
    name: 'No network segmentation between agents',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multi-agent system lacks network segmentation — agents can reach any internal service.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;
      let hasNetworkPolicy = false;
      for (const file of allFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/NetworkPolicy|network.?policy|firewall.?rule|security.?group|ingress|egress|network.?segmentation/i.test(content)) {
          hasNetworkPolicy = true;
          break;
        }
      }
      if (!hasNetworkPolicy) {
        findings.push({
          id: 'AA-CF-037-0',
          ruleId: 'AA-CF-037',
          title: 'No network segmentation between agents',
          description: `Multi-agent system with ${graph.agents.length} agents lacks network segmentation or policies.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Apply network policies or security groups so agents cannot freely reach all internal services.',
          standards: STD_EXT,
        });
      }
      return findings;
    },
  },

  // 43. AA-CF-038 — Shared database credentials across agents
  {
    id: 'AA-CF-038',
    name: 'Shared database credentials across agents',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multiple agents use the same database connection string or credentials.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;
      const dbCreds: Set<string> = new Set();
      const dbCredPattern = /(?:DATABASE_URL|DB_CONNECTION|MONGO_URI|POSTGRES_URL|MYSQL_URL|REDIS_URL)\s*[=:]\s*["']?([^\s"']+)/g;
      for (const file of allFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        dbCredPattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = dbCredPattern.exec(content)) !== null) {
          dbCreds.add(m[1]);
        }
      }
      if (dbCreds.size === 1 && graph.agents.length > 1) {
        findings.push({
          id: 'AA-CF-038-0',
          ruleId: 'AA-CF-038',
          title: 'Shared database credentials across agents',
          description: `All ${graph.agents.length} agents appear to share a single database credential.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Use per-agent database credentials with least-privilege access scoping.',
          standards: STD_EXT,
        });
      }
      return findings;
    },
  },

  // 44. AA-CF-039 — No per-agent resource quotas
  {
    id: 'AA-CF-039',
    name: 'No per-agent resource quotas',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multi-agent system has no per-agent quotas for CPU, memory, or API calls.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;
      let hasQuota = false;
      for (const file of allFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/quota|ResourceQuota|per.?agent.?limit|agent.?quota|per.?agent.?budget|LimitRange/i.test(content)) {
          hasQuota = true;
          break;
        }
      }
      if (!hasQuota) {
        findings.push({
          id: 'AA-CF-039-0',
          ruleId: 'AA-CF-039',
          title: 'No per-agent resource quotas',
          description: `Multi-agent system with ${graph.agents.length} agents lacks per-agent resource quotas.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Define per-agent quotas for CPU, memory, and API calls to limit blast radius.',
          standards: STD_EXT,
        });
      }
      return findings;
    },
  },

  // 45. AA-CF-040 — Unlimited resource allocation per agent
  {
    id: 'AA-CF-040',
    name: 'Unlimited resource allocation per agent',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent can allocate unbounded resources (spawn processes, open connections) without limits.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const spawnPatterns = /(?:subprocess\.Popen|subprocess\.run|child_process\.exec|child_process\.spawn|os\.system|exec\(|fork\()\s*\(/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        spawnPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = spawnPatterns.exec(content)) !== null) {
          const region = content.substring(Math.max(0, m.index - 300), Math.min(content.length, m.index + 400));
          if (!/max.?process|pool.?size|semaphore|limit|max.?workers|max.?concurrent/i.test(region)) {
            findings.push({
              id: `AA-CF-040-${findings.length}`,
              ruleId: 'AA-CF-040',
              title: 'Unbounded process/resource spawning',
              description: `Process spawn in ${file.relativePath} at line ${lineAt(content, m.index)} has no concurrency limit.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Use a pool or semaphore to cap concurrent process/resource allocation per agent.',
              standards: STD_EXT,
            });
          }
        }
      }
      return findings;
    },
  },

  // 46. AA-CF-041 — No process isolation between agents
  {
    id: 'AA-CF-041',
    name: 'No process isolation between agents',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Multiple agents run in a single process with no isolation — a crash or OOM kills all agents.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;
      let hasIsolation = false;
      for (const agent of graph.agents) {
        if (agent.isolationLevel && agent.isolationLevel !== 'none') {
          hasIsolation = true;
          break;
        }
      }
      if (!hasIsolation) {
        // Also check for container/process isolation in configs
        for (const file of allFiles(graph)) {
          const content = readFile(file.path);
          if (!content) continue;
          if (/docker.?compose|Dockerfile|multiprocessing|worker_process|subprocess|cluster\.fork|child_process|container.?per.?agent/i.test(content)) {
            hasIsolation = true;
            break;
          }
        }
      }
      if (!hasIsolation) {
        findings.push({
          id: 'AA-CF-041-0',
          ruleId: 'AA-CF-041',
          title: 'No process isolation between agents',
          description: `${graph.agents.length} agents appear to share a single process with no isolation.`,
          severity: 'high',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Run agents in separate processes or containers so one agent crash does not affect others.',
          standards: STD_EXT,
        });
      }
      return findings;
    },
  },

  // 47. AA-CF-042 — Shared infrastructure modification allowed
  {
    id: 'AA-CF-042',
    name: 'Shared infrastructure modification allowed',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Agents can modify shared infrastructure (env vars, configs, global state) affecting other agents.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const infraModPatterns = /(?:os\.environ\[|process\.env\[|os\.putenv|setenv|global\s+\w+\s*=|globalThis\.\w+\s*=|shared_config\[)/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        infraModPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = infraModPatterns.exec(content)) !== null) {
          findings.push({
            id: `AA-CF-042-${findings.length}`,
            ruleId: 'AA-CF-042',
            title: 'Agent modifies shared infrastructure',
            description: `Shared infrastructure mutation in ${file.relativePath} at line ${lineAt(content, m.index)} — can affect other agents.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
            remediation: 'Prevent agents from modifying shared env vars, globals, or configs. Use per-agent configuration.',
            standards: STD_EXT,
          });
        }
      }
      return findings;
    },
  },

  // 48. AA-CF-043 — Dependent systems not identified
  {
    id: 'AA-CF-043',
    name: 'Dependent systems not identified',
    domain: 'cascading-failures',
    severity: 'medium',
    confidence: 'medium',
    description: 'No dependency map or health-check registry exists to identify which systems agents depend on.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length === 0) return findings;
      let hasDependencyMap = false;
      for (const file of allFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/dependency.?map|service.?registry|health.?check|readiness.?probe|liveness.?probe|depends_on|service.?discovery|consul|eureka/i.test(content)) {
          hasDependencyMap = true;
          break;
        }
      }
      if (!hasDependencyMap) {
        findings.push({
          id: 'AA-CF-043-0',
          ruleId: 'AA-CF-043',
          title: 'Dependent systems not identified',
          description: 'No dependency map, health checks, or service registry found for agent dependencies.',
          severity: 'medium',
          confidence: 'medium',
          domain: 'cascading-failures',
          location: { file: graph.rootPath, line: 1 },
          remediation: 'Create a dependency map and health-check registry so blast radius can be assessed during incidents.',
          standards: STD_EXT,
        });
      }
      return findings;
    },
  },

  // 49. AA-CF-044 — Recovery without verification
  {
    id: 'AA-CF-044',
    name: 'Recovery without verification',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'System recovery logic does not verify health before resuming traffic or operations.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      const restartPatterns = /(?:restart|respawn|auto.?heal|recover|reconnect|re.?init)\s*(?:\(|=|:)/g;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        restartPatterns.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = restartPatterns.exec(content)) !== null) {
          const region = content.substring(m.index, Math.min(content.length, m.index + 500));
          if (!/health.?check|verify|validate|ready|ping|is.?healthy|is.?alive|warm.?up/i.test(region)) {
            findings.push({
              id: `AA-CF-044-${findings.length}`,
              ruleId: 'AA-CF-044',
              title: 'Recovery without health verification',
              description: `Recovery logic in ${file.relativePath} at line ${lineAt(content, m.index)} resumes without health check.`,
              severity: 'high',
              confidence: 'medium',
              domain: 'cascading-failures',
              location: { file: file.relativePath, line: lineAt(content, m.index), snippet: m[0].substring(0, 60) },
              remediation: 'Add a health check or readiness probe before resuming traffic after recovery.',
              standards: STD_EXT,
            });
          }
        }
      }
      return findings;
    },
  },

  // 50. AA-CF-045 — Cascade depth unlimited
  {
    id: 'AA-CF-045',
    name: 'Cascade depth unlimited',
    domain: 'cascading-failures',
    severity: 'high',
    confidence: 'medium',
    description: 'Agent delegation chains have no depth limit — errors can cascade through unbounded delegation layers.',
    frameworks: ['all'],
    owaspAgentic: ['ASI09'],
    standards: STD_EXT,
    check: (graph: AgentGraph): Finding[] => {
      const findings: Finding[] = [];
      if (graph.agents.length < 2) return findings;
      let hasDepthLimit = false;
      for (const file of codeFiles(graph)) {
        const content = readFile(file.path);
        if (!content) continue;
        if (/max.?depth|max.?delegation|delegation.?limit|recursion.?limit|max.?hops|depth.?limit|max.?chain/i.test(content)) {
          hasDepthLimit = true;
          break;
        }
      }
      if (!hasDepthLimit) {
        const delegating = graph.agents.filter(a => a.delegationTargets && a.delegationTargets.length > 0);
        if (delegating.length > 0) {
          findings.push({
            id: 'AA-CF-045-0',
            ruleId: 'AA-CF-045',
            title: 'No delegation depth limit',
            description: `${delegating.length} agent(s) delegate to others with no depth limit — unbounded cascade risk.`,
            severity: 'high',
            confidence: 'medium',
            domain: 'cascading-failures',
            location: { file: delegating[0].file, line: delegating[0].line },
            remediation: 'Set a max_depth or delegation_limit to prevent unbounded cascading through agent chains.',
            standards: STD_EXT,
          });
        }
      }
      return findings;
    },
  },
];
