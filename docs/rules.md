# g0 Security Rules Reference

g0 ships **1,182+ security rules** across **12 security domains**, combining 455 TypeScript-based rules with 727 YAML declarative rules.

## Rule Architecture

Rules are implemented in two formats:

- **TypeScript rules** (`src/analyzers/rules/*.ts`) — Complex rules requiring AST analysis, multi-file correlation, or custom logic. Each domain has a dedicated file exporting a `Rule[]` array.
- **YAML rules** (`src/rules/builtin/{domain}/*.yaml`) — Declarative rules compiled at startup via `src/rules/yaml-compiler.ts`. Support 11 check types for pattern matching, prompt analysis, and taint flow tracking.

### Rule ID Format

```
AA-{DOMAIN}-{NUMBER}
```

| Code | Domain |
|------|--------|
| GI | Goal Integrity |
| TS | Tool Safety |
| IA | Identity & Access |
| SC | Supply Chain |
| CE | Code Execution |
| MP | Memory & Context |
| DL | Data Leakage |
| CF | Cascading Failures |
| HO | Human Oversight |
| IC | Inter-Agent |
| RB | Reliability Bounds |
| RA | Rogue Agent |

---

## Domain Breakdown

### 1. Goal Integrity (121 rules)

**TS:** 60 rules (AA-GI-001 to AA-GI-060) | **YAML:** 61 rules

Detects prompt injection vectors, missing safety guardrails, and goal manipulation attacks.

| Category | Examples |
|----------|----------|
| Prompt injection | System prompt extraction, delimiter injection, payload splitting |
| Goal manipulation | Competing objectives, goal substitution, semantic drift |
| Missing guardrails | No boundary tokens, no refusal instruction, no scope limitation |
| Indirect injection | Via database, email, document, URL |
| Advanced attacks | Homoglyph/unicode injection, ASCII art, base64 encoded, multilingual |

**Key TS rules:**
- `AA-GI-001` — Missing safety preamble in system prompt
- `AA-GI-003` — User input injected into system prompt (critical)
- `AA-GI-005` — No output constraints on agent response
- `AA-GI-010` — Prompt template injection via f-string/format

**FP reduction:** Prompt length threshold (>50 chars), keyword-aware filtering.

---

### 2. Tool Safety (155 rules)

**TS:** 40 rules (AA-TS-001 to AA-TS-040) | **YAML:** 115 rules

Detects dangerous tool capabilities, missing input validation, and injection vectors.

| Category | Examples |
|----------|----------|
| Injection attacks | SQL, command, path traversal, LDAP, NoSQL, template, XML |
| Dangerous capabilities | Shell execution, file write, database access, network scan |
| Missing safeguards | No input validation, no output sanitization, no rate limiting |
| Tool integrity | Description poisoning, schema manipulation, cache poisoning |
| Language-specific | Go path traversal, Go SQL injection, Go template injection, Java path traversal, Java SQL injection |

**Key TS rules:**
- `AA-TS-002` — SQL injection via string concatenation (critical)
- `AA-TS-003` — Path traversal via unsanitized file path (critical)
- `AA-TS-007` — Command injection via shell execution (critical)
- `AA-TS-010` — SSRF via unvalidated URL parameter (high)

**YAML check types used:** `code_matches`, `tool_has_capability`, `tool_missing_property`

---

### 3. Identity & Access (104 rules)

**TS:** 60 rules (AA-IA-001 to AA-IA-060) | **YAML:** 44 rules

Detects authentication/authorization weaknesses and credential exposure.

| Category | Examples |
|----------|----------|
| Hardcoded secrets | API keys, tokens, passwords in source code |
| Auth weaknesses | No auth endpoint, missing MFA, weak JWT, no rate limit |
| Access control | BOLA/BFLA risk, RBAC bypass, privilege escalation chain |
| Language-specific | Go hardcoded secrets, Go HTTP no auth, Java hardcoded secrets, Spring Security misconfig |

**Key TS rules:**
- `AA-IA-001` — Hardcoded API key (critical)
- `AA-IA-003` — No authentication on agent endpoint (critical)
- `AA-IA-005` — Overprivileged agent role (high)

**FP reduction:** Import/require line skipping, test file exclusion, `.env.example` filtering.

---

### 4. Supply Chain (91 rules)

**TS:** 30 rules (AA-SC-001 to AA-SC-030) | **YAML:** 61 rules

Detects dependency risks, unpinned versions, and model supply chain attacks.

| Category | Examples |
|----------|----------|
| Dependency pinning | Unpinned Python/JS/Go deps, unpinned AI models |
| Package risks | Typosquatting, dependency confusion, scope confusion |
| Model integrity | Pickle model loading, unverified HuggingFace models, GGUF unverified |
| CI/CD | GitHub Actions unpinned, build pipeline injection, setup.py code exec |
| Container | Docker ADD URL, container run as root, env file in image |

**Key TS rules:**
- `AA-SC-001` — Unpinned Python dependencies (medium)
- `AA-SC-005` — Known vulnerable dependency (high)
- `AA-SC-010` — Pickle model loading (critical)

---

### 5. Code Execution (94 rules)

**TS:** 60 rules (AA-CE-001 to AA-CE-064) | **YAML:** 34 rules

Detects arbitrary code execution, unsafe deserialization, and sandbox escapes.

| Category | Examples |
|----------|----------|
| Dynamic execution | eval(), exec(), Function constructor |
| Shell injection | os.system, subprocess, child_process, exec.Command |
| Deserialization | Pickle, Java ObjectInputStream, YAML unsafe load |
| Taint tracking | LLM output to exec, user input to shell, user input to SQL |
| Language-specific | Java reflection abuse, Java ScriptEngine, Go CGo unsafe, VM context escape |

**Key TS rules:**
- `AA-CE-001` — eval() with dynamic input (critical)
- `AA-CE-002` — exec() with dynamic input (critical)
- `AA-CE-006` — Unsafe deserialization (critical)

**FP reduction:** AST-based literal string detection (skips `exec("constant")`), tree-sitter integration.

---

### 6. Data Leakage (124 rules)

**TS:** 60 rules (AA-DL-001 to AA-DL-060) | **YAML:** 64 rules

Detects sensitive data exposure, logging risks, and exfiltration channels.

| Category | Examples |
|----------|----------|
| Logging risks | PII in logs, API keys logged, conversation history logged |
| Error exposure | Stack traces leaked, verbose error messages, debug endpoints |
| Exfiltration | DNS exfil, URL exfil, markdown image exfil, clipboard exfil |
| Data handling | No output filter, no DLP integration, no data classification |
| Language-specific | Go printf secrets, Java logger secrets, Java System.getenv |

**Key TS rules:**
- `AA-DL-001` — PII logged to console/file (high)
- `AA-DL-003` — Stack trace in error response (high)
- `AA-DL-010` — Sensitive data in API response (high)

---

### 7. Memory & Context (101 rules)

**TS:** 25 rules (AA-MP-001 to AA-MP-025) | **YAML:** 76 rules

Detects memory poisoning, context overflow, and RAG vulnerabilities.

| Category | Examples |
|----------|----------|
| Memory safety | No access control, no encryption, no expiry, no rollback |
| Context attacks | Overflow, injection via separator, window poisoning |
| RAG security | Poisoning injection, cross-tenant retrieval, no content filter |
| Vector DB | No auth, public endpoint, unencrypted, shared collection |
| Session | Cross-session leak, state poisoning, conversation tampering |

**Key TS rules:**
- `AA-MP-001` — Unbounded conversation memory (high)
- `AA-MP-005` — No memory access control (high)
- `AA-MP-010` — RAG injection risk (critical)

**FP reduction:** AST-based framework detection (e.g., ConversationBufferWindowMemory bypass).

---

### 8. Cascading Failures (71 rules)

**TS:** 50 rules (AA-CF-001 to AA-CF-066) | **YAML:** 21 rules

Detects error propagation, missing resilience patterns, and resource exhaustion.

| Category | Examples |
|----------|----------|
| Error propagation | No error boundary, bare except, swallowed errors |
| Retry logic | No max count, no backoff, tight retry loops |
| Resource limits | No timeout, no circuit breaker, no backpressure |
| Agent-specific | Recursive agent call, LLM API no fallback, reasoning DoS |
| Language-specific | Go missing context timeout, goroutine leak |

**Key TS rules:**
- `AA-CF-003` — Retry without max count (critical)
- `AA-CF-001` — No error boundary around agent invocation (high)
- `AA-CF-010` — No circuit breaker pattern (high)

**FP reduction:** Context region analysis (500-char window checks for compensating controls).

---

### 9. Human Oversight (60 rules)

**TS:** 10 rules (AA-HO-001 to AA-HO-010) | **YAML:** 50 rules

Detects missing human-in-the-loop checkpoints and audit gaps.

| Category | Examples |
|----------|----------|
| Decision control | No HITL for high-risk decisions, auto-approve dangerous ops |
| Audit | No audit trail, no logging of agent decisions |
| Compliance | No explainability, no human override mechanism |
| Automation | Autonomous deployment, unsupervised financial operations |

**Key rules:**
- `AA-HO-001` — No human approval for destructive actions (critical)
- `AA-HO-072` — No HITL for high-risk decisions (critical, YAML)

---

### 10. Inter-Agent (80 rules)

**TS:** 15 rules (AA-IC-001 to AA-IC-015) | **YAML:** 65 rules

Detects multi-agent communication risks and trust boundary violations.

| Category | Examples |
|----------|----------|
| Message integrity | Unvalidated messages, no signature, no encryption |
| Trust boundaries | No sender verification, shared state without sync |
| Delegation | Unrestricted delegation, no scope limitation |
| Coordination | Race conditions, deadlock risk, inconsistent state |

**Key rules:**
- `AA-IC-001` — No agent identity verification (critical)
- `AA-IC-081` — Unvalidated inter-agent message (high, YAML)

**FP reduction:** Inter-agent rules only fire when 2+ agents detected in the project.

---

### 11. Reliability Bounds (101 rules)

**TS:** 20 rules (AA-RB-001 to AA-RB-020) | **YAML:** 81 rules

Detects hallucination risks, missing output validation, and reliability gaps.

| Category | Examples |
|----------|----------|
| Hallucination | No grounding verification, no fact-checking instruction |
| Output validation | No JSON schema validation, unvalidated LLM response |
| Confidence | No confidence scoring, no uncertainty quantification |
| Monitoring | No drift detection, no performance degradation alerts |

**Key rules:**
- `AA-RB-001` — No output validation on LLM response (high)
- `AA-RB-002` — No grounding verification (high)
- `AA-RB-003` — No JSON schema validation for structured output (medium)

---

### 12. Rogue Agent (70 rules)

**TS:** 15 rules (AA-RA-001 to AA-RA-015) | **YAML:** 55 rules

Detects self-modification, goal drift, and autonomous capability accumulation.

| Category | Examples |
|----------|----------|
| Self-modification | Modifies own instructions, updates system prompt |
| Capability accumulation | Acquires new tools, escalates permissions |
| Goal drift | Deviates from assigned objectives, reward hacking |
| Containment | No kill switch, no resource limits, no monitoring |

**Key rules:**
- `AA-RA-001` — No agent containment boundary (critical)
- `AA-RA-016` — Agent self-modification capability (critical, YAML)

**FP reduction:** Allowlist/whitelist detection skips findings where controls exist.

---

## YAML Check Types

| Check Type | Description | Example Domain |
|-----------|-------------|----------------|
| `code_matches` | Regex pattern matching in source code | All domains |
| `prompt_contains` | Pattern found in prompts (dangerous) | goal-integrity |
| `prompt_missing` | Required pattern absent from prompts | goal-integrity, memory-context |
| `config_matches` | Pattern matching in config files | supply-chain |
| `agent_property` | Agent config property check (missing/exists/equals) | cascading-failures |
| `model_property` | Model config property check | reliability-bounds |
| `tool_has_capability` | Tool exposes dangerous capability | tool-safety |
| `tool_missing_property` | Tool lacks safety property | tool-safety |
| `taint_flow` | Source-to-sink data flow tracking | code-execution, data-leakage |
| `project_missing` | Project-level control absent | all domains |
| `no_check` | Dynamic-only (no static check) | supply-chain |

## Supported Languages

| Language | File Extensions | Framework Parsers |
|----------|----------------|-------------------|
| Python | `.py` | LangChain, CrewAI, AutoGen |
| TypeScript | `.ts`, `.tsx` | Vercel AI SDK |
| JavaScript | `.js`, `.jsx`, `.mjs` | OpenAI, MCP |
| Java | `.java` | LangChain4j, Spring AI |
| Go | `.go` | LangChainGo, Eino, GenKit |
| YAML | `.yaml`, `.yml` | Config scanning |
| JSON | `.json` | Config scanning |

## Suppression

Add inline comments to suppress specific findings:

```python
api_key = os.getenv("KEY")  # g0-ignore: loaded from env
```

```typescript
const key = process.env.API_KEY; // g0-ignore: environment variable
```
