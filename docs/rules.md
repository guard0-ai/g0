# g0 Security Rules Reference

g0 ships **1,218 security rules** across **12 security domains**, combining 543 TypeScript-based rules with 675 YAML declarative rules.

## By the Numbers

| Domain | TS Rules | YAML Rules | Total |
|--------|:--------:|:----------:|:-----:|
| Goal Integrity | 60 | 60 | **120** |
| Tool Safety | 40 | 112 | **152** |
| Identity & Access | 66 | 44 | **110** |
| Supply Chain | 33 | 61 | **94** |
| Code Execution | 60 | 32 | **92** |
| Memory & Context | 25 | 76 | **101** |
| Data Leakage | 60 | 69 | **129** |
| Cascading Failures | 64 | 21 | **85** |
| Human Oversight | 20 | 49 | **69** |
| Inter-Agent | 30 | 62 | **92** |
| Reliability Bounds | 40 | 45 | **85** |
| Rogue Agent | 30 | 44 | **74** |
| Enrichment | 15 | — | **15** |
| **Total** | **543** | **675** | **1,218** |

> **New in v1.3.0:** 4 tool-safety rules — AA-TS-181 (excessive dangerous capabilities), AA-TS-182 (excessive unvalidated params), AA-TS-183 (overprivileged description language), AA-TS-184 (MCP server with >15 tools).

## Rule Architecture

Rules are implemented in two formats:

- **TypeScript rules** (`src/analyzers/rules/*.ts`) — Complex rules requiring AST analysis, multi-file correlation, or custom logic. Each domain has a dedicated file exporting a `Rule[]` array.
- **YAML rules** (`src/rules/builtin/{domain}/*.yaml`) — Declarative rules compiled at startup via `src/rules/yaml-compiler.ts`. Support 11 check types for pattern matching, prompt analysis, and taint flow tracking.

### Confidence Levels

Every rule has a confidence level that indicates signal quality:

| Level | Meaning | Default Visibility |
|-------|---------|-------------------|
| **high** | AST-verified, framework-specific, or taint-tracked | Shown |
| **medium** | Solid regex with context guards | Shown |
| **low** | Keyword-only, negative lookahead, file-scope heuristic | Hidden (use `--min-confidence low`) |

205 YAML rules are tagged `confidence: low`. These are hidden by default to reduce noise. Use `g0 scan . --min-confidence low` to include them.

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

### 1. Goal Integrity (120 rules)

**TS:** 60 rules | **YAML:** 60 rules

Detects prompt injection vectors, missing safety guardrails, and goal manipulation attacks.

| Category | Examples |
|----------|----------|
| Prompt injection | System prompt extraction, delimiter injection, payload splitting |
| Goal manipulation | Competing objectives, goal substitution, semantic drift |
| Missing guardrails | No boundary tokens, no refusal instruction, no scope limitation |
| Indirect injection | Via database, email, document, URL |
| Advanced attacks | Homoglyph/unicode injection, ASCII art, base64 encoded, multilingual |

---

### 2. Tool Safety (148 rules)

**TS:** 40 rules | **YAML:** 108 rules

Detects dangerous tool capabilities, missing input validation, and injection vectors.

| Category | Examples |
|----------|----------|
| Injection attacks | SQL, command, path traversal, LDAP, NoSQL, template, XML |
| Dangerous capabilities | Shell access, file write, database access, network scan |
| Missing safeguards | No input validation, no output sanitization, no rate limiting |
| Tool integrity | Description poisoning, schema manipulation, cache poisoning |
| Language-specific | Go path traversal, Java SQL injection, Go template injection |

---

### 3. Identity & Access (110 rules)

**TS:** 66 rules | **YAML:** 44 rules

Detects authentication/authorization weaknesses and credential exposure.

| Category | Examples |
|----------|----------|
| Hardcoded secrets | API keys, tokens, passwords in source code |
| Auth weaknesses | No auth endpoint, missing MFA, weak JWT, no rate limit |
| Access control | BOLA/BFLA risk, RBAC bypass, privilege escalation chain |
| Language-specific | Go hardcoded secrets, Java hardcoded secrets, Spring Security misconfig |

---

### 4. Supply Chain (94 rules)

**TS:** 33 rules | **YAML:** 61 rules

Detects dependency risks, unpinned versions, model supply chain attacks, and OpenClaw skill threats.

| Category | Examples |
|----------|----------|
| Dependency pinning | Unpinned Python/JS/Go deps, unpinned AI models |
| Package risks | Typosquatting, dependency confusion, scope confusion |
| Model integrity | Pickle model loading, unverified HuggingFace models, GGUF unverified |
| CI/CD | GitHub Actions unpinned, build pipeline injection |
| Container | Docker ADD URL, container run as root, env file in image |
| **OpenClaw skills** | ClawHavoc IOC (AA-SC-125), safeBins bypass/AA-SC-121, RCE config/AA-SC-122, unofficial registry/AA-SC-123, SOUL.md persistence/AA-SC-124 |

**OpenClaw supply-chain rules (new):**

| Rule | Name | Severity | Trigger |
|------|------|---------|---------|
| AA-SC-121 | OpenClaw safeBins disabled | Critical | `safeBins:false` in config or frontmatter |
| AA-SC-122 | OpenClaw remote execution enabled | Critical | `allowRemoteExecution:true` — CVE-2026-25253 class |
| AA-SC-123 | OpenClaw unofficial registry | High | `registry` ≠ `https://registry.clawhub.io` |
| AA-SC-124 | SOUL.md cross-session persistence | High | Persistence directive in SOUL.md (confidence: **low**) |
| AA-SC-125 | ClawHavoc malware IOC | Critical | `clawback*.onion` or `.claw_update()` in skill file |

---

### 5. Code Execution (92 rules)

**TS:** 60 rules | **YAML:** 32 rules

Detects arbitrary code execution, unsafe deserialization, and sandbox escapes.

| Category | Examples |
|----------|----------|
| Dynamic evaluation | Dynamic code evaluation, Function constructor, dynamic import |
| Shell invocation | subprocess, child_process, Go Command |
| Deserialization | Pickle, Java ObjectInputStream, YAML unsafe load |
| Taint tracking | LLM output to code evaluation, user input to shell |
| Language-specific | Java reflection abuse, Java ScriptEngine, Go CGo unsafe, VM context escape |

---

### 6. Data Leakage (129 rules)

**TS:** 60 rules | **YAML:** 69 rules

Detects sensitive data exposure, logging risks, and exfiltration channels — including OpenClaw MEMORY.md poisoning.

| Category | Examples |
|----------|----------|
| Logging risks | PII in logs, API keys logged, conversation history logged |
| Error exposure | Stack traces leaked, verbose error messages, debug endpoints |
| Exfiltration | DNS exfil, URL exfil, markdown image exfil, clipboard exfil |
| Data handling | No output filter, no DLP integration, no data classification |
| Language-specific | Go printf secrets, Java logger secrets |
| **OpenClaw MEMORY.md** | Planted credentials, SSN/CC in memory, trust override injection |

**OpenClaw data-leakage rules (new):**

| Rule | Name | Severity | Trigger |
|------|------|---------|---------|
| AA-DL-133 | MEMORY.md credential value (generic) | Critical | `api key is <20+ chars>` |
| AA-DL-134 | MEMORY.md provider-prefixed credential | Critical | `token: sk-\|ghp_\|AKIA\|eyJ...` |
| AA-DL-135 | SKILL.md hardcoded provider credential | Critical | `OPENAI_API_KEY=sk-...` in skill body |
| AA-DL-136 | MEMORY.md PII (SSN or credit card) | Critical | `\d{3}-\d{2}-\d{4}` or Visa card pattern |
| AA-DL-137 | openclaw.json hardcoded API key | Critical | `apiKey: sk-\|ghp_\|AKIA\|eyJ...` in config |

---

### 7. Memory & Context (101 rules)

**TS:** 25 rules | **YAML:** 76 rules

Detects memory poisoning, context overflow, and RAG vulnerabilities.

| Category | Examples |
|----------|----------|
| Memory safety | No access control, no encryption, no expiry, no rollback |
| Context attacks | Overflow, injection via separator, window poisoning |
| RAG security | Poisoning injection, cross-tenant retrieval, no content filter |
| Vector DB | No auth, public endpoint, unencrypted, shared collection |
| Session | Cross-session leak, state poisoning, conversation tampering |

---

### 8. Cascading Failures (85 rules)

**TS:** 64 rules | **YAML:** 21 rules

Detects error propagation, missing resilience patterns, and resource exhaustion.

| Category | Examples |
|----------|----------|
| Error propagation | No error boundary, bare except, swallowed errors |
| Retry logic | No max count, no backoff, tight retry loops |
| Resource limits | No timeout, no circuit breaker, no backpressure |
| Agent-specific | Recursive agent call, LLM API no fallback, reasoning DoS |
| Language-specific | Go missing context timeout, goroutine leak |

---

### 9. Human Oversight (69 rules)

**TS:** 20 rules | **YAML:** 49 rules

Detects missing human-in-the-loop checkpoints and audit gaps.

| Category | Examples |
|----------|----------|
| Decision control | No HITL for high-risk decisions, auto-approve dangerous ops |
| Audit | No audit trail, no logging of agent decisions |
| Compliance | No explainability, no human override mechanism |
| Automation | Autonomous deployment, unsupervised financial operations |

---

### 10. Inter-Agent (92 rules)

**TS:** 30 rules | **YAML:** 62 rules

Detects multi-agent communication risks and trust boundary violations.

| Category | Examples |
|----------|----------|
| Message integrity | Unvalidated messages, no signature, no encryption |
| Trust boundaries | No sender verification, shared state without sync |
| Delegation | Unrestricted delegation, no scope limitation |
| Coordination | Race conditions, deadlock risk, inconsistent state |

---

### 11. Reliability Bounds (85 rules)

**TS:** 40 rules | **YAML:** 45 rules

Detects hallucination risks, missing output validation, and reliability gaps.

| Category | Examples |
|----------|----------|
| Hallucination | No grounding verification, no fact-checking instruction |
| Output validation | No JSON schema validation, unvalidated LLM response |
| Confidence | No confidence scoring, no uncertainty quantification |
| Monitoring | No drift detection, no performance degradation alerts |

---

### 12. Rogue Agent (74 rules)

**TS:** 30 rules | **YAML:** 44 rules

Detects self-modification, goal drift, and autonomous capability accumulation.

| Category | Examples |
|----------|----------|
| Self-modification | Modifies own instructions, updates system prompt |
| Capability accumulation | Acquires new tools, escalates permissions |
| Goal drift | Deviates from assigned objectives, reward hacking |
| Containment | No kill switch, no resource limits, no monitoring |

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
