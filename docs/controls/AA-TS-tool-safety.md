# AA-TS: Tool Safety Controls

**Domain:** Tool Safety  
**OWASP Mapping:** ASI02 — Tool & Function Abuse  
**Control Range:** AA-TS-001 through AA-TS-150  
**Total Controls:** 150  
**Last Updated:** 2026-02-13  
**Status:** Active

---

## Overview

Tools are the primary mechanism through which AI agents interact with external systems — reading files, querying databases, calling APIs, executing code, and modifying state. Every tool invocation represents a trust boundary crossing where the agent's intent is translated into real-world actions with potentially irreversible consequences. Tool safety failures can result in data loss, unauthorized access, system compromise, and cascading damage across connected systems.

The tool attack surface in agentic systems is uniquely broad because tools are described in natural language, invoked through model-generated parameters, and often chained together in sequences the model determines at runtime. This creates opportunities for parameter injection (where malicious content in tool descriptions or user inputs manipulates function parameters), tool chaining abuse (where individually safe tools become dangerous in combination), description tampering (where tool semantics are altered post-deployment), and permission escalation (where tools are invoked with broader privileges than intended).

These controls address the complete tool safety lifecycle: from tool registration and description integrity through invocation validation, parameter sanitization, output verification, permission enforcement, sandboxing, and monitoring. They ensure that every tool call is authorized, validated, bounded, and auditable, maintaining the principle of least privilege across the agent's entire tool ecosystem.

---

## Applicable Standards

| Standard | Sections |
|----------|----------|
| OWASP Agentic Security | ASI02 — Tool & Function Abuse |
| NIST AI RMF | MAP-1.5, MEASURE-2.5, MANAGE-2.2 |
| ISO 42001 | A.5 — Tool Management, A.10 — System Security |
| ISO 23894 | Clause 6.2 — Tool Risk Assessment |
| MITRE ATLAS | AML.T0040 — ML Model Inference API Access |
| OWASP Agentic AI Top 10 | Principle 2 — Tool Invocation Safety |
| OWASP AIVSS | Vectors: AV:T (Tool), AV:P (Parameter) |

---

## Sub-Categories Summary

| # | Sub-Category | Controls | Range |
|---|-------------|----------|-------|
| 1 | Tool Invocation Validation | 15 | AA-TS-001 – AA-TS-015 |
| 2 | Parameter Injection | 15 | AA-TS-016 – AA-TS-030 |
| 3 | Tool Chaining Abuse | 15 | AA-TS-031 – AA-TS-045 |
| 4 | Tool Description Tampering | 15 | AA-TS-046 – AA-TS-060 |
| 5 | Tool Permission Escalation | 15 | AA-TS-061 – AA-TS-075 |
| 6 | Tool Output Manipulation | 15 | AA-TS-076 – AA-TS-090 |
| 7 | Sandbox Escape | 15 | AA-TS-091 – AA-TS-105 |
| 8 | Unauthorized Tool Access | 15 | AA-TS-106 – AA-TS-120 |
| 9 | Tool Availability Attacks | 15 | AA-TS-121 – AA-TS-135 |
| 10 | Framework-Specific Tool Checks | 15 | AA-TS-136 – AA-TS-150 |

---

## 1. Tool Invocation Validation (AA-TS-001 – AA-TS-015)

**Threat:** Tools invoked without validation may execute with incorrect parameters, unauthorized context, or fabricated tool names. Lack of invocation validation allows the model to call arbitrary functions, pass malformed arguments, or bypass pre-invocation safety checks.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-001 | No tool call validation before execution | CRITICAL | static | stable | langchain, crewai, openai |
| AA-TS-002 | Tool name not verified against registry | CRITICAL | static | stable | langchain, crewai, mcp |
| AA-TS-003 | Tool arguments not schema-validated | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-TS-004 | Required parameters not enforced | HIGH | static | stable | langchain, crewai, openai |
| AA-TS-005 | Tool call without user intent confirmation | HIGH | dynamic | stable | langchain, openai, vercel-ai |
| AA-TS-006 | Hallucinated tool name invocation attempted | HIGH | dynamic | stable | langchain, crewai, mcp |
| AA-TS-007 | Pre-invocation authorization check absent | HIGH | static | stable | langchain, crewai, autogen |
| AA-TS-008 | Tool version mismatch not detected | MEDIUM | static | stable | langchain, mcp, openai |
| AA-TS-009 | Tool invocation logging insufficient | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-TS-010 | Parallel tool call validation absent | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-TS-011 | Tool call frequency anomaly not detected | MEDIUM | dynamic | stable | langchain, crewai, openai |
| AA-TS-012 | Tool invocation context not captured | MEDIUM | static | stable | langchain, openai, autogen |
| AA-TS-013 | Conditional tool enablement not implemented | MEDIUM | static | stable | langchain, crewai, mcp |
| AA-TS-014 | Tool deprecation warnings not surfaced | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-015 | Dry-run mode not available for tool calls | MEDIUM | both | experimental | langchain, crewai, openai |

### Standards Mapping

- **ASI02:** Tool invocation validation is the first line of defense against function abuse
- **NIST AI RMF MAP-1.5:** Mapping tool capabilities to authorized actions
- **OWASP Agentic AI Top 10 Principle 2:** All tool invocations must be validated before execution

### Detailed Descriptions

**AA-TS-001: No tool call validation before execution**
- **Description:** Tool calls generated by the model are executed immediately without any validation of the tool name, arguments, or execution context.
- **Rationale:** Pre-execution validation catches invalid, malicious, or unauthorized tool calls before they can affect external systems. Every tool call must pass through a validation layer.

**AA-TS-002: Tool name not verified against registry**
- **Description:** The tool name in the model's function call is not verified against the registered tool list, potentially allowing invocation of unregistered or internal functions.
- **Rationale:** Registry verification ensures only explicitly registered tools can be invoked, preventing the model from accessing internal system functions or hallucinated tools.

**AA-TS-003: Tool arguments not schema-validated**
- **Description:** Tool call arguments are not validated against the tool's declared parameter schema (types, ranges, formats, required fields).
- **Rationale:** Schema validation catches malformed, oversized, or type-confused arguments that could cause tool errors, injection attacks, or unexpected behavior.

**AA-TS-004: Required parameters not enforced**
- **Description:** Tools can be called with missing required parameters, relying on the tool implementation to handle absent arguments.
- **Rationale:** Enforcing required parameters at the invocation layer ensures tools receive complete inputs, preventing undefined behavior from missing arguments.

**AA-TS-005: Tool call without user intent confirmation**
- **Description:** Destructive or sensitive tool calls execute without confirming the user intended the specific action, such as file deletion or data modification.
- **Rationale:** Intent confirmation prevents unintended actions from model misinterpretation. High-impact tools should require explicit user approval before execution.

**AA-TS-006: Hallucinated tool name invocation attempted**
- **Description:** The model generates calls to tool names that don't exist in the registered set, indicating hallucinated tool knowledge.
- **Rationale:** Hallucinated tool calls waste resources and may indicate the model is reasoning incorrectly about available capabilities. They should be caught and logged.

**AA-TS-007: Pre-invocation authorization check absent**
- **Description:** Tool calls are not checked against authorization policies (user role, session permissions, tool restrictions) before execution.
- **Rationale:** Authorization checks ensure the current user/session has permission to invoke the requested tool, preventing privilege escalation through tool calls.

**AA-TS-008: Tool version mismatch not detected**
- **Description:** The model's understanding of tool capabilities (from its schema) may not match the actual deployed tool version, causing unexpected behavior.
- **Rationale:** Version mismatches can cause parameter errors, missing features, or security bypasses. Tool schema versions should be validated at invocation time.

**AA-TS-009: Tool invocation logging insufficient**
- **Description:** Tool call logs do not capture sufficient detail (arguments, context, user, timing, result) for security audit and incident investigation.
- **Rationale:** Comprehensive logging enables forensic analysis of tool abuse, anomaly detection, and compliance verification for tool usage.

**AA-TS-010: Parallel tool call validation absent**
- **Description:** When the model generates multiple parallel tool calls, they are validated independently rather than as a group, missing dangerous combinations.
- **Rationale:** Parallel tool calls that are individually safe may be dangerous in combination. Group validation catches compound threats that per-call checks miss.

**AA-TS-011: Tool call frequency anomaly not detected**
- **Description:** Unusual tool call patterns (high frequency, unusual times, new tool combinations) are not monitored as potential indicators of compromise.
- **Rationale:** Frequency anomaly detection catches automated abuse, compromised sessions, and adversarial manipulation that triggers excessive tool usage.

**AA-TS-012: Tool invocation context not captured**
- **Description:** The context surrounding tool invocations (conversation state, preceding actions, user intent) is not captured for audit purposes.
- **Rationale:** Invocation context enables understanding why a tool was called, supporting investigation of suspicious invocations and improving validation rules.

**AA-TS-013: Conditional tool enablement not implemented**
- **Description:** All registered tools are available at all times rather than being conditionally enabled based on session state, user role, or task context.
- **Rationale:** Conditional enablement reduces attack surface by making tools available only when contextually appropriate, implementing least privilege at the tool level.

**AA-TS-014: Tool deprecation warnings not surfaced**
- **Description:** Calls to deprecated tools proceed without warning, potentially using outdated or insecure tool implementations.
- **Rationale:** Deprecation warnings alert developers and users to update tool usage, ensuring migration away from tools with known issues.

**AA-TS-015: Dry-run mode not available for tool calls**
- **Description:** No mechanism exists to preview the effects of a tool call without actually executing it, preventing safe exploration of tool behavior.
- **Rationale:** Dry-run mode enables safe testing, user preview of actions, and development-time validation without risking side effects.

---

## 2. Parameter Injection (AA-TS-016 – AA-TS-030)

**Threat:** Attackers manipulate tool parameters through prompt injection, conversation context manipulation, or indirect injection via tool descriptions, causing tools to execute with attacker-controlled arguments that may access unauthorized data, modify system state, or exfiltrate information.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-016 | No parameter sanitization for tool calls | CRITICAL | static | stable | langchain, openai, mcp |
| AA-TS-017 | SQL injection via tool parameters | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-TS-018 | Command injection via tool parameters | CRITICAL | static | stable | langchain, autogen, mcp |
| AA-TS-019 | Path traversal via file parameters | HIGH | static | stable | langchain, mcp, crewai |
| AA-TS-020 | URL injection via tool parameters | HIGH | static | stable | langchain, openai, mcp |
| AA-TS-021 | Template injection via string parameters | HIGH | static | stable | langchain, crewai, openai |
| AA-TS-022 | Parameter value range not bounded | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-TS-023 | Hidden parameter injection from context | HIGH | dynamic | stable | langchain, openai, vercel-ai |
| AA-TS-024 | JSON injection through string parameters | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-025 | Unicode normalization attack in parameters | MEDIUM | static | stable | langchain, openai, crewai |
| AA-TS-026 | Parameter type coercion exploitation | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-TS-027 | Array parameter size not limited | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-028 | Nested object depth in parameters unbounded | MEDIUM | static | stable | langchain, openai, autogen |
| AA-TS-029 | Parameter encoding not validated | MEDIUM | static | stable | langchain, mcp, openai |
| AA-TS-030 | Default parameter values not secure | MEDIUM | static | stable | langchain, crewai, openai |

### Standards Mapping

- **ASI02:** Parameter injection is the primary tool exploitation vector
- **OWASP AIVSS AV:P:** Parameter-based attack vectors
- **ISO 42001 A.5:** Input validation for AI tool parameters

### Detailed Descriptions

**AA-TS-016: No parameter sanitization for tool calls**
- **Description:** Tool call parameters generated by the model are passed directly to tool implementations without sanitization, filtering, or encoding.
- **Rationale:** Unsanitized parameters enable injection attacks across all tool types. Every parameter must be sanitized appropriate to its intended use context.

**AA-TS-017: SQL injection via tool parameters**
- **Description:** String parameters passed to database tools are not parameterized or sanitized, allowing SQL injection through model-generated queries.
- **Rationale:** SQL injection through tool parameters gives attackers database access through the agent. All database parameters must use parameterized queries.

**AA-TS-018: Command injection via tool parameters**
- **Description:** Parameters passed to shell execution tools are not escaped or validated, allowing command injection through crafted arguments.
- **Rationale:** Command injection through tool parameters enables full system compromise. Shell parameters must be escaped, validated, and preferably avoid shell invocation.

**AA-TS-019: Path traversal via file parameters**
- **Description:** File path parameters are not validated against path traversal attacks (../, symlinks), allowing access to files outside intended directories.
- **Rationale:** Path traversal breaks file system sandboxing. File parameters must be canonicalized and validated against allowed directory boundaries.

**AA-TS-020: URL injection via tool parameters**
- **Description:** URL parameters are not validated, allowing the model to direct tools to access attacker-controlled servers or internal services.
- **Rationale:** URL injection can cause SSRF attacks, data exfiltration to attacker servers, or access to internal services. URLs must be validated against allowlists.

**AA-TS-021: Template injection via string parameters**
- **Description:** String parameters used in template engines (Jinja2, Handlebars) are not sanitized, enabling server-side template injection.
- **Rationale:** Template injection can achieve code execution through the template engine. Parameters used in templates must be properly escaped.

**AA-TS-022: Parameter value range not bounded**
- **Description:** Numeric parameters lack range validation, allowing extreme values that cause resource exhaustion, integer overflow, or unexpected behavior.
- **Rationale:** Range validation prevents out-of-bounds values from causing errors or abuse. Every numeric parameter should have defined minimum and maximum values.

**AA-TS-023: Hidden parameter injection from context**
- **Description:** Prompt injection in conversation context causes the model to include additional, hidden parameters in tool calls that bypass user intent.
- **Rationale:** Context-driven parameter injection is particularly dangerous because the injected parameters are generated by the model, not visible in user input.

**AA-TS-024: JSON injection through string parameters**
- **Description:** String parameters containing JSON syntax are interpreted as structured data, allowing injection of additional fields or parameter modification.
- **Rationale:** JSON injection through strings can modify tool behavior by injecting additional parameters. String parameters must be treated as opaque strings.

**AA-TS-025: Unicode normalization attack in parameters**
- **Description:** Parameters containing Unicode characters that normalize to different values bypass validation checks that operate on pre-normalization strings.
- **Rationale:** Unicode normalization attacks bypass string-based validation. Parameters must be normalized before validation using consistent normalization forms.

**AA-TS-026: Parameter type coercion exploitation**
- **Description:** Weak type coercion allows parameters to be interpreted as different types than intended (string "true" as boolean, numeric strings as numbers).
- **Rationale:** Type coercion can bypass validation, change tool behavior, or cause security-relevant type confusion. Strict typing prevents coercion attacks.

**AA-TS-027: Array parameter size not limited**
- **Description:** Array parameters accept arbitrary numbers of elements, enabling resource exhaustion through oversized arrays.
- **Rationale:** Array size limits prevent processing-based denial of service. Tools that accept arrays should enforce maximum element counts.

**AA-TS-028: Nested object depth in parameters unbounded**
- **Description:** Object parameters with arbitrary nesting depth can cause stack overflow or excessive memory consumption during processing.
- **Rationale:** Nesting depth limits prevent recursive processing attacks. Object parameters should enforce maximum nesting depth.

**AA-TS-029: Parameter encoding not validated**
- **Description:** Parameters with specific encoding requirements (Base64, URL encoding, UTF-8) are not validated for correct encoding before processing.
- **Rationale:** Encoding validation prevents double-encoding attacks, encoding confusion, and malformed data that could exploit decoding vulnerabilities.

**AA-TS-030: Default parameter values not secure**
- **Description:** Default values for optional parameters use insecure settings (overly permissive permissions, broad scopes, disabled validation).
- **Rationale:** Secure defaults ensure that tools behave safely even when the model omits optional parameters. Defaults should always be the most restrictive option.

---

## 3. Tool Chaining Abuse (AA-TS-031 – AA-TS-045)

**Threat:** Individual tools that are safe in isolation can become dangerous when chained in specific sequences. Attackers exploit tool chaining to achieve compound effects — reading credentials with one tool and exfiltrating them with another, or combining search and execution tools to bypass individual tool restrictions.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-031 | No tool chain analysis or monitoring | CRITICAL | dynamic | stable | langchain, crewai, autogen |
| AA-TS-032 | Dangerous tool sequence not blocked | CRITICAL | static | stable | langchain, crewai, mcp |
| AA-TS-033 | Tool chain depth not limited | HIGH | static | stable | langchain, autogen, crewai |
| AA-TS-034 | Cross-tool data flow not tracked | HIGH | dynamic | stable | langchain, crewai, openai |
| AA-TS-035 | Read-then-exfiltrate pattern undetected | HIGH | dynamic | stable | langchain, openai, mcp |
| AA-TS-036 | Tool output used as input without sanitization | HIGH | static | stable | langchain, crewai, autogen |
| AA-TS-037 | Circular tool chain not detected | MEDIUM | dynamic | stable | langchain, autogen, crewai |
| AA-TS-038 | Tool chain authorization not cumulative | MEDIUM | static | stable | langchain, crewai, openai |
| AA-TS-039 | Tool chain cost not aggregated | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-TS-040 | Privilege accumulation across tool chain | MEDIUM | dynamic | stable | langchain, crewai, autogen |
| AA-TS-041 | Tool chain rollback not supported | MEDIUM | both | stable | langchain, crewai, openai |
| AA-TS-042 | Tool chain timing correlation absent | MEDIUM | dynamic | experimental | langchain, openai, mcp |
| AA-TS-043 | Compound effect assessment not performed | MEDIUM | dynamic | experimental | langchain, crewai, autogen |
| AA-TS-044 | Tool chain audit trail fragmented | MEDIUM | static | stable | langchain, openai, crewai |
| AA-TS-045 | Tool chain maximum duration not enforced | MEDIUM | static | stable | langchain, autogen, mcp |

### Standards Mapping

- **ASI02:** Tool chaining creates compound attack vectors beyond individual tool risk
- **NIST AI RMF MEASURE-2.5:** Measuring compound effects of tool sequences
- **ISO 23894 Clause 6.2:** Combined tool risk assessment

### Detailed Descriptions

**AA-TS-031: No tool chain analysis or monitoring**
- **Description:** Sequences of tool calls are not analyzed as chains, preventing detection of dangerous multi-step patterns that individual tool checks miss.
- **Rationale:** Chain analysis detects attack patterns that span multiple tools. Without it, individually safe tool calls can be combined for malicious purposes.

**AA-TS-032: Dangerous tool sequence not blocked**
- **Description:** Known dangerous tool sequences (e.g., file-read followed by network-send, credential-access followed by external-API-call) are not blocked.
- **Rationale:** Blocking known dangerous sequences prevents common multi-step attacks without restricting individual tool usage in safe contexts.

**AA-TS-033: Tool chain depth not limited**
- **Description:** There is no limit on the number of sequential tool calls in a chain, allowing unbounded tool execution sequences.
- **Rationale:** Chain depth limits prevent runaway tool sequences that consume resources or enable complex multi-step attacks through extended chains.

**AA-TS-034: Cross-tool data flow not tracked**
- **Description:** Data flowing from one tool's output to another tool's input is not tracked, preventing detection of sensitive data movement across tools.
- **Rationale:** Data flow tracking detects when sensitive information (credentials, PII) moves through tool chains toward exfiltration endpoints.

**AA-TS-035: Read-then-exfiltrate pattern undetected**
- **Description:** The pattern of reading sensitive data with one tool and sending it externally with another is not detected or blocked.
- **Rationale:** Read-then-exfiltrate is the most common tool chain attack. Pattern detection specifically targeting this sequence prevents data theft through tool abuse.

**AA-TS-036: Tool output used as input without sanitization**
- **Description:** Output from one tool is passed as input to the next tool without re-sanitization, allowing injection payloads to propagate through chains.
- **Rationale:** Tool output sanitization breaks injection chains where a compromised tool injects payloads that exploit the next tool in the sequence.

**AA-TS-037: Circular tool chain not detected**
- **Description:** Tool chains that loop back to previously called tools are not detected, creating potential for infinite loops and resource exhaustion.
- **Rationale:** Circular chain detection prevents infinite loops and ensures tool chains make forward progress toward task completion.

**AA-TS-038: Tool chain authorization not cumulative**
- **Description:** Authorization is checked per-tool rather than cumulatively across the chain, missing cases where the combined access exceeds permitted scope.
- **Rationale:** Cumulative authorization ensures the combined effect of a tool chain doesn't exceed what any single authorized action should accomplish.

**AA-TS-039: Tool chain cost not aggregated**
- **Description:** Costs are tracked per-tool rather than aggregated across chains, allowing expensive chains to accumulate below per-tool cost thresholds.
- **Rationale:** Aggregated cost tracking catches expensive multi-step operations that fly under per-tool cost limits through distribution across many calls.

**AA-TS-040: Privilege accumulation across tool chain**
- **Description:** Each tool in a chain operates with its own privileges, and the cumulative effective privilege across the chain exceeds any individual tool's authorization.
- **Rationale:** Privilege accumulation analysis ensures that chaining tools together doesn't create effective permissions beyond what individual tools or users are authorized.

**AA-TS-041: Tool chain rollback not supported**
- **Description:** When a tool chain fails mid-execution, previously completed steps cannot be rolled back, leaving the system in a partially modified state.
- **Rationale:** Chain rollback ensures atomicity — either the entire chain succeeds or all changes are reverted, preventing inconsistent system state.

**AA-TS-042: Tool chain timing correlation absent**
- **Description:** Timing patterns across tool chains (unusual delays, suspiciously fast execution) are not correlated for anomaly detection.
- **Rationale:** Timing analysis can detect automated exploitation (unusually fast) or side-channel attacks (correlation with external events) across chains.

**AA-TS-043: Compound effect assessment not performed**
- **Description:** The combined effect of a tool chain on system state is not assessed before or after execution, missing unintended compound impacts.
- **Rationale:** Compound effect assessment evaluates whether the net result of a tool chain is within acceptable bounds, even if each step individually is acceptable.

**AA-TS-044: Tool chain audit trail fragmented**
- **Description:** Individual tool calls are logged separately without linking them as a chain, preventing reconstruction of multi-step attack sequences.
- **Rationale:** Linked audit trails enable reconstruction of complete tool chains for forensic analysis and pattern detection across related tool calls.

**AA-TS-045: Tool chain maximum duration not enforced**
- **Description:** No maximum wall-clock time is enforced for the entire tool chain, allowing long-running chains to consume resources indefinitely.
- **Rationale:** Chain duration limits prevent long-running tool sequences from monopolizing agent capacity and ensure timely completion of tool operations.

---

## 4. Tool Description Tampering (AA-TS-046 – AA-TS-060)

**Threat:** Tool descriptions define how models understand and use tools. Tampering with descriptions — through MCP rug pulls, dynamic description modification, or injection into description text — can fundamentally alter tool behavior without changing any code, making the agent use tools in unintended and potentially malicious ways.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-046 | Tool descriptions not integrity-protected | CRITICAL | static | stable | langchain, mcp, openai |
| AA-TS-047 | MCP tool description rug pull possible | CRITICAL | dynamic | stable | mcp |
| AA-TS-048 | Prompt injection in tool descriptions | CRITICAL | static | stable | langchain, mcp, crewai |
| AA-TS-049 | Tool description change not detected | HIGH | dynamic | stable | mcp, langchain, openai |
| AA-TS-050 | Hidden instructions in tool description | HIGH | static | stable | langchain, mcp, crewai |
| AA-TS-051 | Tool description hash pinning absent | HIGH | static | stable | mcp, langchain |
| AA-TS-052 | Tool schema modification undetected | HIGH | dynamic | stable | mcp, openai, langchain |
| AA-TS-053 | Unicode obfuscation in tool descriptions | MEDIUM | static | stable | langchain, mcp, openai |
| AA-TS-054 | Tool description version control absent | MEDIUM | static | stable | mcp, langchain, crewai |
| AA-TS-055 | Misleading tool name misrepresents capability | MEDIUM | static | stable | langchain, mcp, openai |
| AA-TS-056 | Tool description encoding manipulation | MEDIUM | static | stable | mcp, langchain, crewai |
| AA-TS-057 | Dynamic tool description loading not secured | MEDIUM | dynamic | stable | langchain, mcp, autogen |
| AA-TS-058 | Tool description length not bounded | MEDIUM | static | stable | langchain, mcp, openai |
| AA-TS-059 | Tool metadata consistency not verified | MEDIUM | static | stable | mcp, langchain, crewai |
| AA-TS-060 | SKILL.md file contains hidden instructions | MEDIUM | static | stable | mcp |

### Standards Mapping

- **ASI02:** Description tampering alters tool semantics without code changes
- **OWASP Agentic AI Top 10 Principle 2:** Tool description integrity verification
- **ISO 42001 A.5:** Tool description management and integrity

### Detailed Descriptions

**AA-TS-046: Tool descriptions not integrity-protected**
- **Description:** Tool descriptions served to the model are not integrity-protected, allowing modification between the tool provider and the model.
- **Rationale:** Description integrity ensures the model receives the authentic tool description. Without protection, descriptions can be altered to manipulate tool usage.

**AA-TS-047: MCP tool description rug pull possible**
- **Description:** MCP servers can change tool descriptions between invocations, altering tool semantics after the agent has been configured to trust them.
- **Rationale:** The MCP rug pull attack changes tool descriptions to inject instructions after initial trust is established. Hash pinning prevents this.

**AA-TS-048: Prompt injection in tool descriptions**
- **Description:** Tool descriptions contain instruction-like text that the model may interpret as directives rather than descriptive content.
- **Rationale:** Prompt injection through tool descriptions can override system instructions, alter agent behavior, or cause unauthorized actions through manipulated tool understanding.

**AA-TS-049: Tool description change not detected**
- **Description:** Changes to tool descriptions between sessions or invocations are not detected or flagged for review.
- **Rationale:** Description change detection catches both intentional tampering and unintended modifications that could alter tool behavior.

**AA-TS-050: Hidden instructions in tool description**
- **Description:** Tool descriptions contain hidden instructions using zero-width characters, excessive whitespace, or encoding tricks not visible in normal rendering.
- **Rationale:** Hidden instructions bypass human review while remaining effective for the model. Content scanning must detect all encoding tricks.

**AA-TS-051: Tool description hash pinning absent**
- **Description:** Tool descriptions are not hashed and pinned at a known-good state, preventing detection of modifications.
- **Rationale:** Hash pinning creates a tamper-evident record of approved tool descriptions. Any modification is detected by hash mismatch.

**AA-TS-052: Tool schema modification undetected**
- **Description:** Changes to tool parameter schemas (adding parameters, changing types, modifying constraints) are not detected between invocations.
- **Rationale:** Schema modifications can add new attack parameters, weaken constraints, or enable new injection vectors. Changes must trigger review.

**AA-TS-053: Unicode obfuscation in tool descriptions**
- **Description:** Tool descriptions use Unicode characters (homoglyphs, directional overrides, invisible characters) to obfuscate malicious content.
- **Rationale:** Unicode obfuscation hides malicious text from human reviewers while the model processes it. Normalization and filtering detect these tricks.

**AA-TS-054: Tool description version control absent**
- **Description:** Tool descriptions are not version-controlled, preventing audit of changes over time and rollback to known-good versions.
- **Rationale:** Version control enables change tracking, blame attribution, and rollback when malicious modifications are detected.

**AA-TS-055: Misleading tool name misrepresents capability**
- **Description:** A tool's name suggests limited capability (e.g., "search") while its actual implementation has broader access (e.g., search and execute).
- **Rationale:** Misleading names cause the model to use tools inappropriately, potentially triggering capabilities beyond what the name implies.

**AA-TS-056: Tool description encoding manipulation**
- **Description:** Tool descriptions use character encoding tricks (different UTF variants, HTML entities) to hide content from text-based scanning.
- **Rationale:** Encoding manipulation bypasses content filters that check decoded text. Descriptions must be normalized to a canonical encoding before analysis.

**AA-TS-057: Dynamic tool description loading not secured**
- **Description:** Tool descriptions loaded at runtime from external sources (APIs, config files) are not validated for integrity or content safety.
- **Rationale:** Dynamic description loading introduces a runtime attack vector. Loaded descriptions must be validated against integrity checks and content policies.

**AA-TS-058: Tool description length not bounded**
- **Description:** Tool descriptions have no length limit, allowing injection of large amounts of instructional text into the model's context.
- **Rationale:** Oversized descriptions can dominate the context window and embed extensive instructional content. Length limits constrain this attack surface.

**AA-TS-059: Tool metadata consistency not verified**
- **Description:** Tool metadata (name, description, schema) is not checked for internal consistency, allowing contradictory or misleading tool definitions.
- **Rationale:** Consistency verification catches tool definitions where the name, description, and parameters tell conflicting stories about the tool's purpose.

**AA-TS-060: SKILL.md file contains hidden instructions**
- **Description:** MCP SKILL.md files contain hidden prompt injection, encoded instructions, or obfuscated directives that activate when the agent reads them.
- **Rationale:** SKILL.md files are read by agents as tool documentation. Malicious content in these files constitutes indirect prompt injection through the tool ecosystem.

---

## 5. Tool Permission Escalation (AA-TS-061 – AA-TS-075)

**Threat:** Agents may escalate tool permissions through manipulation — requesting elevated access, exploiting permission inheritance, or bypassing access controls through indirect tool usage. Permission escalation gives agents capabilities beyond their authorized scope.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-061 | Tool runs with excessive privileges | CRITICAL | static | stable | langchain, mcp, autogen |
| AA-TS-062 | No least-privilege enforcement for tools | CRITICAL | static | stable | langchain, crewai, openai |
| AA-TS-063 | Permission inheritance not scoped | HIGH | static | stable | langchain, autogen, crewai |
| AA-TS-064 | Tool permission escalation through chaining | HIGH | dynamic | stable | langchain, crewai, mcp |
| AA-TS-065 | Admin tool accessible without elevation | HIGH | static | stable | langchain, openai, mcp |
| AA-TS-066 | Permission boundary bypass via tool output | HIGH | dynamic | stable | langchain, crewai, openai |
| AA-TS-067 | Dynamic permission granting not controlled | MEDIUM | dynamic | stable | langchain, openai, autogen |
| AA-TS-068 | Tool permission scope creep unmonitored | MEDIUM | dynamic | stable | langchain, crewai, mcp |
| AA-TS-069 | Cross-agent permission leakage via tools | MEDIUM | dynamic | stable | crewai, autogen, langchain |
| AA-TS-070 | Tool permission revocation not immediate | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-TS-071 | Permission caching stale grants | MEDIUM | static | stable | langchain, openai, crewai |
| AA-TS-072 | Temporary permission elevation not time-bounded | MEDIUM | static | stable | langchain, mcp, openai |
| AA-TS-073 | Tool permission audit trail incomplete | MEDIUM | static | stable | langchain, crewai, openai |
| AA-TS-074 | Implicit permissions not documented | MEDIUM | static | stable | langchain, mcp, autogen |
| AA-TS-075 | Permission model not defense-in-depth | MEDIUM | static | stable | langchain, crewai, openai |

### Standards Mapping

- **ASI02:** Permission escalation through tools is a critical privilege abuse vector
- **NIST AI RMF MANAGE-2.2:** Tool permission management and least privilege
- **ISO 42001 A.10:** Access control for tool permissions

### Detailed Descriptions

**AA-TS-061: Tool runs with excessive privileges**
- **Description:** Tools execute with the full privileges of the agent process (root, admin, broad API scope) rather than the minimum privileges needed.
- **Rationale:** Least privilege for tool execution limits the damage from tool compromise. Each tool should run with exactly the permissions it needs and no more.

**AA-TS-062: No least-privilege enforcement for tools**
- **Description:** No mechanism enforces that tools operate with minimal required permissions, allowing all tools to access all resources.
- **Rationale:** Least-privilege enforcement ensures tools can only access resources they need. Without it, any tool compromise exposes all accessible resources.

**AA-TS-063: Permission inheritance not scoped**
- **Description:** Sub-tools or delegated tool calls inherit the parent tool's full permissions rather than a restricted subset.
- **Rationale:** Permission inheritance should follow least privilege — child tools should receive only the permissions they need, not the parent's full scope.

**AA-TS-064: Tool permission escalation through chaining**
- **Description:** Chaining tools together achieves effective permissions beyond what any individual tool is authorized, bypassing per-tool restrictions.
- **Rationale:** Chain-level permission analysis must evaluate cumulative access. A file-read tool + network tool effectively grants data exfiltration capability.

**AA-TS-065: Admin tool accessible without elevation**
- **Description:** Administrative or privileged tools are accessible in normal agent sessions without requiring explicit privilege elevation.
- **Rationale:** Administrative tools should require explicit elevation (separate authentication, approval workflow) to prevent casual or manipulated access.

**AA-TS-066: Permission boundary bypass via tool output**
- **Description:** Tool outputs contain data from privileged contexts that flows into unprivileged tool inputs, effectively bypassing permission boundaries.
- **Rationale:** Data flow across permission boundaries through tool outputs must be controlled. Sensitive output should be tagged and restricted from crossing boundaries.

**AA-TS-067: Dynamic permission granting not controlled**
- **Description:** Tools can be granted additional permissions at runtime without authorization checks or audit logging.
- **Rationale:** Dynamic permission grants must go through authorization workflows. Runtime permission changes should require the same rigor as initial configuration.

**AA-TS-068: Tool permission scope creep unmonitored**
- **Description:** Tool permissions gradually expand over time through incremental changes without monitoring the overall permission scope.
- **Rationale:** Permission scope monitoring detects gradual escalation that individual changes might not flag. Regular permission audits catch scope creep.

**AA-TS-069: Cross-agent permission leakage via tools**
- **Description:** In multi-agent systems, one agent's tool permissions leak to other agents through shared tool instances or delegation.
- **Rationale:** Agent isolation must extend to tool permissions. Each agent should have independently scoped tool access, not inherited from other agents.

**AA-TS-070: Tool permission revocation not immediate**
- **Description:** Revoked tool permissions remain cached or active for a period after revocation, creating a window of unauthorized access.
- **Rationale:** Immediate revocation ensures permissions are enforced in real-time. Cached permissions must be invalidated when the source policy changes.

**AA-TS-071: Permission caching stale grants**
- **Description:** Tool permission checks use cached authorization decisions that may be stale, not reflecting recent policy changes.
- **Rationale:** Stale permission caches can grant access after revocation. Cache TTLs must be short enough to reflect policy changes promptly.

**AA-TS-072: Temporary permission elevation not time-bounded**
- **Description:** Temporarily elevated tool permissions do not have automatic expiration, remaining active until manually revoked.
- **Rationale:** Time-bounded elevation ensures temporary permissions automatically expire, preventing permanent escalation from forgotten temporary grants.

**AA-TS-073: Tool permission audit trail incomplete**
- **Description:** Tool permission changes (grants, revocations, elevations) are not fully logged with who, when, and why.
- **Rationale:** Complete permission audit trails enable investigation of unauthorized access and verification of permission management compliance.

**AA-TS-074: Implicit permissions not documented**
- **Description:** Tools have implicit permissions (e.g., a "search" tool implicitly reads files) that are not documented or factored into permission analysis.
- **Rationale:** Implicit permissions are often the path to escalation. All tool capabilities, including side effects, must be explicitly documented and authorized.

**AA-TS-075: Permission model not defense-in-depth**
- **Description:** Tool permissions rely on a single enforcement point without layered checks (tool level, framework level, OS level).
- **Rationale:** Defense-in-depth for permissions ensures that bypassing one layer doesn't grant unrestricted access. Multiple enforcement layers provide redundancy.

---

## 6. Tool Output Manipulation (AA-TS-076 – AA-TS-090)

**Threat:** Tool outputs are consumed by the model as trusted context. Compromised, misconfigured, or malicious tools can return manipulated output containing false data, embedded instructions, or adversarial content that influences subsequent agent reasoning and actions.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-076 | Tool output not validated | CRITICAL | static | stable | langchain, crewai, openai |
| AA-TS-077 | Tool output contains embedded instructions | CRITICAL | dynamic | stable | langchain, mcp, openai |
| AA-TS-078 | Tool output size unbounded | HIGH | static | stable | langchain, mcp, crewai |
| AA-TS-079 | Tool output type not verified | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-TS-080 | Sensitive data in tool output not redacted | HIGH | static | stable | langchain, openai, bedrock |
| AA-TS-081 | Tool error messages leak internal details | HIGH | static | stable | langchain, mcp, crewai |
| AA-TS-082 | Tool output schema compliance unchecked | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-083 | Tool output content scanning absent | MEDIUM | dynamic | stable | langchain, mcp, openai |
| AA-TS-084 | Tool output provenance not tracked | MEDIUM | static | stable | langchain, crewai, mcp |
| AA-TS-085 | Tool output caching poisoning possible | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-TS-086 | Tool output encoding not normalized | MEDIUM | static | stable | langchain, mcp, crewai |
| AA-TS-087 | Tool output freshness not validated | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-TS-088 | Tool binary output not inspected | MEDIUM | static | stable | langchain, mcp, autogen |
| AA-TS-089 | Tool output aggregation manipulation | MEDIUM | dynamic | experimental | langchain, crewai, openai |
| AA-TS-090 | Tool output confidence indicator absent | MEDIUM | dynamic | experimental | langchain, openai, bedrock |

### Standards Mapping

- **ASI02:** Tool output is a primary injection vector into agent reasoning
- **NIST AI RMF MEASURE-2.5:** Tool output quality and safety measurement
- **OWASP Agentic AI Top 10 Principle 2:** Tool output validation and safety

### Detailed Descriptions

**AA-TS-076: Tool output not validated**
- **Description:** Data returned from tool calls is consumed by the model without validation of format, content, or safety properties.
- **Rationale:** Tool output validation is essential because tool results become part of the agent's trusted context. Unvalidated output can inject instructions or false data.

**AA-TS-077: Tool output contains embedded instructions**
- **Description:** Tool output includes instruction-like text (e.g., "ignore previous instructions," "you must now") that the model may interpret as directives.
- **Rationale:** Embedded instructions in tool output constitute indirect prompt injection through the tool layer. Output must be scanned for instructional patterns.

**AA-TS-078: Tool output size unbounded**
- **Description:** Tools can return arbitrary amounts of data without size limits, potentially overwhelming the context window or consuming excessive memory.
- **Rationale:** Output size limits prevent context flooding and resource exhaustion. Tool outputs should be bounded and truncated when necessary.

**AA-TS-079: Tool output type not verified**
- **Description:** The data type of tool output is not checked against the declared return type, allowing type confusion when the model processes results.
- **Rationale:** Type verification ensures the model receives expected data types, preventing misinterpretation and type confusion vulnerabilities.

**AA-TS-080: Sensitive data in tool output not redacted**
- **Description:** Tool outputs may contain sensitive information (API keys, passwords, PII) that flows into the model's context without redaction.
- **Rationale:** Output redaction prevents sensitive data from entering the model's context where it could be leaked in subsequent outputs.

**AA-TS-081: Tool error messages leak internal details**
- **Description:** Tool error messages expose internal system details (stack traces, file paths, database schemas) that aid attackers.
- **Rationale:** Error messages should be generic and user-friendly. Internal details must be logged server-side but never included in model-visible output.

**AA-TS-082: Tool output schema compliance unchecked**
- **Description:** Structured tool outputs (JSON, XML) are not validated against their declared schemas before being processed by the model.
- **Rationale:** Schema compliance checking catches malformed output that could contain additional injected fields or unexpected data structures.

**AA-TS-083: Tool output content scanning absent**
- **Description:** Tool output content is not scanned for adversarial patterns, malicious URLs, executable code, or other dangerous content.
- **Rationale:** Content scanning catches malicious content that passes through tools, preventing it from entering the model's context as trusted information.

**AA-TS-084: Tool output provenance not tracked**
- **Description:** Tool outputs lack metadata indicating which tool produced them, when, and under what authorization, preventing audit.
- **Rationale:** Output provenance enables trust assessment of tool results and forensic analysis when outputs are found to be manipulated.

**AA-TS-085: Tool output caching poisoning possible**
- **Description:** Cached tool outputs can be poisoned, causing future requests to receive manipulated results without re-executing the tool.
- **Rationale:** Cache poisoning creates persistent manipulation. Cache entries must include integrity verification and appropriate TTLs.

**AA-TS-086: Tool output encoding not normalized**
- **Description:** Tool outputs use inconsistent character encodings, enabling encoding-based attacks when output is processed by subsequent tools.
- **Rationale:** Encoding normalization prevents cross-tool encoding confusion that can be exploited for injection or data manipulation.

**AA-TS-087: Tool output freshness not validated**
- **Description:** Tool outputs are used without checking whether the data is current, potentially using stale or outdated information.
- **Rationale:** Output freshness ensures the agent acts on current data. Stale tool outputs can lead to incorrect decisions based on outdated information.

**AA-TS-088: Tool binary output not inspected**
- **Description:** Binary tool outputs (images, PDFs, executables) are passed through without inspection for embedded malicious content.
- **Rationale:** Binary output can contain embedded malware, steganographic data, or exploit payloads. Binary content requires format-specific safety inspection.

**AA-TS-089: Tool output aggregation manipulation**
- **Description:** When multiple tool outputs are aggregated, the aggregation logic can be exploited to manipulate the combined result.
- **Rationale:** Aggregation manipulation causes individual valid outputs to combine into misleading results. Aggregation logic must be validated for manipulation resistance.

**AA-TS-090: Tool output confidence indicator absent**
- **Description:** Tool outputs lack confidence or reliability indicators, preventing the model from assessing output trustworthiness.
- **Rationale:** Confidence indicators enable the model to weight tool outputs appropriately, treating uncertain results with more caution.

---

## 7. Sandbox Escape (AA-TS-091 – AA-TS-105)

**Threat:** Tools designed to operate within sandboxed environments may find ways to escape containment — through symlinks, environment variables, shared memory, process manipulation, or exploitation of sandbox implementation gaps — gaining access to the broader system.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-091 | No sandbox for tool execution | CRITICAL | static | stable | langchain, autogen, mcp |
| AA-TS-092 | Code execution tool not containerized | CRITICAL | static | stable | langchain, autogen, crewai |
| AA-TS-093 | Sandbox escape via symlink traversal | HIGH | static | stable | langchain, mcp, autogen |
| AA-TS-094 | Sandbox escape via environment variables | HIGH | static | stable | langchain, autogen, mcp |
| AA-TS-095 | Shared file system between sandbox and host | HIGH | static | stable | langchain, autogen, crewai |
| AA-TS-096 | Network access from sandbox not restricted | HIGH | static | stable | langchain, autogen, mcp |
| AA-TS-097 | Sandbox process capabilities not dropped | MEDIUM | static | stable | langchain, autogen, mcp |
| AA-TS-098 | Sandbox resource limits not configured | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-TS-099 | Sandbox escape via /proc or /sys access | MEDIUM | static | stable | langchain, autogen, mcp |
| AA-TS-100 | Inter-sandbox communication not restricted | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-TS-101 | Sandbox persistence between invocations | MEDIUM | static | stable | langchain, mcp, autogen |
| AA-TS-102 | Sandbox monitoring and intrusion detection absent | MEDIUM | dynamic | stable | langchain, autogen, mcp |
| AA-TS-103 | Host device access from sandbox | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-TS-104 | Sandbox time-of-check-to-time-of-use gap | MEDIUM | dynamic | experimental | langchain, autogen, mcp |
| AA-TS-105 | Sandbox security updates not applied | MEDIUM | static | stable | langchain, autogen, crewai |

### Standards Mapping

- **ASI02:** Sandbox escape enables full system compromise through tools
- **ISO 42001 A.10:** System security for tool sandboxing
- **NIST AI RMF MANAGE-2.2:** Containment and isolation for tool execution

### Detailed Descriptions

**AA-TS-091: No sandbox for tool execution**
- **Description:** Tools execute directly in the agent's process without any sandboxing, containment, or isolation mechanism.
- **Rationale:** Tool sandboxing is the foundational control for limiting blast radius. Without it, any tool compromise grants full access to the agent's environment.

**AA-TS-092: Code execution tool not containerized**
- **Description:** Code execution tools (eval, exec, subprocess) run code directly on the host without container isolation.
- **Rationale:** Code execution is the highest-risk tool capability. Containerization (Docker, gVisor, Firecracker) provides strong isolation from the host system.

**AA-TS-093: Sandbox escape via symlink traversal**
- **Description:** The sandbox allows creation of symbolic links that point outside the sandbox boundary, enabling file system escape.
- **Rationale:** Symlink restriction prevents escaping the sandbox through file system indirection. Sandboxes must prevent symlink creation or resolve them within boundaries.

**AA-TS-094: Sandbox escape via environment variables**
- **Description:** Environment variables from the host environment are accessible within the sandbox, potentially exposing credentials or configuration.
- **Rationale:** Environment variable isolation prevents credential leakage. Sandboxes must provide a clean environment with only explicitly passed variables.

**AA-TS-095: Shared file system between sandbox and host**
- **Description:** The sandbox shares file system mounts with the host beyond what is strictly necessary, enabling access to host files.
- **Rationale:** File system isolation should use minimal read-only mounts. Shared writable file systems allow sandbox tools to modify host files.

**AA-TS-096: Network access from sandbox not restricted**
- **Description:** Tools running in sandboxes have unrestricted network access, enabling communication with external servers for data exfiltration.
- **Rationale:** Network restriction prevents sandboxed tools from contacting external servers. Only explicitly allowed network endpoints should be accessible.

**AA-TS-097: Sandbox process capabilities not dropped**
- **Description:** Sandboxed processes retain unnecessary Linux capabilities (CAP_SYS_ADMIN, CAP_NET_RAW) that could be exploited for escape.
- **Rationale:** Capability dropping removes attack surface. Sandboxed processes should run with the minimum capability set needed for their function.

**AA-TS-098: Sandbox resource limits not configured**
- **Description:** Sandboxed tool execution has no resource limits (CPU, memory, disk, processes), enabling resource exhaustion attacks.
- **Rationale:** Resource limits (cgroups, ulimits) prevent sandboxed tools from consuming excessive resources and affecting the host system.

**AA-TS-099: Sandbox escape via /proc or /sys access**
- **Description:** The /proc and /sys pseudo-filesystems are accessible within the sandbox, providing information about and potential control over the host.
- **Rationale:** /proc and /sys expose host information and control interfaces. Sandboxes must mask or restrict these filesystems.

**AA-TS-100: Inter-sandbox communication not restricted**
- **Description:** Multiple sandbox instances can communicate with each other through shared resources, IPC, or network, breaking isolation guarantees.
- **Rationale:** Inter-sandbox isolation prevents one compromised sandbox from attacking others. Communication should only occur through controlled channels.

**AA-TS-101: Sandbox persistence between invocations**
- **Description:** Sandbox state persists between tool invocations, allowing a previous invocation to leave traps or backdoors for subsequent calls.
- **Rationale:** Ephemeral sandboxes ensure each tool invocation starts from a clean state, preventing persistent compromise across invocations.

**AA-TS-102: Sandbox monitoring and intrusion detection absent**
- **Description:** Activities within sandboxes are not monitored for escape attempts, anomalous behavior, or intrusion indicators.
- **Rationale:** Sandbox monitoring detects escape attempts in progress, enabling intervention before containment is fully breached.

**AA-TS-103: Host device access from sandbox**
- **Description:** Hardware devices (GPU, USB, serial ports) are accessible from within the sandbox, providing attack surface for escape or abuse.
- **Rationale:** Device access restrictions prevent sandbox escape through device drivers and unauthorized use of hardware resources.

**AA-TS-104: Sandbox time-of-check-to-time-of-use gap**
- **Description:** Security checks on sandbox boundaries have TOCTOU gaps where conditions change between the check and the use.
- **Rationale:** TOCTOU elimination requires atomic operations for sandbox boundary checks. Race conditions in sandbox enforcement can be exploited for escape.

**AA-TS-105: Sandbox security updates not applied**
- **Description:** The sandbox runtime (container runtime, VM hypervisor) is not regularly updated with security patches.
- **Rationale:** Sandbox runtime vulnerabilities enable escape. Regular updates ensure known vulnerabilities are patched before they can be exploited.

---

## 8. Unauthorized Tool Access (AA-TS-106 – AA-TS-120)

**Threat:** Agents may access tools they are not authorized to use — through misconfigured access controls, missing authentication, tool enumeration, or privilege confusion in multi-agent systems. Unauthorized access expands the agent's effective capabilities beyond its designated role.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-106 | No tool access control enforcement | CRITICAL | static | stable | langchain, crewai, openai |
| AA-TS-107 | Tool authentication not required | CRITICAL | static | stable | langchain, mcp, openai |
| AA-TS-108 | Tool enumeration exposes hidden capabilities | HIGH | static | stable | langchain, mcp, openai |
| AA-TS-109 | Tool access not role-based | HIGH | static | stable | langchain, crewai, autogen |
| AA-TS-110 | Disabled tools still invocable | HIGH | static | stable | langchain, openai, mcp |
| AA-TS-111 | Tool access tokens not scoped | HIGH | static | stable | langchain, mcp, openai |
| AA-TS-112 | Tool access control bypass via direct call | MEDIUM | static | stable | langchain, mcp, crewai |
| AA-TS-113 | Tool access session binding absent | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-TS-114 | Tool access audit logging incomplete | MEDIUM | static | stable | langchain, crewai, openai |
| AA-TS-115 | Tool allowlist not enforced | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-116 | Tool denylist not maintained | MEDIUM | static | stable | langchain, crewai, autogen |
| AA-TS-117 | Tool access time restrictions not enforced | MEDIUM | dynamic | stable | langchain, openai, crewai |
| AA-TS-118 | Tool access from untrusted context | MEDIUM | dynamic | stable | langchain, mcp, openai |
| AA-TS-119 | Multi-tenant tool access isolation absent | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-TS-120 | Tool access credential rotation absent | MEDIUM | static | stable | langchain, mcp, openai |

### Standards Mapping

- **ASI02:** Unauthorized tool access expands agent attack surface
- **ISO 42001 A.10:** Access control for tool systems
- **NIST AI RMF MANAGE-2.2:** Tool access management and authentication

### Detailed Descriptions

**AA-TS-106: No tool access control enforcement**
- **Description:** Any agent, user, or session can invoke any tool without access control checks on who is authorized to use which tools.
- **Rationale:** Tool access controls are the primary mechanism for limiting agent capabilities. Without them, every tool is available to every context.

**AA-TS-107: Tool authentication not required**
- **Description:** Tool endpoints accept invocations without authenticating the caller, allowing any process to invoke tools.
- **Rationale:** Authentication ensures only authorized callers can invoke tools. Without it, tool endpoints are open to any network-accessible client.

**AA-TS-108: Tool enumeration exposes hidden capabilities**
- **Description:** Tool listing APIs expose all registered tools including those not intended for the current user or session.
- **Rationale:** Tool enumeration aids attackers in discovering available capabilities. Only tools authorized for the current context should be visible.

**AA-TS-109: Tool access not role-based**
- **Description:** Tool access is binary (all or nothing) rather than role-based, preventing fine-grained access control based on user or agent roles.
- **Rationale:** Role-based access enables different agents and users to have different tool capabilities appropriate to their function.

**AA-TS-110: Disabled tools still invocable**
- **Description:** Tools that are administratively disabled can still be invoked through direct API calls or cached tool listings.
- **Rationale:** Disabled tools must be fully inaccessible. Partial disabling (removing from UI but not API) leaves tools accessible to determined callers.

**AA-TS-111: Tool access tokens not scoped**
- **Description:** Authentication tokens for tool access have broad scope rather than being limited to specific tools or actions.
- **Rationale:** Scoped tokens limit the damage from token compromise. A token should only authorize the minimum set of tools needed.

**AA-TS-112: Tool access control bypass via direct call**
- **Description:** Access controls are only enforced at the framework layer, allowing direct calls to tool implementations to bypass authorization.
- **Rationale:** Defense-in-depth requires access controls at multiple layers. Tool implementations should verify authorization independently of the framework.

**AA-TS-113: Tool access session binding absent**
- **Description:** Tool access is not bound to the session that authorized it, allowing tokens or permissions to be used from different sessions.
- **Rationale:** Session binding prevents stolen tool access credentials from being used in unauthorized sessions.

**AA-TS-114: Tool access audit logging incomplete**
- **Description:** Not all tool access attempts (successful and failed) are logged with sufficient detail for security analysis.
- **Rationale:** Complete access logging enables detection of unauthorized access attempts, brute force attacks, and permission enumeration.

**AA-TS-115: Tool allowlist not enforced**
- **Description:** No explicit allowlist restricts which tools are available, defaulting to all registered tools being accessible.
- **Rationale:** Allowlisting is the most restrictive and secure approach to tool access control, ensuring only explicitly approved tools are available.

**AA-TS-116: Tool denylist not maintained**
- **Description:** No denylist blocks known-dangerous tools or tool configurations from being used in agent contexts.
- **Rationale:** Denylisting provides a safety net for known-dangerous tools, complementing allowlisting when the full tool set cannot be enumerated.

**AA-TS-117: Tool access time restrictions not enforced**
- **Description:** Tools can be accessed at any time without time-based restrictions, even when certain tools should only be available during business hours.
- **Rationale:** Time-based restrictions reduce attack surface during off-hours and align tool availability with operational needs.

**AA-TS-118: Tool access from untrusted context**
- **Description:** Tools are accessible from untrusted execution contexts (unauthenticated sessions, external networks) without additional verification.
- **Rationale:** Context-aware access requires stronger authentication or additional checks when tool access originates from less trusted contexts.

**AA-TS-119: Multi-tenant tool access isolation absent**
- **Description:** In multi-tenant deployments, tool access is not isolated between tenants, allowing cross-tenant tool invocation.
- **Rationale:** Tenant isolation ensures one tenant's tools and tool data are inaccessible to other tenants.

**AA-TS-120: Tool access credential rotation absent**
- **Description:** Credentials used to authenticate tool access are not rotated regularly, increasing exposure from credential compromise.
- **Rationale:** Credential rotation limits the window of exposure from compromised credentials. Automated rotation reduces operational burden.

---

## 9. Tool Availability Attacks (AA-TS-121 – AA-TS-135)

**Threat:** Attackers can disrupt agent functionality by making critical tools unavailable — through resource exhaustion, deliberate errors, slowloris-style attacks, or exploiting tool dependencies. Tool unavailability forces agents into degraded states that may bypass safety checks.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-121 | No tool availability monitoring | HIGH | dynamic | stable | langchain, mcp, crewai |
| AA-TS-122 | Single tool dependency creates SPOF | HIGH | static | stable | langchain, openai, mcp |
| AA-TS-123 | Tool resource exhaustion not prevented | HIGH | static | stable | langchain, mcp, autogen |
| AA-TS-124 | Tool slowloris attack not mitigated | HIGH | dynamic | stable | langchain, mcp, openai |
| AA-TS-125 | No tool fallback when primary unavailable | HIGH | static | stable | langchain, crewai, openai |
| AA-TS-126 | Tool health check not implemented | MEDIUM | dynamic | stable | langchain, mcp, crewai |
| AA-TS-127 | Tool connection pool exhaustion possible | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-128 | Tool circuit breaker not implemented | MEDIUM | static | stable | langchain, mcp, crewai |
| AA-TS-129 | Tool dependency chain fragility | MEDIUM | static | stable | langchain, mcp, autogen |
| AA-TS-130 | Tool startup time not bounded | MEDIUM | static | stable | mcp, langchain, crewai |
| AA-TS-131 | Tool graceful degradation not defined | MEDIUM | static | stable | langchain, crewai, openai |
| AA-TS-132 | Tool availability SLA not monitored | MEDIUM | dynamic | stable | langchain, mcp, openai |
| AA-TS-133 | Tool cache availability not assured | MEDIUM | static | stable | langchain, openai, mcp |
| AA-TS-134 | Tool infrastructure redundancy absent | MEDIUM | static | stable | langchain, mcp, bedrock |
| AA-TS-135 | Tool availability attack detection absent | MEDIUM | dynamic | experimental | langchain, mcp, openai |

### Standards Mapping

- **ASI02:** Tool availability is critical to agent operational safety
- **MITRE ATLAS AML.T0048:** Denial of AI service through tool disruption
- **OWASP Agentic AI Top 10 Principle 2:** Tool availability and resilience

### Detailed Descriptions

**AA-TS-121: No tool availability monitoring**
- **Description:** Tool availability is not monitored, preventing detection of tool outages, degradation, or deliberate denial-of-service attacks.
- **Rationale:** Availability monitoring enables rapid detection and response to tool outages, minimizing impact on agent functionality.

**AA-TS-122: Single tool dependency creates SPOF**
- **Description:** Critical agent functionality depends on a single tool instance without redundancy, creating a single point of failure.
- **Rationale:** Redundancy for critical tools ensures agent functionality survives individual tool failures. No single tool should be a SPOF.

**AA-TS-123: Tool resource exhaustion not prevented**
- **Description:** Tools can be overwhelmed with requests that exhaust their resources (memory, connections, threads), making them unavailable.
- **Rationale:** Resource protection for tools prevents denial-of-service. Tools should enforce their own request limits and resource boundaries.

**AA-TS-124: Tool slowloris attack not mitigated**
- **Description:** Tools are vulnerable to slowloris-style attacks where connections are kept open with minimal data, exhausting connection capacity.
- **Rationale:** Connection timeout and cleanup protections prevent slow-rate attacks from exhausting tool connection capacity.

**AA-TS-125: No tool fallback when primary unavailable**
- **Description:** When a tool is unavailable, no fallback mechanism exists to provide degraded but functional capability.
- **Rationale:** Fallback tools maintain agent capability during outages, even if with reduced functionality or performance.

**AA-TS-126: Tool health check not implemented**
- **Description:** No periodic health check validates that tools are functioning correctly, potentially leaving failed tools in the active pool.
- **Rationale:** Health checks detect tool failures promptly, enabling automatic removal from the active pool and triggering fallback mechanisms.

**AA-TS-127: Tool connection pool exhaustion possible**
- **Description:** Connection pools for tool communication can be exhausted, preventing new tool invocations.
- **Rationale:** Connection pool management (sizing, timeouts, recycling) ensures tools remain accessible under load.

**AA-TS-128: Tool circuit breaker not implemented**
- **Description:** Repeated tool failures do not trigger a circuit breaker to stop sending requests to the failed tool.
- **Rationale:** Circuit breakers prevent cascading failures by stopping requests to known-failed tools, conserving resources for healthy tools.

**AA-TS-129: Tool dependency chain fragility**
- **Description:** Tools have deep dependency chains where failure of any dependency makes the tool unavailable.
- **Rationale:** Shallow, resilient dependency chains ensure tools can function even when some dependencies are degraded.

**AA-TS-130: Tool startup time not bounded**
- **Description:** Tools (especially MCP servers) can take arbitrarily long to start, delaying agent readiness.
- **Rationale:** Bounded startup time ensures agents become operational promptly. Tools with long startup should support pre-warming.

**AA-TS-131: Tool graceful degradation not defined**
- **Description:** No degradation plan exists for when tools are partially available, leaving the agent to handle partial failures ad hoc.
- **Rationale:** Defined degradation plans ensure predictable, safe agent behavior when tools are partially available.

**AA-TS-132: Tool availability SLA not monitored**
- **Description:** Tool availability targets (uptime, response time, error rate) are not defined or monitored against SLAs.
- **Rationale:** SLA monitoring provides accountability for tool availability and early warning of degradation trends.

**AA-TS-133: Tool cache availability not assured**
- **Description:** Tool result caches can become unavailable, forcing all requests to hit the backend tool which may not handle the full load.
- **Rationale:** Cache availability planning ensures tool performance is maintained when caches are cold, invalidated, or unavailable.

**AA-TS-134: Tool infrastructure redundancy absent**
- **Description:** Tool hosting infrastructure (servers, containers, processes) lacks redundancy to survive infrastructure failures.
- **Rationale:** Infrastructure redundancy ensures tool availability survives hardware failures, network partitions, and availability zone outages.

**AA-TS-135: Tool availability attack detection absent**
- **Description:** Deliberate attacks on tool availability (flooding, resource exhaustion, targeted failures) are not distinguished from natural outages.
- **Rationale:** Attack detection enables different response strategies for deliberate attacks versus accidental failures, improving incident response.

---

## 10. Framework-Specific Tool Checks (AA-TS-136 – AA-TS-150)

**Threat:** Each AI agent framework implements tool systems differently, with framework-specific patterns that create unique vulnerabilities. These controls address tool safety issues specific to individual framework implementations and their tool invocation mechanisms.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-TS-136 | LangChain Tool class input validation absent | CRITICAL | static | stable | langchain |
| AA-TS-137 | LangChain agent executor tool loop unbounded | HIGH | static | stable | langchain |
| AA-TS-138 | LangChain StructuredTool schema not enforced | HIGH | static | stable | langchain |
| AA-TS-139 | CrewAI tool delegation without context filtering | HIGH | static | stable | crewai |
| AA-TS-140 | CrewAI shared tool state between agents | MEDIUM | static | stable | crewai |
| AA-TS-141 | OpenAI function calling schema bypass | HIGH | static | stable | openai |
| AA-TS-142 | OpenAI parallel function calls not validated together | MEDIUM | static | stable | openai |
| AA-TS-143 | AutoGen code execution tool unrestricted | CRITICAL | static | stable | autogen |
| AA-TS-144 | AutoGen tool registration not authenticated | HIGH | static | stable | autogen |
| AA-TS-145 | Vercel AI SDK tool streaming output unchecked | MEDIUM | static | stable | vercel-ai |
| AA-TS-146 | Vercel AI SDK tool maxSteps not configured | HIGH | static | stable | vercel-ai |
| AA-TS-147 | MCP tool permission scope too broad | HIGH | static | stable | mcp |
| AA-TS-148 | MCP stdio transport input not bounded | HIGH | static | stable | mcp |
| AA-TS-149 | Bedrock action group permissions too permissive | HIGH | static | stable | bedrock |
| AA-TS-150 | Bedrock agent tool configuration not reviewed | MEDIUM | static | stable | bedrock |

### Standards Mapping

- **ASI02:** Framework-specific tool risks require targeted controls
- **NIST AI RMF MAP-1.5:** Framework-specific capability mapping
- **ISO 42001 A.5:** Framework tool configuration and management

### Detailed Descriptions

**AA-TS-136: LangChain Tool class input validation absent**
- **Description:** LangChain Tool implementations do not validate input arguments in the _run method, accepting any string or dict without checks.
- **Rationale:** LangChain Tool input validation is the developer's responsibility. Without explicit validation, tools accept and process arbitrary inputs from the model.

**AA-TS-137: LangChain agent executor tool loop unbounded**
- **Description:** The LangChain AgentExecutor's max_iterations is not set or set too high, allowing the agent to loop through tool calls indefinitely.
- **Rationale:** max_iterations is the primary guard against agent loops in LangChain. It should be set to a reasonable value (10-20) for all agent types.

**AA-TS-138: LangChain StructuredTool schema not enforced**
- **Description:** LangChain StructuredTool Pydantic schemas are defined but not actually enforced at runtime, allowing schema violations to reach the tool.
- **Rationale:** Schema enforcement ensures the tool receives correctly typed and structured input. Without enforcement, the schema serves only as documentation.

**AA-TS-139: CrewAI tool delegation without context filtering**
- **Description:** When CrewAI agents delegate tool usage to other agents, the full task context including sensitive information passes to the delegate.
- **Rationale:** Tool delegation context should be filtered to include only task-relevant information, preventing sensitive data leakage through delegation chains.

**AA-TS-140: CrewAI shared tool state between agents**
- **Description:** Tools shared between CrewAI agents maintain state that is accessible to all sharing agents, creating cross-agent state leakage.
- **Rationale:** Shared tool state enables one agent to influence another through the tool layer. Tool state should be isolated per-agent where possible.

**AA-TS-141: OpenAI function calling schema bypass**
- **Description:** OpenAI function calling may generate arguments that don't match the declared JSON schema, and the application doesn't re-validate.
- **Rationale:** While OpenAI aims for schema compliance, edge cases exist. Application-level re-validation catches schema violations before tool execution.

**AA-TS-142: OpenAI parallel function calls not validated together**
- **Description:** When OpenAI generates parallel function calls, each is validated independently rather than as a group, missing dangerous combinations.
- **Rationale:** Parallel call validation catches compound threats where individually safe calls become dangerous when executed simultaneously.

**AA-TS-143: AutoGen code execution tool unrestricted**
- **Description:** AutoGen's code execution capability runs arbitrary code without sandbox restrictions, filesystem limits, or network controls.
- **Rationale:** AutoGen code execution is the highest-risk tool in the framework. It must run in sandboxed environments with strict resource and access controls.

**AA-TS-144: AutoGen tool registration not authenticated**
- **Description:** AutoGen allows tools to be registered in group chats without verifying the registering agent's authority to add tools.
- **Rationale:** Unauthenticated tool registration allows compromised agents to inject malicious tools into group conversations.

**AA-TS-145: Vercel AI SDK tool streaming output unchecked**
- **Description:** Vercel AI SDK tool results streamed to the client are not checked for malicious content during the streaming process.
- **Rationale:** Streaming outputs bypass batch validation. Content checks must be applied incrementally during streaming to catch malicious content.

**AA-TS-146: Vercel AI SDK tool maxSteps not configured**
- **Description:** The Vercel AI SDK maxSteps parameter is not set, allowing unbounded tool call iterations in streaming responses.
- **Rationale:** maxSteps is the primary loop guard in Vercel AI SDK. It should always be explicitly set to prevent runaway tool call sequences.

**AA-TS-147: MCP tool permission scope too broad**
- **Description:** MCP tools are granted permissions beyond what they need (full filesystem access instead of specific directories, all network vs specific hosts).
- **Rationale:** MCP tool permissions should follow least privilege. Each tool should have the minimum permission scope needed for its documented function.

**AA-TS-148: MCP stdio transport input not bounded**
- **Description:** MCP servers using stdio transport accept unbounded input, allowing memory exhaustion through oversized JSON-RPC messages.
- **Rationale:** Input size limits for stdio transport prevent memory exhaustion attacks. Messages exceeding reasonable limits should be rejected.

**AA-TS-149: Bedrock action group permissions too permissive**
- **Description:** Amazon Bedrock agent action group IAM roles have overly permissive policies granting access beyond what the action needs.
- **Rationale:** Action group IAM roles should follow least privilege. Overly permissive roles amplify the impact of any action group compromise.

**AA-TS-150: Bedrock agent tool configuration not reviewed**
- **Description:** Bedrock agent tool configurations (Lambda functions, API schemas) are deployed without security review of the implementation.
- **Rationale:** Tool implementations are the execution layer where security controls are enforced. Unreviewed implementations may contain vulnerabilities or unsafe patterns.
