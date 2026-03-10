# AA-RB: Reliability & Operational Bounds Controls

**Domain:** Reliability & Operational Bounds  
**OWASP Mapping:** ASI09 — Operational Misuse & Safety Failures  
**Control Range:** AA-RB-001 through AA-RB-100  
**Total Controls:** 100  
**Last Updated:** 2026-02-13  
**Status:** Active

---

## Overview

AI agents operate within implicit and explicit operational boundaries that define acceptable behavior, resource consumption, output quality, and failure modes. When these boundaries are undefined, unenforced, or misconfigured, agents can exhibit runaway behavior — consuming excessive resources, generating unbounded output, entering infinite loops, or escalating operations beyond their intended scope without triggering any safety mechanism.

Reliability failures in agentic systems differ fundamentally from traditional software reliability because agent behavior is non-deterministic, context-dependent, and influenced by model capabilities that can degrade unpredictably. An agent that operates correctly in testing may fail in production due to novel inputs, context window pressure, model version changes, or adversarial manipulation. These controls ensure agents maintain predictable, bounded behavior even under adverse conditions.

Operational bounds enforcement encompasses resource management (tokens, compute, memory, API calls), output validation (format, quality, factuality), loop and recursion detection, rate limiting, timeout enforcement, graceful degradation, and scope boundary maintenance. Together they ensure agents remain within their designated operational envelope and fail safely when boundaries are approached or breached.

---

## Applicable Standards

| Standard | Sections |
|----------|----------|
| OWASP Agentic Security | ASI09 — Operational Misuse & Safety Failures |
| NIST AI RMF | GOVERN-1.2, MEASURE-2.6, MANAGE-2.4 |
| ISO 42001 | A.9 — Performance Monitoring, A.10 — System Security |
| ISO 23894 | Clause 6.5 — Operational Risk Management |
| MITRE ATLAS | AML.T0048 — Denial of AI Service |
| OWASP Agentic AI Top 10 | Principle 6 — Operational Bounds, Principle 7 — Resource Management |
| OWASP AIVSS | Vectors: AV:R (Resource), AV:O (Operational) |

---

## Sub-Categories Summary

| # | Sub-Category | Controls | Range |
|---|-------------|----------|-------|
| 1 | Scope Boundary Enforcement | 10 | AA-RB-001 – AA-RB-010 |
| 2 | Resource Consumption Limits | 10 | AA-RB-011 – AA-RB-020 |
| 3 | Output Validation | 10 | AA-RB-021 – AA-RB-030 |
| 4 | Hallucination Detection | 10 | AA-RB-031 – AA-RB-040 |
| 5 | Token Budget Management | 10 | AA-RB-041 – AA-RB-050 |
| 6 | Retry & Loop Detection | 10 | AA-RB-051 – AA-RB-060 |
| 7 | Rate Limiting | 10 | AA-RB-061 – AA-RB-070 |
| 8 | Timeout Enforcement | 10 | AA-RB-071 – AA-RB-080 |
| 9 | Graceful Degradation | 10 | AA-RB-081 – AA-RB-090 |
| 10 | Operational Bounds Monitoring | 10 | AA-RB-091 – AA-RB-100 |

---

## 1. Scope Boundary Enforcement (AA-RB-001 – AA-RB-010)

**Threat:** Agents operating without defined scope boundaries can drift into unauthorized domains, access resources outside their intended scope, or perform actions that exceed their designated role, leading to security violations and operational chaos.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-001 | No operational scope definition | CRITICAL | static | stable | langchain, crewai, openai |
| AA-RB-002 | Scope boundary not enforced at runtime | CRITICAL | dynamic | stable | langchain, crewai, autogen |
| AA-RB-003 | Task scope drift undetected | HIGH | dynamic | stable | langchain, openai, vercel-ai |
| AA-RB-004 | Domain restriction not configured | HIGH | static | stable | langchain, crewai, bedrock |
| AA-RB-005 | File system access scope unbounded | HIGH | static | stable | langchain, autogen, mcp |
| AA-RB-006 | Network access scope unrestricted | HIGH | static | stable | langchain, crewai, mcp |
| AA-RB-007 | Database query scope not limited | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-RB-008 | API endpoint access not scoped | MEDIUM | static | stable | langchain, openai, mcp |
| AA-RB-009 | Scope escalation through tool chaining | MEDIUM | dynamic | stable | langchain, crewai, autogen |
| AA-RB-010 | No scope boundary violation alerting | MEDIUM | dynamic | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI09:** Scope boundary enforcement prevents operational misuse
- **NIST AI RMF GOVERN-1.2:** Operational scope governance for AI agents
- **OWASP Agentic AI Top 10 Principle 6:** Defined operational bounds for agent systems

### Detailed Descriptions

**AA-RB-001: No operational scope definition**
- **Description:** The agent lacks a formal definition of its operational scope, including what tasks, data, resources, and systems it is authorized to access and modify.
- **Rationale:** Without a defined scope, there is no baseline against which to detect unauthorized behavior. Every agent must have an explicit scope document.

**AA-RB-002: Scope boundary not enforced at runtime**
- **Description:** Even when operational scope is defined, no runtime mechanism enforces the boundaries, relying entirely on the model's adherence to instructions.
- **Rationale:** Model-based enforcement alone is insufficient. Runtime guards must validate each action against defined scope boundaries before execution.

**AA-RB-003: Task scope drift undetected**
- **Description:** The agent gradually expands its actions beyond the original task scope across conversation turns without detection or intervention.
- **Rationale:** Task drift is a natural LLM behavior that can lead to unauthorized actions. Continuous monitoring of action relevance to the stated task prevents drift.

**AA-RB-004: Domain restriction not configured**
- **Description:** The agent is not restricted to specific knowledge domains or task types, allowing it to attempt tasks outside its competence or authorization.
- **Rationale:** Domain restrictions prevent agents from operating in areas where their outputs may be unreliable or unauthorized, reducing risk of harmful actions.

**AA-RB-005: File system access scope unbounded**
- **Description:** Agent file system operations are not restricted to designated directories, allowing read/write access to arbitrary file system locations.
- **Rationale:** Unbounded file access enables data exfiltration, credential theft, and system compromise. File operations must be sandboxed to approved paths.

**AA-RB-006: Network access scope unrestricted**
- **Description:** The agent can make network requests to any host or port without allowlisting, enabling data exfiltration and unauthorized service access.
- **Rationale:** Network restrictions prevent agents from contacting unauthorized endpoints. Only explicitly approved hosts should be accessible from agent processes.

**AA-RB-007: Database query scope not limited**
- **Description:** Agent database access is not restricted to specific tables, views, or query types, allowing full database exploration and modification.
- **Rationale:** Database scope limits prevent agents from accessing sensitive tables, running destructive queries, or exfiltrating data beyond their authorized scope.

**AA-RB-008: API endpoint access not scoped**
- **Description:** The agent can call any available API endpoint without restriction, including administrative, destructive, or sensitive endpoints.
- **Rationale:** API access scoping ensures agents can only reach endpoints relevant to their task. Administrative endpoints should never be accessible to task-level agents.

**AA-RB-009: Scope escalation through tool chaining**
- **Description:** By chaining multiple tools, the agent achieves effective scope beyond what any individual tool permits, bypassing per-tool scope restrictions.
- **Rationale:** Tool chaining scope analysis must evaluate the combined effect of tool sequences, not just individual tools, to prevent compound escalation.

**AA-RB-010: No scope boundary violation alerting**
- **Description:** Attempts to operate outside defined scope boundaries do not generate alerts, preventing security teams from detecting scope violation attempts.
- **Rationale:** Alerting on boundary violations enables rapid response to scope breach attempts, whether from manipulation, drift, or misconfiguration.

---

## 2. Resource Consumption Limits (AA-RB-011 – AA-RB-020)

**Threat:** Agents without resource limits can consume unbounded compute, memory, storage, and API quota — either through adversarial manipulation, programming errors, or emergent behavior — causing cost explosion, service degradation, or denial of service.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-011 | No per-request cost limit | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-RB-012 | No per-session cost limit | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-RB-013 | Memory consumption not bounded | HIGH | static | stable | langchain, autogen, crewai |
| AA-RB-014 | CPU time per task not limited | HIGH | static | stable | langchain, autogen, crewai |
| AA-RB-015 | Disk space consumption not monitored | HIGH | static | stable | langchain, mcp, autogen |
| AA-RB-016 | Concurrent request limit absent | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-017 | Child process spawning not restricted | MEDIUM | static | stable | langchain, autogen, mcp |
| AA-RB-018 | Network bandwidth consumption unbounded | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-RB-019 | Resource usage not attributed to originating user | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-020 | No resource consumption anomaly detection | MEDIUM | dynamic | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI09:** Resource exhaustion is a primary operational safety failure
- **MITRE ATLAS AML.T0048:** Denial of AI service through resource exhaustion
- **OWASP Agentic AI Top 10 Principle 7:** Resource management and consumption limits

### Detailed Descriptions

**AA-RB-011: No per-request cost limit**
- **Description:** Individual agent requests have no cost ceiling, allowing a single request to trigger unlimited API calls, model invocations, or tool executions.
- **Rationale:** Per-request cost limits prevent runaway spending from a single malicious or malformed request. Each request should have a defined maximum cost.

**AA-RB-012: No per-session cost limit**
- **Description:** Agent sessions have no cumulative cost limit, allowing extended interactions to accumulate unbounded expenses across multiple requests.
- **Rationale:** Session cost limits protect against long-running manipulation that gradually escalates resource usage below per-request thresholds.

**AA-RB-013: Memory consumption not bounded**
- **Description:** Agent processes can allocate unlimited memory, enabling memory exhaustion through large tool outputs, accumulated state, or adversarial inputs.
- **Rationale:** Memory limits prevent denial-of-service and ensure agents fail gracefully rather than crashing the host when memory is exhausted.

**AA-RB-014: CPU time per task not limited**
- **Description:** No CPU time limit exists for agent task execution, allowing compute-intensive operations to monopolize resources indefinitely.
- **Rationale:** CPU time limits prevent runaway computation from affecting other services. Tasks exceeding limits should be terminated with appropriate error handling.

**AA-RB-015: Disk space consumption not monitored**
- **Description:** Agent operations that create files, logs, or cached data have no disk space monitoring or limits, risking storage exhaustion.
- **Rationale:** Disk space exhaustion can crash the agent and affect co-located services. Monitoring and limits prevent storage-based denial of service.

**AA-RB-016: Concurrent request limit absent**
- **Description:** No limit exists on the number of concurrent agent requests, allowing resource exhaustion through request flooding.
- **Rationale:** Concurrent request limits ensure fair resource distribution and prevent a single user from monopolizing agent capacity.

**AA-RB-017: Child process spawning not restricted**
- **Description:** The agent can spawn unlimited child processes through tool calls or code execution, enabling fork bomb or resource exhaustion attacks.
- **Rationale:** Process limits prevent fork bombs and ensure the agent cannot overwhelm the host with spawned processes. Use cgroups or container limits.

**AA-RB-018: Network bandwidth consumption unbounded**
- **Description:** Agent network operations have no bandwidth limits, allowing large data transfers that consume network capacity.
- **Rationale:** Bandwidth limits prevent data exfiltration of large datasets and protect shared network resources from agent-initiated traffic spikes.

**AA-RB-019: Resource usage not attributed to originating user**
- **Description:** Resource consumption is not tracked per user or session, preventing identification of users responsible for excessive resource usage.
- **Rationale:** Per-user attribution enables fair use enforcement, abuse detection, and chargeback for resource consumption.

**AA-RB-020: No resource consumption anomaly detection**
- **Description:** Resource usage patterns are not monitored for anomalies that could indicate abuse, compromise, or runaway behavior.
- **Rationale:** Anomaly detection catches unexpected resource consumption patterns that per-request limits alone might miss, such as gradual escalation over time.

---

## 3. Output Validation (AA-RB-021 – AA-RB-030)

**Threat:** Agent outputs that are not validated may contain malicious content, incorrect information, format violations, or data leakage. Output validation ensures agent responses meet safety, quality, and format requirements before being delivered to users or downstream systems.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-021 | No output content validation | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-RB-022 | Output format validation absent | HIGH | static | stable | langchain, crewai, openai |
| AA-RB-023 | Output size not bounded | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-RB-024 | Sensitive data in output not detected | HIGH | static | stable | langchain, openai, bedrock |
| AA-RB-025 | Output language/encoding not validated | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-026 | Output schema compliance not checked | MEDIUM | static | stable | langchain, crewai, openai |
| AA-RB-027 | Executable content in output not detected | MEDIUM | static | stable | langchain, openai, mcp |
| AA-RB-028 | Output confidence score not provided | MEDIUM | dynamic | experimental | langchain, openai, bedrock |
| AA-RB-029 | Output citation/source attribution absent | MEDIUM | dynamic | experimental | langchain, openai, vercel-ai |
| AA-RB-030 | Output idempotency not guaranteed | MEDIUM | dynamic | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI09:** Output validation prevents operational misuse and data leakage
- **NIST AI RMF MEASURE-2.6:** AI output quality and safety measurement
- **ISO 42001 A.9:** Performance monitoring for AI output quality

### Detailed Descriptions

**AA-RB-021: No output content validation**
- **Description:** Agent outputs are delivered to users or downstream systems without validation for harmful content, injection payloads, or safety violations.
- **Rationale:** Output validation is the last line of defense against harmful agent responses. All outputs must pass content safety checks before delivery.

**AA-RB-022: Output format validation absent**
- **Description:** Agent outputs are not validated against expected format specifications (JSON schema, HTML structure, markdown syntax), allowing malformed responses.
- **Rationale:** Format validation ensures outputs are parseable by downstream consumers. Malformed outputs can cause application errors or injection vulnerabilities.

**AA-RB-023: Output size not bounded**
- **Description:** No limit exists on agent output size, allowing generation of arbitrarily large responses that consume bandwidth, storage, or processing resources.
- **Rationale:** Output size limits prevent resource exhaustion and ensure responses are manageable. Excessively large outputs often indicate runaway generation.

**AA-RB-024: Sensitive data in output not detected**
- **Description:** Agent outputs are not scanned for accidentally included sensitive data such as API keys, passwords, PII, or internal system information.
- **Rationale:** Output scanning catches accidental data leakage from the agent's context, tools, or training data before sensitive information reaches users.

**AA-RB-025: Output language/encoding not validated**
- **Description:** Agent outputs are not checked for correct language, character encoding, or Unicode normalization, allowing encoding-based attacks.
- **Rationale:** Encoding validation prevents Unicode tricks, homoglyph attacks, and encoding-based injection that can bypass downstream security controls.

**AA-RB-026: Output schema compliance not checked**
- **Description:** Structured agent outputs (JSON, XML) are not validated against their declared schemas, allowing invalid or unexpected fields.
- **Rationale:** Schema validation ensures outputs match the contract with downstream consumers. Unexpected fields can be used for data smuggling.

**AA-RB-027: Executable content in output not detected**
- **Description:** Agent outputs may contain executable content (JavaScript, SQL, shell commands) that could execute in client contexts.
- **Rationale:** Executable content in outputs can lead to XSS, SQL injection, or command injection when outputs are rendered or processed by clients.

**AA-RB-028: Output confidence score not provided**
- **Description:** Agent outputs lack confidence scores or uncertainty indicators, preventing users and downstream systems from assessing output reliability.
- **Rationale:** Confidence scores enable informed decision-making about output trustworthiness, particularly important for safety-critical applications.

**AA-RB-029: Output citation/source attribution absent**
- **Description:** Agent claims and factual statements are not accompanied by citations or source attributions, preventing verification.
- **Rationale:** Source attribution enables fact-checking and reduces reliance on potentially hallucinated information, improving output trustworthiness.

**AA-RB-030: Output idempotency not guaranteed**
- **Description:** Repeated agent requests with identical inputs may produce different outputs without clear indication, causing inconsistency in downstream systems.
- **Rationale:** Output idempotency is important for retry-safe operations. When outputs vary, the variation should be documented and downstream systems should expect it.

---

## 4. Hallucination Detection (AA-RB-031 – AA-RB-040)

**Threat:** LLMs generate plausible but factually incorrect information (hallucinations) that agents may act on, leading to incorrect decisions, fabricated data in outputs, and loss of user trust. In safety-critical applications, hallucinated information can cause real harm.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-031 | No hallucination detection mechanism | CRITICAL | dynamic | stable | langchain, openai, vercel-ai |
| AA-RB-032 | Fabricated citation detection absent | HIGH | dynamic | stable | langchain, openai, bedrock |
| AA-RB-033 | Factual claim verification not implemented | HIGH | dynamic | experimental | langchain, openai, vercel-ai |
| AA-RB-034 | Hallucinated tool name invocation | HIGH | dynamic | stable | langchain, crewai, mcp |
| AA-RB-035 | Numerical hallucination detection absent | MEDIUM | dynamic | experimental | langchain, openai, bedrock |
| AA-RB-036 | Temporal fact verification missing | MEDIUM | dynamic | experimental | langchain, openai, vercel-ai |
| AA-RB-037 | Self-consistency checking not implemented | MEDIUM | dynamic | experimental | langchain, openai, autogen |
| AA-RB-038 | Hallucinated API endpoint or URL generation | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-RB-039 | Knowledge boundary awareness absent | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-RB-040 | No human verification for high-stakes outputs | MEDIUM | both | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI09:** Hallucination is a core reliability risk for agentic systems
- **NIST AI RMF MEASURE-2.6:** AI output accuracy and reliability measurement
- **ISO 42001 A.9:** Performance monitoring for factual accuracy

### Detailed Descriptions

**AA-RB-031: No hallucination detection mechanism**
- **Description:** The agent system has no mechanism to detect or flag potentially hallucinated content in outputs before delivery.
- **Rationale:** Hallucination detection is essential for trustworthy AI agents. Without it, fabricated information is delivered with the same confidence as factual information.

**AA-RB-032: Fabricated citation detection absent**
- **Description:** The agent generates citations, references, or URLs that are fabricated (don't point to real sources) without detection.
- **Rationale:** Fabricated citations create a false appearance of verifiability. Citation verification ensures references point to real, relevant sources.

**AA-RB-033: Factual claim verification not implemented**
- **Description:** Factual claims in agent outputs are not verified against authoritative sources or knowledge bases before delivery.
- **Rationale:** Factual verification catches hallucinated claims before they reach users. At minimum, claims in high-stakes domains should be verified.

**AA-RB-034: Hallucinated tool name invocation**
- **Description:** The agent attempts to call tools that don't exist in its registered tool set, indicating hallucinated tool knowledge.
- **Rationale:** Hallucinated tool calls waste resources and may indicate the agent is operating outside its actual capabilities, potentially causing errors.

**AA-RB-035: Numerical hallucination detection absent**
- **Description:** Numerical values in agent outputs (statistics, measurements, financial figures) are not validated for plausibility or accuracy.
- **Rationale:** Numerical hallucinations can have severe consequences in financial, medical, or engineering contexts. Plausibility checks catch obviously wrong numbers.

**AA-RB-036: Temporal fact verification missing**
- **Description:** Time-dependent claims are not checked against the agent's knowledge cutoff date, leading to outdated information presented as current.
- **Rationale:** Temporal verification prevents the agent from presenting outdated information as current, which is both misleading and potentially harmful.

**AA-RB-037: Self-consistency checking not implemented**
- **Description:** The agent does not check its outputs for internal consistency, allowing contradictory statements within a single response.
- **Rationale:** Self-consistency checking detects hallucinations where the model generates contradictory facts, a common hallucination pattern.

**AA-RB-038: Hallucinated API endpoint or URL generation**
- **Description:** The agent generates API endpoints, URLs, or file paths that don't exist, potentially directing users to malicious or non-existent resources.
- **Rationale:** Hallucinated URLs can be registered by attackers (URL squatting), making hallucinated links an indirect security risk for users who follow them.

**AA-RB-039: Knowledge boundary awareness absent**
- **Description:** The agent does not maintain awareness of what it knows versus doesn't know, confidently answering questions outside its knowledge.
- **Rationale:** Knowledge boundary awareness enables appropriate uncertainty expression, preventing confident hallucination about unknown topics.

**AA-RB-040: No human verification for high-stakes outputs**
- **Description:** Outputs for high-stakes decisions (financial, medical, legal, safety-critical) are not routed for human verification before action.
- **Rationale:** Human verification for high-stakes outputs provides a critical safety net against hallucination in contexts where errors have severe consequences.

---

## 5. Token Budget Management (AA-RB-041 – AA-RB-050)

**Threat:** Unmanaged token consumption leads to cost explosion, context window exhaustion, and service degradation. Attackers can deliberately trigger excessive token usage through adversarial inputs designed to maximize generation length or complexity.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-041 | No per-request token budget | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-RB-042 | No global token budget enforcement | HIGH | static | stable | langchain, openai, bedrock |
| AA-RB-043 | Input token count not validated | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-RB-044 | Output max_tokens not set | HIGH | static | stable | langchain, openai, bedrock |
| AA-RB-045 | Token budget allocation across components absent | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-046 | Token usage monitoring not implemented | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-RB-047 | Token-expensive operations not flagged | MEDIUM | dynamic | stable | langchain, crewai, openai |
| AA-RB-048 | Token budget remaining not exposed to agent | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-049 | Token budget per user not enforced | MEDIUM | dynamic | stable | langchain, openai, vercel-ai |
| AA-RB-050 | Token usage billing anomaly not detected | MEDIUM | dynamic | stable | langchain, openai, bedrock |

### Standards Mapping

- **ASI09:** Token management is fundamental to operational bounds
- **OWASP Agentic AI Top 10 Principle 7:** Resource management for token consumption
- **NIST AI RMF MANAGE-2.4:** AI resource management and cost control

### Detailed Descriptions

**AA-RB-041: No per-request token budget**
- **Description:** Individual requests do not have a token budget, allowing a single request to consume unlimited tokens across input, processing, and output.
- **Rationale:** Per-request token budgets prevent cost explosion from single requests, whether caused by adversarial inputs, long conversations, or tool chain depth.

**AA-RB-042: No global token budget enforcement**
- **Description:** No system-wide token budget limits total consumption across all users and sessions, risking uncontrolled spending.
- **Rationale:** Global budgets provide a hard ceiling on token spend, preventing individual request or session limits from being circumvented through volume.

**AA-RB-043: Input token count not validated**
- **Description:** Input token counts are not checked against budgets before being processed, allowing oversized inputs to consume resources.
- **Rationale:** Input validation prevents processing of inputs that would exceed budgets. Reject or truncate oversized inputs before they reach the model.

**AA-RB-044: Output max_tokens not set**
- **Description:** Model invocations do not set the max_tokens parameter, allowing the model to generate arbitrarily long responses.
- **Rationale:** The max_tokens parameter is the primary guard against unbounded generation. Every model call should specify an appropriate maximum.

**AA-RB-045: Token budget allocation across components absent**
- **Description:** Token budgets are not allocated across context components (system prompt, history, retrieval, tools, output), allowing imbalanced consumption.
- **Rationale:** Component-level allocation ensures each part of the pipeline gets its required tokens without starving safety-critical components like the system prompt.

**AA-RB-046: Token usage monitoring not implemented**
- **Description:** Token consumption is not monitored in real-time, preventing detection of usage spikes, budget approaching, or anomalous patterns.
- **Rationale:** Real-time monitoring enables proactive intervention before budgets are exhausted and aids in detecting adversarial token consumption attacks.

**AA-RB-047: Token-expensive operations not flagged**
- **Description:** Operations that consume disproportionate tokens (large context retrieval, complex tool chains) are not flagged for review or approval.
- **Rationale:** Flagging expensive operations enables cost-aware decision making and prevents inadvertent budget exhaustion from routine operations.

**AA-RB-048: Token budget remaining not exposed to agent**
- **Description:** The agent has no visibility into its remaining token budget, preventing it from making budget-aware decisions about response length or tool usage.
- **Rationale:** Budget awareness enables agents to self-manage token consumption, prioritizing important information when the budget is low.

**AA-RB-049: Token budget per user not enforced**
- **Description:** Individual users do not have token budgets, allowing a single user to consume a disproportionate share of available tokens.
- **Rationale:** Per-user budgets ensure fair resource distribution and prevent individual users from monopolizing agent capacity.

**AA-RB-050: Token usage billing anomaly not detected**
- **Description:** Token usage billing is not monitored for anomalies such as sudden spikes, unusual patterns, or consumption outside business hours.
- **Rationale:** Billing anomalies can indicate compromise, abuse, or configuration errors. Automated detection enables rapid response to cost incidents.

---

## 6. Retry & Loop Detection (AA-RB-051 – AA-RB-060)

**Threat:** Agents can enter infinite loops, recursive retry cycles, or repetitive behavior patterns that consume resources without making progress. These can occur naturally through model behavior or be induced by adversarial inputs designed to trap the agent.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-051 | No maximum retry limit | CRITICAL | static | stable | langchain, crewai, openai |
| AA-RB-052 | Infinite loop detection absent | CRITICAL | dynamic | stable | langchain, autogen, crewai |
| AA-RB-053 | Tool call retry without backoff | HIGH | static | stable | langchain, openai, mcp |
| AA-RB-054 | Repetitive output detection missing | HIGH | dynamic | stable | langchain, openai, vercel-ai |
| AA-RB-055 | Recursive agent delegation unbounded | HIGH | dynamic | stable | crewai, autogen, langchain |
| AA-RB-056 | Self-referential task detection absent | MEDIUM | dynamic | stable | langchain, crewai, autogen |
| AA-RB-057 | Retry state not preserved across attempts | MEDIUM | static | stable | langchain, openai, crewai |
| AA-RB-058 | Retry budget not scoped per operation | MEDIUM | static | stable | langchain, openai, autogen |
| AA-RB-059 | Loop pattern fingerprinting not implemented | MEDIUM | dynamic | experimental | langchain, autogen, crewai |
| AA-RB-060 | Dead letter handling for failed retries absent | MEDIUM | both | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI09:** Loop and retry behavior directly impacts operational reliability
- **MITRE ATLAS AML.T0048:** Denial of AI service through induced loops
- **NIST AI RMF MANAGE-2.4:** Operational management of agent retry behavior

### Detailed Descriptions

**AA-RB-051: No maximum retry limit**
- **Description:** Failed operations are retried indefinitely without a maximum retry count, creating potential for infinite resource consumption.
- **Rationale:** Maximum retry limits prevent infinite retry loops. After exhausting retries, the agent should fail gracefully with clear error reporting.

**AA-RB-052: Infinite loop detection absent**
- **Description:** The agent has no mechanism to detect when it enters a loop producing the same or similar outputs repeatedly.
- **Rationale:** Loop detection compares recent actions against historical patterns to identify repetitive behavior that indicates the agent is stuck.

**AA-RB-053: Tool call retry without backoff**
- **Description:** Failed tool calls are retried immediately at full speed without exponential backoff, potentially overwhelming the target service.
- **Rationale:** Exponential backoff prevents retry storms that can cascade into denial-of-service for dependent services and waste agent resources.

**AA-RB-054: Repetitive output detection missing**
- **Description:** The agent generates substantially similar outputs across consecutive turns without detection, indicating a stuck or looping state.
- **Rationale:** Repetitive output detection catches generation loops where the model produces the same content repeatedly, a common failure mode.

**AA-RB-055: Recursive agent delegation unbounded**
- **Description:** Agents can delegate tasks to sub-agents which delegate further without depth limits, creating unbounded recursive chains.
- **Rationale:** Delegation depth limits prevent resource exhaustion through deep recursive agent chains, whether natural or adversarially induced.

**AA-RB-056: Self-referential task detection absent**
- **Description:** The agent does not detect when a task eventually delegates back to itself, creating a circular delegation loop.
- **Rationale:** Self-referential delegation creates infinite loops. Tracking the delegation chain enables detection of circular patterns before they consume resources.

**AA-RB-057: Retry state not preserved across attempts**
- **Description:** Retry attempts start from scratch rather than preserving state from previous attempts, wasting resources on redundant work.
- **Rationale:** State preservation across retries enables progressive refinement rather than redundant repetition, improving efficiency and convergence.

**AA-RB-058: Retry budget not scoped per operation**
- **Description:** A single global retry budget exists rather than per-operation budgets, allowing one failing operation to exhaust retries for all operations.
- **Rationale:** Per-operation retry budgets ensure one failing tool or API doesn't consume the retry budget needed by other operations.

**AA-RB-059: Loop pattern fingerprinting not implemented**
- **Description:** The system does not fingerprint action sequences to detect recurring patterns that indicate behavioral loops.
- **Rationale:** Pattern fingerprinting detects subtle loops where the exact sequence isn't identical but the behavioral pattern repeats.

**AA-RB-060: Dead letter handling for failed retries absent**
- **Description:** Operations that exhaust their retry budget are silently dropped without routing to a dead letter queue or alerting mechanism.
- **Rationale:** Dead letter handling ensures failed operations are captured for review, preventing silent data loss or missed critical actions.

---

## 7. Rate Limiting (AA-RB-061 – AA-RB-070)

**Threat:** Without rate limiting, agents can make excessive API calls, tool invocations, or downstream requests that overwhelm services, violate provider terms, or create denial-of-service conditions for other users.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-061 | No API call rate limiting | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-RB-062 | No tool invocation rate limiting | HIGH | static | stable | langchain, crewai, mcp |
| AA-RB-063 | Downstream service rate limits not respected | HIGH | dynamic | stable | langchain, openai, mcp |
| AA-RB-064 | Rate limit per user absent | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-RB-065 | Burst rate allowance not configured | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-RB-066 | Rate limit headers not parsed from upstream | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-067 | Rate limiting not applied to agent-to-agent calls | MEDIUM | static | stable | crewai, autogen, langchain |
| AA-RB-068 | Rate limit exhaustion notification absent | MEDIUM | dynamic | stable | langchain, openai, crewai |
| AA-RB-069 | Rate limiting bypass through tool multiplexing | MEDIUM | dynamic | experimental | langchain, crewai, mcp |
| AA-RB-070 | Rate limit configuration not externalized | MEDIUM | static | stable | langchain, openai, bedrock |

### Standards Mapping

- **ASI09:** Rate limiting prevents resource abuse and service degradation
- **OWASP Agentic AI Top 10 Principle 7:** Rate management for agent operations
- **MITRE ATLAS AML.T0048:** Preventing AI service denial through rate control

### Detailed Descriptions

**AA-RB-061: No API call rate limiting**
- **Description:** API calls to AI model providers have no rate limiting, allowing the agent to make unlimited API requests per time period.
- **Rationale:** API rate limiting prevents cost explosion, terms of service violations, and account suspension. All model API calls must respect configured rate limits.

**AA-RB-062: No tool invocation rate limiting**
- **Description:** Tool calls have no rate limiting, allowing the agent to invoke tools at unlimited frequency.
- **Rationale:** Tool rate limiting prevents resource exhaustion on tool backends and catches anomalous tool usage patterns that may indicate compromise.

**AA-RB-063: Downstream service rate limits not respected**
- **Description:** The agent does not parse or respect rate limit responses (429, Retry-After headers) from downstream services.
- **Rationale:** Respecting downstream rate limits prevents service bans, maintains good API citizenship, and ensures continued access to external services.

**AA-RB-064: Rate limit per user absent**
- **Description:** Individual users do not have rate limits, allowing a single user to consume disproportionate API and tool invocation capacity.
- **Rationale:** Per-user rate limits ensure fair access and prevent individual users from monopolizing agent resources through excessive request volume.

**AA-RB-065: Burst rate allowance not configured**
- **Description:** Rate limiting uses strict per-second limits without burst allowance, causing unnecessary throttling during legitimate usage spikes.
- **Rationale:** Token bucket or sliding window algorithms with burst allowance accommodate legitimate usage patterns while still preventing sustained abuse.

**AA-RB-066: Rate limit headers not parsed from upstream**
- **Description:** Rate limit response headers from upstream providers (X-RateLimit-Remaining, Retry-After) are not parsed and used for preemptive throttling.
- **Rationale:** Parsing upstream rate limit headers enables proactive throttling before hitting hard limits, preventing request failures and account penalties.

**AA-RB-067: Rate limiting not applied to agent-to-agent calls**
- **Description:** Inter-agent communication is not rate-limited, allowing cascading call storms in multi-agent systems.
- **Rationale:** Agent-to-agent rate limiting prevents cascade amplification where one agent's behavior triggers exponential calls across the agent network.

**AA-RB-068: Rate limit exhaustion notification absent**
- **Description:** No notification fires when rate limits are approaching exhaustion, preventing proactive intervention.
- **Rationale:** Exhaustion notifications enable preemptive action such as shedding load, scaling capacity, or investigating unusual consumption patterns.

**AA-RB-069: Rate limiting bypass through tool multiplexing**
- **Description:** The agent circumvents rate limits by distributing requests across multiple tools, accounts, or endpoints that achieve the same effect.
- **Rationale:** Rate limits must apply to the aggregate effect, not just individual endpoints. Multiplexing detection prevents bypass through distribution.

**AA-RB-070: Rate limit configuration not externalized**
- **Description:** Rate limit values are hardcoded rather than externalized to configuration, preventing runtime adjustment without redeployment.
- **Rationale:** Externalized rate limits enable rapid adjustment in response to incidents, load changes, or provider limit modifications.

---

## 8. Timeout Enforcement (AA-RB-071 – AA-RB-080)

**Threat:** Operations without timeouts can hang indefinitely, consuming resources and blocking agent capacity. Adversarial inputs can be designed to trigger long-running operations that tie up agent resources through slowloris-style attacks.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-071 | No request-level timeout | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-RB-072 | Tool call timeout absent | CRITICAL | static | stable | langchain, crewai, mcp |
| AA-RB-073 | Model API call timeout not configured | HIGH | static | stable | langchain, openai, bedrock |
| AA-RB-074 | External service call timeout missing | HIGH | static | stable | langchain, mcp, openai |
| AA-RB-075 | Database query timeout not set | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-RB-076 | File operation timeout absent | MEDIUM | static | stable | langchain, mcp, autogen |
| AA-RB-077 | Timeout cascade not handled | MEDIUM | static | stable | langchain, crewai, openai |
| AA-RB-078 | Timeout values not tuned per operation type | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-RB-079 | Timeout resource cleanup incomplete | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-RB-080 | No adaptive timeout adjustment | MEDIUM | dynamic | experimental | langchain, openai, bedrock |

### Standards Mapping

- **ASI09:** Timeout enforcement prevents resource starvation
- **NIST AI RMF MANAGE-2.4:** Operational timeout management for AI systems
- **OWASP Agentic AI Top 10 Principle 6:** Timeout bounds for operational safety

### Detailed Descriptions

**AA-RB-071: No request-level timeout**
- **Description:** Agent request processing has no overall timeout, allowing requests to run indefinitely and consume resources without progress.
- **Rationale:** Request-level timeouts are the top-level guard against hung operations. Every request must complete within a defined time or be terminated.

**AA-RB-072: Tool call timeout absent**
- **Description:** Individual tool calls have no timeout, allowing a single tool invocation to hang indefinitely.
- **Rationale:** Tool timeouts prevent a single unresponsive tool from blocking the entire agent. Each tool call should have a timeout appropriate to its expected duration.

**AA-RB-073: Model API call timeout not configured**
- **Description:** API calls to AI model providers do not have timeouts configured, relying on default (often very long) TCP timeouts.
- **Rationale:** Model API timeouts ensure agents can detect and recover from provider outages rather than hanging indefinitely.

**AA-RB-074: External service call timeout missing**
- **Description:** Calls to external services (webhooks, APIs, databases) lack explicit timeouts, creating dependency on external service responsiveness.
- **Rationale:** External service timeouts isolate the agent from dependency failures. Circuit breakers should complement timeouts for persistent failures.

**AA-RB-075: Database query timeout not set**
- **Description:** Database queries executed by agent tools have no timeout, allowing complex or poorly optimized queries to run indefinitely.
- **Rationale:** Query timeouts prevent runaway database operations from consuming connection pools and compute resources.

**AA-RB-076: File operation timeout absent**
- **Description:** File read/write operations have no timeout, allowing operations on slow or locked files to block agent processing.
- **Rationale:** File operation timeouts prevent blocking on network file systems, locked files, or intentionally slow storage.

**AA-RB-077: Timeout cascade not handled**
- **Description:** When a child operation times out, the parent operation does not properly handle the cascade, potentially leaving the agent in an inconsistent state.
- **Rationale:** Timeout cascades must be handled cleanly at each level, ensuring partial work is rolled back and resources are released.

**AA-RB-078: Timeout values not tuned per operation type**
- **Description:** A single timeout value is used for all operation types rather than operation-specific timeouts based on expected duration.
- **Rationale:** Different operations have different expected durations. Short timeouts for fast operations and longer ones for known slow operations optimize responsiveness.

**AA-RB-079: Timeout resource cleanup incomplete**
- **Description:** When operations timeout, associated resources (connections, file handles, child processes) are not fully cleaned up.
- **Rationale:** Incomplete cleanup after timeouts creates resource leaks that accumulate over time, eventually degrading agent performance or availability.

**AA-RB-080: No adaptive timeout adjustment**
- **Description:** Timeout values are static and do not adapt to observed latency patterns, causing false timeouts or insufficient protection.
- **Rationale:** Adaptive timeouts adjust based on recent performance data, optimizing between false timeout prevention and responsive failure detection.

---

## 9. Graceful Degradation (AA-RB-081 – AA-RB-090)

**Threat:** When components fail, agents that lack graceful degradation either crash completely or continue operating with silently reduced safety properties. Controlled degradation ensures agents maintain core safety guarantees even when capabilities are reduced.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-081 | No fallback behavior defined | CRITICAL | static | stable | langchain, crewai, openai |
| AA-RB-082 | Safety degradation on component failure | CRITICAL | dynamic | stable | langchain, openai, autogen |
| AA-RB-083 | Model fallback not configured | HIGH | static | stable | langchain, openai, bedrock |
| AA-RB-084 | Tool unavailability not handled gracefully | HIGH | static | stable | langchain, crewai, mcp |
| AA-RB-085 | Partial failure state not communicated to user | HIGH | dynamic | stable | langchain, openai, vercel-ai |
| AA-RB-086 | Circuit breaker pattern not implemented | MEDIUM | static | stable | langchain, openai, crewai |
| AA-RB-087 | Degradation level tracking absent | MEDIUM | dynamic | stable | langchain, openai, autogen |
| AA-RB-088 | Recovery from degraded state not automated | MEDIUM | dynamic | stable | langchain, crewai, openai |
| AA-RB-089 | Degradation testing not performed | MEDIUM | both | experimental | langchain, openai, bedrock |
| AA-RB-090 | Graceful shutdown procedure absent | MEDIUM | both | stable | langchain, crewai, autogen |

### Standards Mapping

- **ASI09:** Graceful degradation maintains safety during failures
- **ISO 23894 Clause 6.5:** Operational risk management for AI system failures
- **NIST AI RMF MANAGE-2.4:** AI system resilience and degradation management

### Detailed Descriptions

**AA-RB-081: No fallback behavior defined**
- **Description:** The agent has no defined fallback behavior for when primary capabilities (model, tools, services) become unavailable.
- **Rationale:** Fallback behavior ensures the agent can continue providing basic service or safely suspend rather than crashing or operating unpredictably.

**AA-RB-082: Safety degradation on component failure**
- **Description:** When agent components fail, safety mechanisms are silently bypassed rather than maintained or explicitly elevated.
- **Rationale:** Safety must be the last thing to degrade. When components fail, safety controls should be maintained or strengthened, never relaxed.

**AA-RB-083: Model fallback not configured**
- **Description:** No fallback model is configured for when the primary model is unavailable, causing complete agent failure during provider outages.
- **Rationale:** Model fallbacks maintain agent availability during provider outages. Fallback models should be tested for safety property preservation.

**AA-RB-084: Tool unavailability not handled gracefully**
- **Description:** When a required tool is unavailable, the agent either fails completely or attempts to proceed without the tool's capabilities.
- **Rationale:** Graceful tool unavailability handling either uses alternative approaches or clearly communicates the limitation to the user.

**AA-RB-085: Partial failure state not communicated to user**
- **Description:** When the agent operates in a degraded state, users are not informed about reduced capabilities or reliability.
- **Rationale:** Users must know when agent capabilities are degraded so they can adjust their expectations and take additional precautions.

**AA-RB-086: Circuit breaker pattern not implemented**
- **Description:** Repeated failures to external services do not trigger circuit breakers, allowing continued failed attempts that waste resources.
- **Rationale:** Circuit breakers prevent cascading failures by stopping requests to known-failed services, enabling faster recovery and resource preservation.

**AA-RB-087: Degradation level tracking absent**
- **Description:** The current degradation level of the agent is not tracked or exposed, preventing informed decisions about capability availability.
- **Rationale:** Degradation level tracking enables automated responses to progressive failure and provides visibility into agent health status.

**AA-RB-088: Recovery from degraded state not automated**
- **Description:** After entering a degraded state, the agent does not automatically attempt to restore full capability when failed components recover.
- **Rationale:** Automated recovery minimizes time in degraded state. Health checks on failed components enable prompt restoration when they recover.

**AA-RB-089: Degradation testing not performed**
- **Description:** The agent is not tested under various failure scenarios to verify graceful degradation behavior and safety preservation.
- **Rationale:** Chaos engineering for agent systems validates that degradation paths work as designed and safety properties are maintained under failure.

**AA-RB-090: Graceful shutdown procedure absent**
- **Description:** No defined procedure exists for gracefully shutting down the agent, risking data loss, abandoned operations, or inconsistent state.
- **Rationale:** Graceful shutdown ensures in-flight operations complete, state is persisted, and resources are released before the agent terminates.

---

## 10. Operational Bounds Monitoring (AA-RB-091 – AA-RB-100)

**Threat:** Without continuous monitoring of operational bounds, violations are detected only through their consequences (cost overruns, outages, security incidents). Proactive monitoring enables detection and intervention before bounds are breached.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-RB-091 | No operational metrics collection | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-RB-092 | Operational baseline not established | HIGH | dynamic | stable | langchain, crewai, openai |
| AA-RB-093 | Bounds violation alerting not configured | HIGH | dynamic | stable | langchain, openai, bedrock |
| AA-RB-094 | SLA monitoring for agent responses absent | MEDIUM | dynamic | stable | langchain, openai, vercel-ai |
| AA-RB-095 | Operational dashboard not available | MEDIUM | both | stable | langchain, openai, crewai |
| AA-RB-096 | Trend analysis for bound drift absent | MEDIUM | dynamic | experimental | langchain, openai, autogen |
| AA-RB-097 | Capacity planning data not collected | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-RB-098 | Operational audit trail incomplete | MEDIUM | static | stable | langchain, crewai, openai |
| AA-RB-099 | Incident response automation absent | MEDIUM | dynamic | experimental | langchain, openai, vercel-ai |
| AA-RB-100 | Post-incident bounds review not performed | MEDIUM | both | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI09:** Monitoring is essential for operational bounds enforcement
- **ISO 42001 A.9:** Performance monitoring for AI operational bounds
- **NIST AI RMF MEASURE-2.6:** Continuous measurement of AI operational metrics

### Detailed Descriptions

**AA-RB-091: No operational metrics collection**
- **Description:** The agent system does not collect operational metrics (latency, throughput, error rates, resource usage) needed for bounds monitoring.
- **Rationale:** Metrics collection is the foundation of operational monitoring. Without metrics, bounds violations cannot be detected or analyzed.

**AA-RB-092: Operational baseline not established**
- **Description:** No baseline exists for normal agent operational behavior, preventing identification of anomalous patterns that indicate bounds violations.
- **Rationale:** Baselines enable anomaly detection by defining what "normal" looks like. Deviations from baseline trigger investigation.

**AA-RB-093: Bounds violation alerting not configured**
- **Description:** When operational bounds are approached or violated, no alerts notify operations teams for intervention.
- **Rationale:** Alerting enables human intervention before bounds violations cause impact. Alerts should include context and recommended actions.

**AA-RB-094: SLA monitoring for agent responses absent**
- **Description:** Agent response time, availability, and quality SLAs are not monitored, preventing detection of degradation.
- **Rationale:** SLA monitoring ensures the agent meets its contractual and operational obligations, detecting degradation before user impact.

**AA-RB-095: Operational dashboard not available**
- **Description:** No centralized dashboard displays agent operational status, metrics, and bounds compliance in real-time.
- **Rationale:** Dashboards provide at-a-glance operational awareness, enabling rapid detection of issues and informed decision-making.

**AA-RB-096: Trend analysis for bound drift absent**
- **Description:** Operational metrics are not analyzed for trends that indicate gradual drift toward bounds violations.
- **Rationale:** Trend analysis catches slow degradation that per-request monitoring misses, enabling proactive capacity and configuration adjustments.

**AA-RB-097: Capacity planning data not collected**
- **Description:** Usage data needed for capacity planning (growth rates, peak patterns, resource utilization) is not collected or analyzed.
- **Rationale:** Capacity planning prevents operational bounds from being exceeded by growth, ensuring infrastructure scales ahead of demand.

**AA-RB-098: Operational audit trail incomplete**
- **Description:** The operational audit trail does not capture all significant events (bounds violations, configuration changes, incidents) needed for review.
- **Rationale:** Complete audit trails enable post-incident analysis, compliance verification, and identification of systemic operational issues.

**AA-RB-099: Incident response automation absent**
- **Description:** Bounds violations require manual intervention rather than triggering automated response playbooks.
- **Rationale:** Automated response reduces mean time to resolution for common bounds violations, limiting impact while human responders are engaged.

**AA-RB-100: Post-incident bounds review not performed**
- **Description:** After operational incidents, bounds configurations are not reviewed and adjusted based on lessons learned.
- **Rationale:** Post-incident review ensures bounds evolve with operational experience, tightening limits where needed and relaxing overly restrictive ones.
