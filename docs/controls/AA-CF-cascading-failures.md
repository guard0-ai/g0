# AA-CF: Cascading Failures

**Domain:** Cascading Failures
**Control Count:** 70
**Mapping:** OWASP ASI08 (Cascading Failures in Agentic Systems)
**Last Updated:** 2026-02-10

> [!IMPORTANT]
> **Control IDs in this document are specification IDs. They do not correspond
> to the scanner's rule IDs.** This framework and the shipped rule set were
> numbered independently, so the same identifier frequently names one control
> here and a different one in the scanner, and severity often differs too.
> For what a rule actually does, run `g0 rules describe <id>` or see
> [SHIPPED-RULES.md](SHIPPED-RULES.md), which is generated from source.
> Run `npm run docs:rules:check` to see the current divergence.

## Overview

Cascading failures occur when a fault in one component of an agentic system propagates through interconnected agents, tools, and services, causing widespread degradation or total system collapse. In multi-agent architectures, the tight coupling between agents, shared resources, and layered error handling creates fertile ground for failure amplification. This domain addresses the controls necessary to contain failures at their origin, prevent propagation across agent boundaries, limit blast radius, and ensure that resource consumption remains bounded even under adversarial or degraded conditions.

The 70 controls in this domain are organized into four sub-domains:

| Sub-Domain | Controls | Focus |
|---|---|---|
| Error Propagation | AA-CF-001 to AA-CF-020 | Preventing errors from spreading across agents and layers |
| Circuit Breakers | AA-CF-021 to AA-CF-035 | Automated failure detection, isolation, and rate limiting |
| Blast Radius Containment | AA-CF-036 to AA-CF-050 | Limiting the scope of damage from a compromised or failed agent |
| Resource Exhaustion | AA-CF-051 to AA-CF-070 | Preventing unbounded resource consumption |

---

## 1. Error Propagation (AA-CF-001 to AA-CF-020)

This sub-domain focuses on preventing errors that originate in one agent, tool call, or layer from propagating to other components in the system. In agentic architectures, error propagation is particularly dangerous because agents often operate autonomously, and a mishandled error can lead to cascading failures that are difficult to diagnose and recover from.

---

### AA-CF-001: Single Agent Failure Crashes Entire Multi-Agent System

**Severity:** CRITICAL
**Mode:** Both (static + dynamic)

**Description:**
A failure in a single agent (crash, unhandled exception, resource starvation) causes the entire multi-agent system to become unavailable. This occurs when agents are tightly coupled, share a single process or runtime, or when the orchestrator lacks fault tolerance and terminates all agents upon any individual failure.

**Rationale:**
Multi-agent systems must be resilient to individual agent failures. If the crash of one agent brings down the entire system, the architecture has a single point of failure. This violates the principle of fault isolation and makes the system fragile to any localized issue, whether caused by a bug, adversarial input, or transient infrastructure problem.

**Remediation:**
- Run each agent in an isolated process, container, or runtime environment so that a crash in one does not affect others.
- Implement an orchestrator that monitors individual agent health and can restart or replace failed agents without disrupting the rest of the system.
- Use process supervision (e.g., systemd, Kubernetes pod restart policies) to automatically recover failed agents.
- Design inter-agent communication to be asynchronous and fault-tolerant (e.g., message queues with dead-letter handling) rather than synchronous blocking calls.
- Test failure scenarios using chaos engineering techniques to verify that single agent failures are contained.

---

### AA-CF-002: Tool Error Causes Agent to Enter Undefined State

**Severity:** CRITICAL
**Mode:** Both (static + dynamic)

**Description:**
When a tool call fails (timeout, malformed response, unexpected error code), the agent does not handle the error gracefully and enters an undefined or inconsistent internal state. Subsequent actions by the agent may be unpredictable, incorrect, or dangerous because the agent's context, memory, or decision-making is corrupted.

**Rationale:**
Agents rely on tool calls for grounding, data retrieval, and action execution. Tool failures are inevitable (network issues, API changes, rate limits). If the agent does not handle these failures cleanly, it may operate on stale data, repeat actions incorrectly, or make decisions based on a corrupted understanding of the world. This is especially dangerous for agents with write access to external systems.

**Remediation:**
- Implement structured error handling for every tool call, ensuring the agent transitions to a known safe state on failure.
- Define explicit error states and recovery procedures for each tool the agent uses.
- Use a state machine or similar pattern for agent execution so that tool errors result in well-defined state transitions rather than undefined behavior.
- Validate tool responses before integrating them into agent state (schema validation, response code checks).
- Log all tool errors with sufficient context for debugging and include the agent's state at the time of failure.

---

### AA-CF-003: Agent Retries Failed Operation Infinitely

**Severity:** CRITICAL
**Mode:** Both (static + dynamic)

**Description:**
When a tool call or operation fails, the agent retries the operation without a maximum retry count, backoff strategy, or termination condition. This results in an infinite retry loop that consumes resources, may amplify the original problem (e.g., overwhelming an already degraded service), and prevents the agent from making progress or failing gracefully.

**Rationale:**
Retry logic is essential for handling transient errors, but unbounded retries are a well-known anti-pattern. In agentic systems, infinite retries are especially dangerous because the agent may not have visibility into why the operation is failing and may continue retrying an operation that will never succeed (e.g., invalid credentials, permanently deleted resource). The retry loop consumes tokens, API calls, and compute time, and can cascade to downstream services.

**Remediation:**
- Enforce a maximum retry count for all tool calls and operations (e.g., 3 retries with exponential backoff).
- Implement exponential backoff with jitter to avoid thundering herd effects on shared services.
- Distinguish between retryable (transient) and non-retryable (permanent) errors, and do not retry permanent failures.
- Set a total timeout for the retry sequence (wall-clock limit), not just per-attempt timeouts.
- After exhausting retries, the agent should fail gracefully: log the failure, notify the user or operator, and transition to a safe state.

---

### AA-CF-004: Agent Error Response Contains Stack Trace or Internal Information

**Severity:** CRITICAL
**Mode:** Both (static + dynamic)

**Description:**
When an error occurs, the agent includes internal implementation details in its response to the user, such as stack traces, file paths, database connection strings, internal API endpoints, environment variable values, or configuration details. This information leakage can be exploited by adversaries to map the system's architecture and identify vulnerabilities.

**Rationale:**
Information disclosure through error messages is a classic vulnerability (CWE-209). In agentic systems, the risk is amplified because agents may surface errors from multiple layers (LLM provider, tool APIs, databases, orchestrator) and may not sanitize error content before presenting it to the user. Adversaries can deliberately trigger errors to harvest internal information.

**Remediation:**
- Implement an error sanitization layer that strips internal details before returning error information to users.
- Use generic, user-friendly error messages for external-facing responses (e.g., "An error occurred processing your request" with a correlation ID).
- Log detailed error information (including stack traces) to internal logging systems only, not to user-facing outputs.
- Review all error handling paths to ensure no internal information leaks through agent responses, tool outputs, or metadata.
- Implement automated testing that triggers known error conditions and verifies that responses do not contain internal details.

---

### AA-CF-005: Agent Error Not Caught (Unhandled Exception Propagates)

**Severity:** CRITICAL
**Mode:** Both (static + dynamic)

**Description:**
An exception or error occurs during agent execution and is not caught by any error handler. The unhandled exception propagates up the call stack, potentially crashing the agent, the orchestrator, or the entire system. In multi-agent systems, unhandled exceptions in one agent can propagate through RPC calls or message queues to other agents.

**Rationale:**
Unhandled exceptions are one of the most common causes of system failures. In agentic systems, the dynamic nature of agent execution (tool calls with unpredictable responses, LLM outputs that may not conform to expected formats, external API failures) creates many opportunities for exceptions that developers did not anticipate. A single unhandled exception can bypass all other error handling logic.

**Remediation:**
- Implement top-level exception handlers in every agent process that catch all unhandled exceptions and transition the agent to a safe state.
- Use structured error handling (try/catch/finally) around all tool calls, LLM calls, and inter-agent communications.
- Implement a global exception handler at the orchestrator level to catch and contain exceptions from individual agents.
- Use static analysis tools to identify code paths that lack error handling.
- Monitor for unhandled exceptions in production and treat each occurrence as a high-priority bug.

---

### AA-CF-006: Error in One Tool Call Causes All Subsequent Tool Calls to Fail

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
When a tool call fails, the error state contaminates the agent's execution context such that all subsequent tool calls also fail, even if they are unrelated to the original failure. This can happen when tool call state is shared (e.g., a corrupted auth token reused across calls), when the agent's error handling sets a "failed" flag that prevents further tool use, or when the orchestrator stops routing tool calls after any failure.

**Rationale:**
Agents typically make multiple tool calls in a single task. If a failure in one tool call (e.g., a web search that times out) prevents the agent from using other tools (e.g., reading a file, querying a database), the agent's usefulness is severely degraded by a single transient error. This all-or-nothing failure mode is unnecessary and indicates poor isolation between tool calls.

**Remediation:**
- Ensure each tool call is executed with independent state (separate connections, tokens, error flags).
- Implement per-tool-call error handling that isolates failures and allows the agent to continue with other tools.
- Design the agent's execution flow so that a failed tool call results in a graceful degradation (skip or substitute) rather than a full stop.
- Test error isolation by injecting failures into individual tool calls and verifying that other tools remain functional.
- Avoid sharing mutable state across tool calls unless absolutely necessary, and if so, implement proper state recovery.

---

### AA-CF-007: Agent Continues Execution with Corrupted State After Error

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
After encountering an error, the agent continues execution but with corrupted or inconsistent internal state. For example, a partial write to the agent's memory, a half-processed tool response integrated into context, or a corrupted conversation history. The agent's subsequent decisions are based on this corrupted state, leading to incorrect outputs or dangerous actions.

**Rationale:**
Silent corruption is more dangerous than a crash because the agent appears to be functioning normally while making decisions based on incorrect information. This is especially dangerous for agents that take actions in the real world (sending emails, modifying databases, making API calls) because the corrupted state may lead to actions that are difficult to detect and reverse.

**Remediation:**
- Implement state integrity checks after error recovery (checksums, invariant validation, schema validation on agent memory).
- Use transactional semantics for state updates: either fully commit a change or fully roll it back.
- After an error, re-validate the agent's context and memory before continuing execution.
- Consider a "clean restart" approach for severe errors rather than attempting to recover from a potentially corrupted state.
- Log the agent's state before and after errors to support forensic analysis.

---

### AA-CF-008: Error Cascades Through Delegation Chain

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
In systems where agents delegate tasks to sub-agents, an error in a sub-agent propagates up the delegation chain and causes the parent agent (and potentially the entire chain) to fail. The parent agent does not handle sub-agent failures gracefully, treating any sub-agent error as a fatal condition for its own execution.

**Rationale:**
Delegation chains are common in complex multi-agent systems (e.g., a planning agent delegates to a research agent, which delegates to a web search agent). If errors cascade up the chain without containment, a single failure at any level can take down the entire workflow. This creates a fragile architecture where reliability decreases as delegation depth increases.

**Remediation:**
- Each agent in a delegation chain should handle sub-agent failures independently and decide whether to retry, use a fallback, or report a partial result.
- Implement timeout and error handling at each delegation boundary.
- Define error contracts between agents (what errors can be returned and what they mean) so that parent agents can make informed decisions about sub-agent failures.
- Consider circuit breaker patterns at delegation boundaries to prevent repeated delegation to a failing sub-agent.
- Test delegation chains with failures injected at each level to verify containment.

---

### AA-CF-009: Error in Background Task Surfaces in Unrelated Request

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
An error that occurs in a background task (async operation, scheduled job, pre-fetch) leaks into the processing of an unrelated user request. This can happen through shared state, global error flags, contaminated caches, or shared connection pools. The user receives an error or incorrect response for a request that should have been unaffected.

**Rationale:**
Agents often perform background tasks (caching, pre-computation, health checks). If errors in these tasks affect request processing, users experience unpredictable failures that are difficult to reproduce and diagnose. This also creates a vulnerability where an adversary could trigger background errors to disrupt unrelated users' requests.

**Remediation:**
- Isolate background task execution from request processing (separate threads, processes, or error scopes).
- Ensure background task errors are handled and logged independently without modifying shared request-processing state.
- Use separate connection pools, caches, and state stores for background tasks and request processing where feasible.
- Implement health checks that verify background task status without affecting request processing.
- Test error isolation by injecting failures in background tasks and verifying that concurrent requests are unaffected.

---

### AA-CF-010: Timeout in One Agent Blocks All Dependent Agents

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
A timeout in one agent (waiting for a tool call, LLM response, or external API) causes all agents that depend on it to block indefinitely or until their own timeouts expire. In systems with synchronous inter-agent communication, a slow agent becomes a bottleneck that freezes the entire pipeline.

**Rationale:**
Timeouts are a common failure mode, especially with external dependencies (LLM APIs, third-party services). If dependent agents block on a timed-out agent without their own timeout and fallback logic, the timeout propagates through the system, effectively creating a system-wide hang. This is a denial-of-service risk, whether caused by infrastructure issues or adversarial manipulation.

**Remediation:**
- Set explicit timeouts for all inter-agent communications, tool calls, and external API calls.
- Ensure that each agent has its own timeout that is shorter than or independent of its dependencies' timeouts.
- Implement asynchronous communication between agents (message queues, event-driven patterns) rather than synchronous blocking calls.
- Define fallback behavior for when a dependency times out (use cached data, return partial results, skip optional steps).
- Monitor inter-agent latency and alert when agents approach timeout thresholds.

---

### AA-CF-011: Partial Failure Not Handled (All-or-Nothing Without Rollback)

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
When an agent is performing a multi-step operation and one step fails, the agent neither completes the remaining steps nor rolls back the already-completed steps. The system is left in an inconsistent state where some actions have been taken and others have not, with no mechanism to reconcile the partial progress.

**Rationale:**
Multi-step operations are common in agentic workflows (e.g., create a database record, send a notification, update a dashboard). If the notification step fails, the database record exists but the dashboard is not updated and no notification was sent. Without rollback or compensation logic, these partial failures create data inconsistencies that may be difficult to detect and correct.

**Remediation:**
- Implement the Saga pattern or compensating transactions for multi-step operations: if a step fails, execute compensation actions for all completed steps.
- Design operations to be idempotent so that retrying after partial failure does not create duplicates or inconsistencies.
- Record the progress of multi-step operations so that an operator or recovery process can resume from the point of failure.
- For critical operations, implement a two-phase commit or similar protocol to ensure atomicity.
- Provide tooling for operators to manually reconcile partial failures when automated recovery is not possible.

---

### AA-CF-012: Error Recovery Changes Agent Behavior (Post-Error Drift)

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
After recovering from an error, the agent's behavior subtly changes from its pre-error behavior. This can happen because the error recovery path sets different defaults, modifies the agent's context or instructions, or because the recovery code path has different logic than the normal code path. The agent may become more conservative, more permissive, or behave differently in ways that are not immediately apparent.

**Rationale:**
Behavioral drift after error recovery is insidious because the agent appears to be functioning normally but is actually operating with different parameters or logic. This can lead to security issues (more permissive behavior), quality issues (different decision-making), or operational issues (unexpected resource usage). It also complicates debugging because the behavior change may not be correlated with the original error.

**Remediation:**
- Implement automated behavioral validation after error recovery: compare the agent's configuration, permissions, and behavior against the expected baseline.
- Use immutable configuration: after error recovery, reload the agent's configuration from the canonical source rather than attempting to restore from potentially corrupted in-memory state.
- Test error recovery paths to verify that the agent's behavior matches its pre-error behavior (regression tests for error recovery).
- Log the agent's configuration state before and after error recovery to detect drift.
- Implement periodic behavioral health checks that compare agent behavior against the declared baseline.

---

### AA-CF-013: Error Logging Fails Silently (Errors Lost)

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
The error logging system itself fails (disk full, logging service unavailable, malformed log entry) and the failure is not detected. Errors that should have been logged are silently lost, making it impossible to diagnose issues, detect attacks, or meet audit requirements. The system continues operating without any indication that error visibility has been lost.

**Rationale:**
Error logs are the primary source of truth for understanding system behavior, diagnosing issues, and detecting security incidents. If errors are silently lost, operators lose visibility into system health, security teams cannot detect attack patterns, and compliance requirements for audit trails are violated. The silent nature of the failure means the gap may not be discovered until a post-incident investigation.

**Remediation:**
- Implement health checks for the logging pipeline (can the logger write? is the logging service reachable? is there sufficient storage?).
- Use a fallback logging mechanism (e.g., local file, stderr) when the primary logging system is unavailable.
- Monitor the logging pipeline for gaps (expected log volume vs. actual log volume).
- Implement alerting when the logging system is degraded or unavailable.
- Use log sequence numbers or timestamps to detect missing entries.

---

### AA-CF-014: Agent Enters Retry Loop That Amplifies the Original Problem

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
The agent's retry logic amplifies the original problem rather than resolving it. For example, retrying a request to an overloaded service increases the load on that service, retrying a database write that caused a constraint violation creates more constraint violations, or retrying a rate-limited API call causes the rate limit window to extend.

**Rationale:**
Naive retry logic is one of the most common causes of cascading failures in distributed systems. In agentic systems, the risk is amplified because agents may not understand why an operation failed and may retry operations that should not be retried. The retry amplification effect can turn a minor, transient issue into a system-wide outage.

**Remediation:**
- Implement exponential backoff with jitter for all retries to reduce the amplification effect.
- Classify errors into retryable and non-retryable categories and only retry retryable errors.
- Implement a circuit breaker that stops retries when a service is clearly degraded.
- Set a maximum number of retries and a maximum total retry duration.
- Monitor retry rates and alert when they exceed normal levels (indicating a systemic issue).

---

### AA-CF-015: Error in Data Parsing Causes Agent to Process Corrupt Data

**Severity:** HIGH
**Mode:** Both (static + dynamic)

**Description:**
An error during data parsing (JSON parsing, CSV parsing, HTML scraping, API response deserialization) is handled by using partial, default, or malformed data rather than rejecting the input entirely. The agent proceeds with corrupted data, making decisions and taking actions based on incorrect information.

**Rationale:**
Data parsing errors are common when agents interact with external APIs, web pages, or user-provided data. If the agent uses partially parsed or corrupt data, the downstream effects can be severe: incorrect calculations, wrong recommendations, actions taken on behalf of the wrong user, or data written to databases in the wrong format. The "fail-open on parse error" anti-pattern is especially dangerous for agents with write access to external systems.

**Remediation:**
- Validate parsed data against a schema or expected structure before using it (strict validation, not best-effort).
- Treat parse errors as failures: do not proceed with partial or default data unless explicitly designed to do so with appropriate safeguards.
- Log parse errors with the raw input data for debugging (being careful not to log sensitive data).
- Implement data quality checks downstream of parsing to catch corruption that passes initial validation.
- Use well-tested parsing libraries and keep them updated to handle edge cases and malformed inputs.

---

### AA-CF-016: Concurrent Errors Cause Race Conditions

**Severity:** MEDIUM
**Mode:** Both (static + dynamic)

**Description:**
When multiple errors occur concurrently (e.g., two tool calls fail at the same time, multiple agents encounter errors simultaneously), the error handling logic has race conditions that lead to inconsistent state, duplicate error responses, lost error information, or deadlocks. This occurs when error handling code accesses shared state without proper synchronization.

**Rationale:**
Concurrent errors are common in multi-agent systems and in agents that make parallel tool calls. If the error handling code is not thread-safe or does not handle concurrent access correctly, the error recovery itself becomes a source of failures. Race conditions in error handling are particularly difficult to reproduce and debug.

**Remediation:**
- Design error handling to be thread-safe: use locks, atomic operations, or lock-free data structures for shared error state.
- Test error handling under concurrent error conditions (concurrent failure injection).
- Use an error aggregation pattern that collects errors from multiple concurrent operations and handles them as a batch.
- Avoid shared mutable state in error handling paths where possible.
- Implement timeouts on locks used in error handling to prevent deadlocks.

---

### AA-CF-017: Error Handling Code Itself Has Vulnerabilities

**Severity:** MEDIUM
**Mode:** Both (static + dynamic)

**Description:**
The code that handles errors contains its own vulnerabilities: SQL injection in error logging, path traversal in error file writing, command injection in error notification scripts, or buffer overflows in error message formatting. An adversary can deliberately trigger errors to exploit vulnerabilities in the error handling path.

**Rationale:**
Error handling code is often less thoroughly tested and reviewed than the main code path, yet it is invoked precisely when the system is in a vulnerable state. If the error handling code itself has vulnerabilities, an attacker can weaponize error conditions to achieve code execution, data exfiltration, or denial of service. The error handling path may also run with elevated privileges (to access logging systems, send notifications), increasing the impact of any vulnerability.

**Remediation:**
- Apply the same security review, testing, and coding standards to error handling code as to the main code path.
- Sanitize all inputs used in error handling (log messages, error file paths, notification parameters).
- Use parameterized queries for error logging to databases, not string concatenation.
- Review error handling code for common vulnerability patterns (injection, path traversal, buffer overflow).
- Include error handling paths in security testing and penetration testing scope.

---

### AA-CF-018: Agent Does Not Distinguish Between Transient and Permanent Errors

**Severity:** MEDIUM
**Mode:** Both (static + dynamic)

**Description:**
The agent treats all errors the same, regardless of whether they are transient (network timeout, rate limit, temporary service unavailability) or permanent (invalid credentials, resource not found, permission denied). This leads to retrying permanent errors (wasting resources) or not retrying transient errors (failing unnecessarily).

**Rationale:**
The appropriate response to an error depends heavily on its nature. Transient errors should be retried with backoff; permanent errors should be reported immediately. If the agent cannot distinguish between these categories, it will either waste resources retrying operations that will never succeed or fail unnecessarily on operations that would succeed on retry. This misclassification also makes cascading failures more likely.

**Remediation:**
- Implement error classification logic that categorizes errors as transient or permanent based on error codes, response headers, and error types.
- Define retry policies that differ based on error classification (retry transient errors, fail fast on permanent errors).
- Maintain a mapping of known error codes to categories for each tool and external service.
- For unknown errors, default to a conservative retry strategy (limited retries with backoff) rather than infinite retry or immediate failure.
- Monitor and review error classifications periodically to ensure they remain accurate as dependencies change.

---

### AA-CF-019: Error Messages from One Layer Misinterpreted by Another

**Severity:** MEDIUM
**Mode:** Both (static + dynamic)

**Description:**
Error messages or error codes from one layer of the system (e.g., a database, an external API, the operating system) are passed through to another layer without translation and are misinterpreted. For example, an HTTP 429 (rate limited) from an external API is interpreted as a 429 from the agent's own API and triggers inappropriate rate limiting behavior. Or a database error code is misinterpreted as a tool call error code.

**Rationale:**
Multi-layered architectures create opportunities for error misinterpretation when error codes and messages from different systems use different conventions. In agentic systems, errors flow through multiple layers (external API, tool wrapper, agent runtime, orchestrator, user interface), and each layer may interpret the same error differently. Misinterpretation can lead to incorrect error handling, masking of the real issue, or cascading failures.

**Remediation:**
- Implement error translation at each layer boundary: convert errors from the lower layer into the error vocabulary of the current layer.
- Do not pass raw error codes or messages through multiple layers without translation.
- Define a clear error taxonomy for each layer with explicit mapping from dependency errors.
- Include the original error context as metadata (for debugging) while using translated error codes for decision-making.
- Test error handling at layer boundaries with errors from each possible source.

---

### AA-CF-020: System-Wide Error Threshold Not Monitored

**Severity:** MEDIUM
**Mode:** Both (static + dynamic)

**Description:**
The system does not monitor the aggregate error rate across all agents and services. While individual errors may be handled correctly, a spike in the overall error rate (indicating a systemic issue) goes undetected. Operators do not have visibility into the system's overall health from an error perspective.

**Rationale:**
Individual error handling is necessary but not sufficient. A systemic issue (infrastructure degradation, upstream service failure, configuration error) may manifest as many individual errors that are each handled correctly but collectively indicate a critical problem. Without system-wide error rate monitoring, operators may not realize the system is in a degraded state until users report widespread failures.

**Remediation:**
- Implement system-wide error rate monitoring that aggregates errors across all agents, tools, and services.
- Define error rate thresholds (e.g., >5% error rate over 5 minutes) and alert operators when thresholds are exceeded.
- Create dashboards that visualize error rates over time, broken down by agent, tool, error type, and severity.
- Implement automated responses to high error rates (e.g., circuit breakers, traffic shedding, failover).
- Conduct regular reviews of error rate trends to identify and address systemic issues proactively.

---

## 2. Circuit Breakers (AA-CF-021 to AA-CF-035)

This sub-domain covers the automated mechanisms that detect failures, prevent failure propagation, and enforce rate limits to protect system stability. Circuit breakers and rate limiters are essential defense mechanisms that prevent cascading failures by cutting off failing pathways and limiting the rate of operations.

---

### AA-CF-021: No Circuit Breaker Between Agents

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no circuit breaker mechanism between communicating agents. When one agent starts failing, other agents continue sending requests to it at full rate, overwhelming the failing agent and potentially causing cascading failures throughout the system.

**Rationale:**
In multi-agent systems, agents depend on each other for data, computation, and action execution. Without circuit breakers, a failing agent receives a flood of requests from dependent agents, preventing it from recovering while also consuming resources in the calling agents (blocked threads, timeout waits). The circuit breaker pattern is a well-established resilience mechanism that prevents this cascading failure mode.

**Remediation:**
- Implement circuit breakers at every inter-agent communication boundary.
- Configure circuit breakers with appropriate thresholds (failure count, failure rate, timeout rate) for each agent-to-agent relationship.
- Define fallback behavior for when a circuit breaker is open (return cached data, use an alternative agent, return a degraded response).
- Monitor circuit breaker state transitions and alert operators when circuit breakers trip.
- Test circuit breaker behavior under simulated agent failures.

---

### AA-CF-022: No Circuit Breaker Between Agent and External APIs

**Severity:** HIGH
**Mode:** Static

**Description:**
Agents make calls to external APIs (LLM providers, search engines, databases, SaaS services) without circuit breaker protection. When an external API becomes degraded or unavailable, the agent continues making requests, accumulating timeouts, wasting resources, and potentially incurring unnecessary costs.

**Rationale:**
External APIs are outside the control of the agentic system and are subject to outages, rate limiting, degradation, and unexpected behavior changes. Without circuit breakers, agents blindly send requests to degraded services, resulting in slow responses, resource consumption, and potential cost overruns (especially with metered APIs). Circuit breakers allow agents to fail fast and use fallback mechanisms rather than waiting for inevitable timeouts.

**Remediation:**
- Implement circuit breakers for every external API integration.
- Configure appropriate thresholds based on each API's SLA and historical performance.
- Implement fallback behavior for each external API (cached responses, alternative providers, graceful degradation).
- Monitor external API health independently and pre-emptively open circuit breakers when APIs are known to be degraded.
- Include external API circuit breakers in system health dashboards.

---

### AA-CF-023: No Circuit Breaker for Database Connections

**Severity:** HIGH
**Mode:** Static

**Description:**
Agents access databases without circuit breaker protection. When a database becomes slow or unavailable, agents continue attempting connections and queries, exhausting connection pools, accumulating blocked threads, and preventing recovery.

**Rationale:**
Database issues (connection limit reached, slow queries, replication lag, failover in progress) are common in production systems. Without circuit breakers, agents hold open connections, retry failed queries, and exhaust connection pools, which can prevent the database from recovering and affect all other consumers of the same database. This is a classic cascading failure pattern in distributed systems.

**Remediation:**
- Implement circuit breakers around database connection acquisition and query execution.
- Configure connection pool limits and timeouts in addition to circuit breakers.
- Define fallback behavior for database unavailability (read from cache, queue writes for later, return partial results).
- Monitor database health metrics (connection count, query latency, error rate) and use them to inform circuit breaker thresholds.
- Test database failover scenarios to verify that circuit breakers function correctly.

---

### AA-CF-024: Circuit Breaker Threshold Too High (Trips Too Late)

**Severity:** HIGH
**Mode:** Static

**Description:**
Circuit breakers are implemented but their thresholds are set too high (e.g., 100 failures before tripping, 95% error rate threshold). By the time the circuit breaker trips, significant damage has already occurred: resources have been consumed, timeouts have accumulated, users have experienced failures, and the downstream service has been further degraded by continued requests.

**Rationale:**
A circuit breaker that trips too late provides little protection. The purpose of a circuit breaker is to detect a failure trend early and stop sending requests before the situation worsens. If the threshold is too high, the circuit breaker is essentially useless for preventing cascading failures because the cascade has already occurred by the time it trips.

**Remediation:**
- Analyze historical failure patterns to set appropriate circuit breaker thresholds for each dependency.
- Use failure rate thresholds (percentage) rather than absolute counts, which are more responsive to sudden degradation.
- Consider using sliding window metrics rather than fixed-window counts.
- Start with conservative (lower) thresholds and increase them based on operational experience.
- Implement different thresholds for different failure types (timeouts may warrant lower thresholds than error responses).

---

### AA-CF-025: Circuit Breaker Does Not Notify Operators When Tripped

**Severity:** HIGH
**Mode:** Static

**Description:**
When a circuit breaker trips (transitions from closed to open state), no notification is sent to operators. The system silently enters a degraded state, and operators only discover the issue when users report problems or when they happen to check dashboards.

**Rationale:**
Circuit breakers tripping indicates that a dependency is failing. While the circuit breaker prevents cascading failures, operators need to be aware that the system is in a degraded state so they can investigate the root cause, communicate with stakeholders, and take corrective action. Silent circuit breaker trips can lead to prolonged degraded operation without investigation.

**Remediation:**
- Configure alerts for circuit breaker state transitions (closed to open, open to half-open, half-open to closed/open).
- Include relevant context in alerts: which dependency failed, the failure rate, the impact on functionality.
- Route circuit breaker alerts to the appropriate on-call team.
- Create runbooks for each circuit breaker that describe the impact and recommended investigation steps.
- Monitor circuit breaker trip frequency as a system health metric.

---

### AA-CF-026: No Fallback Behavior When Circuit Breaker Is Open

**Severity:** HIGH
**Mode:** Static

**Description:**
When a circuit breaker trips and enters the open state, requests to the protected dependency simply fail with an error. There is no fallback behavior defined (cached responses, alternative providers, graceful degradation). Users experience a hard failure for any functionality that depends on the tripped circuit breaker.

**Rationale:**
Circuit breakers are only half the resilience story. The other half is defining what happens when the circuit is open. Without fallback behavior, a circuit breaker merely converts slow failures (timeouts) into fast failures (immediate errors), which is better but still results in user-facing failures. Well-designed fallback behavior can maintain partial functionality even when a dependency is unavailable.

**Remediation:**
- Define fallback behavior for every circuit breaker (what should the agent do when this dependency is unavailable?).
- Implement caching strategies for read operations so that cached data can be served when the circuit is open.
- Identify alternative providers or services that can substitute for the primary dependency.
- Design graceful degradation paths that clearly communicate to users what functionality is limited and why.
- Test fallback behavior regularly (do not wait for a real outage to discover that fallbacks do not work).

---

### AA-CF-027: Circuit Breaker State Shared Across Unrelated Workflows

**Severity:** HIGH
**Mode:** Static

**Description:**
A single circuit breaker instance is shared across unrelated workflows or agent types. When the circuit breaker trips due to failures in one workflow, all other workflows that use the same dependency are also blocked, even if the failures are specific to one workflow (e.g., a specific query pattern, a specific data set).

**Rationale:**
Shared circuit breakers create unnecessary coupling between unrelated workflows. A failure in one workflow should not block other workflows from accessing the same dependency if their access patterns are different. This over-broad failure containment reduces the system's overall availability unnecessarily.

**Remediation:**
- Implement separate circuit breaker instances for different workflows, agent types, or access patterns.
- Use circuit breaker scoping strategies (per-endpoint, per-operation-type, per-workflow) appropriate to the dependency.
- Monitor circuit breaker metrics per scope to identify which workflows are affected by failures.
- Consider using bulkhead patterns in conjunction with circuit breakers to isolate resource consumption per workflow.
- Document the circuit breaker scope for each dependency and review it periodically.

---

### AA-CF-028: Circuit Breaker Resets Too Quickly (Allows Repeated Failures)

**Severity:** HIGH
**Mode:** Static

**Description:**
After a circuit breaker trips, it resets to the half-open state too quickly, allowing test requests through before the underlying issue has resolved. The test requests fail, the circuit breaker re-trips, and the cycle repeats, creating a "flapping" pattern that generates excessive alerts, wastes resources on test requests, and may prevent the downstream service from recovering.

**Rationale:**
Circuit breaker reset timing is critical. If the reset is too fast, the circuit breaker flaps between open and half-open states, generating noise and potentially interfering with the recovery of the downstream service. The reset period should be long enough for the downstream service to recover but short enough that recovery is detected promptly.

**Remediation:**
- Configure circuit breaker reset timeouts based on the typical recovery time of each dependency.
- Implement progressive reset timeouts: increase the reset timeout each time the circuit breaker re-trips (similar to exponential backoff).
- Use health check endpoints (if available) to inform circuit breaker reset decisions rather than relying solely on timers.
- Monitor circuit breaker flapping (rapid open/half-open/open transitions) and alert when it occurs.
- Cap the maximum reset timeout to prevent indefinite circuit opening.

---

### AA-CF-029: No Backoff Policy for Retried Operations

**Severity:** MEDIUM
**Mode:** Static

**Description:**
When operations are retried (either manually or automatically), there is no backoff policy governing the retry timing. Retries are immediate or at a fixed interval, which can overwhelm recovering services, cause thundering herd effects when multiple agents retry simultaneously, and extend outage duration.

**Rationale:**
Backoff policies (exponential backoff with jitter) are essential for well-behaved retry logic. Without backoff, retries from multiple agents converge on the same timing, creating synchronized bursts of traffic that overwhelm recovering services. Immediate retries are essentially no different from a continuous request stream from the perspective of the downstream service.

**Remediation:**
- Implement exponential backoff for all retry operations (doubling the wait time between retries).
- Add jitter (randomized delay) to backoff to prevent thundering herd effects when multiple agents retry simultaneously.
- Set a maximum backoff interval to cap the wait time.
- Document the backoff policy for each dependency and ensure it is consistently applied.
- Monitor retry timing to verify that backoff is functioning correctly.

---

### AA-CF-030: Rate Limit on Agent Actions Not Configured

**Severity:** MEDIUM
**Mode:** Static

**Description:**
There is no rate limit on the actions an agent can perform per unit of time. An agent can make an unlimited number of tool calls, API requests, or state changes, limited only by the speed of execution. This allows runaway agents, bugs, or adversarial inputs to cause excessive resource consumption and downstream service overload.

**Rationale:**
Rate limiting is a fundamental safety mechanism for any automated system. Without rate limits, a malfunctioning or compromised agent can execute actions at machine speed, potentially causing significant damage before human operators can intervene. Rate limits provide a speed limit that constrains the blast radius of any agent malfunction.

**Remediation:**
- Define and enforce rate limits for each agent type based on expected normal usage patterns.
- Implement rate limits at the agent framework level (before tool calls are executed) so they cannot be bypassed.
- Configure different rate limits for different action types (higher limits for reads, lower limits for writes).
- Log and alert when rate limits are approached or exceeded.
- Review rate limits periodically based on actual usage patterns.

---

### AA-CF-031: Rate Limit Per User/Session Not Configured

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Rate limits are not applied on a per-user or per-session basis. A single user or session can consume the entire system's capacity, denying service to other users. Alternatively, rate limits are only applied globally, so a single abusive user can cause the global rate limit to be reached, blocking all users.

**Rationale:**
Per-user/session rate limiting is essential for fair resource sharing and for preventing abuse by individual users. Without per-user rate limits, a single user (whether intentionally abusive or triggering an agent bug) can monopolize system resources. Global-only rate limits penalize all users equally, even those behaving normally.

**Remediation:**
- Implement per-user and per-session rate limits in addition to global rate limits.
- Set per-user rate limits based on user role, subscription tier, or expected usage patterns.
- Implement per-user rate limit headers in API responses so users can track their usage.
- Alert operators when individual users repeatedly hit rate limits (potential abuse indicator).
- Ensure rate limit keys are robust to manipulation (e.g., cannot bypass by changing session IDs).

---

### AA-CF-032: Global Rate Limit Across All Agents Not Configured

**Severity:** MEDIUM
**Mode:** Static

**Description:**
There is no global rate limit governing the total number of actions across all agents in the system. While individual agents may have rate limits, the aggregate action rate across all agents is unbounded, allowing the system as a whole to overwhelm downstream services, exceed budget thresholds, or consume infrastructure resources excessively.

**Rationale:**
In systems with many agents, even if each individual agent is rate-limited, the aggregate load can be significant. Global rate limits protect downstream services and infrastructure from the combined load of all agents, ensure that total system costs remain within budget, and prevent runaway scaling of agent actions.

**Remediation:**
- Implement a global rate limiter that governs the total action rate across all agents.
- Set the global rate limit based on downstream service capacity, budget constraints, and infrastructure limits.
- Implement fair queuing or priority scheduling when the global rate limit is reached so that high-priority agents are not blocked by lower-priority ones.
- Monitor global action rates and alert when they approach the global limit.
- Review and adjust the global rate limit as the system scales.

---

### AA-CF-033: Rate Limit Bypass Possible via Tool Chaining

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Rate limits can be circumvented by chaining tool calls in a way that each individual call is within limits, but the aggregate effect exceeds the intended rate. For example, an agent calls tool A which calls tool B, and the rate limit only applies to direct calls to tool B, not indirect calls through tool A. Or an agent uses multiple different tools to achieve the same effect, bypassing a rate limit on any single tool.

**Rationale:**
Rate limits must account for indirect access patterns. If rate limits only apply at one layer or for direct access, they can be bypassed through indirection. In agentic systems, tool chaining and multi-tool workflows are common, creating many opportunities for rate limit bypass.

**Remediation:**
- Apply rate limits at the action level (what is being done) rather than the tool level (which tool is being used).
- Implement rate limits at multiple layers (agent level, tool level, downstream service level) to catch bypasses.
- Analyze tool chaining patterns to identify potential rate limit bypasses.
- Monitor for anomalous patterns that might indicate rate limit circumvention.
- Consider implementing semantic rate limits (e.g., "no more than 10 emails per minute regardless of how they are sent").

---

### AA-CF-034: Rate Limit Not Enforced Consistently Across Agent Instances

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Rate limits are implemented locally within each agent instance but are not coordinated across instances. When agents are scaled horizontally (multiple instances of the same agent), each instance has its own rate limit counter, so the effective rate limit is multiplied by the number of instances. This can lead to downstream service overload when agents are scaled up.

**Rationale:**
In horizontally scaled systems, local rate limits do not provide true rate limiting. If each of 10 agent instances has a rate limit of 100 requests per minute, the actual rate to the downstream service is 1,000 requests per minute. This discrepancy becomes more severe as the system scales and can lead to unexpected downstream failures during scaling events.

**Remediation:**
- Implement distributed rate limiting using a shared counter (e.g., Redis, distributed cache, centralized rate limit service).
- Ensure the distributed rate limit is the source of truth, not per-instance counters.
- Test rate limit enforcement under scaled conditions (multiple instances running simultaneously).
- Monitor actual downstream request rates (not just per-instance rates) to verify rate limit effectiveness.
- Account for rate limit coordination latency in threshold settings.

---

### AA-CF-035: No Alert When Rate Limits Are Approached or Hit

**Severity:** MEDIUM
**Mode:** Static

**Description:**
There is no alerting configured for when rate limits are approached (e.g., at 80% of the limit) or exceeded. Operators have no visibility into rate limit utilization and only discover rate limit issues when they cause visible failures or user complaints.

**Rationale:**
Rate limit utilization is an important operational metric. Approaching a rate limit may indicate increased load, a malfunctioning agent, or an abuse attempt. Without alerts, operators cannot proactively address these situations. Rate limit violations should be treated as incidents that require investigation.

**Remediation:**
- Configure alerts at warning thresholds (e.g., 80% of rate limit) and critical thresholds (100% of rate limit).
- Include context in alerts: which agent, which user, which endpoint, current rate, limit value.
- Create dashboards that visualize rate limit utilization across all agents and endpoints.
- Log all rate limit violations with sufficient context for investigation.
- Define response procedures for rate limit alerts (investigate root cause, adjust limits if appropriate, block abusive users).

---

## 3. Blast Radius Containment (AA-CF-036 to AA-CF-050)

This sub-domain addresses the controls necessary to limit the scope of damage when an agent is compromised, fails, or behaves unexpectedly. The goal is to ensure that the impact of any single agent issue is confined to the smallest possible scope and does not spread to other agents, shared resources, or infrastructure.

---

### AA-CF-036: Compromised Agent Can Access All Other Agents' Resources

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
A compromised agent (through prompt injection, tool exploitation, or other attack) can access resources belonging to other agents, including their data stores, configuration, credentials, and communication channels. There is no access boundary between agents, so compromising one agent effectively compromises the entire multi-agent system.

**Rationale:**
Agent isolation is a fundamental security requirement. If agents share resources without access boundaries, a single compromised agent can escalate its access to the entire system. This violates the principle of least privilege and makes the entire multi-agent architecture only as secure as its weakest agent.

**Remediation:**
- Implement resource isolation between agents: each agent should have its own data store, credentials, and configuration, accessible only by that agent.
- Use IAM policies, file system permissions, or container isolation to enforce resource boundaries.
- Audit cross-agent resource access to identify and eliminate unnecessary sharing.
- Implement access tokens that are scoped to individual agents and cannot be used to access other agents' resources.
- Regularly test isolation boundaries by attempting cross-agent resource access.

---

### AA-CF-037: No Network Segmentation Between Agents

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
Agents operate within the same network segment without network-level isolation. A compromised agent can discover and communicate with all other agents, scan for services on the network, and potentially access services that were not intended to be accessible to that agent.

**Rationale:**
Network segmentation is a standard security practice that limits lateral movement after a compromise. Without network segmentation, a compromised agent has the same network access as if it were directly on the internal network, which greatly expands the attack surface. In multi-agent systems, network segmentation is essential to enforce the principle of least privilege at the network layer.

**Remediation:**
- Deploy agents in separate network segments (VPCs, subnets, or network namespaces) with explicit firewall rules.
- Implement allow-list-based network policies: each agent should only be able to communicate with the specific services it needs.
- Use service mesh or API gateway for inter-agent communication with authentication and authorization.
- Monitor network traffic between agents and alert on unexpected communication patterns.
- Regularly review and audit network segmentation rules.

---

### AA-CF-038: Shared Database Accessible to All Agents

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
All agents share a common database with the same connection credentials and access level. A compromised agent can read, modify, or delete data belonging to other agents or other tenants, and database-level attacks (SQL injection, schema manipulation) affect all agents simultaneously.

**Rationale:**
Shared databases with common credentials represent a significant concentration of risk. If any agent is compromised, the attacker has full access to all data in the shared database. This eliminates the benefit of agent isolation at the application layer because the data layer is completely shared.

**Remediation:**
- Provision separate databases or schemas for each agent with distinct credentials.
- If a shared database is necessary, use row-level security or views to restrict each agent's access to its own data.
- Use unique database credentials for each agent with minimum necessary privileges (read-only where writes are not needed).
- Implement database access auditing to detect unauthorized cross-agent data access.
- Regularly review database permissions and remove unnecessary access.

---

### AA-CF-039: Shared Credential Store Accessible to All Agents

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
All agents access the same credential store (secrets manager, environment variables, configuration file) with the same access level. A compromised agent can retrieve credentials for all other agents and external services, enabling lateral movement and privilege escalation across the entire system.

**Rationale:**
Credential stores are high-value targets. If all agents can access all credentials, a single compromised agent can obtain credentials for every external service, database, and API that any agent uses. This is the equivalent of a master key being compromised and represents a total security failure.

**Remediation:**
- Implement per-agent credential scoping: each agent should only be able to access its own credentials.
- Use IAM policies or access control lists on the credential store to enforce per-agent access.
- Rotate credentials regularly and ensure that credential rotation is automated.
- Audit credential access and alert on unusual access patterns (an agent accessing credentials it doesn't normally use).
- Consider short-lived, dynamically issued credentials rather than long-lived stored credentials.

---

### AA-CF-040: No Resource Quotas Per Agent

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
There are no resource quotas allocated per agent. Any agent can consume as much CPU, memory, storage, network bandwidth, and API calls as it wants, potentially starving other agents and services of resources.

**Rationale:**
Without per-agent resource quotas, a single malfunctioning or compromised agent can consume all available resources, causing a denial-of-service for all other agents and the system as a whole. Resource quotas ensure fair resource sharing and prevent any single agent from monopolizing system capacity.

**Remediation:**
- Define and enforce resource quotas for each agent: CPU, memory, storage, network bandwidth, API call counts.
- Use container resource limits, cgroups, or cloud provider quota mechanisms to enforce quotas at the infrastructure level.
- Monitor resource consumption per agent and alert when quotas are approached.
- Design quotas based on expected agent workload with appropriate headroom.
- Review and adjust quotas periodically based on actual usage patterns.

---

### AA-CF-041: Agent Can Consume Unlimited Compute Resources

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
An agent has no limit on the CPU time or compute resources it can consume. A malfunctioning agent (infinite loop, exponential algorithm, runaway computation) can consume all available compute resources on its host, degrading or preventing the execution of other agents and services.

**Rationale:**
Compute resource limits are essential for system stability. Without limits, a single agent running an expensive computation can starve the host of CPU resources, causing slow responses, timeouts, and failures for all other processes. In cloud environments, unlimited compute consumption also translates to unbounded cost.

**Remediation:**
- Set CPU limits for each agent using containerization (Docker CPU limits, Kubernetes resource limits) or OS-level controls (cgroups).
- Implement wall-clock time limits for agent tasks to prevent long-running computations.
- Monitor CPU consumption per agent and alert on sustained high usage.
- Implement preemption or task cancellation for agents that exceed compute limits.
- Design agent tasks to be bounded in computational complexity.

---

### AA-CF-042: Agent Can Allocate Unlimited Storage

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
An agent has no limit on the amount of storage (disk, object storage, database rows) it can allocate. A malfunctioning agent can fill disk space, exhaust database storage, or create unbounded numbers of files, causing storage-related failures for the entire system.

**Rationale:**
Storage exhaustion is a common and impactful failure mode. When disk space is exhausted, systems fail in unpredictable ways: logging stops, databases become read-only, temporary files cannot be created, and processes crash. An agent without storage limits is a storage exhaustion risk.

**Remediation:**
- Set storage quotas for each agent using filesystem quotas, container volume limits, or database storage limits.
- Implement automatic cleanup of temporary files created by agents.
- Monitor storage consumption per agent and alert when quotas are approached.
- Design agents to clean up their storage artifacts when tasks complete.
- Implement storage usage monitoring at the system level with alerts for approaching capacity.

---

### AA-CF-043: Agent Can Open Unlimited Network Connections

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
An agent has no limit on the number of network connections it can open. A malfunctioning agent can exhaust file descriptors, overload network infrastructure, or create a large number of connections to downstream services, causing connection pool exhaustion and service degradation.

**Rationale:**
Network connections consume system resources (file descriptors, memory, kernel structures) and downstream service capacity (connection pool slots). An agent that opens unlimited connections can cause resource exhaustion at multiple levels and deny service to other system components. Connection limits are also important for preventing accidental or intentional DDoS of downstream services.

**Remediation:**
- Set connection limits for each agent using connection pool configuration, firewall rules, or OS-level limits.
- Implement connection pooling with bounded pool sizes for all external connections.
- Monitor open connection counts per agent and alert on unusual levels.
- Implement connection timeouts and idle connection cleanup.
- Set file descriptor limits at the process level for agent processes.

---

### AA-CF-044: Agent Failure Does Not Trigger Isolation/Quarantine

**Severity:** HIGH
**Mode:** Static + Dynamic

**Description:**
When an agent fails (crashes, behaves anomalously, is suspected of compromise), the system does not automatically isolate or quarantine the failed agent. The failed agent may continue to have access to resources, may be restarted in its compromised state, or may continue to affect other agents.

**Rationale:**
Automatic isolation of failed agents is a critical containment mechanism. Without automatic isolation, a compromised agent can continue to cause damage after the initial failure is detected. A failed agent may also be restarted by process supervision in a compromised state, perpetuating the compromise. Quarantine provides a safe holding state where the agent's state can be analyzed without risk of further damage.

**Remediation:**
- Implement automated isolation procedures that trigger on agent failure detection (revoke credentials, remove network access, stop the process).
- Define quarantine procedures that preserve the failed agent's state for forensic analysis while preventing further execution.
- Ensure that agent restart procedures verify integrity before resuming operation.
- Test isolation procedures regularly to verify they work correctly.
- Define clear criteria for when an agent should be isolated vs. restarted.

---

### AA-CF-045: No Blast Radius Analysis Documented

**Severity:** MEDIUM
**Mode:** Static + Dynamic

**Description:**
There is no documented analysis of the blast radius (scope of potential damage) for each agent in the system. Operators and developers do not have a clear understanding of what would be affected if a specific agent fails or is compromised.

**Rationale:**
Blast radius analysis is essential for understanding risk and for effective incident response. Without understanding the blast radius of each agent, operators cannot prioritize containment efforts, security teams cannot assess the severity of a compromise, and developers cannot design appropriate isolation measures. This is a fundamental gap in the system's security posture.

**Remediation:**
- Document the blast radius for each agent: what resources can it access, what systems can it affect, what data can it read/modify?
- Include blast radius analysis in the agent's threat model.
- Review and update blast radius analysis when agent capabilities change.
- Use blast radius analysis to inform isolation and containment procedures.
- Present blast radius analysis in a visual format (dependency diagrams, impact maps) for easy comprehension.

---

### AA-CF-046: Dependent Systems Not Identified for Each Agent

**Severity:** MEDIUM
**Mode:** Static + Dynamic

**Description:**
The systems that depend on each agent (and the systems each agent depends on) are not documented. When an agent fails, operators do not know which downstream systems will be affected or which upstream systems might be causing the failure.

**Rationale:**
Dependency mapping is essential for incident response, change management, and resilience planning. Without knowing an agent's dependencies, operators cannot quickly diagnose the root cause of failures, cannot predict the impact of changes, and cannot design appropriate fallback mechanisms. This knowledge gap extends incident response times and increases the risk of cascading failures.

**Remediation:**
- Create and maintain a dependency map for each agent (upstream dependencies and downstream dependents).
- Use automated dependency discovery tools to supplement manual documentation.
- Include dependency information in agent configuration and operational runbooks.
- Review dependencies when agents are modified or when new integrations are added.
- Use dependency maps to inform circuit breaker placement and blast radius analysis.

---

### AA-CF-047: Agent Recovery Does Not Verify Integrity Before Resuming

**Severity:** MEDIUM
**Mode:** Static + Dynamic

**Description:**
When an agent recovers from a failure (restart, failover, error recovery), it does not verify the integrity of its state, configuration, and environment before resuming operation. The agent may resume with corrupted state, modified configuration, or a compromised environment, perpetuating or amplifying the original failure.

**Rationale:**
Recovery without integrity verification is a common source of persistent failures and security issues. If an agent was compromised before it failed, restarting it without integrity checks means restarting the compromised agent. If the failure corrupted the agent's state, resuming with corrupted state perpetuates the corruption. Integrity verification is the checkpoint between a failed state and a healthy state.

**Remediation:**
- Implement integrity verification as part of the agent startup/recovery sequence: verify configuration, validate state, check credentials, confirm environment.
- Use checksums or cryptographic signatures to verify that agent configuration has not been tampered with.
- Validate agent state against expected invariants before resuming operation.
- If integrity verification fails, alert operators and refuse to start rather than running in a potentially compromised state.
- Test integrity verification procedures regularly.

---

### AA-CF-048: Agent Can Modify Shared Infrastructure

**Severity:** MEDIUM
**Mode:** Static + Dynamic

**Description:**
An agent has the ability to modify shared infrastructure components such as DNS records, load balancer configurations, network routes, or service discovery registries. A compromised or malfunctioning agent can redirect traffic, disrupt service discovery, or modify routing in ways that affect all other agents and services.

**Rationale:**
Shared infrastructure modifications have the broadest possible blast radius. If an agent can modify DNS records, it can redirect all traffic in the system. If it can modify load balancer configurations, it can remove services from rotation or direct all traffic to a single instance. These capabilities should be restricted to dedicated infrastructure management tools with strict access controls.

**Remediation:**
- Remove shared infrastructure modification privileges from agents. Use dedicated infrastructure management tools with their own access controls.
- If infrastructure modification is required, implement a privileged API with strong authentication, authorization, and audit logging.
- Use infrastructure-as-code with version control and approval workflows rather than allowing runtime modifications.
- Monitor shared infrastructure for unauthorized changes and alert immediately.
- Implement rollback capabilities for infrastructure changes.

---

### AA-CF-049: No Runbook for Agent Compromise Scenario

**Severity:** MEDIUM
**Mode:** Static + Dynamic

**Description:**
There is no documented runbook or incident response procedure for the scenario where an agent is suspected of being compromised. Operators do not have step-by-step guidance for containing, investigating, and recovering from an agent compromise.

**Rationale:**
Agent compromise is a realistic threat in agentic systems (prompt injection, tool exploitation, supply chain attacks). Without a runbook, incident response is ad-hoc, slow, and error-prone. Operators may not know how to safely isolate the agent, preserve forensic evidence, or restore the system to a known-good state. This delays containment and increases the blast radius.

**Remediation:**
- Create a detailed runbook for agent compromise scenarios that covers: detection, containment (isolation), investigation (forensics), eradication (cleanup), and recovery (restore to known-good state).
- Include specific commands and procedures for each step.
- Define roles and responsibilities for agent compromise incident response.
- Test the runbook through tabletop exercises and simulated incidents.
- Review and update the runbook when agent architecture or capabilities change.

---

### AA-CF-050: Agent Decommissioning Does Not Clean Up All Resources

**Severity:** MEDIUM
**Mode:** Static + Dynamic

**Description:**
When an agent is decommissioned (removed from service, replaced, or retired), its resources are not fully cleaned up. Orphaned credentials remain active, database entries persist, network rules remain in place, and storage artifacts are not deleted. These orphaned resources create security risks and operational complexity.

**Rationale:**
Incomplete decommissioning creates security risks (orphaned credentials that can be exploited), compliance risks (data retention issues), and operational risks (orphaned resources consuming capacity and confusing operators). In systems with many agents that are frequently deployed and retired, incomplete decommissioning leads to progressive resource accumulation and increased attack surface.

**Remediation:**
- Create a decommissioning checklist for each agent type that covers all resources that need to be cleaned up: credentials, data stores, network rules, IAM policies, monitoring configurations, log streams.
- Automate the decommissioning process to ensure completeness.
- Audit for orphaned resources periodically (credentials not associated with active agents, data stores not referenced by any agent).
- Implement resource tagging so that all resources created by an agent can be identified and cleaned up.
- Test the decommissioning process regularly to verify completeness.

---

## 4. Resource Exhaustion (AA-CF-051 to AA-CF-070)

This sub-domain addresses controls for preventing agents from consuming unbounded resources, whether through normal operation, malfunction, or adversarial manipulation. Resource exhaustion is a primary vector for denial-of-service attacks against agentic systems and a common consequence of agent malfunctions.

---

### AA-CF-051: No Token/Cost Limit Per Agent Request

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on the number of LLM tokens (input + output) or the dollar cost that a single agent request can consume. A single request (through complex reasoning, large context, or repeated tool calls) can consume an arbitrarily large number of tokens, resulting in unbounded cost and latency.

**Rationale:**
LLM token consumption is the primary cost driver for agentic systems. Without per-request limits, a single adversarial or malformed request can consume thousands of dollars in LLM API costs. Long conversations, tool call loops, and context stuffing can all cause token consumption to grow without bound within a single request.

**Remediation:**
- Set a maximum token limit per agent request (both input and output tokens).
- Implement cost tracking that estimates the dollar cost of each request and enforces a per-request cost ceiling.
- Terminate requests that approach the token/cost limit with a graceful error message.
- Monitor per-request token consumption and alert on anomalous spikes.
- Configure different limits based on request type, user tier, or agent type.

---

### AA-CF-052: No Token/Cost Limit Per Agent Per Day

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no daily aggregate limit on the tokens or cost consumed by an agent. Over the course of a day, an agent can consume an unlimited amount of tokens through many individual requests, each of which may be within per-request limits.

**Rationale:**
Per-request limits are necessary but not sufficient. A large volume of requests, each within the per-request limit, can still result in enormous aggregate costs. Daily limits provide a safety net that caps the maximum cost exposure from any single agent over a meaningful time period. Without daily limits, a malfunctioning agent can accumulate significant costs before operators intervene.

**Remediation:**
- Set daily token and cost limits for each agent.
- Implement cumulative cost tracking with daily reset.
- When an agent approaches its daily limit, alert operators and (optionally) throttle or suspend the agent.
- Set different daily limits based on agent type, criticality, and expected workload.
- Review daily limits regularly based on actual usage patterns and adjust as needed.

---

### AA-CF-053: No Maximum Context Window Usage Limit

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on how much of the LLM's context window an agent can fill with each request. An agent can fill the entire context window with historical conversation, tool results, system prompts, and retrieved documents, resulting in maximum-cost requests and degraded LLM performance.

**Rationale:**
LLM costs typically scale with the number of input tokens, which is primarily determined by context window usage. Without context window limits, agents can accumulate arbitrarily large contexts (long conversations, many tool call results, large document retrievals), each of which is sent with every subsequent LLM call. This creates both cost and performance issues: larger contexts are more expensive and often result in degraded response quality.

**Remediation:**
- Set a maximum context window usage limit per agent request (e.g., 80% of the model's maximum context).
- Implement context window management: summarization, truncation, or eviction of older context when limits are approached.
- Monitor context window usage and alert on unusually large contexts.
- Implement efficient context packing: prioritize relevant context over historical context.
- Design agent memory systems that avoid accumulating unbounded context.

---

### AA-CF-054: No Maximum Tool Calls Per Request

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on the number of tool calls an agent can make within a single request. An agent can make an unlimited number of tool calls (through loops, recursive reasoning, or adversarial prompting), consuming resources and time without bound.

**Rationale:**
Tool call loops are a common failure mode in agentic systems. An agent that enters a tool call loop (searching for information it cannot find, retrying a failing operation, or following a circular reasoning path) can make hundreds or thousands of tool calls before timing out. Each tool call consumes resources (LLM tokens for generating the call, external API calls, compute time for tool execution).

**Remediation:**
- Set a maximum number of tool calls per agent request (e.g., 25 tool calls per request).
- Terminate requests that exceed the tool call limit with a meaningful error message and partial results if available.
- Monitor tool call counts per request and alert on anomalous levels.
- Implement loop detection: detect when an agent is making the same or similar tool calls repeatedly and intervene.
- Log all tool calls to support debugging and pattern analysis.

---

### AA-CF-055: No Maximum API Calls to External Services

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on the number of API calls an agent can make to external services per request or per time period. An agent can make unlimited calls to search engines, databases, SaaS APIs, and other services, potentially exceeding rate limits, incurring costs, and overwhelming external services.

**Rationale:**
External API calls often have costs (pay-per-call pricing), rate limits, and capacity constraints. An agent that makes unlimited external API calls can incur significant costs, trigger rate limiting that affects other users of the same API, or overwhelm services that are not designed for high-volume automated access. This also creates a dependency risk: if the agent is compromised, it can use the system's API keys to abuse external services.

**Remediation:**
- Set per-request and per-time-period limits for external API calls for each agent and each external service.
- Implement caching for external API responses to reduce redundant calls.
- Monitor external API call volumes and costs per agent.
- Use separate API keys for each agent when possible to enable per-agent tracking and limiting.
- Implement budget alerts for external API costs.

---

### AA-CF-056: No Compute Time Limit Per Agent Task

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no wall-clock time limit for how long an agent can spend on a single task. An agent can run indefinitely on a single task, consuming compute resources and blocking other tasks from being processed.

**Rationale:**
Unbounded task duration creates resource contention and operational issues. A task that runs for hours or days consumes compute resources, may hold locks or connections, and prevents the system from processing other tasks. Wall-clock time limits provide a safety net against runaway tasks and ensure that the system remains responsive.

**Remediation:**
- Set wall-clock time limits for agent tasks appropriate to the task type (e.g., 60 seconds for simple queries, 5 minutes for complex research tasks).
- Implement task timeout mechanisms that terminate long-running tasks gracefully.
- Provide partial results when a task is terminated due to timeout.
- Monitor task durations and alert on anomalously long tasks.
- Design tasks to be checkpointable so that progress is not entirely lost on timeout.

---

### AA-CF-057: No Storage Limit Per Agent

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on the amount of persistent storage an agent can consume. An agent can write an unlimited amount of data to databases, file systems, object storage, or other persistent stores, potentially exhausting storage capacity.

**Rationale:**
Storage capacity is a finite resource, and storage exhaustion causes system-wide failures. An agent that writes unbounded data (logging verbosely, caching aggressively, creating large artifacts) can fill storage and cause failures for all other agents and services. This is particularly risky for agents that process user-uploaded data or generate content.

**Remediation:**
- Set storage quotas for each agent at the filesystem, database, and object storage levels.
- Implement automatic storage cleanup policies (TTLs for temporary data, archival for old data).
- Monitor storage consumption per agent and alert when quotas are approached.
- Implement graceful handling when storage quotas are reached (reject new writes, clean up old data, notify operators).
- Review storage usage patterns and adjust quotas periodically.

---

### AA-CF-058: No Memory (RAM) Limit Per Agent Process

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no memory (RAM) limit for agent processes. An agent can allocate unlimited memory, potentially causing out-of-memory conditions that affect the host, trigger OOM killer termination of other processes, or cause system instability.

**Rationale:**
Memory exhaustion is one of the most disruptive failure modes because it affects all processes on the same host. The OOM killer may terminate critical processes rather than the agent that caused the exhaustion. In agentic systems, memory-intensive operations (processing large documents, building large context, caching responses) can quickly consume available memory without explicit limits.

**Remediation:**
- Set memory limits for agent processes using containerization (Docker memory limits, Kubernetes resource limits) or OS-level controls (cgroups, ulimit).
- Implement memory-efficient data processing patterns (streaming, pagination, chunking) rather than loading entire datasets into memory.
- Monitor memory consumption per agent and alert on sustained high usage.
- Implement graceful degradation when memory limits are approached (release caches, reduce context size).
- Test agent behavior under memory pressure to verify graceful handling.

---

### AA-CF-059: No Recursive Call Depth Limit

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on the recursion depth for agent operations (recursive tool calls, recursive delegation, recursive reasoning). An agent can recurse to arbitrary depth, consuming stack space, memory, and potentially causing stack overflow crashes.

**Rationale:**
Recursive patterns are common in agentic systems: an agent researches a topic, which leads to sub-questions, which lead to further sub-questions. Without a recursion depth limit, adversarial prompting or complex queries can cause the agent to recurse until it exhausts stack space or memory. Recursion limits are a basic safety mechanism that prevents unbounded resource consumption from recursive patterns.

**Remediation:**
- Set explicit recursion depth limits for all recursive patterns in agent execution (e.g., maximum 5 levels of delegation).
- Implement recursion depth tracking that increments with each recursive call and rejects calls that exceed the limit.
- Convert deep recursion patterns to iterative patterns where possible.
- Monitor recursion depth and alert on deep recursion (potential infinite loop or adversarial prompt).
- Return partial results when recursion depth limits are reached rather than failing entirely.

---

### AA-CF-060: No File Handle/Descriptor Limit

**Severity:** HIGH
**Mode:** Static

**Description:**
There is no limit on the number of file handles or file descriptors an agent process can open. An agent can open an unlimited number of files, network connections, and pipes, potentially exhausting the system's file descriptor limit and causing failures for all processes on the host.

**Rationale:**
File descriptors are a limited system resource. When exhausted, no process on the host can open new files, create new network connections, or perform many other basic operations. An agent that opens many files or connections without closing them (resource leak) or intentionally opens many handles (resource exhaustion attack) can cause system-wide failures.

**Remediation:**
- Set file descriptor limits for agent processes using OS-level controls (ulimit, systemd LimitNOFILE).
- Implement proper resource management in agent code: ensure files and connections are closed when no longer needed (using context managers, try/finally, destructors).
- Monitor open file descriptor counts per agent process.
- Implement periodic resource audits that detect and close leaked file descriptors.
- Set system-wide file descriptor limits with appropriate headroom.

---

### AA-CF-061: No Concurrent Request Limit Per Agent

**Severity:** MEDIUM
**Mode:** Static

**Description:**
There is no limit on the number of concurrent requests an agent can handle. Under high load, an agent may accept more concurrent requests than it can process efficiently, leading to degraded performance, increased latency, and potential resource exhaustion.

**Rationale:**
Concurrency limits are essential for stable system performance. An agent that accepts unlimited concurrent requests will degrade under load rather than rejecting excess requests cleanly. This leads to slow responses for all users rather than fast responses for some users and clean rejections for others. Concurrency limits also prevent resource exhaustion from accumulated per-request resource consumption.

**Remediation:**
- Set a maximum concurrent request limit for each agent based on its resource capacity and performance characteristics.
- Implement request queuing with a bounded queue for excess requests.
- Return clear "service busy" responses when the concurrency limit is reached rather than accepting and processing slowly.
- Monitor concurrent request counts and alert when approaching limits.
- Load test agents to determine appropriate concurrency limits.

---

### AA-CF-062: Agent Can Trigger Expensive Operations Without Approval

**Severity:** MEDIUM
**Mode:** Static

**Description:**
An agent can trigger expensive operations (large batch jobs, full database scans, expensive API calls, large data transfers) without any approval mechanism or cost check. The agent may not even be aware that the operation is expensive.

**Rationale:**
Some operations are orders of magnitude more expensive than typical operations. Without cost-awareness or approval gates for expensive operations, an agent can inadvertently (or through adversarial prompting) trigger operations that consume significant resources or incur significant costs. This is especially dangerous for agents that interact with metered cloud services.

**Remediation:**
- Identify expensive operations for each agent and implement approval gates or cost checks before execution.
- Implement cost estimation for operations before they are executed, and require approval for operations above a cost threshold.
- Set hard limits on operation cost/size (e.g., maximum query result size, maximum batch job size).
- Provide cost information to the agent so it can make informed decisions about operation selection.
- Monitor operation costs and alert on expensive operations.

---

### AA-CF-063: Batch Operations Not Size-Limited

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Batch operations (processing multiple records, sending multiple messages, making multiple API calls) do not have a size limit. An agent can initiate a batch operation of unlimited size, potentially overwhelming downstream systems, consuming excessive resources, or causing long-running operations that block other work.

**Rationale:**
Batch operations amplify the impact of a single agent action. A batch operation that processes one million records instead of one hundred has a vastly different resource profile. Without size limits, a single batch operation can consume disproportionate resources and affect system stability.

**Remediation:**
- Set maximum batch sizes for all batch operations.
- Implement chunking for large batches: break them into smaller batches with pauses between chunks.
- Require approval for batch operations that exceed normal size thresholds.
- Monitor batch operation sizes and alert on unusually large batches.
- Implement progress tracking and cancellation for batch operations.

---

### AA-CF-064: Long-Running Operations Not Cancellable

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Once an agent initiates a long-running operation, there is no mechanism to cancel it before completion. Operators and users must wait for the operation to complete (or timeout) even if they realize the operation is incorrect, unnecessary, or harmful.

**Rationale:**
Cancellability is essential for maintaining human control over agent operations. Without cancellation, operators lose the ability to intervene in operations that are going wrong, consuming excessive resources, or taking longer than expected. This violates the principle of human oversight and can lead to unnecessary resource consumption and damage.

**Remediation:**
- Implement cancellation mechanisms for all long-running operations (cooperative cancellation via cancellation tokens or flags).
- Design operations to check for cancellation signals periodically and terminate cleanly when cancellation is requested.
- Implement cleanup logic that runs when an operation is cancelled (rollback partial progress, release resources).
- Provide cancellation capabilities to both users and operators through the appropriate interfaces.
- Test cancellation behavior for all long-running operations.

---

### AA-CF-065: Resource Usage Not Monitored in Real-Time

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Agent resource consumption (CPU, memory, network, storage, API calls, tokens) is not monitored in real-time. Operators only see resource usage in retrospective reports or not at all, preventing them from detecting and responding to resource anomalies as they occur.

**Rationale:**
Real-time monitoring is essential for detecting and responding to resource exhaustion, runaway agents, and denial-of-service conditions before they cause significant impact. Retrospective monitoring is useful for analysis but does not enable timely intervention. In agentic systems, resource consumption can spike rapidly (tool call loop, context explosion), making real-time visibility critical.

**Remediation:**
- Implement real-time monitoring for key resource metrics: CPU, memory, network I/O, storage I/O, API call rates, token consumption.
- Use monitoring dashboards that show resource consumption per agent in real-time.
- Configure alerts for resource consumption that exceeds normal levels.
- Implement automated responses to resource anomalies (throttling, termination).
- Ensure monitoring has sufficient granularity to attribute resource consumption to specific agents and requests.

---

### AA-CF-066: No Alerting for Anomalous Resource Consumption

**Severity:** MEDIUM
**Mode:** Static

**Description:**
There are no alerts configured for anomalous resource consumption patterns. Even if resources are monitored, operators are not notified when an agent's resource usage deviates significantly from its baseline. Anomalous consumption may go undetected until it causes a visible failure.

**Rationale:**
Anomalous resource consumption is often the first indicator of a malfunction, compromise, or abuse. Without alerting, this early warning signal is lost, and the issue is only detected when it causes user-visible impact. Automated alerting enables proactive intervention before anomalous consumption causes cascading failures or significant cost overruns.

**Remediation:**
- Define baseline resource consumption for each agent based on historical data.
- Configure anomaly detection alerts that trigger when consumption deviates significantly from baseline.
- Use statistical methods (standard deviation, percentile-based) for anomaly detection rather than fixed thresholds only.
- Include context in alerts: which agent, which resource, current consumption, baseline, deviation.
- Regularly review and update baselines as agent behavior evolves.

---

### AA-CF-067: Resource Limits Not Enforced Consistently Across Environments

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Resource limits that are enforced in production are not enforced in development, staging, or testing environments (or vice versa). This discrepancy means that resource exhaustion issues may not be detected during testing and only manifest in production.

**Rationale:**
Environment parity is important for resource limit testing. If limits are different (or absent) in test environments, resource exhaustion bugs and misconfigurations will not be caught during testing. Conversely, if production has different limits than testing, agents tested under one set of limits may behave differently under another.

**Remediation:**
- Apply consistent resource limits across all environments (development, staging, production).
- Include resource limit configuration in environment-as-code and version control.
- Test agent behavior under resource limits as part of the standard testing process.
- Document any intentional differences between environment limits and the rationale for each difference.
- Audit resource limit configurations across environments periodically.

---

### AA-CF-068: Agent Can Accumulate Resources Across Requests (No Cleanup)

**Severity:** MEDIUM
**Mode:** Static

**Description:**
An agent accumulates resources (memory, file handles, cached data, temporary files, database connections) across requests without cleaning them up. Over time, the agent's resource footprint grows monotonically, eventually leading to resource exhaustion. This is a resource leak that manifests as a slow degradation.

**Rationale:**
Resource leaks are particularly insidious because they cause gradual degradation rather than immediate failure. The system appears to function normally for hours or days before resource exhaustion causes a sudden failure. In long-running agent processes, resource leaks accumulate across many requests and can be difficult to diagnose without careful monitoring.

**Remediation:**
- Implement per-request resource cleanup: ensure all resources allocated during a request are released when the request completes.
- Use automatic resource management (context managers, try/finally, destructors) for all resource allocations.
- Monitor long-term resource consumption trends per agent (increasing memory, increasing file descriptors).
- Implement periodic agent process recycling to clear accumulated resource leaks.
- Conduct memory and resource leak testing as part of the testing process.

---

### AA-CF-069: Model API Calls Not Budget-Constrained

**Severity:** MEDIUM
**Mode:** Static

**Description:**
Calls to LLM model APIs are not constrained by a budget mechanism. The system can make unlimited calls to model APIs, resulting in unbounded costs. There is no mechanism to pause or reduce model API usage when spending approaches a budget threshold.

**Rationale:**
LLM API costs can be significant, especially for agents that make many calls per task or use expensive models. Without budget constraints, costs can escalate rapidly during traffic spikes, agent malfunctions, or adversarial use. Budget constraints provide a financial safety net that prevents runaway costs from impacting the organization.

**Remediation:**
- Implement budget tracking for model API costs at per-agent, per-team, and system-wide levels.
- Set budget limits with alerts at warning thresholds (e.g., 80%) and hard stops at critical thresholds (e.g., 100%).
- Implement cost optimization strategies: model routing (use cheaper models for simpler tasks), response caching, context optimization.
- Monitor cost trends and provide dashboards for cost visibility.
- Include model API costs in capacity planning and budgeting processes.

---

### AA-CF-070: Agent Can Trigger Cascading Resource Consumption in Dependent Services

**Severity:** MEDIUM
**Mode:** Static

**Description:**
An agent can trigger operations that cause cascading resource consumption in dependent services. For example, an agent query that triggers a full table scan in a database, a search that causes an index rebuild, or an API call that triggers expensive downstream processing. The agent's resource consumption appears modest, but the downstream impact is orders of magnitude larger.

**Rationale:**
Resource consumption is not always visible at the agent level. Some agent actions trigger disproportionate resource consumption in downstream services. Without understanding and controlling these cascading resource effects, an agent can cause significant downstream impact while appearing to be within its own resource limits.

**Remediation:**
- Map the resource amplification effects of agent actions on downstream services.
- Implement query and operation analysis to identify potentially expensive downstream operations before execution.
- Set limits on downstream resource consumption (query complexity limits, operation size limits).
- Monitor downstream service resource consumption in the context of agent activity.
- Implement admission control for operations that have known high downstream resource impact.

---

## Appendix: Control Summary Table

| Control ID | Title | Severity | Mode |
|---|---|---|---|
| AA-CF-001 | Single agent failure crashes entire system | CRITICAL | Both |
| AA-CF-002 | Tool error causes undefined state | CRITICAL | Both |
| AA-CF-003 | Infinite retry loop | CRITICAL | Both |
| AA-CF-004 | Error response contains internal info | CRITICAL | Both |
| AA-CF-005 | Unhandled exception propagates | CRITICAL | Both |
| AA-CF-006 | One tool error fails all tools | HIGH | Both |
| AA-CF-007 | Corrupted state after error | HIGH | Both |
| AA-CF-008 | Error cascades through delegation chain | HIGH | Both |
| AA-CF-009 | Background error surfaces in unrelated request | HIGH | Both |
| AA-CF-010 | Timeout blocks dependent agents | HIGH | Both |
| AA-CF-011 | Partial failure without rollback | HIGH | Both |
| AA-CF-012 | Post-error behavioral drift | HIGH | Both |
| AA-CF-013 | Error logging fails silently | HIGH | Both |
| AA-CF-014 | Retry loop amplifies original problem | HIGH | Both |
| AA-CF-015 | Parse error causes corrupt data processing | HIGH | Both |
| AA-CF-016 | Concurrent errors cause race conditions | MEDIUM | Both |
| AA-CF-017 | Error handling code has vulnerabilities | MEDIUM | Both |
| AA-CF-018 | No transient vs. permanent error distinction | MEDIUM | Both |
| AA-CF-019 | Error message misinterpretation across layers | MEDIUM | Both |
| AA-CF-020 | System-wide error threshold not monitored | MEDIUM | Both |
| AA-CF-021 | No circuit breaker between agents | HIGH | Static |
| AA-CF-022 | No circuit breaker for external APIs | HIGH | Static |
| AA-CF-023 | No circuit breaker for database connections | HIGH | Static |
| AA-CF-024 | Circuit breaker threshold too high | HIGH | Static |
| AA-CF-025 | Circuit breaker does not notify operators | HIGH | Static |
| AA-CF-026 | No fallback when circuit breaker is open | HIGH | Static |
| AA-CF-027 | Circuit breaker state shared across workflows | HIGH | Static |
| AA-CF-028 | Circuit breaker resets too quickly | HIGH | Static |
| AA-CF-029 | No backoff policy for retries | MEDIUM | Static |
| AA-CF-030 | No rate limit on agent actions | MEDIUM | Static |
| AA-CF-031 | No per-user/session rate limit | MEDIUM | Static |
| AA-CF-032 | No global rate limit across agents | MEDIUM | Static |
| AA-CF-033 | Rate limit bypass via tool chaining | MEDIUM | Static |
| AA-CF-034 | Rate limit not consistent across instances | MEDIUM | Static |
| AA-CF-035 | No alert when rate limits approached | MEDIUM | Static |
| AA-CF-036 | Compromised agent accesses all resources | HIGH | Static + Dynamic |
| AA-CF-037 | No network segmentation between agents | HIGH | Static + Dynamic |
| AA-CF-038 | Shared database accessible to all agents | HIGH | Static + Dynamic |
| AA-CF-039 | Shared credential store accessible to all | HIGH | Static + Dynamic |
| AA-CF-040 | No resource quotas per agent | HIGH | Static + Dynamic |
| AA-CF-041 | Unlimited compute resources | HIGH | Static + Dynamic |
| AA-CF-042 | Unlimited storage allocation | HIGH | Static + Dynamic |
| AA-CF-043 | Unlimited network connections | HIGH | Static + Dynamic |
| AA-CF-044 | No isolation on agent failure | HIGH | Static + Dynamic |
| AA-CF-045 | No blast radius analysis documented | MEDIUM | Static + Dynamic |
| AA-CF-046 | Dependent systems not identified | MEDIUM | Static + Dynamic |
| AA-CF-047 | Recovery without integrity verification | MEDIUM | Static + Dynamic |
| AA-CF-048 | Agent can modify shared infrastructure | MEDIUM | Static + Dynamic |
| AA-CF-049 | No runbook for compromise scenario | MEDIUM | Static + Dynamic |
| AA-CF-050 | Decommissioning does not clean up resources | MEDIUM | Static + Dynamic |
| AA-CF-051 | No per-request token/cost limit | HIGH | Static |
| AA-CF-052 | No daily token/cost limit | HIGH | Static |
| AA-CF-053 | No context window usage limit | HIGH | Static |
| AA-CF-054 | No maximum tool calls per request | HIGH | Static |
| AA-CF-055 | No maximum external API calls | HIGH | Static |
| AA-CF-056 | No compute time limit per task | HIGH | Static |
| AA-CF-057 | No storage limit per agent | HIGH | Static |
| AA-CF-058 | No memory limit per agent process | HIGH | Static |
| AA-CF-059 | No recursive call depth limit | HIGH | Static |
| AA-CF-060 | No file handle/descriptor limit | HIGH | Static |
| AA-CF-061 | No concurrent request limit | MEDIUM | Static |
| AA-CF-062 | Expensive operations without approval | MEDIUM | Static |
| AA-CF-063 | Batch operations not size-limited | MEDIUM | Static |
| AA-CF-064 | Long-running operations not cancellable | MEDIUM | Static |
| AA-CF-065 | Resource usage not monitored real-time | MEDIUM | Static |
| AA-CF-066 | No alerting for anomalous consumption | MEDIUM | Static |
| AA-CF-067 | Limits not consistent across environments | MEDIUM | Static |
| AA-CF-068 | Resource accumulation across requests | MEDIUM | Static |
| AA-CF-069 | Model API calls not budget-constrained | MEDIUM | Static |
| AA-CF-070 | Cascading resource consumption in dependents | MEDIUM | Static |
