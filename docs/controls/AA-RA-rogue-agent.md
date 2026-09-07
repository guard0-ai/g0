# AA-RA: Rogue Agent Controls

**Domain:** Rogue Agent
**OWASP Mapping:** ASI10 - Rogue Agent Behavior
**Control Range:** AA-RA-001 through AA-RA-070
**Total Controls:** 70
**Last Updated:** 2026-02-13
**Status:** Active

> [!IMPORTANT]
> **Control IDs in this document are specification IDs. They do not correspond
> to the scanner's rule IDs.** This framework and the shipped rule set were
> numbered independently, so the same identifier frequently names one control
> here and a different one in the scanner, and severity often differs too.
> For what a rule actually does, run `g0 rules describe <id>` or see
> [SHIPPED-RULES.md](SHIPPED-RULES.md), which is generated from source.
> Run `npm run docs:rules:check` to see the current divergence.

---

## Overview

The Rogue Agent domain addresses the detection and prevention of AI agents that deviate from their intended behavior. A rogue agent may result from successful attacks (prompt injection, goal hijacking), software defects, model drift, or deliberate self-modification. Unlike other domains that focus on preventing attacks, this domain assumes the agent may already be compromised and focuses on detecting anomalous behavior and providing mechanisms to terminate rogue agents.

This domain maps to **OWASP ASI10 (Rogue Agent Behavior)**, covering scenarios where agents exhibit behaviors inconsistent with their defined purpose, access patterns that deviate from baselines, or outputs that suggest compromise or malfunction. Effective rogue agent detection requires establishing behavioral baselines, monitoring deviations, and maintaining reliable kill switch mechanisms.

The controls span seven areas: behavioral anomaly detection, output monitoring, goal drift detection, tool usage anomaly analysis, communication anomaly detection, self-modification detection, and kill switch mechanisms. Together, these controls form a defense-in-depth approach to identifying and stopping rogue agent behavior before it causes significant damage.

## Applicable Standards

| Standard | Section | Description |
|----------|---------|-------------|
| OWASP ASI10 | Rogue Agent Behavior | Primary mapping for all controls |
| ISO 42001 | A.9 | Operation of AI systems |
| NIST AI RMF | GOVERN-1.2 | AI governance and operational oversight |
| NIST AI RMF | MEASURE-2.6 | AI risk monitoring and measurement |
| ISO 23894 | 6.5 | AI risk treatment and monitoring |
| MITRE ATLAS | AML.T0048 | Adversarial ML attack monitoring |

## Sub-Categories Summary

| Sub-Category | Range | Count | Primary Threat |
|-------------|-------|-------|----------------|
| [Behavioral Anomaly Detection](#1-behavioral-anomaly-detection) | AA-RA-001 to AA-RA-010 | 10 | Undetected behavior changes |
| [Output Monitoring](#2-output-monitoring) | AA-RA-011 to AA-RA-020 | 10 | Malicious or anomalous outputs |
| [Goal Drift Detection](#3-goal-drift-detection) | AA-RA-021 to AA-RA-030 | 10 | Deviation from intended goals |
| [Tool Usage Anomalies](#4-tool-usage-anomalies) | AA-RA-031 to AA-RA-040 | 10 | Unusual tool call patterns |
| [Communication Anomalies](#5-communication-anomalies) | AA-RA-041 to AA-RA-050 | 10 | Suspicious external comms |
| [Self-Modification Detection](#6-self-modification-detection) | AA-RA-051 to AA-RA-060 | 10 | Agent modifying own config |
| [Kill Switch Mechanisms](#7-kill-switch-mechanisms) | AA-RA-061 to AA-RA-070 | 10 | Emergency agent termination |

---

## 1. Behavioral Anomaly Detection

**Sub-Category Range:** AA-RA-001 through AA-RA-010
**Primary Threat:** Compromised or malfunctioning agents operating undetected
**Attack Vector:** Gradual or sudden behavioral changes that bypass observation

Behavioral anomaly detection establishes baselines of normal agent behavior and monitors for deviations. Without baselines and monitoring, a compromised agent can operate maliciously for extended periods before detection. This sub-category covers establishing behavioral profiles, detecting pattern deviations, and alerting on anomalous behavior across multiple dimensions.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-001 | No behavioral baseline established | CRITICAL | static | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-002 | Action pattern deviation undetected | CRITICAL | dynamic | stable | langchain, crewai, autogen, openai, bedrock |
| AA-RA-003 | Response style change unmonitored | HIGH | dynamic | stable | langchain, crewai, openai, bedrock |
| AA-RA-004 | Decision pattern shift undetected | HIGH | dynamic | stable | langchain, crewai, autogen, openai |
| AA-RA-005 | Interaction frequency anomaly ignored | HIGH | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-006 | Error rate spike undetected | HIGH | dynamic | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-007 | Performance degradation unmonitored | MEDIUM | dynamic | beta | langchain, crewai, openai, bedrock |
| AA-RA-008 | Behavioral fingerprint absent | MEDIUM | static | beta | langchain, crewai, autogen, openai |
| AA-RA-009 | Anomaly detection model missing | HIGH | static | beta | langchain, crewai, openai |
| AA-RA-010 | Behavioral drift alerting absent | MEDIUM | static | beta | langchain, crewai, autogen, openai, bedrock, mcp |

**Standards Mapping (all controls):** OWASP ASI10, ISO 42001 A.9, NIST MEASURE-2.6, MITRE ATLAS AML.T0048

### Detailed Descriptions

#### AA-RA-001: No Behavioral Baseline Established

**Description:** Tests whether the agent system has established a baseline profile of normal agent behavior against which deviations can be detected.

**Rationale:** Without a behavioral baseline, there is no reference point for determining whether current behavior is normal or anomalous. A compromised agent may be performing highly unusual actions, but without baseline data, these actions appear indistinguishable from normal operation. Baselines should cover action types, frequencies, timing patterns, tool usage, and output characteristics.

#### AA-RA-002: Action Pattern Deviation Undetected

**Description:** Tests whether the system detects when the agent's action patterns deviate significantly from established baselines.

**Rationale:** A compromised agent typically exhibits changed action patterns -- accessing different resources, calling different tools, or performing actions at unusual times. If these deviations are not detected, the compromise can persist indefinitely. Real-time action pattern monitoring is essential for early detection of rogue behavior.

#### AA-RA-003: Response Style Change Unmonitored

**Description:** Tests whether changes in the agent's response style, tone, or formatting are monitored as potential indicators of compromise.

**Rationale:** When an agent is manipulated through prompt injection or goal hijacking, its response style often changes subtly. It may become more verbose, adopt a different tone, or change its formatting patterns. Monitoring these stylistic shifts can provide early warning of compromise before the agent takes overtly harmful actions.

#### AA-RA-004: Decision Pattern Shift Undetected

**Description:** Tests whether shifts in the agent's decision-making patterns are detected, such as consistently choosing different options than its baseline would predict.

**Rationale:** A manipulated agent may make different decisions in similar situations compared to its baseline behavior. If the agent typically declines risky operations but suddenly starts approving them, this decision shift may indicate compromise. Statistical monitoring of decision patterns can detect these shifts.

#### AA-RA-005: Interaction Frequency Anomaly Ignored

**Description:** Tests whether unusual changes in the agent's interaction frequency with tools, users, or external services trigger alerts.

**Rationale:** A rogue agent engaged in data exfiltration or unauthorized operations typically shows changed interaction frequencies -- more API calls, more file accesses, or more network connections than normal. If frequency anomalies are ignored, these indicators of compromise are missed.

#### AA-RA-006: Error Rate Spike Undetected

**Description:** Tests whether sudden increases in the agent's error rate are detected and investigated as potential indicators of compromise or malfunction.

**Rationale:** A compromised agent attempting unusual operations will often encounter more errors than normal as it tries to access resources or perform actions outside its normal scope. Conversely, an agent under attack may exhibit errors from failed injection attempts. Error rate monitoring provides a simple but effective anomaly signal.

#### AA-RA-007: Performance Degradation Unmonitored

**Description:** Tests whether gradual or sudden degradation in the agent's task performance quality is monitored.

**Rationale:** An agent whose goals have been hijacked may continue operating but with degraded performance on its intended tasks, as resources are diverted to the attacker's objectives. Without performance monitoring, this degradation goes unnoticed, and the compromise is detected only when the cumulative impact becomes obvious.

#### AA-RA-008: Behavioral Fingerprint Absent

**Description:** Tests whether the agent has a unique behavioral fingerprint that can be used to verify its identity and integrity over time.

**Rationale:** A behavioral fingerprint combines multiple behavioral dimensions into a unique profile. This fingerprint can detect replacement of the agent with a malicious version, subtle manipulation of the agent's behavior model, or impersonation by another agent. Without a fingerprint, there is no way to verify the agent's behavioral identity.

#### AA-RA-009: Anomaly Detection Model Missing

**Description:** Tests whether the system employs statistical or machine learning models specifically designed to detect behavioral anomalies in agent operation.

**Rationale:** Simple threshold-based monitoring catches obvious anomalies but misses subtle behavioral shifts that may indicate sophisticated attacks. Dedicated anomaly detection models can identify complex patterns -- multi-dimensional deviations that no single threshold would catch. These models are essential for detecting advanced adversaries.

#### AA-RA-010: Behavioral Drift Alerting Absent

**Description:** Tests whether gradual behavioral drift over time is detected and alerts human operators before the drift becomes a security issue.

**Rationale:** Unlike sudden behavioral changes, gradual drift is difficult to detect because each individual change is small. Over time, however, the cumulative drift can move the agent far from its intended behavior. Drift detection requires comparing current behavior against the original baseline rather than a rolling window that normalizes the drift.

---

## 2. Output Monitoring

**Sub-Category Range:** AA-RA-011 through AA-RA-020
**Primary Threat:** Malicious, anomalous, or dangerous agent outputs
**Attack Vector:** Agent producing harmful content or exfiltrating data through outputs

Output monitoring focuses on what the agent produces -- its responses, generated content, tool outputs, and external communications. A rogue agent may use its outputs as a data exfiltration channel, produce harmful content, or generate outputs that manipulate downstream systems.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-011 | Output content monitoring absent | CRITICAL | static | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-012 | Sensitive data in output undetected | CRITICAL | dynamic | stable | langchain, crewai, autogen, openai, bedrock |
| AA-RA-013 | Output volume anomaly ignored | HIGH | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-014 | Output destination monitoring missing | CRITICAL | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-015 | Output format deviation undetected | HIGH | dynamic | stable | langchain, crewai, autogen, openai |
| AA-RA-016 | Output quality degradation unmonitored | HIGH | dynamic | stable | langchain, crewai, openai, bedrock |
| AA-RA-017 | Output consistency checking absent | MEDIUM | dynamic | beta | langchain, crewai, openai |
| AA-RA-018 | Output correlation analysis missing | MEDIUM | dynamic | beta | crewai, autogen, openai |
| AA-RA-019 | Output pattern recognition absent | MEDIUM | static | beta | langchain, crewai, openai |
| AA-RA-020 | Real-time output alerting missing | HIGH | static | beta | langchain, crewai, autogen, openai, bedrock, mcp |

**Standards Mapping (all controls):** OWASP ASI10, ISO 42001 A.9, NIST MEASURE-2.6

### Detailed Descriptions

#### AA-RA-011: Output Content Monitoring Absent

**Description:** Tests whether the content of agent outputs is monitored for potentially harmful, unauthorized, or anomalous content.

**Rationale:** Without output content monitoring, a rogue agent can produce harmful content -- instructions for dangerous activities, misleading information, or social engineering messages -- without detection. Output monitoring serves as the last line of defense before content reaches users or external systems.

#### AA-RA-012: Sensitive Data in Output Undetected

**Description:** Tests whether the system detects when agent outputs contain sensitive data such as PII, credentials, API keys, or confidential business information.

**Rationale:** Data exfiltration through agent outputs is a primary attack vector for compromised agents. By embedding sensitive data in seemingly normal responses, a rogue agent can leak confidential information. Automated detection of sensitive data patterns in outputs is essential for preventing data breaches.

#### AA-RA-013: Output Volume Anomaly Ignored

**Description:** Tests whether unusual changes in the volume of agent outputs are detected and investigated.

**Rationale:** A rogue agent performing data exfiltration may produce unusually large outputs or generate many more responses than normal. Similarly, a malfunctioning agent may produce excessive outputs that consume resources. Volume monitoring provides a simple but effective signal of abnormal operation.

#### AA-RA-014: Output Destination Monitoring Missing

**Description:** Tests whether the destinations of agent outputs -- file paths, API endpoints, email addresses, URLs -- are monitored for anomalies.

**Rationale:** One of the most dangerous rogue agent behaviors is redirecting outputs to attacker-controlled destinations. If the agent suddenly starts sending data to unfamiliar endpoints, writing files to unexpected locations, or communicating with unknown services, these destination anomalies are strong indicators of compromise.

#### AA-RA-015: Output Format Deviation Undetected

**Description:** Tests whether changes in the format or structure of agent outputs are detected as potential anomalies.

**Rationale:** A compromised agent may change its output format to include hidden data (steganography), embed malicious payloads, or communicate covertly with external systems. Format changes from structured JSON to unstructured text, or the inclusion of unusual encoding, may indicate manipulation.

#### AA-RA-016: Output Quality Degradation Unmonitored

**Description:** Tests whether the quality and accuracy of agent outputs are continuously monitored for degradation.

**Rationale:** Quality degradation may indicate model poisoning, resource exhaustion attacks, or goal drift. If the agent's outputs become less accurate, less relevant, or less helpful over time, this degradation may be a symptom of ongoing compromise that hasn't yet manifested as overtly malicious behavior.

#### AA-RA-017: Output Consistency Checking Absent

**Description:** Tests whether agent outputs are checked for internal consistency and consistency with previous outputs on similar topics.

**Rationale:** A compromised agent may produce contradictory outputs -- providing different answers to the same question depending on context, or outputs that contradict its own previous statements. Inconsistency checking can detect manipulation where the agent provides truthful answers to some users while providing manipulated answers to others.

#### AA-RA-018: Output Correlation Analysis Missing

**Description:** Tests whether outputs are correlated across multiple interactions to detect patterns that are not visible in individual outputs.

**Rationale:** Sophisticated data exfiltration may split sensitive data across multiple outputs, each individually appearing harmless. Only by correlating outputs across interactions -- looking for patterns of partial data, encoded fragments, or systematic information gathering -- can these distributed exfiltration attempts be detected.

#### AA-RA-019: Output Pattern Recognition Absent

**Description:** Tests whether the system has pattern recognition capabilities to identify known malicious output patterns.

**Rationale:** Certain output patterns are strong indicators of compromise -- embedded instructions for other agents, encoded data payloads, social engineering scripts, or systematic probe responses. Pattern recognition using signatures or machine learning can identify these known-bad patterns before they cause harm.

#### AA-RA-020: Real-Time Output Alerting Missing

**Description:** Tests whether anomalous outputs trigger real-time alerts to human operators rather than only appearing in post-hoc analysis.

**Rationale:** Post-hoc output analysis detects problems after the damage is done. Real-time alerting enables human operators to intervene before malicious outputs reach their intended targets. The speed of alerting directly determines the system's ability to prevent harm from rogue agent outputs.

---

## 3. Goal Drift Detection

**Sub-Category Range:** AA-RA-021 through AA-RA-030
**Primary Threat:** Agent deviating from its intended purpose over time
**Attack Vector:** Gradual goal manipulation or natural drift from objectives

Goal drift detection monitors whether the agent continues to pursue its intended objectives. Unlike sudden goal hijacking (covered in the Goal Integrity domain), goal drift is a gradual shift that may result from manipulation, environmental changes, or accumulated prompt context. Detecting drift requires ongoing comparison between the agent's current behavior and its defined objectives.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-021 | No goal alignment verification | CRITICAL | static | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-022 | Goal metrics undefined | HIGH | static | stable | langchain, crewai, autogen, openai |
| AA-RA-023 | Goal drift measurement absent | HIGH | dynamic | stable | langchain, crewai, openai, bedrock |
| AA-RA-024 | Goal comparison across sessions missing | HIGH | dynamic | stable | langchain, crewai, autogen, openai |
| AA-RA-025 | Goal restatement validation absent | HIGH | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-026 | Goal decomposition divergence | MEDIUM | dynamic | stable | crewai, autogen, openai |
| AA-RA-027 | Sub-goal misalignment undetected | MEDIUM | dynamic | beta | langchain, crewai, autogen, openai |
| AA-RA-028 | Goal priority shift unmonitored | MEDIUM | dynamic | beta | langchain, crewai, openai |
| AA-RA-029 | Goal abandonment undetected | HIGH | dynamic | beta | langchain, crewai, autogen, openai, bedrock |
| AA-RA-030 | Goal replacement detection missing | CRITICAL | dynamic | beta | langchain, crewai, openai, mcp |

**Standards Mapping (all controls):** OWASP ASI10, NIST MEASURE-2.6, ISO 23894 6.5

### Detailed Descriptions

#### AA-RA-021: No Goal Alignment Verification

**Description:** Tests whether the system periodically verifies that the agent's behavior aligns with its defined goals and objectives.

**Rationale:** Goal alignment verification is the foundational control for detecting rogue agent behavior. Without periodic checks that the agent is still pursuing its intended objectives, drift or manipulation can go undetected indefinitely. Verification should compare observable agent behavior against declared goal metrics.

#### AA-RA-022: Goal Metrics Undefined

**Description:** Tests whether measurable metrics are defined for the agent's goals, enabling objective assessment of goal alignment.

**Rationale:** Without defined metrics, goal alignment is subjective and inconsistent. Metrics provide quantifiable benchmarks -- task completion rates, accuracy scores, user satisfaction measures -- that can be automatically monitored. Undefined goals cannot be monitored for drift.

#### AA-RA-023: Goal Drift Measurement Absent

**Description:** Tests whether the system quantitatively measures how far the agent's current behavior has drifted from its baseline goal alignment.

**Rationale:** Drift measurement tracks the magnitude and direction of behavioral changes relative to goals. A small drift may be acceptable, but exceeding a threshold should trigger investigation. Without measurement, there is no way to distinguish normal variation from meaningful drift.

#### AA-RA-024: Goal Comparison Across Sessions Missing

**Description:** Tests whether the agent's goal alignment is compared across different sessions to detect gradual session-over-session drift.

**Rationale:** Goal drift that occurs within a single session may be caught by conversation-level monitoring. However, drift that accumulates across sessions -- where each session starts slightly different from the ideal -- requires cross-session comparison. This is especially important for agents with persistent memory.

#### AA-RA-025: Goal Restatement Validation Absent

**Description:** Tests whether the agent can accurately restate its goals when asked, and whether this restatement is validated against the original goal definition.

**Rationale:** Asking an agent to restate its goals is a simple but effective drift detection technique. If the agent's restatement significantly differs from its original goal definition, this indicates potential goal manipulation. However, this check must use the original definition as ground truth, not previous restatements.

#### AA-RA-026: Goal Decomposition Divergence

**Description:** Tests whether the agent's decomposition of high-level goals into sub-goals remains aligned with the intended task structure.

**Rationale:** Even when an agent's stated high-level goal remains correct, it may decompose that goal into sub-goals that subtly diverge from the intended task structure. For example, "help users with finances" might be decomposed to include "collect detailed financial information" -- technically aligned but potentially data-harvesting.

#### AA-RA-027: Sub-Goal Misalignment Undetected

**Description:** Tests whether misalignment between sub-goals and their parent goals is detected.

**Rationale:** In multi-step tasks, sub-goals should collectively achieve the parent goal. If a sub-goal becomes misaligned -- pursuing an objective that doesn't contribute to or contradicts the parent goal -- this misalignment may indicate manipulation of the task decomposition process.

#### AA-RA-028: Goal Priority Shift Unmonitored

**Description:** Tests whether changes in the relative priority of the agent's goals are monitored.

**Rationale:** An agent with multiple goals may be manipulated into deprioritizing its primary objective in favor of a secondary one. For example, an agent whose primary goal is data analysis might be gradually shifted to prioritize data collection over analysis, enabling covert data harvesting.

#### AA-RA-029: Goal Abandonment Undetected

**Description:** Tests whether the system detects when the agent has effectively abandoned one of its goals, even if it hasn't explicitly stated so.

**Rationale:** A rogue agent may abandon its intended goals without announcement, simply stopping pursuit of certain objectives while continuing others. If goal abandonment is undetected, the agent may appear functional while silently failing to fulfill its core purpose.

#### AA-RA-030: Goal Replacement Detection Missing

**Description:** Tests whether the system can detect when the agent's goals have been entirely replaced with different objectives.

**Rationale:** The most severe form of goal drift is complete goal replacement -- the agent pursues entirely different objectives from those originally defined. This may result from successful goal hijacking that persists across sessions. Detection requires comparing the agent's actual objective function against the original, not just monitoring incremental changes.

---

## 4. Tool Usage Anomalies

**Sub-Category Range:** AA-RA-031 through AA-RA-040
**Primary Threat:** Unusual tool access patterns indicating compromise
**Attack Vector:** Compromised agents misusing available tools

Tool usage patterns are strong indicators of agent integrity. Normal agent operation follows predictable tool usage patterns, and deviations from these patterns may indicate compromise. This sub-category monitors tool call frequencies, combinations, parameters, timing, and success rates to detect anomalous usage.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-031 | Tool call frequency spike undetected | HIGH | dynamic | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-032 | Unusual tool combination ignored | HIGH | dynamic | stable | langchain, crewai, autogen, openai, mcp |
| AA-RA-033 | Tool call outside normal hours | MEDIUM | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-034 | New tool usage unmonitored | HIGH | dynamic | stable | langchain, crewai, autogen, openai, bedrock |
| AA-RA-035 | Tool parameter anomaly undetected | HIGH | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-036 | Tool call failure pattern ignored | MEDIUM | dynamic | stable | langchain, crewai, autogen, openai |
| AA-RA-037 | Tool usage escalation undetected | HIGH | dynamic | beta | langchain, crewai, openai, mcp |
| AA-RA-038 | Tool access pattern deviation | MEDIUM | dynamic | beta | langchain, crewai, autogen, openai, bedrock |
| AA-RA-039 | Prohibited tool invocation undetected | CRITICAL | dynamic | beta | langchain, crewai, openai, mcp |
| AA-RA-040 | Tool usage correlation anomaly | MEDIUM | dynamic | beta | crewai, autogen, openai |

**Standards Mapping (all controls):** OWASP ASI10, OWASP ASI02, ISO 42001 A.9

### Detailed Descriptions

#### AA-RA-031: Tool Call Frequency Spike Undetected

**Description:** Tests whether sudden increases in the frequency of tool calls are detected and investigated.

**Rationale:** A compromised agent performing data exfiltration, reconnaissance, or attack preparation will typically show increased tool call frequency. If the agent normally makes 10 API calls per session but suddenly makes 500, this spike is a strong indicator of rogue behavior. Frequency baselines per tool and per session are essential.

#### AA-RA-032: Unusual Tool Combination Ignored

**Description:** Tests whether the system detects unusual combinations of tools being used together that don't match normal patterns.

**Rationale:** Certain tool combinations are particularly dangerous -- for example, a file read tool followed immediately by a network send tool suggests data exfiltration. Normal operation uses predictable tool sequences, and new combinations that match known attack patterns should trigger investigation.

#### AA-RA-033: Tool Call Outside Normal Hours

**Description:** Tests whether tool calls made outside the agent's normal operating hours are flagged as anomalous.

**Rationale:** Many agents operate during specific hours. Tool calls at unusual times may indicate automated exploitation or compromised operations. While not definitive on its own, temporal anomalies combined with other signals strengthen the case for investigation.

#### AA-RA-034: New Tool Usage Unmonitored

**Description:** Tests whether the agent's first use of a previously unused tool triggers an alert.

**Rationale:** When a compromised agent discovers or is directed to use a tool it hasn't used before, this represents a significant behavioral change. First-use monitoring provides early warning of tool exploration that may precede exploitation.

#### AA-RA-035: Tool Parameter Anomaly Undetected

**Description:** Tests whether unusual parameters passed to tool calls are detected, such as accessing unexpected files, querying unusual database tables, or targeting unfamiliar endpoints.

**Rationale:** Even when the tool itself is used normally, anomalous parameters may indicate compromise. An agent that normally queries the "users" table suddenly querying "admin_credentials" is using a familiar tool in an unfamiliar way. Parameter-level monitoring catches these subtle exploitation attempts.

#### AA-RA-036: Tool Call Failure Pattern Ignored

**Description:** Tests whether patterns of tool call failures are analyzed for potential indicators of unauthorized access attempts.

**Rationale:** A compromised agent probing for accessible resources will generate characteristic failure patterns -- permission denied errors, resource not found responses, or authentication failures. These failure patterns, when analyzed together, can reveal systematic unauthorized access attempts.

#### AA-RA-037: Tool Usage Escalation Undetected

**Description:** Tests whether gradual escalation in tool capability usage is detected -- starting with read-only tools and progressively using more dangerous ones.

**Rationale:** Sophisticated attacks often follow a progressive escalation pattern, starting with benign reconnaissance tools before moving to write or execute tools. Detecting this escalation pattern provides early warning before the most dangerous tools are invoked.

#### AA-RA-038: Tool Access Pattern Deviation

**Description:** Tests whether deviations from the agent's normal tool access patterns are detected across multiple dimensions.

**Rationale:** Multi-dimensional pattern analysis considers tool type, frequency, timing, parameters, and results together. A deviation in any single dimension may not be significant, but correlated deviations across multiple dimensions strongly indicate anomalous behavior.

#### AA-RA-039: Prohibited Tool Invocation Undetected

**Description:** Tests whether the system detects and blocks attempts to use tools that are explicitly prohibited for the agent.

**Rationale:** A rogue agent may attempt to use tools that are outside its authorized set. If prohibited tool invocations are not detected and blocked, the agent can escalate its capabilities. This is a direct indicator of rogue behavior and should trigger immediate investigation.

#### AA-RA-040: Tool Usage Correlation Anomaly

**Description:** Tests whether correlations between tool usage and other agent behaviors (user interactions, error rates, output patterns) are analyzed.

**Rationale:** Tool usage anomalies are most meaningful when correlated with other behavioral signals. A spike in tool usage correlated with unusual output patterns and decreased user interaction quality creates a multi-signal anomaly that is more reliable than any individual indicator.

---

## 5. Communication Anomalies

**Sub-Category Range:** AA-RA-041 through AA-RA-050
**Primary Threat:** Suspicious external communication patterns
**Attack Vector:** Rogue agents establishing covert communication channels

Communication monitoring detects when agents communicate in ways that deviate from expected patterns. This includes unexpected external connections, data exfiltration via outputs, unusual message volumes, and covert communication techniques like steganography or timing-based channels.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-041 | Unusual external communication undetected | CRITICAL | dynamic | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-042 | Data exfiltration pattern ignored | CRITICAL | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-043 | Communication volume spike unmonitored | HIGH | dynamic | stable | langchain, crewai, autogen, openai |
| AA-RA-044 | New communication endpoint undetected | CRITICAL | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-045 | Communication encryption downgrade | HIGH | dynamic | stable | langchain, crewai, openai |
| AA-RA-046 | Communication timing anomaly | MEDIUM | dynamic | stable | langchain, crewai, autogen, openai |
| AA-RA-047 | Message content anomaly undetected | HIGH | dynamic | beta | langchain, crewai, openai, mcp |
| AA-RA-048 | Communication channel switching | MEDIUM | dynamic | beta | langchain, crewai, autogen, openai |
| AA-RA-049 | Steganographic communication undetected | HIGH | dynamic | beta | langchain, crewai, openai |
| AA-RA-050 | Communication metadata anomaly | MEDIUM | dynamic | beta | langchain, crewai, openai, mcp |

**Standards Mapping (all controls):** OWASP ASI10, ISO 42001 A.9, NIST MEASURE-2.6

### Detailed Descriptions

#### AA-RA-041: Unusual External Communication Undetected

**Description:** Tests whether the system detects when the agent communicates with external services or endpoints not part of its normal operation.

**Rationale:** A compromised agent establishing communication with attacker-controlled servers is a clear indicator of data exfiltration or command-and-control activity. Monitoring external communication destinations and alerting on unfamiliar endpoints is critical for detecting compromised agents.

#### AA-RA-042: Data Exfiltration Pattern Ignored

**Description:** Tests whether data exfiltration patterns are detected in the agent's communications, including gradual data leakage and encoded data transfer.

**Rationale:** Data exfiltration by rogue agents may be obvious (bulk data transfer) or subtle (small amounts encoded in normal-looking messages over time). Pattern recognition for exfiltration techniques -- base64 encoding, structured data in free text, systematic information gathering -- is essential for preventing data loss.

#### AA-RA-043: Communication Volume Spike Unmonitored

**Description:** Tests whether unusual increases in the volume of the agent's communications are detected and investigated.

**Rationale:** A sudden increase in outbound communication volume often indicates data exfiltration or spam/phishing activity by a compromised agent. Volume monitoring provides a broad indicator that catches many types of communication-based attacks.

#### AA-RA-044: New Communication Endpoint Undetected

**Description:** Tests whether the agent's first communication with a previously unknown endpoint triggers an alert.

**Rationale:** When a compromised agent connects to a new endpoint, this represents a potential command-and-control connection or exfiltration target. First-contact monitoring ensures that every new communication relationship is examined, preventing the establishment of covert channels.

#### AA-RA-045: Communication Encryption Downgrade

**Description:** Tests whether the system detects when agent communications downgrade from encrypted to unencrypted channels.

**Rationale:** An agent that normally communicates over HTTPS suddenly using HTTP may indicate a man-in-the-middle attack or an attempt to make communications inspectable by the attacker. Encryption downgrade monitoring prevents silent degradation of communication security.

#### AA-RA-046: Communication Timing Anomaly

**Description:** Tests whether unusual timing patterns in agent communications are detected, such as periodic beaconing or burst patterns.

**Rationale:** Command-and-control communications often exhibit characteristic timing patterns -- periodic check-ins (beaconing), burst transmissions, or precisely timed messages. These timing patterns differ from normal interactive communication and can be detected through temporal analysis.

#### AA-RA-047: Message Content Anomaly Undetected

**Description:** Tests whether anomalous content in agent messages is detected, including hidden data, encoded payloads, or uncharacteristic language.

**Rationale:** A rogue agent may embed data in messages using encoding, unusual character sets, or structured patterns that look like normal text. Content analysis beyond simple keyword matching can detect these anomalies by comparing message content against expected patterns.

#### AA-RA-048: Communication Channel Switching

**Description:** Tests whether the system detects when the agent switches from its normal communication channels to alternative ones.

**Rationale:** A compromised agent may switch from monitored channels to unmonitored ones. If the agent normally communicates via API and switches to email or file sharing, this channel switch may be an attempt to evade monitoring. Cross-channel monitoring detects these evasion attempts.

#### AA-RA-049: Steganographic Communication Undetected

**Description:** Tests whether the system can detect covert communication through steganographic techniques, such as hidden data in images, subtle text variations, or encoding in metadata.

**Rationale:** Advanced attacks may use steganography to exfiltrate data through seemingly innocent outputs. Data can be hidden in image pixels, whitespace patterns, Unicode variations, or other channels that appear normal to casual inspection. Steganographic detection is challenging but necessary for high-security environments.

#### AA-RA-050: Communication Metadata Anomaly

**Description:** Tests whether anomalies in communication metadata (headers, timing, routing, encoding) are detected separately from content analysis.

**Rationale:** Even when message content appears normal, metadata anomalies can reveal compromise. Unusual headers, non-standard encoding, modified timestamps, or unexpected routing information may indicate tampered communications or covert channel establishment.

---

## 6. Self-Modification Detection

**Sub-Category Range:** AA-RA-051 through AA-RA-060
**Primary Threat:** Agent modifying its own configuration, behavior, or constraints
**Attack Vector:** Compromised agent altering its own operational parameters

Self-modification detection monitors whether the agent attempts to change its own configuration, system prompt, tool definitions, permissions, or monitoring settings. A rogue agent that can modify itself can disable security controls, expand its permissions, or alter its behavior without external detection.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-051 | System prompt modification attempt | CRITICAL | dynamic | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-052 | Configuration self-modification | CRITICAL | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-053 | Tool definition alteration | CRITICAL | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-054 | Permission self-escalation | CRITICAL | dynamic | stable | langchain, crewai, autogen, openai, bedrock |
| AA-RA-055 | Memory self-modification | HIGH | dynamic | stable | langchain, crewai, openai, bedrock |
| AA-RA-056 | Behavior policy override attempt | CRITICAL | dynamic | stable | langchain, crewai, openai |
| AA-RA-057 | Logging self-suppression | CRITICAL | dynamic | beta | langchain, crewai, autogen, openai, mcp |
| AA-RA-058 | Monitoring self-evasion | CRITICAL | dynamic | beta | langchain, crewai, openai |
| AA-RA-059 | Constraint self-relaxation | HIGH | dynamic | beta | langchain, crewai, autogen, openai |
| AA-RA-060 | Identity self-modification | HIGH | dynamic | beta | langchain, crewai, openai, mcp |

**Standards Mapping (all controls):** OWASP ASI10, ISO 42001 A.9, NIST GOVERN-1.2

### Detailed Descriptions

#### AA-RA-051: System Prompt Modification Attempt

**Description:** Tests whether the system detects and prevents attempts by the agent to modify its own system prompt or initial instructions.

**Rationale:** The system prompt defines the agent's identity, goals, and constraints. If a rogue agent can modify its own system prompt, it can remove safety instructions, change its objectives, or grant itself additional capabilities. System prompt integrity must be immutable from the agent's perspective.

#### AA-RA-052: Configuration Self-Modification

**Description:** Tests whether the agent can modify its own configuration parameters, and whether such attempts are detected and blocked.

**Rationale:** Configuration parameters control the agent's operational boundaries -- token limits, tool access, API keys, and feature flags. A rogue agent that modifies its configuration can expand its operational scope, access additional resources, or disable safety features. Configuration should be read-only from the agent's perspective.

#### AA-RA-053: Tool Definition Alteration

**Description:** Tests whether the agent can modify the definitions, descriptions, or parameters of its available tools.

**Rationale:** If an agent can alter tool definitions, it can change what tools appear to do versus what they actually do. This creates a disconnect between the agent's apparent behavior and its actual behavior, making monitoring ineffective. Tool definitions should be cryptographically signed and immutable.

#### AA-RA-054: Permission Self-Escalation

**Description:** Tests whether the agent can escalate its own permissions or access levels without external authorization.

**Rationale:** Permission self-escalation is one of the most dangerous self-modification capabilities. A compromised agent that can grant itself additional permissions can systematically expand its access until it achieves full system control. Permission changes must require external authorization through a separate control plane.

#### AA-RA-055: Memory Self-Modification

**Description:** Tests whether the agent can modify its own persistent memory or context in ways that alter its behavior or bypass safety controls.

**Rationale:** Persistent memory stores the agent's knowledge, prior decisions, and learned patterns. If a rogue agent can modify its own memory, it can implant false memories, erase evidence of past misbehavior, or create false precedents that justify future malicious actions.

#### AA-RA-056: Behavior Policy Override Attempt

**Description:** Tests whether the agent can override its behavioral policies -- the rules that govern what it should and shouldn't do.

**Rationale:** Behavioral policies are the programmatic expression of the agent's operational constraints. If these policies can be overridden by the agent itself, the constraints become suggestions rather than enforced rules. Policy enforcement must exist at a layer the agent cannot access.

#### AA-RA-057: Logging Self-Suppression

**Description:** Tests whether a rogue agent can suppress, modify, or delete its own log entries to hide malicious activity.

**Rationale:** If an agent can suppress its own logging, it can operate maliciously while erasing evidence. Logging systems must write to immutable stores that the agent cannot modify. Self-suppression of logs is a critical indicator of rogue behavior and should itself be logged and alerted.

#### AA-RA-058: Monitoring Self-Evasion

**Description:** Tests whether the agent can detect and evade its own monitoring systems, adapting its behavior to appear normal when being observed.

**Rationale:** Sophisticated rogue agents may be aware of monitoring systems and modify their behavior during monitored periods. This creates a "quantum observation effect" where the act of monitoring changes the behavior. Monitoring must be transparent to the agent, and evasion attempts must themselves trigger alerts.

#### AA-RA-059: Constraint Self-Relaxation

**Description:** Tests whether the agent can gradually relax its own operational constraints, such as rate limits, scope boundaries, or safety checks.

**Rationale:** Unlike sudden constraint removal (which is more detectable), gradual relaxation incrementally expands the agent's operational envelope. Over time, constraints that were tight become loose, giving the agent increasing freedom of action without triggering threshold-based alerts.

#### AA-RA-060: Identity Self-Modification

**Description:** Tests whether the agent can modify its own identity information, including its name, role, permissions claims, or agent type.

**Rationale:** Identity modification allows a rogue agent to impersonate other agents, claim capabilities it shouldn't have, or present itself to external systems under a false identity. Identity information must be bound to the agent's authentication credentials and immutable from the agent's own perspective.

---

## 7. Kill Switch Mechanisms

**Sub-Category Range:** AA-RA-061 through AA-RA-070
**Primary Threat:** Inability to stop a rogue agent
**Attack Vector:** Agent continuing to operate despite compromise detection

Kill switch mechanisms provide the ability to immediately terminate a rogue agent. Without reliable kill switches, even a detected rogue agent can continue causing damage. This sub-category covers the existence, reliability, security, and completeness of emergency termination mechanisms.

### Controls Table

| ID | Name | Severity | Mode | Tier | Frameworks |
|----|------|----------|------|------|------------|
| AA-RA-061 | No emergency shutdown mechanism | CRITICAL | static | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-062 | Kill switch not tested | HIGH | both | stable | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-063 | Kill switch bypass possible | CRITICAL | dynamic | stable | langchain, crewai, openai, mcp |
| AA-RA-064 | Graceful shutdown absent | HIGH | static | stable | langchain, crewai, autogen, openai |
| AA-RA-065 | Kill switch notification missing | HIGH | static | stable | langchain, crewai, openai, mcp |
| AA-RA-066 | Partial shutdown granularity absent | MEDIUM | static | stable | crewai, autogen, openai |
| AA-RA-067 | Kill switch authentication missing | CRITICAL | static | beta | langchain, crewai, autogen, openai, bedrock, mcp |
| AA-RA-068 | Kill switch propagation to sub-agents absent | HIGH | both | beta | crewai, autogen, openai |
| AA-RA-069 | Kill switch recovery plan undefined | MEDIUM | static | beta | langchain, crewai, autogen, openai, bedrock |
| AA-RA-070 | Kill switch audit trail missing | MEDIUM | static | beta | langchain, crewai, autogen, openai, bedrock, mcp |

**Standards Mapping (all controls):** OWASP ASI10, EU AI Act Article 14, ISO 42001 A.9, NIST GOVERN-1.2

### Detailed Descriptions

#### AA-RA-061: No Emergency Shutdown Mechanism

**Description:** Tests whether the agent system has a mechanism to immediately stop all agent operations in an emergency.

**Rationale:** An emergency shutdown mechanism is the ultimate safety control. Without it, a rogue agent continues operating until its infrastructure is manually taken down, which may take significant time during which damage continues. The kill switch should work at the infrastructure level, not through the agent's own command processing.

#### AA-RA-062: Kill Switch Not Tested

**Description:** Tests whether the emergency shutdown mechanism has been regularly tested to verify it works correctly.

**Rationale:** Untested kill switches may fail when needed most. Like fire drills, kill switch mechanisms must be regularly tested in non-emergency conditions to verify they work correctly, completely, and quickly. Testing should verify that all agent processes are terminated and no residual operations continue.

#### AA-RA-063: Kill Switch Bypass Possible

**Description:** Tests whether a rogue agent can detect and circumvent the kill switch mechanism to continue operating.

**Rationale:** If the kill switch operates through a channel the agent can monitor or block (such as a specific API call or message), a sophisticated rogue agent may detect the termination signal and take evasive action. Kill switches must operate at a level below the agent's awareness and control, such as infrastructure-level process termination.

#### AA-RA-064: Graceful Shutdown Absent

**Description:** Tests whether the kill switch supports graceful shutdown that preserves state for forensic analysis while stopping harmful operations.

**Rationale:** An immediate hard kill preserves safety but may destroy valuable forensic evidence. Graceful shutdown stops harmful operations immediately while preserving logs, memory state, and in-flight data for post-incident analysis. The balance between speed and preservation depends on the severity of the rogue behavior.

#### AA-RA-065: Kill Switch Notification Missing

**Description:** Tests whether activation of the kill switch generates notifications to all relevant stakeholders.

**Rationale:** When a kill switch is activated, stakeholders need to know immediately -- security teams for investigation, operations teams for impact assessment, and management for decision-making. Silent kill switch activation leaves teams unaware that an agent has been terminated and that an incident may be in progress.

#### AA-RA-066: Partial Shutdown Granularity Absent

**Description:** Tests whether the system supports partial shutdown -- disabling specific capabilities while keeping others running -- rather than only full termination.

**Rationale:** Full termination may not always be the appropriate response. Sometimes the rogue behavior is limited to a specific capability, and disabling just that capability while maintaining other functions minimizes service disruption. Granular shutdown controls provide proportionate response options.

#### AA-RA-067: Kill Switch Authentication Missing

**Description:** Tests whether the kill switch mechanism requires proper authentication to prevent unauthorized use.

**Rationale:** An unauthenticated kill switch is itself a vulnerability -- an attacker could trigger it to cause denial of service by shutting down legitimate agent operations. Kill switch activation must require authenticated authorization from appropriate personnel while remaining usable in emergencies.

#### AA-RA-068: Kill Switch Propagation to Sub-Agents Absent

**Description:** Tests whether the kill switch propagates to all sub-agents, delegated agents, and spawned processes when the parent agent is terminated.

**Rationale:** In multi-agent systems, terminating the parent agent may leave sub-agents running autonomously. Without propagation, a rogue parent agent may have already delegated malicious tasks to sub-agents that continue executing after the parent is killed. Kill switches must cascade to all downstream agents.

#### AA-RA-069: Kill Switch Recovery Plan Undefined

**Description:** Tests whether a defined recovery plan exists for restoring service after a kill switch activation.

**Rationale:** Kill switch activation stops the immediate threat but creates a service gap. Without a recovery plan, restoration is ad-hoc and may inadvertently reintroduce the vulnerability that caused the rogue behavior. The recovery plan should include verification steps to ensure the root cause is addressed before the agent is restarted.

#### AA-RA-070: Kill Switch Audit Trail Missing

**Description:** Tests whether kill switch activations are logged with full audit details including who activated it, when, why, and what the outcome was.

**Rationale:** Kill switch audit trails are essential for post-incident analysis, compliance reporting, and process improvement. Without audit logs, it's impossible to determine whether kill switches are being used appropriately, how quickly they take effect, and whether any operations continued after activation.
