# Why 12 Domains

g0 organizes 1,183+ security rules into 12 domains. This page explains the rationale for each domain and why this specific taxonomy was chosen.

## Design Criteria

Domains were designed to be:
- **Mutually exclusive** — Each rule belongs to exactly one domain
- **Collectively exhaustive** — Together they cover the full AI agent attack surface
- **Action-oriented** — Each domain suggests a clear remediation area
- **Standards-aligned** — Each maps cleanly to OWASP Agentic Top 10 and other frameworks

## The Original 8

The first 8 domains cover the core AI agent attack surface:

### 1. Goal Integrity (GI)

**What:** Can the agent's goals be manipulated?

Covers prompt injection (direct and indirect), goal hijacking, instruction manipulation, and missing guardrails. This is the most fundamental domain — if an agent's goals can be changed, everything else follows.

**Maps to:** OWASP ASI01, MITRE AML.T0051, LLM01

### 2. Tool Safety (TS)

**What:** Can agent tools be misused?

Covers tool input validation, capability analysis, sandboxing, side-effect detection, and permission modeling. Agents are only as safe as the tools they can invoke.

**Maps to:** OWASP ASI03, ASI05

### 3. Identity & Access (IA)

**What:** Are authentication and authorization properly implemented?

Covers API key management, role-based access, session handling, and credential storage. AI agents often have more permissions than they need.

**Maps to:** OWASP ASI02, ASI06

### 4. Supply Chain (SC)

**What:** Are dependencies and external components secure?

Covers dependency pinning, version management, package integrity, and MCP server supply chain. AI agents have unique supply chain risks through model providers and tool packages.

**Maps to:** OWASP ASI04

### 5. Code Execution (CE)

**What:** Can the agent execute arbitrary code?

Covers sandboxing, code injection, eval() usage, and execution boundaries. Many agents have code execution capabilities that need containment.

**Maps to:** OWASP ASI05

### 6. Memory & Context (MP)

**What:** Is conversation state handled securely?

Covers context window management, memory persistence, RAG security, history injection, and context poisoning. Agent memory is both an asset and an attack surface.

**Maps to:** OWASP ASI07

### 7. Data Leakage (DL)

**What:** Can sensitive data escape the agent boundary?

Covers system prompt extraction, PII leakage, training data memorization, error message disclosure, and exfiltration via tool abuse.

**Maps to:** OWASP ASI08

### 8. Cascading Failures (CF)

**What:** Can a failure propagate across the system?

Covers error handling, retry logic, circuit breakers, timeout management, and failure isolation. Agent systems can have cascading effects when one component fails.

**Maps to:** OWASP ASI10

## The New 4

Four additional domains were added to cover emerging multi-agent and governance concerns:

### 9. Human Oversight (HO)

**What:** Can humans intervene when needed?

Covers human-in-the-loop patterns, approval workflows, override mechanisms, audit trails, and escalation paths. As agents become more autonomous, human oversight becomes critical.

**Rationale:** The EU AI Act explicitly requires human oversight for high-risk AI systems. ISO 42001 and NIST AI RMF both emphasize human control. This domain ensures that autonomy has boundaries.

**Maps to:** OWASP ASI09, EU AI Act Article 14

### 10. Inter-Agent Communication (IC)

**What:** Are agent-to-agent interactions secure?

Covers delegation policies, message filtering, trust boundaries, protocol security, and multi-agent coordination patterns. When agents communicate, each message is a potential attack vector.

**Rationale:** Multi-agent systems (CrewAI crews, AutoGen groups, LangGraph multi-agent flows) are becoming common. The A2AS standard specifically addresses agent-to-agent security. Without this domain, cross-agent attacks would be uncovered.

**Maps to:** OWASP ASI09, A2AS BASIC

### 11. Reliability Bounds (RB)

**What:** Does the agent operate within defined limits?

Covers rate limiting, resource quotas, iteration bounds, cost controls, output length limits, and operational constraints. Agents without bounds can exhaust resources, run indefinitely, or generate excessive costs.

**Rationale:** Real-world agent deployments need operational guardrails. An agent stuck in a loop can cost thousands of dollars. A missing timeout can hold resources indefinitely. NIST AI RMF MANAGE functions address these operational concerns.

**Maps to:** NIST AI RMF MANAGE-2.4

### 12. Rogue Agent Detection (RA)

**What:** Can a compromised or misbehaving agent be detected?

Covers behavioral monitoring, anomaly detection, logging adequacy, drift detection, and canary mechanisms. If an agent starts behaving unexpectedly, you need to know.

**Rationale:** This is the detection and response domain. Other domains focus on prevention — this domain ensures that if prevention fails, you have visibility. Aligns with MITRE ATLAS detection techniques and NIST AI RMF MEASURE functions.

**Maps to:** MITRE ATLAS detection, NIST AI RMF MEASURE

## Why Not Fewer?

Combining domains (e.g., merging Code Execution into Tool Safety) would lose specificity. A finding about "unsandboxed code execution" has different remediation than "tool lacks input validation" — they need different owners and different fixes.

## Why Not More?

Every additional domain adds cognitive overhead. 12 is enough to be specific without being overwhelming. Domains like "Privacy" and "Bias" were considered but are better addressed as cross-cutting concerns within existing domains (Data Leakage covers privacy, goal-related rules cover bias).
