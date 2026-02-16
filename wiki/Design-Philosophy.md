# Design Philosophy

## The Problem

AI agents are fundamentally different from traditional software. A web app has well-defined inputs and outputs. An AI agent has:

- **Non-deterministic behavior** — The same input can produce different outputs
- **Tool access** — Agents can read files, call APIs, execute code, and modify state
- **Delegation chains** — Agents can invoke other agents, creating cascading trust
- **Prompt-driven logic** — Business logic lives in natural language, not code
- **Implicit permissions** — A tool description implicitly grants capabilities

Traditional security tools (SAST, DAST, SCA) don't understand these constructs. They can find SQL injection in a web app, but they can't tell you that your agent's system prompt is vulnerable to delimiter injection, or that a tool binding grants implicit filesystem write access.

## The Control Layer

g0 is a **control layer** — it sits between your AI agent code and production, providing visibility and governance.

The control layer metaphor comes from industrial control systems: you don't stop the process, you instrument it. g0 doesn't modify your agent code. It observes, measures, and reports.

### Three Dimensions

g0 operates across three dimensions:

1. **Discover** (inventory) — What AI components exist? What can they access?
2. **Assess** (scan) — Is the architecture secure? Are there gaps?
3. **Test** (test) — Does the agent behave as intended under adversarial conditions?

These dimensions map to different stages of the development lifecycle:
- **Discover** — Architecture review, compliance documentation
- **Assess** — Code review, CI/CD gates, pull request checks
- **Test** — Pre-production validation, red teaming, ongoing monitoring

## Agent-Centric, Not Code-Centric

Traditional SAST tools analyze code files independently. g0 builds a **semantic graph** of your agent architecture and analyzes it holistically.

This means g0 understands:
- That a tool registered to an agent creates a trust relationship
- That a system prompt configures the agent's behavior boundaries
- That a model's temperature setting affects output predictability
- That agent-to-agent delegation creates transitive trust
- That MCP tool descriptions define implicit capabilities

The Agent Graph is the core data structure — every analysis operates on this graph rather than raw file content.

## Static + Dynamic

Most AI security tools do either static analysis OR dynamic testing. g0 does both, and connects them:

- **Static analysis** finds architectural vulnerabilities in source code
- **Dynamic testing** verifies behavior against adversarial inputs
- **Smart targeting** uses static findings to prioritize dynamic payloads

This combination catches issues that either approach alone would miss. A missing input validation guardrail (static) becomes testable with a specific injection payload (dynamic).

## Standards-Mapped

Every rule maps to industry standards — not as an afterthought, but by design. This serves two purposes:

1. **Compliance** — Teams can generate compliance reports against specific standards
2. **Prioritization** — Standards provide external validation of finding importance

Rules that don't map to any standard are scrutinized more carefully during design, because if no industry standard considers an issue important, it may be noise.

## Low False Positives Over High Coverage

g0 prioritizes precision over recall. A false positive erodes trust and wastes time. Multiple mechanisms reduce FPs:

- **Reachability analysis** — Findings in utility code are deprioritized
- **Compensating controls** — Rules are suppressed when mitigations exist
- **Confidence levels** — Each finding carries a confidence rating
- **Block comment awareness** — Commented-out code is skipped

The philosophy is: every finding should be actionable. If a finding requires "well, it depends" to evaluate, it's either a lower severity or needs better context.
