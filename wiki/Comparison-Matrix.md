# Comparison Matrix

How g0 compares to other tools in the AI security and general security space.

## Overview

| Feature | g0 | Semgrep | Snyk Code | Garak | Promptfoo |
|---------|-----|---------|-----------|-------|-----------|
| **Focus** | AI agent security | General SAST | General SAST + SCA | LLM red teaming | LLM evaluation |
| **Analysis Type** | Static + Dynamic | Static | Static + SCA | Dynamic | Dynamic |
| **AI Agent Awareness** | Yes | No | No | Partial | Partial |
| **Agent Graph** | Yes | No | No | No | No |
| **Framework Parsers** | 10 | Generic | Generic | N/A | N/A |
| **Security Domains** | 12 AI-specific | Generic | Generic | N/A | N/A |
| **Standards Mapping** | 10 standards | CWE | CWE, CVE | N/A | N/A |
| **Adversarial Testing** | Yes | No | No | Yes | Yes |
| **Adaptive Multi-Turn Attacks** | Yes (5 strategies) | No | No | No | No |
| **CVSS Scoring for Findings** | Yes (3.1) | No | No | No | No |
| **AI-BOM/Inventory** | Yes | No | SCA only | No | No |
| **MCP Security** | Yes | No | No | No | No |
| **Scoring** | 0-100 with grades | Findings only | Priority score | Pass/Fail | Scores |
| **Languages** | Py, TS, JS, Java, Go | 30+ | 10+ | N/A | N/A |
| **CI/CD Integration** | SARIF, gate command | SARIF | Dashboard | JSON | JSON |
| **Free** | Yes | Freemium | Freemium | Yes | Yes |

## Detailed Comparisons

### g0 vs Semgrep

**Semgrep** is a general-purpose SAST tool with a large rule library covering OWASP Top 10 web vulnerabilities.

**Where Semgrep is stronger:**
- Broader language support (30+ languages)
- Larger community rule library
- More mature pattern matching engine
- Generic web vulnerability detection (SQLi, XSS, etc.)

**Where g0 is stronger:**
- Understands AI agent constructs (agents, tools, prompts, models)
- Builds a semantic Agent Graph, not just file-level patterns
- 12 AI-specific security domains
- AI-BOM inventory generation
- MCP security assessment with rug-pull detection
- Dynamic adversarial testing
- 10 AI-specific standards (OWASP Agentic, NIST AI RMF, etc.)
- Reachability scoring specific to agent execution paths

**When to use both:** Semgrep for general web/API security, g0 for AI agent-specific security. They complement each other in a CI pipeline.

### g0 vs Snyk Code

**Snyk** provides SAST, SCA, container scanning, and IaC scanning.

**Where Snyk is stronger:**
- SCA vulnerability database (CVE tracking)
- Container and IaC scanning
- Broader ecosystem integration
- Auto-fix suggestions

**Where g0 is stronger:**
- AI-specific analysis (same advantages as vs Semgrep)
- Agent Graph construction
- AI-BOM (beyond package SCA)
- Dynamic adversarial testing
- AI standards mapping

**When to use both:** Snyk for general dependency and container security, g0 for AI agent analysis.

### g0 vs Garak

**Garak** is an LLM vulnerability scanner focused on dynamic probing.

**Where Garak is stronger:**
- Larger payload library for LLM probing
- More LLM provider integrations
- Deeper focus on model-level attacks
- Plugin architecture for custom probes

**Where g0 is stronger:**
- Static analysis of source code (Garak is dynamic only)
- Agent architecture analysis (tools, prompts, delegation)
- Source code vulnerability detection
- AI-BOM and inventory
- Standards compliance mapping
- Smart targeting (static → dynamic)
- MCP security

**When to use both:** g0 for static analysis and architecture review, Garak for deep model-level probing. g0's `--auto` flag bridges the gap by using static findings to prioritize dynamic tests.

### g0 vs Promptfoo

**Promptfoo** is an LLM evaluation framework for testing prompts and models.

**Where Promptfoo is stronger:**
- Prompt optimization and A/B testing
- Custom evaluation criteria
- Broader evaluation use cases (accuracy, not just security)
- YAML-based test definitions

**Where g0 is stronger:**
- Static analysis of agent source code
- Agent Graph and architecture analysis
- 12 security domain coverage
- AI-BOM and inventory
- Standards compliance mapping
- MCP security

**When to use both:** Promptfoo for prompt engineering and quality evaluation, g0 for security assessment. They address different stages of the development lifecycle.

## When to Use g0

g0 is the right choice when you need to:

- **Assess AI agent security** across the full codebase, not just test the model
- **Inventory AI components** for compliance and governance
- **Map to industry standards** (OWASP Agentic, NIST AI RMF, ISO 42001, EU AI Act)
- **Secure MCP deployments** with tool description pinning
- **Gate CI/CD pipelines** based on AI security scoring
- **Bridge static and dynamic** with smart targeting

g0 is not a replacement for general-purpose SAST (Semgrep, Snyk) or deep model probing (Garak). It fills the gap between them — the AI agent architecture layer that neither addresses.
