# g0 Documentation

Welcome to the g0 documentation. g0 is the security control layer for AI agents — it discovers, assesses, and tests your AI agent infrastructure across 12 security domains.

## Getting Started

- [**Getting Started**](getting-started.md) — Install g0, run your first scan, and understand the output

## Core Concepts

- [**Architecture**](architecture.md) — How the g0 pipeline works: discovery, parsing, analysis, scoring
- [**Rules Reference**](rules.md) — All 1,183+ rules across 12 security domains
- [**Custom Rules**](custom-rules.md) — Write your own YAML rules with 11 check types
- [**Scoring Methodology**](scoring.md) — How the 0-100 score is calculated
- [**Compliance Mapping**](compliance.md) — 10 industry standards and how rules map to them

## Usage Guides

- [**Understanding Findings**](findings.md) — Finding anatomy, filtering, suppression, and triage
- [**AI Asset Inventory**](inventory.md) — Discover and document all AI components (AI-BOM)
- [**MCP Security**](mcp-security.md) — Assess MCP servers, detect rug-pulls, pin tool descriptions
- [**Dynamic Testing**](dynamic-testing.md) — 3,800+ adversarial payloads, 20 mutators, canary tokens, multi-turn strategies, per-category LLM judge
- [**Framework Guide**](frameworks.md) — Per-framework detection, patterns, and findings

## Integration

- [**Endpoint Monitoring**](endpoint-monitoring.md) — Fleet-wide daemon, heartbeats, drift detection
- [**CI/CD Integration**](ci-cd.md) — GitHub Actions, GitLab CI, Jenkins, pre-commit hooks
- [**Programmatic API**](api.md) — Use g0 as a library in your own tools

## Reference

- [**FAQ**](faq.md) — Common questions and answers
- [**Glossary**](glossary.md) — Key terms and concepts
- [**Control Domain Specs**](controls/) — Detailed specifications for each security domain
