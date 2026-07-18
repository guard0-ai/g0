# g0 Documentation

Welcome to the g0 documentation. g0 runs background checks on your AI agents — discovering every component, assessing 1,128 risk patterns across 12 domains, and adversarially testing behavior before you ship.

## By the Numbers

| | | | |
|:---:|:---:|:---:|:---:|
| **1,128** | **1,200+** | **1,184+** | **10** |
| Security Rules | Adversarial Payloads | Malicious Skill IOCs | Framework Parsers |
| **10** | **5** | **25** | **20** |
| Compliance Standards | Languages | Attack Categories | Encoding Mutators |

## Getting Started

- [**Getting Started**](getting-started.md) — Install g0, run your first scan, and understand the output
- [**Platform & Authentication**](platform.md) — Optional `g0 login`, entitlements, premium threat feed, and what's free vs. platform

## Core Concepts

- [**Architecture**](architecture.md) — How the g0 pipeline works: discovery, parsing, analysis, scoring
- [**Rules Reference**](rules.md) — All 1,128 rules across 12 security domains with per-domain breakdown
- [**Custom Rules**](custom-rules.md) — Write your own YAML rules with 13 check types
- [**Scoring Methodology**](scoring.md) — How the 0-100 score is calculated
- [**Compliance Mapping**](compliance.md) — 10 industry standards and how rules map to them

## Usage Guides

- [**Understanding Findings**](findings.md) — Finding anatomy, filtering, confidence levels, suppression, and triage
- [**AI Asset Inventory**](inventory.md) — Discover and document all AI components (AI-BOM)
- [**MCP Security**](mcp-security.md) — Assess MCP servers, detect rug-pulls, pin tool descriptions
- [**g0 as an MCP Server**](mcp-server.md) — Run g0 inside Claude Code/Cursor/Windsurf via `g0 mcp serve`
- [**Dynamic Testing**](dynamic-testing.md) — 1,200+ adversarial payloads, adaptive attacks, CVSS scoring, 20 attack categories, 20 mutators
- [**Framework Guide**](frameworks.md) — Per-framework detection, patterns, and findings
- [**Framework Remediation Guides**](frameworks/) — Framework-specific fixes for common g0 findings

## Integration

- [**Endpoint Assessment & Monitoring**](endpoint-monitoring.md) — Multi-layer endpoint scanning (network, artifacts, forensics, browser), scoring, remediation, drift detection, fleet-wide daemon
- [**Runtime Proxy (`g0 proxy`)**](runtime-proxy.md) — Policy-enforcing MCP man-in-the-middle: allow/deny/redact/coach, EDM fingerprinting, dataflow tracking, confidence-fusion Policy DSL v2
- [**CI/CD Integration**](ci-cd.md) — GitHub Actions, GitLab CI, Jenkins, pre-commit hooks
- [**OpenClaw Security**](openclaw-security.md) — Static scanning, supply-chain auditing, adversarial testing, live hardening, deployment audit
- [**OpenClaw Deployment Guide**](openclaw-deployment-guide.md) — Self-hosted deployment hardening, config generation, monitoring, enforcement
- [**Enforcement Integrations**](enforcement-integrations.md) — Tetragon, Falco, auditd, iptables, event receiver
- [**Programmatic API**](api.md) — Use g0 as a library in your own tools

## Reference

- [**FAQ**](faq.md) — Common questions and answers
- [**Glossary**](glossary.md) — Key terms and concepts
- [**Control Domain Specs**](controls/) — Detailed specifications for each security domain
