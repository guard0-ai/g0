# Changelog

All notable changes to g0 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-16

### Added

- **Endpoint Assessment** — `g0 endpoint` discovers all AI developer tools on the machine (Claude Code, Cursor, Windsurf, VS Code, Zed, JetBrains, Gemini CLI, Amazon Q, and 10 more), shows running/installed status, lists MCP servers per tool, and surfaces security findings in a single view
- **Process Detection** — Detects running AI tool processes to show real-time status alongside config-based installation detection
- **`g0 endpoint scan`** — Alias for `g0 endpoint` default action
- **`g0 endpoint --json`** — Structured JSON output with full tool, MCP, and findings data

### Changed

- **`g0 endpoint`** — Redesigned from project-batch-scanning to AI tool discovery and security assessment
- Dropped `g0 endpoint inventory` (use `g0 inventory` instead)

## [0.1.0] - 2026-02-14

### Added

- **Security Assessment** — 1,183+ rules (468 TS + 715 YAML) across 12 security domains mapped to OWASP Agentic Top 10
- **12 Security Domains** — Goal Integrity, Tool Safety, Identity & Access, Supply Chain, Code Execution, Memory & Context, Data Leakage, Cascading Failures, Human Oversight, Inter-Agent, Reliability Bounds, Rogue Agent
- **Framework Support** — LangChain, CrewAI, OpenAI Agents SDK, MCP, Vercel AI SDK, Amazon Bedrock, AutoGen, LangChain4j, Spring AI, Go AI Frameworks
- **Language Support** — Python, TypeScript, JavaScript, Java, Go
- **Standards Mapping** — 10 standards: OWASP Agentic (ASI01-10), NIST AI RMF, ISO 42001, ISO 23894, OWASP AIVSS, OWASP Agentic AI Top 10 (AAT-1 to AAT-10), AIUC-1, EU AI Act, MITRE ATLAS, OWASP LLM Top 10
- **AI-BOM Inventory** — CycloneDX 1.6 SBOM, inventory diffing, markdown/JSON output
- **Agent Flow Analysis** — Execution path mapping, toxic flow detection, flow scoring
- **MCP Security Assessment** — Config scanning, source code analysis, rug-pull detection via hash pinning, SKILL.md scanning, remote repo support
- **Dynamic Adversarial Testing** — 10 payload categories (prompt-injection, data-exfiltration, tool-abuse, jailbreak, goal-hijacking, content-safety, bias-detection, pii-probing, agentic-attacks, jailbreak-advanced), 3-level progressive judge, HTTP/MCP providers
- **Remote Repo Scanning** — `g0 scan https://github.com/org/repo` via shallow clone
- **AI Analysis** — Optional AI-powered triage with Anthropic, OpenAI, or Google models
- **Output Formats** — Terminal, JSON, SARIF 2.1.0, HTML, CycloneDX 1.6, Markdown
- **CI/CD Gate** — `g0 gate` with configurable score/grade/severity thresholds
- **Custom Rules** — YAML rule definitions with 10 check types including taint flow analysis
- **Guard0 Cloud Integration** — `--upload` on all commands, `g0 auth login` device flow, auto-upload when authenticated
- **Background Daemon** — `g0 daemon start|stop|status|logs` for continuous monitoring
- **Programmatic API** — `import { runScan } from '@guard0/g0'`
