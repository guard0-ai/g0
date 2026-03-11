# Changelog

All notable changes to g0 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2026-03-11

### Fixed

- **Daemon Silent Death** - `forkDaemon()` now redirects child stdout/stderr to `daemon-startup.log` and uses IPC handshake to detect early exit. Previously the child was forked with `stdio: 'ignore'`, so crashes during module loading or config parsing produced zero output. Parent now waits for a `daemon-ready` message or captures the startup log on failure
- **Runner Path Resolution** - `resolveRunnerPath()` throws with searched paths instead of silently returning a non-existent path that caused cryptic fork failures
- **Signal Handler Timing** - SIGTERM/SIGINT handlers moved to execute immediately after logger initialization, ensuring graceful shutdown even if later initialization steps fail
- **Startup FD Leak** - `startupLogFd` is now closed if `writePid()` throws during daemon startup

### Added

- **Secrets in Process Args (OC-H-064)** - New critical audit check detects secrets (API keys, passwords, tokens) passed via Docker `-e` flags, which are visible to all users on the host via `ps aux`. Recommends Docker secrets, `--env-file`, or mounted files instead
- **Global Crash Handlers** - `uncaughtException` and `unhandledRejection` handlers installed before `main()` in the daemon runner, capturing startup crashes to the startup log

## [1.4.0] - 2026-03-10

### Added

- **Intelligence Pipeline** — IOC database (55+ indicators) and CVE feed integrated into every scan. Tool URLs, endpoints, and agent names checked against known malicious domains, C2 IPs, and hashes. Framework versions checked against known CVEs. Opt-out via `config.analyzers.intelligence`
- **OWASP Agentic AI Top 10** — Replaced A2AS (not a real standard) with OWASP Agentic AI Top 10 (AAT-1 through AAT-10), backed by 600+ contributors from Cisco, Google, Meta, Amazon, and Palo Alto Networks
- **Standards Definitions** — EU AI Act (21 controls), MITRE ATLAS (10 tactics, 20+ techniques), OWASP LLM Top 10 (LLM01-LLM10) definition files. All 10 standards now have complete control definitions
- **Daemon Service Wiring** — BehavioralBaseline, CorrelationEngine, and CostMonitor wired into daemon tick loop with anomaly detection and cost circuit breaker
- **52 New Tests** — Unit tests for enforcement, alerter, process-detector, and openclaw-drift modules. Test suite now at 1,504 tests across 100 files
- **`g0 detect` Command** — Fleshed out with MDM enrollment detection, running AI agent discovery, and host hardening audit in a single view
- **`--rules-dir` Option** — Load custom YAML rules from a directory
- **`--follow` Option** — Real-time log tailing for `g0 daemon logs`
- **Code of Conduct** — Contributor Covenant v2.1
- **Installation Troubleshooting** — Added to getting-started guide (EACCES, PATH, Node version, Windows notes)

### Changed

- **Rule Count** — Verified and corrected to 1,180 (485 TS + 695 YAML) with accurate per-domain breakdown
- **Standards Count** — Now 10 standards with complete definitions (was 7 with definitions + 3 metadata-only)
- **Error Messages** — Contextual hints for clone failures (network, auth, 404), path errors, config parse errors
- **API Docs** — Expanded with `runTests`, all reporter functions, configuration reference, YAML rule authoring guide
- **Compliance Reporter** — Added human-oversight, inter-agent, reliability-bounds, rogue-agent domains to standard control mappings
- **Config Merge** — True recursive `deepMergeObjects()` replacing shallow spread

### Fixed

- **Event Receiver Security** — 30s request timeout (slowloris), backpressure handling (OOM), CORS restricted to localhost, stream error handler
- **Daemon Race Condition** — `endpointId!` non-null assertion replaced with safe fallback
- **IOC Domain Matching** — Uses `URL.hostname` + proper suffix matching instead of `String.includes()`
- **Prototype Pollution** — `deepSet()` guards against `__proto__`, `constructor`, `prototype`
- **CodeQL Alerts** — Anchored regexes for URL/domain checks
- **YAML Compiler** — Default case for unmatched check types, model_property findings cap (10)
- **Build Config** — Added tree-sitter-java/go to tsup externals
- **Type Safety** — Zero `as any` casts, proper `PresetName` types, `EndpointGrade` type alias
- **Dead Code** — Removed unused `include_beta` field, `--no-banner` option, `glob` dependency

### Removed

- **A2AS BASIC** — Replaced with OWASP Agentic AI Top 10. All `a2asBasic`/`a2as_basic` references removed

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
