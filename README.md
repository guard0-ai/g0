<p align="center">
  <strong>g0 - The control layer for AI agents</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@guard0/g0"><img src="https://img.shields.io/npm/v/@guard0/g0.svg" alt="npm version"></a>
  <a href="https://github.com/guard0-ai/g0/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg" alt="Node.js >= 20"></a>
  <a href="https://owasp.org/www-project-agentic-security/"><img src="https://img.shields.io/badge/OWASP-Agentic%20Top%2010-orange.svg" alt="OWASP Agentic"></a>
  <img src="https://img.shields.io/badge/rules-1%2C183%2B-blueviolet.svg" alt="1,183+ rules">
  <a href="https://github.com/guard0-ai/g0/actions"><img src="https://github.com/guard0-ai/g0/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<p align="center"><strong>Assess. Map. Control.</strong></p>

```bash
npx @guard0/g0 scan ./my-agent
```

> **[Guard0 Cloud](https://guard0.ai)** — Free dashboard with architecture visualization, compliance mapping, and AI-powered triage. Run `g0 scan . --upload` to see your results.

---

## How It Works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/architecture.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/architecture-light.png">
  <img alt="g0 architecture diagram" src="docs/assets/architecture-light.png">
</picture>

<!--
## Terminal Demo
TODO: Add asciinema recording or SVG terminal capture
[![asciicast](https://asciinema.org/a/TODO.svg)](https://asciinema.org/a/TODO)
-->

---

## Why g0

Every AI agent is a bundle of decisions — which models, which tools, which data, which permissions. Those decisions define your blast radius.

g0 gives you visibility and control across three dimensions:

| | What g0 Does | Why It Matters |
|---|---|---|
| **Discover** | Inventory every AI component — models, tools, agents, MCP servers, vector DBs | You can't secure what you can't see |
| **Assess** | Evaluate security posture across 12 domains mapped to 10 industry standards | Quantified risk, not guesswork |
| **Test** | Send adversarial payloads and judge responses with a 3-level progressive engine | Verify behavior before production |

## Quick Start

```bash
# Install globally
npm install -g @guard0/g0

# Assess a local project
g0 scan ./my-agent

# Assess a remote repository
g0 scan https://github.com/org/repo

# Upload to Guard0 Cloud (free)
g0 scan . --upload

# npx (no install)
npx @guard0/g0 scan .
```

## The Three Questions

g0 answers the three questions every team should ask before shipping an AI agent:

### 1. What agents do you have?

```bash
g0 inventory .               # AI Bill of Materials
g0 inventory . --cyclonedx   # CycloneDX 1.6 SBOM
```

Discover every AI component in your codebase: models, frameworks, tools, agents, vector databases, and MCP servers — across Python, TypeScript, JavaScript, Java, and Go.

### 2. What can they access?

```bash
g0 scan .                    # Security assessment across 12 domains
g0 flows .                   # Map execution paths and data flows
g0 mcp .                     # Assess MCP server configurations
```

Map the blast radius: which data sources does your agent read? Which tools can it invoke? What execution paths exist from user input to code execution? Where are the trust boundaries?

### 3. Is their behavior aligned?

```bash
g0 test --target http://localhost:3000/api/chat   # Adversarial testing
g0 test --mcp "python server.py"                  # Test MCP servers
g0 test --target http://localhost:3000 --auto .    # Smart targeting from static scan
```

Adversarial payloads across 10 attack categories with a 3-level progressive judge — deterministic, heuristic, and LLM-as-judge. Verify your agent does what you intended and nothing more.

## What g0 Covers

**12 security domains** — Goal Integrity, Tool Safety, Identity & Access, Supply Chain, Code Execution, Memory & Context, Data Leakage, Cascading Failures, Human Oversight, Inter-Agent Communication, Reliability Bounds, Rogue Agent Detection.

**10 frameworks** — LangChain/LangGraph, CrewAI, OpenAI Agents SDK, MCP, Vercel AI SDK, Amazon Bedrock, AutoGen, LangChain4j, Spring AI, Go AI frameworks.

**5 languages** — Python, TypeScript, JavaScript, Java, Go.

**10 standards** — OWASP Agentic Top 10, NIST AI RMF, ISO 42001, ISO 23894, OWASP AIVSS, A2AS, AIUC-1, EU AI Act, MITRE ATLAS, OWASP LLM Top 10.

## Commands

| Command | Purpose |
|---------|---------|
| `g0 scan [path]` | Security assessment with scoring and grading |
| `g0 inventory [path]` | AI Bill of Materials (CycloneDX 1.6, JSON, Markdown) |
| `g0 flows [path]` | Agent execution path mapping and toxic flow detection |
| `g0 mcp [path]` | MCP server assessment and rug-pull detection |
| `g0 test` | Dynamic adversarial testing (HTTP and MCP targets) |
| `g0 endpoint` | Discover AI developer tools and assess endpoint security |
| `g0 gate [path]` | CI/CD quality gate with configurable thresholds |
| `g0 auth` | Guard0 Cloud authentication |
| `g0 daemon` | Background monitoring for fleet-wide visibility |

All commands support `--upload` to sync results to Guard0 Cloud, `--json` for programmatic output, and `--sarif` for GitHub Code Scanning integration.

## Endpoint Assessment

Discover every AI developer tool on your machine, see which are running, what MCP servers they have, and the security posture — in one command:

```bash
g0 endpoint                             # Discover tools & assess security
g0 endpoint --json                      # Structured JSON output
g0 endpoint status                      # Machine info & daemon health
```

```
  AI Developer Tools
  ──────────────────────────────────────────────────────────
  ● Claude Code       running   1 MCP server    ~/.claude/settings.json
  ● Cursor            running   0 MCP servers   ~/.cursor/mcp.json
  ○ Claude Desktop    installed 0 MCP servers   ~/Library/.../claude_desktop_config.json

  MCP Servers
  ──────────────────────────────────────────────────────────
   CRIT  clay-mcp  npx @clayhq/clay-mcp@latest
    Client: Claude Code | Config: ~/.claude/settings.json

  Findings
  ──────────────────────────────────────────────────────────
   CRIT  Hardcoded secret in MCP config [clay-mcp] via Claude Code
    Server "clay-mcp" has hardcoded secret in env var "CLAY_API_KEY"

  Summary
  ──────────────────────────────────────────────────────────
   CRITICAL   AI Tools: 3 detected, 2 running   MCP Servers: 1   Findings: 1
```

Detects 18 AI tools: Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Zed, JetBrains (Junie), Gemini CLI, Amazon Q, Cline, Roo Code, Copilot CLI, Kiro, Continue, Augment Code, Neovim (mcphub), BoltAI, 5ire.

### Fleet Monitoring

Deploy g0 across developer machines for continuous visibility:

```bash
g0 auth login                           # Authenticate to Guard0 Cloud
g0 daemon start --watch ~/projects      # Start background monitoring
g0 daemon start --interval 15           # Custom scan interval (minutes)
g0 daemon status                        # Check daemon health
```

The daemon registers the machine as an endpoint, then periodically scans MCP configurations, checks tool description pins for rug-pulls, diffs AI inventories for component drift, and sends heartbeats to Guard0 Cloud. See [docs/endpoint-monitoring.md](docs/endpoint-monitoring.md) for the full guide.

## CI/CD Integration

### GitHub Actions

```yaml
name: AI Agent Assessment
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: g0 Security Assessment
        run: |
          npx @guard0/g0 gate . --min-score 70 --sarif results.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx @guard0/g0 gate . --min-score 70 --no-critical --quiet
```

See [docs/ci-cd.md](docs/ci-cd.md) for GitLab CI, Jenkins, and more.

## Configuration

Create a `.g0.yaml` in your project root:

```yaml
min_score: 70
rules_dir: ./rules          # Custom rules directory
exclude_rules:
  - AA-GI-001
exclude_paths:
  - tests/
  - node_modules/
```

## Programmatic API

```typescript
import { runScan } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });
console.log(result.score.grade);     // 'B'
console.log(result.findings.length); // 12
```

See [docs/api.md](docs/api.md) for the full SDK reference.

## Output Formats

Terminal (default), JSON, SARIF 2.1.0, HTML, CycloneDX 1.6, and Markdown.

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, first scan, reading output |
| [Architecture](docs/architecture.md) | Pipeline overview, module map, data flow |
| [Rules Reference](docs/rules.md) | All 1,183+ rules — domains, severities, check types |
| [Custom Rules](docs/custom-rules.md) | YAML rule schema, all 11 check types, examples |
| [Framework Guide](docs/frameworks.md) | Per-framework detection, patterns, and findings |
| [Understanding Findings](docs/findings.md) | Finding anatomy, filtering, suppression, triage |
| [AI Asset Inventory](docs/inventory.md) | AI-BOM, CycloneDX, diffing, compliance |
| [MCP Security](docs/mcp-security.md) | MCP assessment, rug-pull detection, hash pinning |
| [Dynamic Testing](docs/dynamic-testing.md) | Adversarial payloads, judges, smart targeting |
| [Endpoint Monitoring](docs/endpoint-monitoring.md) | Fleet-wide daemon, heartbeats, drift detection |
| [CI/CD Integration](docs/ci-cd.md) | GitHub Actions, GitLab CI, Jenkins, pre-commit |
| [Programmatic API](docs/api.md) | SDK exports, runScan, runDiscovery, getAllRules |
| [Scoring Methodology](docs/scoring.md) | Formula, weights, multipliers, grades |
| [Compliance Mapping](docs/compliance.md) | 10 standards with full domain matrix |
| [FAQ](docs/faq.md) | Common questions and answers |
| [Glossary](docs/glossary.md) | Key terms and concepts |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding rules, framework parsers, and submitting PRs.

## Development

```bash
git clone https://github.com/guard0-ai/g0.git
cd g0
npm install
npm test
npm run build
```

## License

[AGPL-3.0](LICENSE) — free to use, modify, and distribute. If you modify g0 and serve it over a network, you must release your source code under the same license.

**Commercial license** available for organizations that want to embed g0 without copyleft obligations. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) or contact [licensing@guard0.ai](mailto:licensing@guard0.ai).

---

<sub>g0 is an open-source project by [Guard0](https://guard0.ai). AI Thinks. We Secure.</sub>
