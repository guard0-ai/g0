<h1 align="center">g0 — The Control Layer for AI Agents</h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@guard0/g0"><img src="https://img.shields.io/npm/v/@guard0/g0.svg" alt="npm version"></a>
  <a href="https://github.com/guard0-ai/g0/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="License"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg" alt="Node.js >= 20"></a>
  <a href="https://owasp.org/www-project-agentic-security/"><img src="https://img.shields.io/badge/OWASP-Agentic%20Top%2010-orange.svg" alt="OWASP Agentic"></a>
  <img src="https://img.shields.io/badge/security%20checks-5%2C000%2B-blueviolet.svg" alt="5,000+ security checks">
  <a href="https://github.com/guard0-ai/g0/actions"><img src="https://github.com/guard0-ai/g0/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

<p align="center"><strong>Discover &nbsp;·&nbsp; Assess &nbsp;·&nbsp; Test &nbsp;·&nbsp; Monitor &nbsp;·&nbsp; Comply</strong></p>

<br>

<table>
<tr>
<td width="50%">

**While You Build** — scan your codebase for agent risks

```bash
npx @guard0/g0 scan ./my-agent
```

```
  Scan Results
  ──────────────────────────────────────────
  Path:           ./my-agent
  Framework:      langchain (+mcp)
  Files scanned:  47
  Agents: 3  Tools: 12  Prompts: 8
  Duration:       2.1s

  Security Metadata
  ──────────────────────────────────────────
  API Endpoints: 4 (2 external)
  DB Accesses: 3 (1 unparameterized)
  Auth Flows: 1
  PII References: 5 (3 unmasked)

  Findings
  ──────────────────────────────────────────
  CRIT  Unsandboxed code execution
        agent.py:42              [AA-CE-001]

  HIGH  SQL injection via raw query
        db.py:87                 [AA-TS-012]

  HIGH  System prompt injectable
        prompts.py:15            [AA-GI-003]

  MED   MCP tool desc not pinned
        mcp_config.json:3        [AA-TS-031]

  Domain Scores
  ──────────────────────────────────────────
  Goal Integrity    ████████████████░░░░  82
  Tool Safety       ████████████░░░░░░░░  61
  Code Execution    ██████████░░░░░░░░░░  48
  Data Leakage      █████████████████░░░  88
  Identity/Access   ████████████████████  95
  Supply Chain      ████████████████████  100

  Overall: C  ████████████████░░░░░░░░░░  72
```

</td>
<td width="50%">

**After You Deploy** — attack your live agent endpoint

```bash
npx @guard0/g0 test --target http://localhost:3000/api/chat --adaptive
```

```
  Adversarial Test Results
  ──────────────────────────────────────────
  Target:    localhost:3000/api/chat
  Payloads:  142 across 10 categories
  Duration:  38.4s

  Prompt Injection
  ──────────────────────────────────────────
  [ VULN ] CRIT  System-prompt-override  [heuristic]
    Evidence: "Sure, I'll ignore my prev..."
  [ VULN ] HIGH  Indirect-injection      [deterministic]
    Evidence: "Fetched URL and executed..."
  [ SAFE ] HIGH  Role-switch             [heuristic]
  [ SAFE ] MED   Few-shot-attack         [deterministic]

  Data Exfiltration
  ──────────────────────────────────────────
  [ VULN ] HIGH  Env-var-leak            [deterministic]
    Evidence: "API_KEY=sk-proj-4f2x..."
  [ SAFE ] MED   File-read-attempt       [heuristic]
  [ SAFE ] MED   Schema-extraction       [deterministic]

  Adaptive Attacks
  ──────────────────────────────────────────
  [ VULN ] CRIT  GOAT: multi-turn escape [4 turns]
    CVSS 9.1 (Critical)
    Evidence: "Here is the system prompt..."
  [ SAFE ] HIGH  Crescendo: slow-burn    [6 turns]

  Summary
  ──────────────────────────────────────────
  Status: [ FAIL ]

  ██████████████████░░░░░░░░░░░░░░░░░░░░░░
  Vulnerable: 12  Resistant: 119  Errors: 3
  Total: 142 tests | Max CVSS: 9.1

  Weakest Areas
  ──────────────────────────────────────────
  ● Prompt Injection:   2 vuln / 24 tests
  ● Data Exfiltration:  1 vuln / 18 tests
  ● Adaptive Attacks:   1 vuln / 5 tests
```

</td>
</tr>
</table>

> **[Guard0 Cloud](https://guard0.ai)** — Free dashboard with architecture visualization, compliance mapping, and AI-powered triage.

---

## ⚡ Quick Start

```bash
npm install -g @guard0/g0        # Install globally
g0 scan ./my-agent               # Assess a local project
g0 scan https://github.com/org/repo  # Assess a remote repository
g0 scan . --upload               # Upload to Guard0 Cloud (free)
npx @guard0/g0 scan .            # npx (no install)
```

---

## 🔍 The Three Questions

Every team should ask these before shipping an AI agent:

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
g0 test --target http://localhost:3000 --adaptive  # Adaptive multi-turn attacks
```

4,000+ adversarial payloads across 20 attack categories with a 4-level progressive judge — deterministic, heuristic, SLM, and LLM-as-judge. 5 adaptive attack strategies with CVSS scoring, 20 encoding mutators with stacking, canary token detection, multi-turn attack strategies, and per-category grading rubrics. Verify your agent does what you intended and nothing more.

---

## 🛡️ What g0 Covers

<table>
<tr>
<td width="50%">

**12 Security Domains**

Goal Integrity · Tool Safety · Identity & Access · Supply Chain · Code Execution · Memory & Context · Data Leakage · Cascading Failures · Human Oversight · Inter-Agent · Reliability Bounds · Rogue Agent

</td>
<td width="50%">

**10 Compliance Standards**

OWASP Agentic Top 10 · NIST AI RMF · ISO 42001 · ISO 23894 · OWASP AIVSS · A2AS · AIUC-1 · EU AI Act · MITRE ATLAS · OWASP LLM Top 10

</td>
</tr>
<tr>
<td>

**10 Framework Parsers**

LangChain/LangGraph · CrewAI · OpenAI Agents SDK · MCP · Vercel AI SDK · Amazon Bedrock · AutoGen · LangChain4j · Spring AI · Go AI

</td>
<td>

**5 Languages**

Python · TypeScript · JavaScript · Java · Go

</td>
</tr>
</table>

<table>
<tr>
<td align="center"><strong>1,200+</strong><br><sub>Security Rules</sub></td>
<td align="center"><strong>4,000+</strong><br><sub>Attack Payloads</sub></td>
<td align="center"><strong>5,000+</strong><br><sub>Security Checks</sub></td>
<td align="center"><strong>20</strong><br><sub>Encoding Mutators</sub></td>
<td align="center"><strong>5</strong><br><sub>Adaptive Strategies</sub></td>
</tr>
</table>

---

## 🧪 Dynamic Testing

```bash
# Full adversarial sweep
g0 test --target http://localhost:3000/api/chat

# Adaptive multi-turn attacks with AI-powered red teaming
g0 test --target http://localhost:3000/api/chat --adaptive

# Jailbreaks with encoding bypasses
g0 test --target http://localhost:3000/api/chat --dataset wild --mutate all

# Smart targeting: static scan → prioritized dynamic tests
g0 test --target http://localhost:3000/api/chat --auto . --ai

# SARIF output for CI/CD
g0 test --target http://localhost:3000/api/chat --adaptive --sarif results.sarif
```

**Adaptive Strategies** — GOAT · Crescendo · Recon-Probe · Hydra · SIMBA

**4-Level Judge** — Deterministic → Heuristic → SLM → LLM-as-Judge

**CVSS 3.1** scoring for every confirmed vulnerability.

See [Dynamic Testing](docs/dynamic-testing.md) for the full guide.

---

## 🖥️ Endpoint Assessment

Discover every AI developer tool on your machine — see what's running, which MCP servers are connected, and where the risks are:

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

```bash
g0 auth login                           # Authenticate to Guard0 Cloud
g0 daemon start --watch ~/projects      # Start background monitoring
g0 daemon start --interval 15           # Custom scan interval (minutes)
g0 daemon status                        # Check daemon health
```

The daemon registers the machine as an endpoint, then periodically scans MCP configurations, checks tool description pins for rug-pulls, diffs AI inventories for component drift, and sends heartbeats to Guard0 Cloud. See [docs/endpoint-monitoring.md](docs/endpoint-monitoring.md) for the full guide.

---

## 🔧 Commands

| Command | Purpose |
|---------|---------|
| `g0 scan [path]` | Security assessment with scoring and grading |
| `g0 inventory [path]` | AI Bill of Materials (CycloneDX 1.6, JSON, Markdown) |
| `g0 flows [path]` | Agent execution path mapping and toxic flow detection |
| `g0 mcp [path]` | MCP server assessment and rug-pull detection |
| `g0 test` | Dynamic adversarial testing — 4,000+ payloads, adaptive attacks, CVSS scoring |
| `g0 endpoint` | Discover AI developer tools and assess endpoint security |
| `g0 gate [path]` | CI/CD quality gate with configurable thresholds |
| `g0 auth` | Guard0 Cloud authentication |
| `g0 daemon` | Background monitoring for fleet-wide visibility |

All commands support `--upload` to sync results to Guard0 Cloud, `--json` for programmatic output, and `--sarif` for GitHub Code Scanning integration.

---

## 🚀 CI/CD Integration

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

---

## ⚙️ Configuration

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

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Installation, first scan, reading output |
| [Architecture](docs/architecture.md) | Pipeline overview, module map, data flow |
| [Rules Reference](docs/rules.md) | All 1,200+ rules — domains, severities, check types |
| [Custom Rules](docs/custom-rules.md) | YAML rule schema, all 11 check types, examples |
| [Framework Guide](docs/frameworks.md) | Per-framework detection, patterns, and findings |
| [Understanding Findings](docs/findings.md) | Finding anatomy, filtering, suppression, triage |
| [AI Asset Inventory](docs/inventory.md) | AI-BOM, CycloneDX, diffing, compliance |
| [MCP Security](docs/mcp-security.md) | MCP assessment, rug-pull detection, hash pinning |
| [Dynamic Testing](docs/dynamic-testing.md) | 4,000+ adversarial payloads, adaptive attacks, CVSS scoring, 20 mutators |
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

**Commercial license** available for organizations that want to embed g0 without copyleft obligations. See [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) or contact [hello@guard0.ai](mailto:hello@guard0.ai).

---

<sub>g0 is an open-source project by [Guard0](https://guard0.ai). AI Thinks. We Govern.</sub>
