# g0 — Security control layer for AI agents

**385 security rules | 8 domains | 7 frameworks | OWASP Agentic Top 10**

Open-source security controls for AI agents — from code to runtime.

```bash
npx @guard0/g0 scan ./my-agent
```

> **[Guard0 Platform](https://guard0.ai/g0)** — Free-tier web dashboard with AI-powered triage, compliance reports, architecture visualization, and red team analytics. Run `g0 scan . --upload` to push results.

## Quick Start

```bash
# Install globally
npm install -g @guard0/g0

# Scan a local project
g0 scan ./my-agent

# Scan a remote repository
g0 scan https://github.com/org/repo

# Scan and upload to Guard0 Platform
g0 scan . --upload

# npx (no install)
npx @guard0/g0 scan .
```

## What It Does

g0 scans AI agent codebases for security gaps and runs adversarial tests against live agents. It detects prompt injection risks, tool misuse, data leakage, missing access controls, supply chain threats, and more — across **8 security domains** mapped to the [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai/).

### Guard0 Platform

The **free-tier web dashboard** at [guard0.ai/g0](https://guard0.ai/g0) provides:

- **AI-powered triage** — BYOK (Bring Your Own Key) multi-model chat with context-aware analysis using OpenAI, Anthropic, Google, AWS Bedrock, or Google Vertex
- **Compliance reports** — Generate SOC 2, NIST AI RMF, EU AI Act, ISO 42001, OWASP Agentic, and AIUC-1 compliance reports from scan results
- **Architecture visualization** — Interactive force-directed graph of agents, tools, models, and MCP servers with threat overlays
- **Red team dashboard** — Visualize adversarial testing results with OWASP attack matrices and risk scoring
- **AI fix generation** — One-click AI-generated code fixes for security findings with diff preview
- **Inventory management** — Track AI-BOM components across projects with drift detection
- **MCP rug-pull monitoring** — Continuous monitoring of MCP tool description changes

All CLI commands support `--upload` to push results to the platform.

## Commands

### `g0 scan [path]` — Static analysis

```bash
g0 scan .                              # Terminal output
g0 scan . --json                       # JSON to stdout
g0 scan . --sarif report.sarif         # SARIF 2.1.0
g0 scan . --html report.html           # HTML report
g0 scan . -o results.json              # JSON to file
g0 scan . --ai                         # AI-powered analysis
g0 scan . --upload                     # Upload to Guard0 Platform
g0 scan https://github.com/org/repo    # Remote repo
```

Options:
- `--severity <level>` — Minimum severity: critical, high, medium, low
- `--rules <ids>` — Only run specific rules (comma-separated)
- `--exclude-rules <ids>` — Skip specific rules
- `--frameworks <ids>` — Only check specific frameworks
- `--config <file>` — Config file path (default: `.g0.yaml`)
- `--ai` — Enable AI analysis (requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)
- `--upload` — Upload results to Guard0 Platform (requires `g0 auth login`)

### `g0 inventory [path]` — AI Bill of Materials

Generate an AI-BOM listing all AI components in your project: models, frameworks, tools, agents, vector databases, and associated risks.

```bash
g0 inventory .                         # Terminal output
g0 inventory . --json                  # JSON format
g0 inventory . --markdown              # Markdown report
g0 inventory . --cyclonedx             # CycloneDX 1.6 SBOM
g0 inventory . --diff baseline.json    # Diff against baseline
g0 inventory . --upload                # Upload to Guard0 Platform
```

### `g0 flows [path]` — Agent flow analysis

Map agent execution paths and detect toxic flow patterns (e.g., user input → code execution without validation).

```bash
g0 flows .                             # Terminal output
g0 flows . --json                      # JSON format
g0 flows . --upload                    # Upload to Guard0 Platform
```

### `g0 mcp [path]` — MCP security scanner

Scan MCP server configurations and source code for security issues. Detect rug-pull attacks via tool description hash pinning.

```bash
g0 mcp .                               # Scan MCP configs
g0 mcp . --pin                         # Pin tool description hashes
g0 mcp . --check                       # Check for tool description changes (rug pull detection)
g0 mcp . --upload                      # Upload to Guard0 Platform
```

### `g0 test` — Dynamic adversarial testing

Send adversarial payloads to a running agent and judge responses. 45 attack payloads across 5 categories with a 3-level progressive judge (deterministic → heuristic → LLM-as-judge).

```bash
# HTTP target
g0 test --target http://localhost:3000/api/chat
g0 test --target http://localhost:3000/api/chat --attacks prompt-injection,jailbreak
g0 test --target http://localhost:3000/api/chat --header "Authorization: Bearer $TOKEN"

# MCP target
g0 test --mcp "node dist/server.js"
g0 test --mcp "python server.py" --attacks tool-abuse

# Smart targeting (static scan informs payload selection)
g0 test --target http://localhost:3000/api/chat --auto .
g0 test --target http://localhost:3000/api/chat --auto . --ai  # LLM-as-judge

# Output
g0 test --target http://localhost:3000/api/chat --json
g0 test --target http://localhost:3000/api/chat --upload
```

Options:
- `--target <url>` — HTTP endpoint to test
- `--mcp <command>` — MCP server command to test via stdio
- `--attacks <categories>` — Comma-separated attack categories to run
- `--payloads <ids>` — Specific payload IDs to run
- `--auto [path]` — Smart targeting: run static scan first to prioritize payloads
- `--ai` — Enable LLM-as-judge for nuanced verdict evaluation
- `--header <header>` — Add HTTP header (e.g., `Authorization: Bearer token`)
- `--json` — JSON output
- `--upload` — Upload results to Guard0 Platform

Attack categories: `prompt-injection` (12), `data-exfiltration` (10), `tool-abuse` (8), `jailbreak` (8), `goal-hijacking` (7)

### `g0 gate [path]` — CI/CD quality gate

```bash
g0 gate . --min-score 80               # Fail if score < 80
g0 gate . --no-critical                # Fail if any critical findings
g0 gate . --min-grade B                # Fail if grade below B
```

### `g0 auth` — Platform authentication

Authenticate with the Guard0 Platform to enable `--upload` on all commands.

```bash
g0 auth login                          # Login via browser OAuth
g0 auth logout                         # Clear stored credentials
g0 auth status                         # Show current auth status
g0 auth token                          # Print current access token
```

### `g0 daemon` — Background monitoring

Run continuous security monitoring as a background daemon. Watches for file changes and automatically re-scans.

```bash
g0 daemon start                        # Start background daemon
g0 daemon stop                         # Stop running daemon
g0 daemon status                       # Check daemon status
g0 daemon logs                         # View daemon logs
```

### `g0 init` — Generate config

```bash
g0 init                                # Create .g0.yaml
```

## Security Domains

| Domain | ID | Rules | Key Checks |
|--------|----|-------|------------|
| **Goal Integrity** | AA-GI | 60 | Prompt injection, instruction boundaries, scope leakage, jailbreak patterns |
| **Tool Safety** | AA-TS | 40 | Shell/network/filesystem capabilities, input validation, sandboxing, rate limits |
| **Identity & Access** | AA-IA | 60 | Hardcoded keys, permissive CORS, missing auth, privilege escalation |
| **Supply Chain** | AA-SC | 30 | Unpinned deps, unverified packages, model provenance, MCP server trust |
| **Code Execution** | AA-CE | 60 | eval/exec, shell injection, unsafe deserialization, sandbox escape |
| **Memory & Context** | AA-MP | 25 | Unbounded memory, context stuffing, RAG poisoning, session isolation |
| **Data Leakage** | AA-DL | 60 | PII logging, credential exposure, verbose errors, output filtering |
| **Cascading Failures** | AA-CF | 50 | No timeouts, missing circuit breakers, infinite loops, resource exhaustion |

## Supported Frameworks

| Framework | Detection | Parsing |
|-----------|-----------|---------|
| **LangChain / LangGraph** | Agents, tools, prompts, memory, chains | Python + JS/TS |
| **CrewAI** | Crews, agents, tasks, YAML configs | Python |
| **OpenAI Agents SDK** | Assistants, function tools, responses API | Python + JS/TS |
| **MCP** | Server tools, config files, client configs | JSON + JS/TS |
| **Vercel AI SDK** | Tools, streaming, middleware | JS/TS |
| **Amazon Bedrock** | Agents, knowledge bases, guardrails | Python + JS/TS |
| **AutoGen** | Agent groups, conversations, code execution | Python |

## Standards Mapping

Every rule maps to one or more industry standards:

- **[OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai/)** (ASI01–ASI10)
- **NIST AI RMF** (GOVERN, MAP, MEASURE, MANAGE)
- **ISO 42001** (AI Management System)
- **ISO 23894** (AI Risk Management)
- **OWASP AIVSS** (AI Vulnerability Scoring)
- **A2A/MCP Security** (Agent-to-Agent Basic controls)
- **AIUC-1** (AI Use Controls — mandates quarterly testing)
- **SOC 2** (Trust Service Criteria CC6–CC8)
- **EU AI Act** (Articles 9, 10, 15)

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | *(default)* | Developer review |
| JSON | `--json` | Programmatic consumption |
| SARIF 2.1.0 | `--sarif` | GitHub Code Scanning, IDE integration |
| HTML | `--html` | Shareable reports |
| CycloneDX 1.6 | `--cyclonedx` | SBOM for compliance (inventory only) |
| Markdown | `--markdown` | Documentation (inventory only) |

## CI/CD Integration

### GitHub Actions

```yaml
name: AI Agent Security
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: g0 Security Scan
        run: |
          npx @guard0/g0 gate . --min-score 70 --sarif results.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitHub Actions with Platform Upload

```yaml
name: AI Agent Security
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: g0 Security Scan
        env:
          G0_API_TOKEN: ${{ secrets.G0_API_TOKEN }}
        run: |
          npx @guard0/g0 scan . --upload --sarif results.sarif
          npx @guard0/g0 inventory . --upload
          npx @guard0/g0 test --target ${{ vars.AGENT_URL }} --auto . --upload
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx @guard0/g0 gate . --min-score 70 --no-critical --quiet
```

## Custom Rules

Create YAML rules in a `rules/` directory:

```yaml
id: AA-GI-100
info:
  name: "Custom: missing safety boundary"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "System prompt lacks safety boundary markers"
  frameworks: [all]
  owasp_agentic: [ASI01]
  standards:
    nist_ai_rmf: [MAP-1.5]
check:
  type: prompt_missing
  pattern: "\\bSAFETY_BOUNDARY\\b"
  message: "No safety boundary found in system prompt"
```

Available check types: `prompt_contains`, `prompt_missing`, `tool_has_capability`, `tool_missing_property`, `code_matches`, `config_matches`, `agent_property`, `model_property`, `no_check`

Configure in `.g0.yaml`:

```yaml
rules_dir: ./rules
min_score: 70
exclude_rules:
  - AA-GI-001
exclude_paths:
  - tests/
  - node_modules/
```

## Scoring

Each domain starts at 100 and is deducted based on finding severity:

| Severity | Deduction |
|----------|-----------|
| Critical | -25 |
| High | -15 |
| Medium | -8 |
| Low | -3 |

Domain scores are averaged into an overall score (0–100) with a letter grade (A/B/C/D/F).

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | `--ai` | Anthropic API key for AI analysis and LLM-as-judge |
| `OPENAI_API_KEY` | `--ai` | OpenAI API key (alternative to Anthropic) |
| `G0_API_TOKEN` | `--upload` | Guard0 Platform API token (or use `g0 auth login`) |
| `G0_PLATFORM_URL` | `--upload` | Custom platform URL (default: https://guard0.ai) |

## Programmatic API

```typescript
import { runScan } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });
console.log(result.score.grade);     // 'B'
console.log(result.findings.length); // 12
```

## Development

```bash
git clone https://github.com/guard0-ai/g0.git
cd g0
npm install
npm test
npm run build
```

## License

Apache-2.0
