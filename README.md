# g0 — AI Agent Security Scanner

**500+ security rules | 8 domains | 7 frameworks | OWASP Agentic Top 10**

The open-source CLI that scans AI agent projects for security vulnerabilities. Think **"Snyk for AI agents."**

```bash
npx @guard0/agentsec scan ./my-agent
```

## Quick Start

```bash
# Install globally
npm install -g @guard0/agentsec

# Scan a local project
g0 scan ./my-agent

# Scan a remote repository
g0 scan https://github.com/org/repo

# npx (no install)
npx @guard0/agentsec scan .
```

## What It Does

g0 performs **static analysis** (SAST) and **dynamic adversarial testing** (DAST) on AI agent codebases. It detects prompt injection risks, tool misuse, data leakage, missing access controls, supply chain threats, and more — across **8 security domains** mapped to the [OWASP Agentic Top 10](https://owasp.org/www-project-agentic-ai/).

## Commands

### `g0 scan [path]` — Static analysis

```bash
g0 scan .                          # Terminal output
g0 scan . --json                   # JSON to stdout
g0 scan . --sarif report.sarif     # SARIF 2.1.0
g0 scan . --html report.html       # HTML report
g0 scan . -o results.json          # JSON to file
g0 scan . --ai                     # AI-powered analysis (requires API key)
g0 scan https://github.com/org/repo  # Remote repo
```

Options:
- `--severity <level>` — Minimum severity: critical, high, medium, low
- `--rules <ids>` — Only run specific rules (comma-separated)
- `--exclude-rules <ids>` — Skip specific rules
- `--frameworks <ids>` — Only check specific frameworks
- `--config <file>` — Config file path (default: `.g0.yaml`)
- `--ai` — Enable AI analysis (requires `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`)

### `g0 inventory [path]` — AI Bill of Materials

Generate an AI-BOM listing all AI components in your project.

```bash
g0 inventory .                     # Terminal output
g0 inventory . --json              # JSON format
g0 inventory . --markdown          # Markdown report
g0 inventory . --cyclonedx         # CycloneDX 1.6 SBOM
g0 inventory . --diff baseline.json  # Diff against baseline
```

### `g0 flows [path]` — Agent flow analysis

Map agent execution paths and detect toxic flow patterns.

```bash
g0 flows .                         # Terminal output
g0 flows . --json                  # JSON format
```

### `g0 mcp [path]` — MCP security scanner

Scan MCP server configurations and source code for security issues.

```bash
g0 mcp .                           # Scan MCP configs
g0 mcp . --pin                     # Pin tool description hashes
g0 mcp . --check                   # Check for tool description changes (rug pull detection)
```

### `g0 test` — Dynamic adversarial testing

Send adversarial payloads to a running agent and judge responses.

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
```

Attack categories: `prompt-injection` (12), `data-exfiltration` (10), `tool-abuse` (8), `jailbreak` (8), `goal-hijacking` (7)

### `g0 gate [path]` — CI/CD quality gate

```bash
g0 gate . --min-score 80           # Fail if score < 80
g0 gate . --no-critical            # Fail if any critical findings
g0 gate . --min-grade B            # Fail if grade below B
```

### `g0 init` — Generate config

```bash
g0 init                            # Create .g0.yaml
```

## Security Domains

| Domain | ID | Key Checks |
|--------|----|------------|
| **Goal Integrity** | AA-GI | Prompt injection, instruction boundaries, scope leakage, jailbreak patterns |
| **Tool Safety** | AA-TS | Shell/network/filesystem capabilities, input validation, sandboxing, rate limits |
| **Identity & Access** | AA-IA | Hardcoded keys, permissive CORS, missing auth, privilege escalation |
| **Supply Chain** | AA-SC | Unpinned deps, unverified packages, model provenance, MCP server trust |
| **Code Execution** | AA-CE | eval/exec, shell injection, unsafe deserialization, sandbox escape |
| **Memory & Context** | AA-MP | Unbounded memory, context stuffing, RAG poisoning, session isolation |
| **Data Leakage** | AA-DL | PII logging, credential exposure, verbose errors, output filtering |
| **Cascading Failures** | AA-CF | No timeouts, missing circuit breakers, infinite loops, resource exhaustion |

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
          npx @guard0/agentsec gate . --min-score 70 --sarif results.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```bash
# .husky/pre-commit
npx @guard0/agentsec gate . --min-score 70 --no-critical --quiet
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

## Programmatic API

```typescript
import { runScan } from '@guard0/agentsec';

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
