# g0 — The security control layer for AI agents

**Assess. Map. Control.**

```bash
npx @guard0/g0 scan ./my-agent
```

> **[Guard0 Cloud](https://guard0.ai)** — Free dashboard with architecture visualization, compliance mapping, and AI-powered triage. Run `g0 scan . --upload` to see your results.

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

See [docs/rules.md](docs/rules.md) for the full rules reference and [docs/compliance.md](docs/compliance.md) for the complete standards mapping.

## Commands

| Command | Purpose |
|---------|---------|
| `g0 scan [path]` | Security assessment with scoring and grading |
| `g0 inventory [path]` | AI Bill of Materials (CycloneDX 1.6, JSON, Markdown) |
| `g0 flows [path]` | Agent execution path mapping and toxic flow detection |
| `g0 mcp [path]` | MCP server assessment and rug-pull detection |
| `g0 test` | Dynamic adversarial testing (HTTP and MCP targets) |
| `g0 gate [path]` | CI/CD quality gate with configurable thresholds |
| `g0 auth` | Guard0 Cloud authentication |
| `g0 daemon` | Background monitoring daemon |

All commands support `--upload` to sync results to Guard0 Cloud, `--json` for programmatic output, and `--sarif` for GitHub Code Scanning integration.

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

## Output Formats

Terminal (default), JSON, SARIF 2.1.0, HTML, CycloneDX 1.6, and Markdown.

## Documentation

| Document | Description |
|----------|-------------|
| [docs/rules.md](docs/rules.md) | Complete rules reference — all domains, severities, and check types |
| [docs/compliance.md](docs/compliance.md) | Standards mapping — 10 frameworks with full domain matrix |
| [docs/scoring.md](docs/scoring.md) | Scoring methodology — formula, weights, multipliers, grades |

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

[Apache-2.0](LICENSE)

---

<sub>g0 is an open-source project by [Guard0](https://guard0.ai). AI Thinks. We Secure.</sub>
