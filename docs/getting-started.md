# Getting Started with g0

This guide walks you through installing g0, running your first scan, and understanding the results.

## Prerequisites

- **Node.js 20+** — g0 requires Node.js 20 or later
- **npm** or **npx** — Comes with Node.js

## Installation

```bash
# Install globally
npm install -g @guard0/g0

# Or run directly with npx (no install)
npx @guard0/g0 scan .
```

## Your First Scan

Point g0 at any directory containing AI agent code:

```bash
g0 scan ./my-agent
```

g0 will:
1. **Discover** — Walk the directory tree, detect frameworks, and identify AI components
2. **Parse** — Extract agents, tools, prompts, models, and MCP servers from source code
3. **Build** — Construct an Agent Graph representing the component relationships
4. **Analyze** — Run 1,183+ security rules against the graph
5. **Score** — Calculate a 0-100 score across 12 security domains
6. **Report** — Display findings grouped by severity and domain

## Reading the Output

The terminal output includes:

### Score and Grade

```
  Score: 72/100 (C)
```

The overall score is a weighted average of 12 domain scores. Grades range from A (90-100) to F (0-59).

### Domain Breakdown

Each of the 12 security domains gets its own score:

```
  Goal Integrity       85/100  B
  Tool Safety          62/100  D
  Identity & Access    90/100  A
  ...
```

### Findings

Findings are grouped by severity:

```
  CRITICAL  AA-CE-003  Unsandboxed code execution in agent tool
            src/tools/execute.py:42
            Reachability: agent-reachable

  HIGH      AA-TS-012  Tool lacks input validation
            src/tools/search.py:18
            Reachability: tool-reachable
```

Each finding includes:
- **Severity** — critical, high, medium, low, or info
- **Rule ID** — e.g., `AA-CE-003` (domain code + number)
- **Description** — What the rule detected
- **Location** — File path and line number
- **Reachability** — How accessible the code is from agent entry points

## Scanning Remote Repositories

Scan any public GitHub repository directly:

```bash
g0 scan https://github.com/org/repo
```

g0 clones the repository to a temporary directory, scans it, and cleans up.

## Output Formats

```bash
g0 scan . --json                    # JSON to stdout
g0 scan . --json -o results.json    # JSON to file
g0 scan . --sarif results.sarif     # SARIF 2.1.0
g0 scan . --html report.html        # HTML report
```

## Uploading to Guard0 Cloud

```bash
# First, authenticate
g0 auth login

# Then scan with --upload
g0 scan . --upload
```

Guard0 Cloud provides architecture visualization, compliance mapping, historical trends, and AI-powered finding triage — all free.

## AI-Powered Analysis

Enable AI analysis for deeper insights:

```bash
g0 scan . --ai

# Consensus mode — run FP detection N times, keep only majority-agreed decisions
g0 scan . --ai --ai-consensus 3
```

Requires one of: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `GOOGLE_API_KEY`.

The AI pass includes a meta-analyzer that reviews all findings holistically, considering taint flows, cross-file chains, and analyzability gaps to reduce false positives.

## Configuration

Create a `.g0.yaml` in your project root to customize behavior:

```yaml
# Use a preset as a starting point
preset: strict  # strict | balanced | permissive

min_score: 70
rules_dir: ./rules
exclude_rules:
  - AA-GI-001
exclude_paths:
  - tests/
  - node_modules/

# Override severity for specific rules
severity_overrides:
  AA-DL-001: critical
  AA-TS-050: low

# Tune finding thresholds
thresholds:
  max_findings_per_rule: 50
  low_severity_cap: 10
  medium_severity_cap: 30

# Enable/disable specific analyzers
analyzers:
  taint_flow: true
  cross_file: true
  pipeline_taint: true
  analyzability: true

# Adjust domain weights for scoring
domain_weights:
  data-leakage: 1.5
  tool-safety: 1.2
```

### Presets

Presets provide sensible defaults you can override:

| Preset | Description |
|--------|-------------|
| `strict` | High-signal only — critical+high findings, fail_on: medium, min_score: 80 |
| `balanced` | Default behavior — all severities, standard thresholds |
| `permissive` | Critical only — relaxed thresholds, optional analyzers disabled |

```bash
g0 scan . --preset strict
```

## Next Steps

- [Understanding Findings](findings.md) — Deep dive into finding anatomy, filtering, and triage
- [AI Asset Inventory](inventory.md) — Discover all AI components in your codebase
- [MCP Security](mcp-security.md) — Assess MCP server configurations
- [Dynamic Testing](dynamic-testing.md) — Run adversarial tests against live agents
- [CI/CD Integration](ci-cd.md) — Add g0 to your pipeline
- [Custom Rules](custom-rules.md) — Write rules specific to your organization
