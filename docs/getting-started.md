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

## Your First Background Check

The fastest way to get value from g0 is the one-command background check:

```bash
g0 check
```

It discovers the AI tools, MCP servers, and agent skills installed on your
machine, checks them against the known-malicious database (campaign IOCs,
infostealer artifacts), and prints a single grade. If anything known-malicious
is present, the grade is capped at F and the command exits 1 — safe to drop
straight into a shell script or CI job. Use `g0 check [path]` to include a
project's skills, `--no-endpoint` to audit skills only, and `--json` for
machine-readable output.

## Your First Scan

Point g0 at any directory containing AI agent code:

```bash
g0 scan ./my-agent
```

g0 will:
1. **Discover** — Walk the directory tree, detect frameworks, and identify AI components
2. **Parse** — Extract agents, tools, prompts, models, and MCP servers from source code
3. **Build** — Construct an Agent Graph representing the component relationships
4. **Analyze** — Run 1,128 security rules against the graph
5. **Score** — Calculate a 0-100 score across 12 security domains
6. **Report** — Display findings grouped by severity and domain

## Reading the Output

The terminal output includes:

### Score and Grade

```
  Score: 72/100 (C)
```

Grades range from A (90-100) to F (0-59), based on findings across 12 security domains.

The grade is **capped** when critical findings are present, so a project with
serious issues can never read as a healthy grade even if most domains look clean.
When this happens the output shows the reason (e.g. `Grade capped: 3 exploitable
critical findings`). See [Scoring Methodology](scoring.md#grade-cap-criticals-never-read-as-a-healthy-grade).

g0 shows domain-level scores for all 12 security domains. For trend analysis over time → [Guard0 Platform](https://guard0.ai/signup).

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
- **Fix** — Remediation guidance (how to resolve the issue)
- **Standards** — Mapped compliance standards (OWASP, NIST, ISO, etc.)
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
g0 scan . --sarif                   # SARIF 2.1.0 to stdout
g0 scan . --sarif report.sarif      # SARIF to file
g0 scan . --junit                   # JUnit XML to stdout
g0 scan . --junit results.xml       # JUnit XML to file (CI test reporting)
```

## Guard0 Platform

For HTML dashboards, compliance reporting, team collaboration, and enterprise features:

→ [Guard0 Platform](https://guard0.ai/signup)

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

### Validating Your Config

Validate `.g0.yaml` locally before CI does:

```bash
g0 config validate              # validate g0 config files found in the current directory
g0 config validate .g0.yaml     # validate a specific file (or a directory)
```

Prints per-file errors and warnings and exits non-zero on errors, so it works in CI too.

## Pre-commit Hooks

Generate a git hook that runs `g0 scan --ci` before every commit:

```bash
g0 init --hooks
```

g0 auto-detects your hook manager — husky (`.husky/` or a `husky` dependency), lefthook (`lefthook.yml`/`.yaml` or a `lefthook` dependency), or a standalone `.git/hooks` script otherwise. Options:

- `--hook-manager <manager>` — force `husky`, `lefthook`, or `standalone`
- `--hook-type <type>` — `pre-commit` (default) or `pre-push`
- `--min-severity <severity>` — minimum severity to block on (default: `high`)
- `-f, --force` — overwrite an existing hook

Bypass a blocking hook with `git commit --no-verify` (use with caution).

## Troubleshooting

### npm permission errors (EACCES)

If you see `EACCES: permission denied` during `npm install -g`:

```bash
# Option 1: Configure npm to use a user-writable directory (recommended)
mkdir -p ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
npm install -g @guard0/g0

# Option 2: Use npx instead (no global install needed)
npx @guard0/g0 scan .
```

Avoid using `sudo npm install -g` — it can cause ownership issues with your npm cache.

### "Command not found: g0"

After installing globally, if `g0` is not found:

```bash
# Check where npm installs global binaries
echo "$(npm config get prefix)/bin"

# Add that directory to your PATH if it's not already
# For bash:
echo 'export PATH=$(npm config get prefix)/bin:$PATH' >> ~/.bashrc && source ~/.bashrc

# For zsh:
echo 'export PATH=$(npm config get prefix)/bin:$PATH' >> ~/.zshrc && source ~/.zshrc

# Verify
which g0
```

### Node.js version too old

g0 requires Node.js 20 or later. Check your version:

```bash
node --version
```

If you see v18 or earlier, upgrade via:

```bash
# Using nvm (recommended)
nvm install 20
nvm use 20

# Using Homebrew (macOS)
brew install node@20

# Using the official installer
# https://nodejs.org/en/download
```

### Tree-sitter optional dependency warnings

During installation you may see warnings like:

```
npm warn optional SKIPPING OPTIONAL DEPENDENCY: tree-sitter-python
```

These are safe to ignore. Tree-sitter is an optional dependency used for enhanced parsing. g0 falls back to regex-based parsing when tree-sitter is not available. All core functionality works without it.

### Windows Notes

g0 works on Windows via PowerShell or WSL. A few things to note:

- **WSL recommended** — Host hardening checks (`g0 detect`) rely on Unix tools (`ps`, `lsof`) and will skip on native Windows.
- **Long paths** — Enable long path support if scanning deep directory trees: `git config --system core.longpaths true`.
- **Line endings** — Use `git config core.autocrlf input` to avoid CRLF issues in rule YAML files.
- **npx on PowerShell** — If npx hangs, try `npx.cmd @guard0/g0 scan .`.

## Next Steps

- [OpenClaw Security](openclaw-security.md) — Full OpenClaw/MCP security coverage
- [MCP Security](mcp-security.md) — Assess MCP server configurations
- [Dynamic Testing](dynamic-testing.md) — Run adversarial tests against live agents
- [Understanding Findings](findings.md) — Deep dive into finding anatomy and triage
- [AI Asset Inventory](inventory.md) — Discover all AI components in your codebase
- [CI/CD Integration](ci-cd.md) — Add g0 to your pipeline
- [Custom Rules](custom-rules.md) — Write rules specific to your organization

## Beyond Scanning

g0 finds the problems. For the full security lifecycle:

| What You Need | Where |
|---|---|
| Remediation guidance and standards mapping | Included in g0 (`Fix:` and `Standards:` on every finding) |
| SARIF output for GitHub Code Scanning | Included in g0 (`--sarif`) |
| Domain score breakdown | Included in g0 (12 domains shown in terminal) |
| Premium real-time threat feed | Included after `g0 login` — see [Platform & Authentication](platform.md) |
| Compliance reports (EU AI Act, NIST, ISO 42001) | [Guard0 Platform](https://guard0.ai/signup) |
| Team dashboard and shared visibility | [Guard0 Platform](https://guard0.ai/signup) |
| Adaptive red teaming (GOAT, Crescendo, SIMBA) | [Guard0 Platform](https://guard0.ai/signup) |
| Historical trends and regression alerts | [Guard0 Platform](https://guard0.ai/signup) |
| HTML reports for Jira, Splunk, stakeholders | [Guard0 Platform](https://guard0.ai/signup) |

Scanning stays fully offline and needs no account. To unlock the premium threat feed, run `g0 login` (browser device flow, or `--api-key` for CI) — it connects the CLI to your account without ever uploading your scans. See [Platform & Authentication](platform.md).
