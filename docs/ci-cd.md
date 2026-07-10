# CI/CD Integration

g0 integrates into your CI/CD pipeline to catch AI security issues before they reach production.

## Quality Gate

The `g0 gate` command is designed for CI — configurable thresholds with SARIF output:

```bash
g0 gate .                           # Pass/fail (default: min-score 70)
g0 gate . --min-score 80            # Custom score threshold
g0 gate . --min-grade B             # Minimum grade
g0 gate . --no-critical             # Fail on any critical findings
g0 gate . --sarif results.sarif     # Also output SARIF for Code Scanning
g0 gate . -o results.json           # Also save JSON results
```

### Diff-based gating (regression mode)

Adopt g0 on an existing codebase without gating on pre-existing debt — baseline
today's findings, then fail only on findings that are **new** relative to the
baseline:

```bash
g0 gate . --write-baseline .g0-baseline.json   # snapshot current findings (commit this)
g0 gate . --baseline .g0-baseline.json         # CI: fails only on new findings
```

In baseline mode the absolute score/grade thresholds are skipped (pre-existing
debt is intentionally tolerated) and the gate defaults to failing on any new
critical/high finding. Baseline fingerprints are line-independent (rule + file +
normalized title), so unrelated edits that shift line numbers don't resurface a
known finding.

## GitHub Actions

### Basic Security Gate

```yaml
name: AI Agent Security
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: g0 Security Gate
        run: npx @guard0/g0 gate .
        # Exits 1 if critical or high findings detected
```

### With SARIF + GitHub Code Scanning

```yaml
name: AI Agent Security
on: [push, pull_request]

permissions:
  security-events: write
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: g0 Security Gate
        run: npx @guard0/g0 gate . --min-score 70 --sarif results.sarif

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### Inventory Diff Check

Detect unauthorized AI component changes:

```yaml
name: AI Inventory Check
on: [pull_request]

jobs:
  inventory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Generate inventory
        run: npx @guard0/g0 inventory . --json -o current.json

      - name: Diff against baseline
        run: npx @guard0/g0 inventory . --diff baseline.json
```

### MCP Pin Check

Detect MCP tool description changes:

```yaml
- name: Check MCP pins
  run: npx @guard0/g0 mcp --check
```

## GitLab CI

```yaml
ai-security:
  image: node:20
  stage: test
  script:
    - npx @guard0/g0 gate . --min-score 70 -o results.json
  artifacts:
    reports:
      sast: results.sarif
    when: always
```

### With JSON Report

```yaml
ai-security:
  image: node:20
  stage: test
  script:
    - npx @guard0/g0 gate . --min-score 70
    - npx @guard0/g0 scan . --json -o g0-report.json
  artifacts:
    paths:
      - g0-report.json
    when: always
```

## Jenkins

### Declarative Pipeline

```groovy
pipeline {
    agent { docker { image 'node:20' } }

    stages {
        stage('AI Security') {
            steps {
                sh 'npx @guard0/g0 gate . --min-score 70 -o results.json'
            }
            post {
                always {
                    recordIssues(tools: [sarif(pattern: 'results.sarif')])
                }
            }
        }
    }
}
```

## Pre-commit Hook

### With Husky

```bash
# .husky/pre-commit
npx @guard0/g0 gate . --min-score 70 --no-critical
```

### With lint-staged

```json
{
  "lint-staged": {
    "*.{py,ts,js,java,go}": "npx @guard0/g0 gate . --no-critical"
  }
}
```

## Policy-Based CI Gate

g0 supports policy-as-code via `.g0-policy.yaml`. Use `--ci` to evaluate scan results against your security policy:

### .g0-policy.yaml

```yaml
apiVersion: guard0.dev/v1
kind: SecurityPolicy
spec:
  scan:
    min_grade: B
    max_critical: 0
    required_standards: [owasp-asi, nist-ai-rmf]
  runtime:
    kill_switch: required
    injection_response: block
  host:
    firewall: required
    disk_encryption: required
  enforcement:
    ci_gate: true
```

### Usage

```bash
g0 scan . --ci                    # Evaluate against .g0-policy.yaml
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All policy requirements met |
| 1 | Critical or high policy violation |
| 2 | Medium or low policy violation (warning) |

### GitHub Actions

```yaml
- name: g0 Policy Gate
  run: npx @guard0/g0 scan . --ci
```

When running in GitHub Actions, g0 automatically outputs `::error::` and `::warning::` annotations for each policy violation.

## Configuration

Use `.g0.yaml` to configure thresholds and exclusions for CI:

```yaml
min_score: 70
exclude_rules:
  - AA-GI-001          # Accepted risk
exclude_paths:
  - tests/
  - examples/
  - docs/
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All thresholds passed |
| 1 | One or more thresholds failed |
| 2 | Scan error (invalid path, config error, etc.) |

## Recommended Pipeline

```
PR opened
  ├── g0 gate (fast, blocks merge)
  ├── g0 scan --json(annotations on PR)
  └── g0 inventory --diff (component change detection)

Merge to main
  ├── g0 scan (track history)
  ├── g0 inventory (track components)
  └── g0 test --auto (dynamic testing in staging)
```
