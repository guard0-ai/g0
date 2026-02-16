# CI/CD Integration

g0 integrates into your CI/CD pipeline to catch AI security issues before they reach production.

## Quality Gate

The `g0 gate` command is designed for CI — it exits with code 1 if the scan fails your thresholds:

```bash
g0 gate .                           # Default: min score 70
g0 gate . --min-score 80            # Custom score threshold
g0 gate . --min-grade B             # Grade-based threshold
g0 gate . --no-critical             # Fail on any critical finding
g0 gate . --no-high                 # Fail on any high or critical finding
g0 gate . --sarif results.sarif     # Also produce SARIF output
```

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
        run: npx @guard0/g0 gate . --min-score 70
```

### With SARIF Upload (GitHub Code Scanning)

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

      - name: g0 Security Assessment
        run: npx @guard0/g0 gate . --min-score 70 --sarif results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

SARIF findings appear as annotations on pull requests and in the Security tab.

### Full Assessment with Guard0 Cloud

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

      - name: g0 Security Assessment
        env:
          G0_API_KEY: ${{ secrets.G0_API_KEY }}
        run: |
          npx @guard0/g0 gate . --min-score 70 --sarif results.sarif
          npx @guard0/g0 scan . --upload
          npx @guard0/g0 inventory . --upload

      - name: Upload SARIF
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
    - npx @guard0/g0 gate . --min-score 70 --sarif results.sarif
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
                sh 'npx @guard0/g0 gate . --min-score 70 --sarif results.sarif'
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
npx @guard0/g0 gate . --min-score 70 --no-critical --quiet
```

### With lint-staged

```json
{
  "lint-staged": {
    "*.{py,ts,js,java,go}": "npx @guard0/g0 gate . --no-critical --quiet"
  }
}
```

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
  ├── g0 scan --sarif (annotations on PR)
  └── g0 inventory --diff (component change detection)

Merge to main
  ├── g0 scan --upload (track history)
  ├── g0 inventory --upload (track components)
  └── g0 test --auto (dynamic testing in staging)
```
