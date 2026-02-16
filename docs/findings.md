# Understanding Findings

This guide explains how to read, filter, suppress, and triage g0 findings.

## Finding Anatomy

Every finding has these fields:

| Field | Description |
|-------|-------------|
| `ruleId` | Unique rule identifier (e.g., `AA-CE-003`) |
| `name` | Human-readable rule name |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `confidence` | `high`, `medium`, or `low` |
| `domain` | Security domain (e.g., `code-execution`) |
| `description` | What the rule detected |
| `location` | File path and line number |
| `reachability` | How accessible the code is from agent entry points |
| `exploitability` | Exploitability assessment |
| `standards` | Mapped standards (OWASP Agentic, NIST, ISO, etc.) |

### Reachability Levels

| Level | Multiplier | Meaning |
|-------|-----------|---------|
| `agent-reachable` | 1.0x | In agent definition or directly called by agent |
| `tool-reachable` | 1.0x | In tool implementation called by agent |
| `endpoint-reachable` | 0.8x | In API route handler or HTTP endpoint |
| `utility-code` | 0.3x | Helper/library code not on agent path |
| `unknown` | 0.6x | Reachability not determined |

Reachability directly affects the score — a critical finding in utility code has less impact than one in agent-reachable code.

## Reading Terminal Output

The default terminal output groups findings by severity:

```
  CRITICAL (2)

    AA-CE-003  Unsandboxed code execution in agent tool
               src/tools/execute.py:42
               Domain: code-execution | Reachability: agent-reachable
               OWASP: ASI05 | NIST: MAP-2.3

    AA-DL-001  System prompt leaked via error message
               src/agent.py:87
               Domain: data-leakage | Reachability: agent-reachable

  HIGH (5)

    AA-TS-012  Tool lacks input validation
               src/tools/search.py:18
               ...
```

### Score Summary

```
  ┌─────────────────────────────────────────┐
  │  Score: 72/100 (C)                      │
  │                                         │
  │  Goal Integrity       85/100  B         │
  │  Tool Safety          62/100  D         │
  │  Identity & Access    90/100  A         │
  │  Code Execution       45/100  F         │
  │  ...                                    │
  └─────────────────────────────────────────┘
```

## JSON Output

```bash
g0 scan . --json
```

JSON findings include all fields:

```json
{
  "findings": [
    {
      "ruleId": "AA-CE-003",
      "name": "Unsandboxed code execution in agent tool",
      "severity": "critical",
      "confidence": "high",
      "domain": "code-execution",
      "description": "Agent tool executes code without sandboxing...",
      "location": {
        "file": "src/tools/execute.py",
        "line": 42
      },
      "reachability": "agent-reachable",
      "standards": {
        "owaspAgentic": ["ASI05"],
        "nistAiRmf": ["MAP-2.3"],
        "iso42001": ["A.8"],
        "mitreAtlas": ["AML.T0040"]
      }
    }
  ],
  "score": {
    "overall": 72,
    "grade": "C",
    "domains": { ... }
  }
}
```

## SARIF Output

```bash
g0 scan . --sarif results.sarif
```

SARIF 2.1.0 format integrates with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools. Findings appear as annotations on pull requests.

## Filtering Findings

### By Severity

```bash
g0 scan . --severity high          # Only high and critical
g0 scan . --severity critical      # Only critical
```

### By Confidence

```bash
g0 scan . --min-confidence high    # Only high-confidence findings
```

### By Rule

```bash
g0 scan . --rules AA-CE-003,AA-TS-012    # Only these rules
g0 scan . --exclude-rules AA-GI-001      # Skip these rules
```

### By Framework

```bash
g0 scan . --frameworks langchain,openai   # Only these frameworks
```

### Show Suppressed Findings

By default, findings in utility code are suppressed. To see everything:

```bash
g0 scan . --show-all
```

## Suppressing Findings

### Inline Suppression

Add a `g0-ignore` comment on the line before or on the same line:

```python
# g0-ignore: AA-GI-001
agent = create_react_agent(llm, tools, prompt)
```

```typescript
// g0-ignore: AA-TS-012
const tool = new Tool({ name: 'search' }); // g0-ignore: AA-TS-005
```

### Configuration-Based Suppression

In `.g0.yaml`:

```yaml
exclude_rules:
  - AA-GI-001
  - AA-TS-012

exclude_paths:
  - tests/
  - examples/
  - node_modules/
```

### Compensating Controls

Some rules are automatically suppressed when g0 detects compensating security controls in your project. For example, a "missing rate limiting" finding is suppressed if g0 detects rate-limiting middleware in your codebase.

## Triaging Findings

### Priority Order

1. **Critical + agent-reachable** — Fix immediately. These represent exploitable vulnerabilities in agent-accessible code.
2. **Critical + tool-reachable** — Fix soon. Vulnerabilities in tools the agent invokes.
3. **High + agent-reachable** — Plan remediation. Significant risks on the agent path.
4. **High + endpoint-reachable** — Address in next sprint. Risks in API endpoints.
5. **Medium findings** — Review and address based on context.
6. **Low/Info findings** — Informational. Consider during code reviews.

### Context Matters

Not every finding is a bug. Consider:

- **Is the code in production?** Test/example code may have intentional insecurities.
- **Are there compensating controls?** A firewall, WAF, or API gateway may mitigate the risk.
- **What's the threat model?** An internal tool has different risk than a public-facing agent.

### Using AI Triage

```bash
g0 scan . --ai
```

AI analysis provides contextual explanations for each finding, including whether it's likely a true positive and suggested remediations.

### Using Guard0 Cloud

```bash
g0 scan . --upload
```

Guard0 Cloud provides:
- Historical trend tracking
- Architecture visualization showing finding locations in the agent graph
- AI-powered triage with remediation suggestions
- Compliance reports mapping findings to standards
