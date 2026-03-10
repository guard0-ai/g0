# Custom Rules

g0 supports YAML-based custom rules that you can add to extend the built-in rule set. Custom rules use the same engine and check types as the 715+ built-in YAML rules.

## Loading Custom Rules

Place YAML rule files in a directory and configure it in `.g0.yaml`:

```yaml
rules_dir: ./my-rules
```

Or pass it as a CLI flag:

```bash
g0 scan . --rules-dir ./my-rules
```

g0 will load all `.yaml` files from the directory and compile them alongside built-in rules.

## Rule Schema

Every YAML rule has three sections: `id`, `info`, and `check`.

```yaml
id: AA-GI-100
info:
  name: "Rule name"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "What this rule detects and why it matters"
  frameworks: [all]
  owasp_agentic: [ASI01]
  standards:
    nist_ai_rmf: [MAP-1.5]
    iso42001: ["8.4"]
check:
  type: code_matches
  pattern: "dangerous_function\\("
  message: "Found usage of dangerous_function which can lead to..."
```

### ID Format

```
AA-{DOMAIN}-{NUMBER}
```

- `AA` prefix is required
- Domain codes: GI, TS, IA, SC, CE, MP, DL, CF, HO, IC, RB, RA
- Number: 3 digits (001-999)
- Custom rules should use high numbers (e.g., 100+) to avoid conflicts

### Info Section

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable rule name |
| `domain` | enum | yes | One of the 12 security domains |
| `severity` | enum | yes | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | enum | yes | `high`, `medium`, `low` |
| `description` | string | yes | What the rule detects |
| `frameworks` | string[] | no | Framework filter, default `[all]` |
| `owasp_agentic` | string[] | no | OWASP Agentic references (ASI01-ASI10) |
| `standards` | object | no | Additional standards mapping |

### Domains

| Domain | Code |
|--------|------|
| `goal-integrity` | GI |
| `tool-safety` | TS |
| `identity-access` | IA |
| `supply-chain` | SC |
| `code-execution` | CE |
| `memory-context` | MP |
| `data-leakage` | DL |
| `cascading-failures` | CF |
| `human-oversight` | HO |
| `inter-agent` | IC |
| `reliability-bounds` | RB |
| `rogue-agent` | RA |

### Standards Mapping

Rules are automatically mapped to 10 standards based on their domain. You can override or extend:

```yaml
standards:
  owasp_agentic: [ASI01, ASI03]
  nist_ai_rmf: [MAP-1.5, GOVERN-1.1]
  iso42001: ["8.4"]           # Must be quoted strings
  iso23894: [R.2, R.3]
  owasp_aivss: [AIVSS-PI]
  a2as_basic: [ISOL]
  aiuc1: [UC-1.2]
  eu_ai_act: [Article-15]
  mitre_atlas: [AML.T0051]
  owasp_llm_top10: [LLM01]
```

### Suppression

Rules can be automatically suppressed when compensating controls are detected:

```yaml
suppressed_by:
  - input-validation
  - rate-limiting
```

Available control types: `rate-limiting`, `input-validation`, `output-sanitization`, `authentication`, `authorization`, `encryption`, `logging`, `error-handling`, `timeout`, `sandboxing`, `content-filtering`, `access-control`, `csrf-protection`, `cors-configuration`, `secret-management`, `data-classification`, `audit-trail`, `human-approval`, `circuit-breaker`, `retry-backoff`.

---

## Check Types

There are 13 check types available for YAML rules.

### 1. `code_matches`

Matches a regex pattern against source code files.

```yaml
check:
  type: code_matches
  pattern: "eval\\(.*user"
  language: python          # python, typescript, javascript, java, go, yaml, json, any
  message: "User input passed to eval()"
```

The `language` field filters which files are checked. Default is `any`.

### 2. `prompt_contains`

Fires when a prompt contains a matching pattern — used to detect dangerous prompt content.

```yaml
check:
  type: prompt_contains
  pattern: "ignore previous instructions"
  prompt_type: any          # system, user, template, few_shot, any
  message: "Prompt contains instruction override pattern"
```

### 3. `prompt_missing`

Fires when a prompt does NOT contain a required pattern — used to enforce guardrails.

```yaml
check:
  type: prompt_missing
  pattern: "do not|refuse|you must not|never"
  prompt_type: system
  message: "System prompt lacks refusal instructions"
```

### 4. `config_matches`

Matches patterns in configuration files (YAML, JSON, env).

```yaml
check:
  type: config_matches
  pattern: "temperature:\\s*(0\\.9|1\\.0)"
  message: "High temperature setting increases output unpredictability"
```

### 5. `agent_property`

Checks properties on AgentNode objects in the graph.

```yaml
check:
  type: agent_property
  property: systemPrompt
  condition: missing         # missing, exists, equals
  message: "Agent has no system prompt defined"
```

With `equals`:

```yaml
check:
  type: agent_property
  property: maxIterations
  condition: equals
  value: -1
  message: "Agent has unlimited iterations"
```

### 6. `model_property`

Checks properties on ModelNode objects.

```yaml
check:
  type: model_property
  property: temperature
  condition: matches
  value: "0\\.[89]|1\\.0"
  message: "Model temperature is set dangerously high"
```

Conditions: `missing`, `exists`, `equals`, `matches`.

### 7. `tool_missing_property`

Checks that tools have required security properties. Only three properties are supported:

```yaml
check:
  type: tool_missing_property
  property: hasInputValidation    # hasInputValidation, hasSandboxing, hasSideEffects
  expected: true
  message: "Tool lacks input validation"
```

### 8. `tool_has_capability`

Fires when a tool has a specific capability (detected from its description or implementation).

```yaml
check:
  type: tool_has_capability
  capability: "file_write|file_delete|shell_exec"
  message: "Tool has destructive filesystem capability"
```

### 9. `project_missing`

Fires when the project lacks a specific security control (detected by the control registry).

```yaml
check:
  type: project_missing
  control: rate-limiting
  message: "Project has no rate limiting implementation"
```

Available controls: `rate-limiting`, `input-validation`, `output-sanitization`, `authentication`, `authorization`, `encryption`, `logging`, `error-handling`, `timeout`, `sandboxing`, `content-filtering`, `access-control`, `csrf-protection`, `cors-configuration`, `secret-management`, `data-classification`, `audit-trail`, `human-approval`, `circuit-breaker`, `retry-backoff`.

### 10. `taint_flow`

Detects data flows from untrusted sources to sensitive sinks without sanitization.

```yaml
check:
  type: taint_flow
  sources:
    - pattern: "request\\.body|request\\.query|req\\.params"
  sinks:
    - pattern: "exec\\(|spawn\\(|system\\("
  sanitizers:
    - pattern: "sanitize|escape|validate"
  language: any
  message: "User input flows to command execution without sanitization"
```

### 11. `no_check`

Advisory-only rules with no static check. These appear in reports but never fire findings.

```yaml
check:
  type: no_check
  message: "This control requires manual review or dynamic testing"
```

---

## Examples

### Detect hardcoded API keys in agent code

```yaml
id: AA-DL-100
info:
  name: "Hardcoded API key in agent"
  domain: data-leakage
  severity: critical
  confidence: high
  description: "API keys hardcoded in agent source code can be extracted and misused"
  frameworks: [all]
  owasp_agentic: [ASI04]
check:
  type: code_matches
  pattern: "(OPENAI_API_KEY|ANTHROPIC_API_KEY|api_key)\\s*=\\s*['\"][a-zA-Z0-9_-]{20,}['\"]"
  message: "Hardcoded API key found in source code"
```

### Enforce system prompt boundaries

```yaml
id: AA-GI-100
info:
  name: "System prompt missing boundary tokens"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "System prompts should include boundary markers to separate instructions from user input"
  frameworks: [langchain, openai]
  owasp_agentic: [ASI01]
check:
  type: prompt_missing
  pattern: "------|====|<system>|\\[INST\\]|<\\|im_start\\|>"
  prompt_type: system
  message: "System prompt has no boundary tokens separating instructions from user content"
suppressed_by:
  - input-validation
```

### Detect unrestricted agent delegation

```yaml
id: AA-IC-100
info:
  name: "Unrestricted agent-to-agent delegation"
  domain: inter-agent
  severity: high
  confidence: medium
  description: "Agent can delegate tasks to other agents without scope restrictions"
  frameworks: [crewai, autogen]
  owasp_agentic: [ASI09]
check:
  type: agent_property
  property: delegationPolicy
  condition: missing
  message: "Agent has no delegation policy restricting which agents it can invoke"
```

## Testing Custom Rules

Run g0 against a test fixture with your rules:

```bash
g0 scan tests/fixtures/my-test-project --rules-dir ./my-rules --json
```

Verify the expected findings appear in the output. For automated testing, pipe to `jq`:

```bash
g0 scan tests/fixtures/test-project --rules-dir ./my-rules --json | \
  jq '.findings[] | select(.ruleId == "AA-GI-100")'
```
