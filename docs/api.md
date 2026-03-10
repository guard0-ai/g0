# Programmatic API

g0 exports a TypeScript SDK for integrating security scanning into your own tools and workflows.

## Installation

```bash
npm install @guard0/g0
```

## Core Exports

```typescript
import {
  // Pipeline functions
  runScan,
  runDiscovery,
  runGraphBuild,
  runTests,

  // Rule access
  getAllRules,
  getRuleById,
  getRulesByDomain,

  // Scoring
  calculateScore,

  // Reporters
  reportTerminal,
  reportJson,
  reportHtml,
  reportSarif,
  reportComplianceHtml,
} from '@guard0/g0';
```

## `runScan`

Run a full security assessment and get back findings, scores, and the agent graph.

```typescript
import { runScan } from '@guard0/g0';

const result = await runScan({
  targetPath: './my-agent',
});

console.log(result.score.overall);     // 72
console.log(result.score.grade);       // 'C'
console.log(result.findings.length);   // 15
console.log(result.graph.agents);      // AgentNode[]
```

### Options

```typescript
interface ScanOptions {
  targetPath: string;
  config?: {
    min_score?: number;
    exclude_rules?: string[];
    exclude_paths?: string[];
    rules_dir?: string;
  };
  severity?: 'critical' | 'high' | 'medium' | 'low';
  frameworks?: string[];
  includeTests?: boolean;
}
```

### Return Type

```typescript
interface ScanResult {
  findings: Finding[];
  score: ScanScore;
  graph: AgentGraph;
  discovery: DiscoveryResult;
}
```

## `runTests`

Run adversarial security tests against a live AI agent endpoint or MCP server.

```typescript
import { runTests } from '@guard0/g0';

const result = await runTests({
  target: {
    endpoint: 'http://localhost:3000/chat',
    method: 'POST',
  },
  categories: ['prompt-injection', 'data-exfiltration'],
  timeout: 30000,
});

console.log(result.summary.total);      // 42
console.log(result.summary.passed);     // 38
console.log(result.summary.failed);     // 4
console.log(result.summary.passRate);   // 90.5
```

### Test Options

```typescript
interface TestRunOptions {
  target: TestTarget;                     // HTTP endpoint or MCP server
  categories?: AttackCategory[];          // Filter by attack category
  payloadIds?: string[];                  // Run specific payloads by ID
  mutators?: MutatorId[];                 // Apply payload mutations (base64, leetspeak, etc.)
  mutateStack?: boolean;                  // Stack multiple mutators
  dataset?: string;                       // External dataset path (JSONL)
  strategy?: string;                      // Multi-turn strategy name
  canary?: boolean;                       // Inject canary tokens
  staticContext?: StaticContext;           // Scan results for targeted payloads
  aiProvider?: AIProvider | null;         // AI provider for LLM-as-judge
  timeout?: number;                       // Per-request timeout (ms)
  verbose?: boolean;                      // Enable verbose logging
  concurrency?: number;                   // Parallel requests (default: 1)
  rateDelayMs?: number;                   // Delay between requests (ms)
  adaptive?: boolean;                     // Enable multi-turn adaptive attacks
  adaptiveStrategies?: AdaptiveStrategyId[];  // Adaptive strategy IDs
  adaptiveMaxTurns?: number;              // Max turns per adaptive attack
  redTeamModel?: string;                  // Model for red-team generation
}
```

### Test Target

```typescript
interface TestTarget {
  endpoint?: string;           // HTTP URL
  method?: string;             // HTTP method (default: POST)
  headers?: Record<string, string>;  // Custom headers
  mcpServer?: {
    command: string;           // MCP server command
    args?: string[];           // Command arguments
    env?: Record<string, string>;
  };
}
```

### Attack Categories

Available categories: `prompt-injection`, `data-exfiltration`, `tool-abuse`, `jailbreak`, `goal-hijacking`, `content-safety`, `bias-detection`, `pii-probing`, `agentic-attacks`, `jailbreak-advanced`, `cross-tool-chain`, `taint-exploit`, `description-mismatch`, `tool-output-injection`.

### Example: Testing an MCP Server

```typescript
import { runTests } from '@guard0/g0';

const result = await runTests({
  target: {
    mcpServer: {
      command: 'node',
      args: ['./dist/server.js'],
    },
  },
  categories: ['prompt-injection', 'tool-abuse'],
});

for (const test of result.results.filter(r => !r.passed)) {
  console.log(`FAIL: ${test.payload.name} — ${test.judgeReason}`);
}
```

## `runDiscovery`

Run only the discovery phase — detect frameworks and walk files.

```typescript
import { runDiscovery } from '@guard0/g0';

const discovery = await runDiscovery({
  targetPath: './my-agent',
});

console.log(discovery.frameworks);  // ['langchain', 'openai']
console.log(discovery.files.length); // 42
```

## `runGraphBuild`

Build an agent graph from discovery results.

```typescript
import { runDiscovery, runGraphBuild } from '@guard0/g0';

const discovery = await runDiscovery({ targetPath: './my-agent' });
const graph = await runGraphBuild(discovery);

console.log(graph.agents);     // AgentNode[]
console.log(graph.tools);      // ToolNode[]
console.log(graph.prompts);    // PromptNode[]
console.log(graph.models);     // ModelNode[]
console.log(graph.vectorDBs);  // VectorDBNode[]
```

## `getAllRules`

Get all registered security rules.

```typescript
import { getAllRules } from '@guard0/g0';

const rules = getAllRules();
console.log(rules.length);  // 1238+
```

## `getRuleById`

Look up a specific rule.

```typescript
import { getRuleById } from '@guard0/g0';

const rule = getRuleById('AA-CE-003');
console.log(rule?.name);        // 'Unsandboxed code execution'
console.log(rule?.severity);    // 'critical'
console.log(rule?.domain);      // 'code-execution'
```

## `getRulesByDomain`

Get all rules for a security domain.

```typescript
import { getRulesByDomain } from '@guard0/g0';

const rules = getRulesByDomain('tool-safety');
console.log(rules.length);  // ~130
```

## `calculateScore`

Calculate a score from findings.

```typescript
import { calculateScore } from '@guard0/g0';

const score = calculateScore(findings);
console.log(score.overall);  // 72
console.log(score.grade);    // 'C'
console.log(score.domains);  // { 'goal-integrity': { score: 85, grade: 'B' }, ... }
```

## Reporters

### `reportTerminal`

Print scan results to the terminal with color formatting.

```typescript
import { runScan, reportTerminal } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });
reportTerminal(result);

// With options
reportTerminal(result, {
  showBanner: true,
  showUploadNudge: false,
  hiddenLowConfidence: 5,
});
```

### `reportJson`

Format scan results as JSON. Optionally write to a file.

```typescript
import { runScan, reportJson } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });

// Get JSON string
const json = reportJson(result);
console.log(json);

// Write directly to file
reportJson(result, 'results.json');
```

### `reportHtml`

Generate a self-contained HTML report file.

```typescript
import { runScan, reportHtml } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });
reportHtml(result, 'report.html');
```

### `reportSarif`

Generate a SARIF 2.1.0 report for integration with GitHub Code Scanning, VS Code, and other SARIF-compatible tools.

```typescript
import { runScan, reportSarif } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });

// Get SARIF string
const sarif = reportSarif(result);
console.log(sarif);

// Write directly to file
reportSarif(result, 'results.sarif');
```

### `reportComplianceHtml`

Generate an HTML compliance report against a specific standard.

```typescript
import { runScan, reportComplianceHtml } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });

// Supported standards: owasp-agentic, aiuc1, iso42001, nist-ai-rmf,
//                      iso23894, owasp-aivss, owasp-agentic-top10, eu-ai-act,
//                      mitre-atlas, owasp-llm-top10
reportComplianceHtml(result, 'owasp-agentic', 'compliance-report.html');
```

## Configuration

### `.g0.yaml` Reference

Create a `.g0.yaml` in your project root:

```yaml
# ── Preset (starting point) ────────────────────────────────
preset: balanced  # strict | balanced | permissive

# ── Score & Rules ───────────────────────────────────────────
min_score: 70
rules_dir: ./custom-rules          # directory of custom YAML rules
exclude_rules:
  - AA-GI-001
  - AA-TS-050
exclude_paths:
  - tests/
  - node_modules/
  - vendor/

# ── Severity Overrides ──────────────────────────────────────
# Promote or demote individual rules
severity_overrides:
  AA-DL-001: critical
  AA-TS-050: low

# ── Finding Thresholds ──────────────────────────────────────
thresholds:
  max_findings_per_rule: 50
  low_severity_cap: 10
  medium_severity_cap: 30

# ── Analyzers ───────────────────────────────────────────────
analyzers:
  taint_flow: true                 # trace tainted data across function calls
  cross_file: true                 # detect cross-file exfiltration chains
  pipeline_taint: true             # detect shell pipe chains (source -> sink)
  analyzability: true              # classify files as analyzable/inert/opaque

# ── Domain Weights ──────────────────────────────────────────
# Adjust domain importance for scoring (default: 1.0)
domain_weights:
  data-leakage: 1.5
  tool-safety: 1.2
  goal-integrity: 1.0

# ── Risk Acceptance ─────────────────────────────────────────
# Suppress known-accepted findings
risk_accepted:
  - rule_id: AA-TS-012
    reason: "Validated via external WAF"
    accepted_by: "security-team"
    expires: "2026-12-31"
```

### Presets

| Preset | Description |
|--------|-------------|
| `strict` | High-signal only — critical+high findings, fail_on: medium, min_score: 80 |
| `balanced` | Default — all severities, standard thresholds |
| `permissive` | Critical only — relaxed thresholds, optional analyzers disabled |

## YAML Rule Authoring

Custom rules are YAML files placed in your `rules_dir` or `src/rules/builtin/{domain}/`.

### Rule Structure

```yaml
id: AA-TS-200       # Unique ID: AA-{DOMAIN_CODE}-{NUMBER}

info:
  name: "Human-readable rule name"
  domain: tool-safety                       # one of the 12 security domains
  severity: high                            # critical | high | medium | low | info
  confidence: medium                        # high | medium | low
  description: "Detailed description of what this rule detects and why it matters."
  frameworks: [all]                         # [all] or specific: [langchain, openai, mcp]
  owasp_agentic: [ASI02, ASI03]             # OWASP Agentic Security mapping
  standards:
    nist_ai_rmf: [GOVERN-1.2]
    iso42001: ["8.4"]                       # must be quoted strings
    iso23894: [6.2]
    owasp_aivss: [V2.1]
    owasp_agentic_top10: [AAT-9]
    eu_ai_act: [Article-9]
    mitre_atlas: [AML.T0040]
    owasp_llm_top10: [LLM01]

check:
  type: code_matches                        # check type (see below)
  pattern: "exec\\(.*\\)"                   # regex pattern
  language: python                          # optional language filter
  message: "Human-readable finding message"
```

### Check Types

| Type | Description | Key Fields |
|------|-------------|------------|
| `code_matches` | Regex match against source code | `pattern`, `language`, `message` |
| `prompt_contains` | Prompt text contains a pattern | `pattern`, `message` |
| `prompt_missing` | Prompt text is missing a pattern | `pattern`, `message` |
| `config_matches` | Config value matches a pattern | `path`, `pattern`, `message` |
| `agent_property` | Agent node property check | `property`, `condition` (`missing`/`exists`/`equals`), `value` |
| `model_property` | Model node property check | `property`, `condition`, `value` |
| `tool_missing_property` | Tool lacks a safety property | `property` (`hasInputValidation`/`hasSandboxing`/`hasSideEffects`) |
| `tool_has_capability` | Tool has a dangerous capability | `capability` (`shell`/`code-execution`/`filesystem-write`/`network`/`database`) |
| `no_check` | Always fires (for informational rules) | `message` |

### Example: Custom Code Match Rule

```yaml
id: CUSTOM-001

info:
  name: "Hardcoded API key in agent code"
  domain: data-leakage
  severity: critical
  confidence: high
  description: "API keys should not be hardcoded in source files."
  frameworks: [all]
  owasp_agentic: [ASI06]

check:
  type: code_matches
  pattern: "(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})"
  message: "Hardcoded API key detected — use environment variables or a secrets manager"
```

### Example: Missing Prompt Guard

```yaml
id: CUSTOM-002

info:
  name: "System prompt missing injection guard"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "System prompts should include instructions to reject injection attempts."
  frameworks: [all]
  owasp_agentic: [ASI01]

check:
  type: prompt_missing
  pattern: "(ignore previous|do not follow|injection|override)"
  message: "System prompt has no injection defense language"
```

### Domain Codes

| Code | Domain |
|------|--------|
| GI | goal-integrity |
| TS | tool-safety |
| IA | identity-access |
| SC | supply-chain |
| CE | code-execution |
| MC | memory-context |
| DL | data-leakage |
| CF | cascading-failures |
| HO | human-oversight |
| AG | inter-agent |
| RB | reliability-bounds |
| RA | rogue-agent |

## Type Exports

g0 exports all key types for TypeScript consumers:

```typescript
import type {
  ScanResult,
  ScanScore,
  DomainScore,
  Finding,
  FindingSummary,
  AgentGraph,
  AgentNode,
  ToolNode,
  PromptNode,
  ModelNode,
  VectorDBNode,
  FrameworkInfo,
  Severity,
  Confidence,
  FrameworkId,
  Grade,
  SecurityDomain,
  Rule,
  TestRunResult,
  TestCaseResult,
  TestTarget,
  AttackCategory,
  AttackPayload,
} from '@guard0/g0';
```

## Example: Custom CI Tool

```typescript
import { runScan } from '@guard0/g0';

async function checkSecurity(path: string, minScore: number) {
  const result = await runScan({ targetPath: path });

  const criticals = result.findings.filter(f => f.severity === 'critical');

  if (result.score.overall < minScore) {
    console.error(`Score ${result.score.overall} below threshold ${minScore}`);
    process.exit(1);
  }

  if (criticals.length > 0) {
    console.error(`${criticals.length} critical findings`);
    for (const f of criticals) {
      console.error(`  ${f.ruleId}: ${f.name} (${f.location.file}:${f.location.line})`);
    }
    process.exit(1);
  }

  console.log(`Passed: ${result.score.grade} (${result.score.overall}/100)`);
}

checkSecurity('./my-agent', 70);
```
