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

  // Rule access
  getAllRules,
  getRuleById,
  getRulesByDomain,

  // Scoring
  calculateScore,

  // Reporters
  reportJson,
  reportHtml,
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

## `reportJson`

Format scan results as JSON.

```typescript
import { runScan, reportJson } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });
const json = reportJson(result);
console.log(json);  // JSON string
```

## `reportHtml`

Format scan results as an HTML report.

```typescript
import { runScan, reportHtml } from '@guard0/g0';

const result = await runScan({ targetPath: './my-agent' });
const html = reportHtml(result);
// Write to file or serve via HTTP
```

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
