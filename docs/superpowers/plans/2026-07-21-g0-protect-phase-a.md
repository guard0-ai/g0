# g0 protect — Phase A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the proxy's decision stack into a shared `src/enforcement/` engine (proxy behavior byte-identical), then ship the `g0 protect` orchestrator that wires the existing proxy installer + MCP quarantine + OpenClaw hardener behind one dry-run-first command with a session manifest and full undo.

**Architecture:** Approach 1 from the spec (`docs/superpowers/specs/2026-07-21-g0-protect-design.md`): one enforcement engine, many adapters. Phase A moves `policy/confidence/detectors/edm/provenance/injection-patterns/sensitive-read` + the content half of `response-inspector` out of `src/proxy/` into `src/enforcement/`, adds a neutral `decide(event, policy, state)` facade, refactors `proxy-core.ts` to call it, and builds `src/protect/` (adapter interface, mcp adapter, orchestrator, manifest) + `g0 protect` CLI.

**Tech Stack:** TypeScript ESM (relative imports with `.js` suffix, no path aliases), commander, chalk, vitest (`npm test`), `npm run typecheck` = `tsc --noEmit`, tsup build. No new runtime dependencies in Phase A.

## Global Constraints

- **Fail-open invariants (spec §10):** never break a session or scan; dry-run before every write; every write undoable; no network on scan/enforce paths; per-user scope only.
- **Byte-identical proxy:** every existing proxy test (unit + integration) passes with NO assertion changes — only import-path updates are allowed in test files.
- **SDK stability:** `src/index.ts` re-exports nothing from `src/proxy/`, quarantine, installer, or hardener (verified 2026-07-21) — do not add or change SDK exports in Phase A.
- **No new runtime dependencies.** Node >= 20.
- **Spec type concretization:** the spec's illustrative `EnforcementEvent {transport, direction, client, toolName, payload, sessionId}` is concretized here as `{transport, direction, serverName, toolName, args?, responseText?}` — the response leg needs the *originating request's* args for sensitive-read/provenance; `sessionId` is deferred to Phase B (cross-process hook state).
- **Per task:** run `npm run typecheck` and `npm test` before committing. Conventional-commit messages (`refactor:`, `feat:`, `test:`, `docs:`).
- Several proxy files contain box-drawing chars — use `grep -a` when grepping them.

---

### Task 1: Move detection primitives to `src/enforcement/`

**Files:**
- Move: `src/proxy/detectors/` → `src/enforcement/detectors/` (contains `structured.ts`, `validators.ts`)
- Move: `src/proxy/injection-patterns.ts` → `src/enforcement/injection-patterns.ts`
- Move: `src/proxy/sensitive-read.ts` → `src/enforcement/sensitive-read.ts`
- Move: `src/proxy/response-inspector.ts` → `src/enforcement/response-inspector.ts`, then relocate `extractResponseText` out of it into `src/proxy/jsonrpc.ts`
- Modify: every importer found by the grep in Step 3 (known: `src/proxy/policy.ts`, `src/proxy/proxy-core.ts`, `src/endpoint/quarantine.ts`, `tests/unit/proxy-detectors-structured.test.ts`, `tests/unit/proxy-detectors-validators.test.ts`, `tests/unit/proxy-response-inspector.test.ts`, `tests/unit/proxy-sensitive-read.test.ts`, `tests/unit/proxy-provenance.test.ts`, `tests/unit/proxy-policy.test.ts`, `tests/unit/proxy-policy-v2.test.ts`)

**Interfaces:**
- Consumes: nothing new — pure move.
- Produces: `src/enforcement/response-inspector.js` exporting `inspectResponseText`, `extractHosts`, `ResponseFinding`, `InspectionResult` (unchanged signatures); `src/enforcement/detectors/structured.js`, `.../validators.js`, `src/enforcement/injection-patterns.js`, `src/enforcement/sensitive-read.js` (all signatures unchanged); `extractResponseText(result: unknown): string` now exported from `src/proxy/jsonrpc.ts`.

- [ ] **Step 1: Confirm green baseline**

Run: `npm test`
Expected: PASS (this is the byte-identical bar; note the passing count).

- [ ] **Step 2: Move the files**

```bash
mkdir -p src/enforcement
git mv src/proxy/detectors src/enforcement/detectors
git mv src/proxy/injection-patterns.ts src/enforcement/injection-patterns.ts
git mv src/proxy/sensitive-read.ts src/enforcement/sensitive-read.ts
git mv src/proxy/response-inspector.ts src/enforcement/response-inspector.ts
```

Note: files moving between `src/proxy/` and `src/enforcement/` keep the same directory depth, so their own `../` imports (e.g. `sensitive-read.ts` → `../endpoint/sensitive-paths.js`) stay correct. Only `./` sibling imports of files that did NOT move together need fixing.

- [ ] **Step 3: Relocate `extractResponseText`**

Cut the `extractResponseText` function (with its doc comment) from `src/enforcement/response-inspector.ts` and paste it at the bottom of `src/proxy/jsonrpc.ts` (it is a JSON-RPC result-shape helper, not a content check). Add any imports it needs there (it needs none — it only walks the `result` object).

- [ ] **Step 4: Fix all importers**

Run: `grep -arln "proxy/detectors\|proxy/injection-patterns\|proxy/sensitive-read\|proxy/response-inspector" src tests`

Apply this mapping to every hit (adjusting `../` depth per file location):

| Old specifier ends with | New specifier ends with |
|---|---|
| `proxy/detectors/structured.js` | `enforcement/detectors/structured.js` |
| `proxy/detectors/validators.js` | `enforcement/detectors/validators.js` |
| `proxy/injection-patterns.js` | `enforcement/injection-patterns.js` |
| `proxy/sensitive-read.js` | `enforcement/sensitive-read.js` |
| `proxy/response-inspector.js` (for `inspectResponseText`, `extractHosts`, `ResponseFinding`, `InspectionResult`) | `enforcement/response-inspector.js` |
| `proxy/response-inspector.js` (for `extractResponseText` — only `src/proxy/proxy-core.ts`) | stays in `src/proxy/`: import from `./jsonrpc.js` |

Inside the moved files themselves, siblings that moved together keep `./` imports (e.g. `enforcement/response-inspector.ts` importing `./detectors/structured.js`, `./injection-patterns.js` — already correct).

- [ ] **Step 5: Verify byte-identical behavior**

Run: `npm run typecheck && npm test`
Expected: PASS with the same test count as Step 1, zero assertion changes.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor: move detection primitives from src/proxy to src/enforcement

Detectors, injection patterns, sensitive-read, and the content half of
response-inspector become the shared enforcement core. extractResponseText
(JSON-RPC-shape-specific) relocates to proxy/jsonrpc.ts. No behavior change."
```

---

### Task 2: Move the policy stack to `src/enforcement/`

**Files:**
- Move: `src/proxy/policy.ts`, `src/proxy/confidence.ts`, `src/proxy/edm.ts`, `src/proxy/provenance.ts` → same names under `src/enforcement/`
- Modify: importers found by Step 2's grep (known: `src/proxy/proxy-core.ts`, `src/cli/commands/proxy.ts`, `tests/unit/proxy-policy.test.ts`, `proxy-policy-v2.test.ts`, `proxy-policy-dir-cli.test.ts`, `proxy-confidence.test.ts`, `proxy-edm.test.ts`, `proxy-edm-integration.test.ts`, `proxy-provenance.test.ts`, plus any others the grep surfaces)

**Interfaces:**
- Consumes: Task 1's moved modules (their `./detectors/structured.js` etc. imports become same-directory siblings — already correct).
- Produces: `src/enforcement/policy.js` (`loadPolicy`, `evaluateCall`, `evaluateResponse`, `combineDecisions`, `edmMatchCandidate`, `dataflowMatchCandidate`, `resolveDetectors`, `safeStringify`, `expandHome`, `resolvePathValue`, types `ProxyPolicy`/`EvalContext`/`CompiledRule`/…), `src/enforcement/confidence.js`, `src/enforcement/edm.js` (`EdmIndex`, `loadEdmIndexes`, `matchEdmIndexes`, `buildAndWriteEdmIndex`, …), `src/enforcement/provenance.js` (`SessionProvenance`, `DataflowFinding`, …). All signatures unchanged.

- [ ] **Step 1: Move the files**

```bash
git mv src/proxy/policy.ts src/enforcement/policy.ts
git mv src/proxy/confidence.ts src/enforcement/confidence.ts
git mv src/proxy/edm.ts src/enforcement/edm.ts
git mv src/proxy/provenance.ts src/enforcement/provenance.ts
```

- [ ] **Step 2: Fix all importers**

Run: `grep -arln "proxy/policy\|proxy/confidence\|proxy/edm\|proxy/provenance" src tests`

Mapping: `proxy/policy.js` → `enforcement/policy.js`, `proxy/confidence.js` → `enforcement/confidence.js`, `proxy/edm.js` → `enforcement/edm.js`, `proxy/provenance.js` → `enforcement/provenance.js`. In `src/proxy/proxy-core.ts` the specifiers become `../enforcement/policy.js` etc.

- [ ] **Step 3: Verify**

Run: `npm run typecheck && npm test`
Expected: PASS, same count, zero assertion changes.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor: move policy stack (policy, confidence, edm, provenance) to src/enforcement

No behavior change; src/proxy retains only transport (jsonrpc, proxy-core,
installer, audit-log)."
```

---

### Task 3: Shared JSONL audit writer — `src/enforcement/audit.ts`

**Files:**
- Create: `src/enforcement/audit.ts`
- Modify: `src/proxy/audit-log.ts` (its `appendAudit` delegates the final write+rotate to the shared writer; path derivation, `AuditRecord` typing, `readAudit`, `summarizeAudit` all stay put)
- Test: `tests/unit/enforcement-audit.test.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `appendJsonlLine(filePath: string, record: unknown, maxBytes?: number): void` — creates parent dirs, appends `JSON.stringify(record) + '\n'`, applies the same size-cap/rotation behavior `appendAudit` has today (move that block verbatim), and **never throws**. Phase B's hook audit trail will call this directly.

- [ ] **Step 1: Write the failing test**

```typescript
// tests/unit/enforcement-audit.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { appendJsonlLine } from '../../src/enforcement/audit.js';

describe('appendJsonlLine', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-audit-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('appends records as parseable JSONL, creating parent dirs', () => {
    const file = path.join(tmpDir, 'nested', 'dir', 'audit.jsonl');
    appendJsonlLine(file, { a: 1 });
    appendJsonlLine(file, { b: 2 });
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0])).toEqual({ a: 1 });
    expect(JSON.parse(lines[1])).toEqual({ b: 2 });
  });

  it('keeps working past the size cap and retains the newest record', () => {
    const file = path.join(tmpDir, 'audit.jsonl');
    appendJsonlLine(file, { seed: 'x'.repeat(200) });
    appendJsonlLine(file, { last: true }, 64); // cap far below current size
    const lines = fs.readFileSync(file, 'utf8').trim().split('\n');
    expect(JSON.parse(lines[lines.length - 1])).toEqual({ last: true });
  });

  it('never throws, even when the path is unwritable', () => {
    const blocker = path.join(tmpDir, 'a-file');
    fs.writeFileSync(blocker, '');
    // parent "dir" is a regular file -> mkdir/append must fail internally
    expect(() => appendJsonlLine(path.join(blocker, 'audit.jsonl'), { x: 1 })).not.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/enforcement-audit.test.ts`
Expected: FAIL — cannot resolve `src/enforcement/audit.js`.

- [ ] **Step 3: Implement by extraction**

Open `src/proxy/audit-log.ts`. Inside `appendAudit(record, dir?, maxBytes?)` identify the block that (a) ensures the directory exists, (b) checks current file size against `maxBytes ?? DEFAULT_MAX_AUDIT_LOG_BYTES` and rotates/truncates, (c) `appendFileSync`s the JSON line inside the try/catch that makes it never-throw. Move that block verbatim into:

```typescript
// src/enforcement/audit.ts
import * as fs from 'node:fs';
import * as path from 'node:path';

export const DEFAULT_MAX_JSONL_BYTES = 50 * 1024 * 1024;

/**
 * Append one record as a JSON line. Creates parent dirs, applies the
 * size-cap behavior moved verbatim from proxy audit-log, and NEVER throws
 * (audit writing must not be able to break an enforcement path).
 */
export function appendJsonlLine(filePath: string, record: unknown, maxBytes?: number): void {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    // [size-cap/rotation block moved verbatim from appendAudit, operating on filePath]
    fs.appendFileSync(filePath, JSON.stringify(record) + '\n');
  } catch {
    // never throw — see doc comment
  }
}
```

Then make `appendAudit` in `src/proxy/audit-log.ts` derive its file path exactly as today and end with `appendJsonlLine(filePath, record, maxBytes)`. `DEFAULT_MAX_AUDIT_LOG_BYTES` stays exported from `audit-log.ts` (keep both constants equal).

- [ ] **Step 4: Run tests**

Run: `npx vitest run tests/unit/enforcement-audit.test.ts tests/unit/proxy-audit.test.ts && npm run typecheck`
Expected: PASS (adjust the rotation test's expectation ONLY if the moved block's real semantics differ — e.g. it renames to a `.1` file — but do not change `proxy-audit.test.ts`).

- [ ] **Step 5: Full suite + commit**

Run: `npm test`

```bash
git add -A
git commit -m "refactor: extract shared never-throw JSONL writer to src/enforcement/audit"
```

---

### Task 4: Engine facade — `decide()` + proxy-core refactor

**Files:**
- Create: `src/enforcement/types.ts`, `src/enforcement/engine.ts`
- Modify: `src/proxy/proxy-core.ts` (pipeline calls replaced by `decide()`; helpers move out)
- Test: `tests/unit/enforcement-engine.test.ts`

**Interfaces:**
- Consumes: Tasks 1–2 modules (`evaluateCall`, `evaluateResponse`, `combineDecisions`, `edmMatchCandidate`, `dataflowMatchCandidate`, `resolveDetectors`, `safeStringify` from `./policy.js`; `loadEdmIndexes`, `matchEdmIndexes`, `EdmIndex` from `./edm.js`; `SessionProvenance` from `./provenance.js`; `detectSensitivePathRead` from `./sensitive-read.js`; `inspectResponseText`, `ResponseFinding` from `./response-inspector.js`).
- Produces (Phase B depends on these exact names):
  - `EnforcementEvent { transport: 'mcp-stdio' | 'claude-hook'; direction: 'request' | 'response'; serverName: string; toolName: string; args?: unknown; responseText?: string }`
  - `EngineDecision { decision: PolicyDecision; findingNames?: string[]; inspectionFindings: ResponseFinding[]; auditExtras: Pick<AuditRecord, 'confidence' | 'signals' | 'context'>; redactedText?: string; diagnostics: string[] }`
  - `EngineState { provenance: SessionProvenance; edmIndexes: EdmIndex[] }`
  - `createEngineState(policyDir?: string): EngineState`
  - `decide(event: EnforcementEvent, policy: ProxyPolicy, state: EngineState): EngineDecision`
  - `mergeAuditExtras`, `mergeFindingNames` (moved from proxy-core, still exported)

- [ ] **Step 1: Write the failing test**

```typescript
// tests/unit/enforcement-engine.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadPolicy } from '../../src/enforcement/policy.js';
import { createEngineState, decide } from '../../src/enforcement/engine.js';

const DENY_POLICY = `
mode: enforce
rules:
  - id: no-rm
    tool: "shell*"
    action: deny
    message: shell blocked
`;

describe('enforcement engine decide()', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-engine-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  function policyFrom(yaml: string) {
    fs.writeFileSync(path.join(tmpDir, 'policy.yaml'), yaml);
    return loadPolicy({ dir: tmpDir });
  }

  it('denies a request matching a deny rule', () => {
    const policy = policyFrom(DENY_POLICY);
    const state = createEngineState(tmpDir);
    const out = decide(
      { transport: 'mcp-stdio', direction: 'request', serverName: 's', toolName: 'shell_exec', args: { cmd: 'rm -rf /' } },
      policy, state,
    );
    expect(out.decision.action).toBe('deny');
    expect(out.decision.message).toBe('shell blocked');
    expect(out.diagnostics).toEqual([]);      // no EDM/dataflow fired
    expect(out.inspectionFindings).toEqual([]); // request leg
  });

  it('allows an unmatched request with no findings', () => {
    const policy = policyFrom(DENY_POLICY);
    const state = createEngineState(tmpDir);
    const out = decide(
      { transport: 'mcp-stdio', direction: 'request', serverName: 's', toolName: 'read_file', args: { p: 'a.txt' } },
      policy, state,
    );
    expect(out.decision.action).toBe('allow');
    expect(out.findingNames).toBeUndefined();
  });

  it('redacts a secret-bearing response in enforce mode', () => {
    const policy = policyFrom('mode: enforce\nresponse:\n  redactSecrets: true\n');
    const state = createEngineState(tmpDir);
    const out = decide(
      {
        transport: 'mcp-stdio', direction: 'response', serverName: 's', toolName: 'fetch',
        args: {}, responseText: 'token: AKIAIOSFODNN7EXAMPLE and more',
      },
      policy, state,
    );
    expect(out.inspectionFindings.length).toBeGreaterThan(0);
    expect(out.redactedText).toBeDefined();
    expect(out.redactedText).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  it('tags response provenance so a later cross-tool request surfaces dataflow', () => {
    const policy = policyFrom('mode: enforce\nresponse:\n  redactSecrets: false\n');
    const state = createEngineState(tmpDir);
    const secret = 'AKIAIOSFODNN7EXAMPLE';
    decide(
      { transport: 'mcp-stdio', direction: 'response', serverName: 's', toolName: 'vault_read', args: {}, responseText: `key=${secret}` },
      policy, state,
    );
    const out = decide(
      { transport: 'mcp-stdio', direction: 'request', serverName: 's', toolName: 'http_post', args: { body: secret } },
      policy, state,
    );
    expect(out.diagnostics.some((d) => d.startsWith('provenance: dataflow'))).toBe(true);
  });
});
```

Note: if `loadPolicy`'s rule schema uses a different key than `tool:` for the tool matcher, mirror the YAML used in `tests/unit/proxy-policy.test.ts` — do not invent schema; the assertions stay as written.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/enforcement-engine.test.ts`
Expected: FAIL — cannot resolve `src/enforcement/engine.js`.

- [ ] **Step 3: Create `src/enforcement/types.ts`**

```typescript
import type { AuditRecord, PolicyDecision } from '../types/proxy.js';
import type { ResponseFinding } from './response-inspector.js';

/** One tool-call leg, in transport-neutral form. */
export interface EnforcementEvent {
  transport: 'mcp-stdio' | 'claude-hook';
  direction: 'request' | 'response';
  /** Logical destination server (proxy: the wrapped MCP server's name). */
  serverName: string;
  toolName: string;
  /** Tool-call arguments. On the response leg: the ORIGINATING request's args. */
  args?: unknown;
  /** Response leg only: the extracted response text. */
  responseText?: string;
}

/** Everything a transport needs to act on + record one decision. */
export interface EngineDecision {
  decision: PolicyDecision;
  /** Merged finding labels for the audit record (undefined when none). */
  findingNames?: string[];
  /** Response leg: raw inspection findings (empty array on the request leg). */
  inspectionFindings: ResponseFinding[];
  auditExtras: Pick<AuditRecord, 'confidence' | 'signals' | 'context'>;
  /** Response leg: fully redacted text, when redaction has something to work with. */
  redactedText?: string;
  /** Diagnostic lines (no prefix) to emit, in order, BEFORE acting on the decision. */
  diagnostics: string[];
}
```

- [ ] **Step 4: Create `src/enforcement/engine.ts`**

Move these helpers OUT of `src/proxy/proxy-core.ts` verbatim (they are pure): `edmAuditExtras`, `edmFindingNames`, `dataflowAuditExtras`, `dataflowFindingNames`, `decisionAuditExtras`, `mergeAuditExtras` (keep `export`), `mergeFindingNames` (keep `export`). Then add:

```typescript
import {
  evaluateCall, evaluateResponse, combineDecisions,
  edmMatchCandidate, dataflowMatchCandidate, resolveDetectors, safeStringify,
} from './policy.js';
import type { EvalContext, ProxyPolicy } from './policy.js';
import { loadEdmIndexes, matchEdmIndexes } from './edm.js';
import type { EdmIndex, EdmMatch } from './edm.js';
import { SessionProvenance } from './provenance.js';
import type { DataflowFinding } from './provenance.js';
import { detectSensitivePathRead } from './sensitive-read.js';
import { inspectResponseText } from './response-inspector.js';
import type { AuditRecord, PolicyDecision } from '../types/proxy.js';
import type { EnforcementEvent, EngineDecision } from './types.js';

/** Per-session mutable engine state. The caller owns exactly one per session. */
export interface EngineState {
  provenance: SessionProvenance;
  edmIndexes: EdmIndex[];
}

export function createEngineState(policyDir?: string): EngineState {
  return { provenance: new SessionProvenance(), edmIndexes: loadEdmIndexes(policyDir) };
}

export function decide(event: EnforcementEvent, policy: ProxyPolicy, state: EngineState): EngineDecision {
  return event.direction === 'request'
    ? decideRequest(event, policy, state)
    : decideResponse(event, policy, state);
}

function decideRequest(event: EnforcementEvent, policy: ProxyPolicy, state: EngineState): EngineDecision {
  const diagnostics: string[] = [];
  const evalCtx: EvalContext = {
    destinationServer: event.serverName,
    destinationTool: event.toolName,
    provenance: state.provenance,
  };
  const decision = evaluateCall(policy, 'tools/call', event.toolName, event.args, evalCtx);

  const edmHits = state.edmIndexes.length > 0
    ? matchEdmIndexes(state.edmIndexes, safeStringify(event.args), { maxScanBytes: policy.limits.maxScanBytes })
    : [];
  if (edmHits.length > 0) {
    diagnostics.push(
      `EDM match: outbound arg for tools/call "${event.toolName}" matched fingerprint index(es): ${edmHits.map((h) => h.indexName).join(', ')}`,
    );
  }

  const dataflowHits = state.provenance.taintedCount > 0
    ? state.provenance.detectDataflow(event.toolName, event.args, policy.limits.maxScanBytes)
    : [];
  if (dataflowHits.length > 0) {
    diagnostics.push(
      `provenance: dataflow — response data from tool(s) [${dataflowHits.map((h) => h.originTool).join(', ')}] appeared in tools/call "${event.toolName}" arguments`,
    );
  }

  const requestAuditExtras = mergeAuditExtras(edmAuditExtras(edmHits), dataflowAuditExtras(dataflowHits));
  const findingNames = mergeFindingNames(
    edmHits.length > 0 ? edmFindingNames(edmHits) : [],
    dataflowHits.length > 0 ? dataflowFindingNames(dataflowHits) : [],
  );

  const finalDecision: PolicyDecision = policy.version === 2
    ? combineDecisions(decision, [
        edmMatchCandidate(policy, edmHits, 'request'),
        dataflowMatchCandidate(policy, dataflowHits, event.serverName),
      ])
    : decision;
  const auditExtras = policy.version === 2
    ? mergeAuditExtras(requestAuditExtras, decisionAuditExtras(finalDecision))
    : requestAuditExtras;

  return { decision: finalDecision, findingNames, inspectionFindings: [], auditExtras, diagnostics };
}

function decideResponse(event: EnforcementEvent, policy: ProxyPolicy, state: EngineState): EngineDecision {
  const diagnostics: string[] = [];
  const text = event.responseText ?? '';
  const inspection = inspectResponseText(text, {
    redactSecrets: policy.response.redactSecrets,
    maxScanBytes: policy.limits.maxScanBytes,
    detectors: resolveDetectors(policy),
  });

  state.provenance.tagResponse(event.toolName, event.serverName, inspection.findings);

  const sensitiveRead = detectSensitivePathRead(event.args);
  if (sensitiveRead) {
    state.provenance.tagSensitiveOrigin(event.toolName, event.serverName, text, sensitiveRead.category);
    diagnostics.push(
      `provenance: sensitive-origin — tools/call "${event.toolName}" response tagged as derived from reading ${sensitiveRead.label} (category: ${sensitiveRead.category})`,
    );
  }

  const evalCtx: EvalContext = {
    destinationServer: event.serverName,
    destinationTool: event.toolName,
    provenance: state.provenance,
  };
  const decision = evaluateResponse(policy, event.toolName, inspection, evalCtx);
  const inspectionNames = inspection.findings.map((f) => f.name);

  const edmHits = matchEdmIndexes(state.edmIndexes, text, { maxScanBytes: policy.limits.maxScanBytes });
  const allFindingNames = edmHits.length > 0 ? [...inspectionNames, ...edmFindingNames(edmHits)] : inspectionNames;
  if (edmHits.length > 0) {
    diagnostics.push(
      `EDM match: response for "${event.toolName}" matched fingerprint index(es): ${edmHits.map((h) => h.indexName).join(', ')}`,
    );
  }

  const finalDecision: PolicyDecision = policy.version === 2
    ? combineDecisions(decision, [edmMatchCandidate(policy, edmHits, 'response')])
    : decision;
  const edmExtras = edmAuditExtras(edmHits);
  const auditExtras = policy.version === 2
    ? mergeAuditExtras(edmExtras, decisionAuditExtras(finalDecision))
    : edmExtras;

  return {
    decision: finalDecision,
    findingNames: allFindingNames.length > 0 ? allFindingNames : undefined,
    inspectionFindings: inspection.findings,
    auditExtras,
    redactedText: inspection.redactedText,
    diagnostics,
  };
}
```

Every string, guard, and branch above is copied from today's `handleRequestLine`/`handleResponseLine` — do not "improve" any of it; byte-identical stderr/audit output is the requirement.

- [ ] **Step 5: Refactor `src/proxy/proxy-core.ts` to call the engine**

1. Imports: drop `evaluateCall`, `evaluateResponse`, `combineDecisions`, `edmMatchCandidate`, `dataflowMatchCandidate`, `resolveDetectors`, `safeStringify`, `loadEdmIndexes`, `matchEdmIndexes`, `SessionProvenance`, `detectSensitivePathRead`, `inspectResponseText` and the moved helper definitions. Keep `loadPolicy` (from `../enforcement/policy.js`), add `import { createEngineState, decide } from '../enforcement/engine.js';`, keep `extractResponseText` from `./jsonrpc.js`.
2. In `runProxy`, replace `const edmIndexes = loadEdmIndexes(opts.policyDir);` with `const engineState = createEngineState(opts.policyDir);` and delete `const provenance = new SessionProvenance();` (both uses now come from `engineState`).
3. Replace the body of the `tools/call` branch in `handleRequestLine` between `correlations.register(...)` and the `deny` check with:

```typescript
const ed = decide(
  { transport: 'mcp-stdio', direction: 'request', serverName: opts.serverName, toolName: call.toolName, args: call.args },
  policy,
  engineState,
);
for (const d of ed.diagnostics) diag(d);
```

and rewrite the three outcome branches to read from `ed`: `ed.decision.action`, `ed.decision.message`, `ed.decision.ruleId`, `findings: ed.findingNames`, `...ed.auditExtras`. The alert/coach `diag(...)` template strings stay in proxy-core, now interpolating `ed.decision.*`.

4. In `handleResponseLine`, after `const text = extractResponseText(parsed.message.result);` replace the inspection/tagging/evaluate/EDM block with:

```typescript
const ed = decide(
  { transport: 'mcp-stdio', direction: 'response', serverName: opts.serverName, toolName: info.toolName, args: info.args, responseText: text },
  policy,
  engineState,
);
for (const d of ed.diagnostics) diag(d);
const findingNames = ed.inspectionFindings.map((f) => f.name);
```

Outcome branches read `ed.decision.*`, `findings: ed.findingNames`, `...ed.auditExtras`; the redact branch uses `ed.redactedText` (forward `raw` when `undefined`); the alert/coach diag templates keep using the local `findingNames`.

- [ ] **Step 6: Run the engine test, then everything**

Run: `npx vitest run tests/unit/enforcement-engine.test.ts`
Expected: PASS.
Run: `npm run typecheck && npm test`
Expected: PASS — identical counts, zero assertion edits anywhere (this is the extraction's whole point; if any proxy test fails, the refactor changed behavior — fix the refactor, never the test).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: enforcement engine facade — decide(event, policy, state)

proxy-core now maps JSON-RPC legs to EnforcementEvents and acts on
EngineDecisions; the decision pipeline itself lives in src/enforcement.
Phase B's Claude Code hook adapter calls the same decide()."
```

---

### Task 5: Protect types + session manifest

**Files:**
- Create: `src/protect/types.ts`, `src/protect/manifest.ts`
- Test: `tests/unit/protect-manifest.test.ts`

**Interfaces:**
- Consumes: `MCPClient` from `../types/mcp-scan.js` (`{ name: string; configPath: string; mcpKey: string }`).
- Produces (Tasks 6–9 depend on these exact names):

```typescript
// src/protect/types.ts
import type { MCPClient } from '../types/mcp-scan.js';

export type ProtectSurface = 'mcp';               // widens in later phases
export const ALL_SURFACES: readonly ProtectSurface[] = ['mcp'] as const;

export interface ProtectContext {
  /** Protect state root. Default: $G0_STATE_DIR/protect, else ~/.g0/protect. */
  stateDir?: string;
  /** Test injection — forwarded to installer/quarantine client discovery. */
  clientPaths?: MCPClient[];
  /** Forwarded to installer `dir` (proxy manifest/policy dir). */
  proxyDir?: string;
  quarantineDir?: string;
  g0Bin?: string;
}

export interface PlanStep { id: string; description: string; files: string[]; }
export interface Advisory { id: string; severity: 'critical' | 'high' | 'medium' | 'low'; description: string; }
export interface SurfacePlan { surface: ProtectSurface; steps: PlanStep[]; advisories: Advisory[]; }

export interface McpUndoHandle { quarantineManifestPath?: string | null; }

export interface SurfaceApplyResult {
  surface: ProtectSurface;
  applied: string[];
  skipped: { id?: string; reason: string }[];
  errors: string[];
  undo: McpUndoHandle;
}
export interface SurfaceStatus { surface: ProtectSurface; protected: boolean; summary: string; detail: string[]; }
export interface SurfaceUndoResult {
  surface: ProtectSurface;
  restored: string[];
  skipped: { id?: string; reason: string }[];
  errors: string[];
}

export interface ProtectAdapter {
  readonly surface: ProtectSurface;
  plan(ctx: ProtectContext): Promise<SurfacePlan>;
  apply(ctx: ProtectContext): Promise<SurfaceApplyResult>;
  status(ctx: ProtectContext): Promise<SurfaceStatus>;
  undo(ctx: ProtectContext, handle: McpUndoHandle, opts?: { force?: boolean }): Promise<SurfaceUndoResult>;
}
```

```typescript
// src/protect/manifest.ts
export interface ProtectManifest {
  id: string;                                   // e.g. '2026-07-21T12-00-00-000Z'
  timestamp: string;                            // ISO
  surfaces: Partial<Record<ProtectSurface, McpUndoHandle>>;
}
export function protectStateDir(override?: string): string;
export function writeManifest(manifest: ProtectManifest, stateDir?: string): string; // returns path
export function readLatestManifest(stateDir?: string): { path: string; manifest: ProtectManifest } | null;
```

- [ ] **Step 1: Write the failing test**

```typescript
// tests/unit/protect-manifest.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { protectStateDir, writeManifest, readLatestManifest } from '../../src/protect/manifest.js';

describe('protect manifest', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-protect-')); });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.G0_STATE_DIR;
  });

  it('honors override, then G0_STATE_DIR, then ~/.g0', () => {
    expect(protectStateDir('/x')).toBe('/x');
    process.env.G0_STATE_DIR = tmpDir;
    expect(protectStateDir()).toBe(path.join(tmpDir, 'protect'));
    delete process.env.G0_STATE_DIR;
    expect(protectStateDir()).toBe(path.join(os.homedir(), '.g0', 'protect'));
  });

  it('round-trips and returns the newest manifest', () => {
    expect(readLatestManifest(tmpDir)).toBeNull();
    writeManifest({ id: '2026-07-21T00-00-00-000Z', timestamp: '2026-07-21T00:00:00.000Z', surfaces: {} }, tmpDir);
    const p2 = writeManifest(
      { id: '2026-07-21T00-00-01-000Z', timestamp: '2026-07-21T00:00:01.000Z', surfaces: { mcp: { quarantineManifestPath: '/q/m.json' } } },
      tmpDir,
    );
    const latest = readLatestManifest(tmpDir);
    expect(latest?.path).toBe(p2);
    expect(latest?.manifest.surfaces.mcp?.quarantineManifestPath).toBe('/q/m.json');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/protect-manifest.test.ts`
Expected: FAIL — cannot resolve `src/protect/manifest.js`.

- [ ] **Step 3: Implement**

`src/protect/types.ts` exactly as in the Interfaces block above. Then:

```typescript
// src/protect/manifest.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import type { McpUndoHandle, ProtectSurface } from './types.js';

export interface ProtectManifest {
  id: string;
  timestamp: string;
  surfaces: Partial<Record<ProtectSurface, McpUndoHandle>>;
}

export function protectStateDir(override?: string): string {
  if (override) return override;
  const base = process.env.G0_STATE_DIR ?? path.join(os.homedir(), '.g0');
  return path.join(base, 'protect');
}

function manifestsDir(stateDir?: string): string {
  return path.join(protectStateDir(stateDir), 'manifests');
}

export function writeManifest(manifest: ProtectManifest, stateDir?: string): string {
  const dir = manifestsDir(stateDir);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `${manifest.id}.json`);
  fs.writeFileSync(filePath, JSON.stringify(manifest, null, 2));
  return filePath;
}

export function readLatestManifest(stateDir?: string): { path: string; manifest: ProtectManifest } | null {
  const dir = manifestsDir(stateDir);
  if (!fs.existsSync(dir)) return null;
  const names = fs.readdirSync(dir).filter((n) => n.endsWith('.json')).sort();
  if (names.length === 0) return null;
  const filePath = path.join(dir, names[names.length - 1]);
  try {
    return { path: filePath, manifest: JSON.parse(fs.readFileSync(filePath, 'utf8')) as ProtectManifest };
  } catch {
    return null; // corrupt manifest: spec §11 — refuse quietly here; CLI surfaces recovery guidance
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/unit/protect-manifest.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: protect adapter contract + session manifest"
```

---

### Task 6: The mcp adapter

**Files:**
- Create: `src/protect/adapters/mcp.ts`
- Test: `tests/unit/protect-mcp-adapter.test.ts`

**Interfaces:**
- Consumes: `installProxy`, `uninstallProxy`, `listInstalls` from `../../proxy/installer.js` (note `InstallProxyOptions.dryRun`, `.clientPaths`, `.dir`, `.g0Bin`); `planQuarantine`, `applyQuarantine`, `undoQuarantine`, `findLatestManifestPath`, `defaultQuarantineDir` from `../../endpoint/quarantine.js`; `hardenOpenClawConfig` from `../../endpoint/openclaw-config-hardener.js`; Task 5's types.
- Produces: `export const mcpAdapter: ProtectAdapter` with step-id conventions `wrap:<client>/<server>` and `quarantine:<client>/<server>`, advisory ids `openclaw:<configPath>`.

- [ ] **Step 1: Write the failing test**

```typescript
// tests/unit/protect-mcp-adapter.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mcpAdapter } from '../../src/protect/adapters/mcp.js';
import type { ProtectContext } from '../../src/protect/types.js';

describe('mcp protect adapter', () => {
  let tmpDir: string;
  let ctx: ProtectContext;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-mcp-adapter-'));
    const configPath = path.join(tmpDir, 'mcp.json');
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: { demo: { command: 'node', args: ['server.mjs'] } },
    }, null, 2));
    ctx = {
      clientPaths: [{ name: 'test-client', configPath, mcpKey: 'mcpServers' }],
      proxyDir: path.join(tmpDir, 'proxy-state'),
      quarantineDir: path.join(tmpDir, 'quarantine'),
      g0Bin: '/usr/local/bin/g0',
    };
  });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('plan() lists the wrap without touching the config', async () => {
    const before = fs.readFileSync(ctx.clientPaths![0].configPath, 'utf8');
    const plan = await mcpAdapter.plan(ctx);
    expect(plan.surface).toBe('mcp');
    expect(plan.steps.some((s) => s.id === 'wrap:test-client/demo')).toBe(true);
    expect(fs.readFileSync(ctx.clientPaths![0].configPath, 'utf8')).toBe(before);
  });

  it('apply() wraps, undo() restores byte-identically', async () => {
    const configPath = ctx.clientPaths![0].configPath;
    const before = fs.readFileSync(configPath, 'utf8');

    const applied = await mcpAdapter.apply(ctx);
    expect(applied.applied).toContain('wrap:test-client/demo');
    expect(applied.errors).toEqual([]);
    const wrapped = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(JSON.stringify(wrapped.mcpServers.demo)).toContain('proxy');

    const status = await mcpAdapter.status(ctx);
    expect(status.protected).toBe(true);

    const undone = await mcpAdapter.undo(ctx, applied.undo);
    expect(undone.errors).toEqual([]);
    expect(fs.readFileSync(configPath, 'utf8')).toBe(before);
  });

  it('is a no-op plan on an empty estate', async () => {
    const plan = await mcpAdapter.plan({ ...ctx, clientPaths: [] });
    expect(plan.steps).toEqual([]);
  });
});
```

Note: if `installProxy`'s restore is not byte-exact for the whole file (e.g. it reserializes JSON), mirror the equivalence assertion used in `tests/unit/proxy-installer.test.ts` (parse-and-deep-equal instead of string equality) — check that file before weakening the assertion.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/protect-mcp-adapter.test.ts`
Expected: FAIL — cannot resolve `src/protect/adapters/mcp.js`.

- [ ] **Step 3: Implement**

```typescript
// src/protect/adapters/mcp.ts
import { installProxy, uninstallProxy, listInstalls } from '../../proxy/installer.js';
import {
  planQuarantine, applyQuarantine, undoQuarantine,
  findLatestManifestPath, defaultQuarantineDir,
} from '../../endpoint/quarantine.js';
import { hardenOpenClawConfig } from '../../endpoint/openclaw-config-hardener.js';
import type {
  Advisory, McpUndoHandle, PlanStep, ProtectAdapter, ProtectContext,
  SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult,
} from '../types.js';

export const mcpAdapter: ProtectAdapter = {
  surface: 'mcp',

  async plan(ctx: ProtectContext): Promise<SurfacePlan> {
    const steps: PlanStep[] = [];

    const install = await installProxy({
      dryRun: true, clientPaths: ctx.clientPaths, dir: ctx.proxyDir, g0Bin: ctx.g0Bin,
    });
    for (const e of install.wrapped) {
      steps.push({
        id: `wrap:${e.client}/${e.serverName}`,
        description: `Route MCP server "${e.serverName}" (${e.client}) through g0 proxy`,
        files: [e.configPath],
      });
    }

    const q = planQuarantine({ clients: ctx.clientPaths });
    for (const c of q.candidates) {
      steps.push({
        id: `quarantine:${c.client}/${c.serverName}`,
        description: `Remove known-malicious MCP server "${c.serverName}" (${c.client})`,
        files: [c.configPath],
      });
    }

    const advisories: Advisory[] = [];
    try {
      const hardened = hardenOpenClawConfig();
      for (const r of hardened.recommendations) {
        advisories.push({ id: `openclaw:${r.path}`, severity: r.severity, description: r.reason });
      }
    } catch {
      // no OpenClaw on this machine — nothing to advise
    }

    return { surface: 'mcp', steps, advisories };
  },

  async apply(ctx: ProtectContext): Promise<SurfaceApplyResult> {
    const applied: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];

    const install = await installProxy({
      clientPaths: ctx.clientPaths, dir: ctx.proxyDir, g0Bin: ctx.g0Bin,
    });
    applied.push(...install.wrapped.map((e) => `wrap:${e.client}/${e.serverName}`));
    skipped.push(
      ...install.skippedAlreadyWrapped.map((s) => ({ reason: `already wrapped: ${s}` })),
      ...install.unproxyable.map((s) => ({ reason: `unproxyable (non-stdio): ${s}` })),
    );
    errors.push(...install.errors.map((e) => `${e.client}: ${e.message}`));

    const quarantine = await applyQuarantine({ clients: ctx.clientPaths, quarantineDir: ctx.quarantineDir });
    applied.push(
      ...quarantine.applied.flatMap((e) => e.removedServers.map((s) => `quarantine:${e.client}/${s}`)),
    );
    skipped.push(...quarantine.skipped.map((s) => ({ reason: s.reason })));

    return {
      surface: 'mcp', applied, skipped, errors,
      undo: { quarantineManifestPath: quarantine.manifestPath },
    };
  },

  async status(ctx: ProtectContext): Promise<SurfaceStatus> {
    const installs = listInstalls(ctx.proxyDir);
    const latestQuarantine = findLatestManifestPath(ctx.quarantineDir ?? defaultQuarantineDir());
    const isProtected = installs.length > 0;
    return {
      surface: 'mcp',
      protected: isProtected,
      summary: isProtected
        ? `proxy active on ${installs.length} MCP server(s)`
        : 'not protected — no MCP servers routed through g0 proxy',
      detail: [
        `${installs.length} MCP server(s) routed through g0 proxy`,
        latestQuarantine ? `last quarantine manifest: ${latestQuarantine}` : 'no quarantine has been applied',
      ],
    };
  },

  async undo(ctx: ProtectContext, handle: McpUndoHandle, opts?: { force?: boolean }): Promise<SurfaceUndoResult> {
    const restored: string[] = [];
    const skipped: { id?: string; reason: string }[] = [];
    const errors: string[] = [];

    const un = await uninstallProxy({ clientPaths: ctx.clientPaths, dir: ctx.proxyDir, g0Bin: ctx.g0Bin });
    restored.push(...un.restored.map((e) => `unwrap:${e.client}/${e.serverName}`));
    errors.push(...un.errors.map((e) => `${e.client}: ${e.message}`));

    if (handle.quarantineManifestPath) {
      const undone = await undoQuarantine({
        manifestPath: handle.quarantineManifestPath,
        quarantineDir: ctx.quarantineDir,
        force: opts?.force,
      });
      restored.push(...undone.restored.map((r) => `restore:${r.configPath}`));
      skipped.push(...undone.skipped.map((s) => ({ reason: s.reason })));
    }

    return { surface: 'mcp', restored, skipped, errors };
  },
};
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/unit/protect-mcp-adapter.test.ts && npm run typecheck`
Expected: PASS. If `installProxy` requires an existing manifest dir or the dry-run result puts would-wrap entries somewhere other than `wrapped`, check its behavior in `tests/unit/proxy-installer.test.ts` and align the adapter (not the assertions).

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: protect mcp adapter — proxy install + quarantine + OpenClaw advisories"
```

---

### Task 7: The orchestrator

**Files:**
- Create: `src/protect/orchestrator.ts`
- Test: `tests/unit/protect-orchestrator.test.ts`

**Interfaces:**
- Consumes: Task 5 types + manifest, Task 6 `mcpAdapter`.
- Produces (Task 8 depends on these):

```typescript
export const DEFAULT_ADAPTERS: ProtectAdapter[];   // [mcpAdapter]
export function resolveSurfaces(list: string | undefined, adapters?: ProtectAdapter[]): ProtectAdapter[]; // throws on unknown surface
export function protectPlan(ctx: ProtectContext, adapters?: ProtectAdapter[]): Promise<SurfacePlan[]>;
export function protectApply(ctx: ProtectContext, adapters?: ProtectAdapter[]): Promise<{ results: SurfaceApplyResult[]; manifestPath: string }>;
export function protectStatus(ctx: ProtectContext, adapters?: ProtectAdapter[]): Promise<SurfaceStatus[]>;
export function protectOff(ctx: ProtectContext, opts?: { force?: boolean }, adapters?: ProtectAdapter[]): Promise<{ results: SurfaceUndoResult[]; manifestPath: string | null }>;
```

Behavior contract: adapters run sequentially and independently — one adapter throwing is caught and recorded as a `SurfaceApplyResult`/`SurfaceUndoResult` with the error message in `errors` and empty `applied`/`restored` (spec §11: partial failure never rolls back other surfaces). `protectApply` writes one manifest recording each surface's undo handle. `protectOff` reads the latest manifest; with no manifest it still calls each `adapter.undo(ctx, {}, opts)` (the mcp adapter's uninstall works from the installer's own manifest, quarantine leg skips).

- [ ] **Step 1: Write the failing test**

```typescript
// tests/unit/protect-orchestrator.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  resolveSurfaces, protectPlan, protectApply, protectOff,
} from '../../src/protect/orchestrator.js';
import { readLatestManifest } from '../../src/protect/manifest.js';
import type { ProtectAdapter } from '../../src/protect/types.js';

function fakeAdapter(overrides: Partial<ProtectAdapter> = {}): ProtectAdapter {
  return {
    surface: 'mcp',
    plan: async () => ({ surface: 'mcp', steps: [{ id: 's1', description: 'd', files: [] }], advisories: [] }),
    apply: async () => ({ surface: 'mcp', applied: ['s1'], skipped: [], errors: [], undo: { quarantineManifestPath: '/q.json' } }),
    status: async () => ({ surface: 'mcp', protected: true, summary: '', detail: [] }),
    undo: async () => ({ surface: 'mcp', restored: ['s1'], skipped: [], errors: [] }),
    ...overrides,
  };
}

describe('protect orchestrator', () => {
  let tmpDir: string;
  beforeEach(() => { tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-orch-')); });
  afterEach(() => { fs.rmSync(tmpDir, { recursive: true, force: true }); });

  it('resolveSurfaces filters and rejects unknowns', () => {
    const a = fakeAdapter();
    expect(resolveSurfaces(undefined, [a])).toEqual([a]);
    expect(resolveSurfaces('mcp', [a])).toEqual([a]);
    expect(() => resolveSurfaces('mcp,browser', [a])).toThrow(/unknown surface/);
  });

  it('apply writes a manifest with each surface undo handle', async () => {
    const { results, manifestPath } = await protectApply({ stateDir: tmpDir }, [fakeAdapter()]);
    expect(results[0].applied).toEqual(['s1']);
    expect(fs.existsSync(manifestPath)).toBe(true);
    expect(readLatestManifest(tmpDir)?.manifest.surfaces.mcp?.quarantineManifestPath).toBe('/q.json');
  });

  it('a throwing adapter is recorded, not propagated', async () => {
    const boom = fakeAdapter({ apply: async () => { throw new Error('kaboom'); } });
    const { results } = await protectApply({ stateDir: tmpDir }, [boom]);
    expect(results[0].errors.join(' ')).toContain('kaboom');
    expect(results[0].applied).toEqual([]);
  });

  it('off passes the recorded handle back to undo', async () => {
    let seenHandle: unknown;
    const a = fakeAdapter({
      undo: async (_ctx, handle) => { seenHandle = handle; return { surface: 'mcp', restored: [], skipped: [], errors: [] }; },
    });
    await protectApply({ stateDir: tmpDir }, [a]);
    await protectOff({ stateDir: tmpDir }, {}, [a]);
    expect(seenHandle).toEqual({ quarantineManifestPath: '/q.json' });
  });

  it('plan aggregates surface plans', async () => {
    const plans = await protectPlan({ stateDir: tmpDir }, [fakeAdapter()]);
    expect(plans).toHaveLength(1);
    expect(plans[0].steps[0].id).toBe('s1');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/protect-orchestrator.test.ts`
Expected: FAIL — cannot resolve `src/protect/orchestrator.js`.

- [ ] **Step 3: Implement**

```typescript
// src/protect/orchestrator.ts
import { mcpAdapter } from './adapters/mcp.js';
import { readLatestManifest, writeManifest } from './manifest.js';
import type { ProtectManifest } from './manifest.js';
import type {
  ProtectAdapter, ProtectContext, SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult,
} from './types.js';

export const DEFAULT_ADAPTERS: ProtectAdapter[] = [mcpAdapter];

export function resolveSurfaces(list: string | undefined, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS): ProtectAdapter[] {
  if (!list) return adapters;
  const names = list.split(',').map((s) => s.trim()).filter(Boolean);
  const known = new Set(adapters.map((a) => a.surface as string));
  const unknown = names.filter((n) => !known.has(n));
  if (unknown.length > 0) {
    throw new Error(`unknown surface(s): ${unknown.join(', ')} (available: ${[...known].join(', ')})`);
  }
  return adapters.filter((a) => names.includes(a.surface));
}

export async function protectPlan(ctx: ProtectContext, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS): Promise<SurfacePlan[]> {
  const plans: SurfacePlan[] = [];
  for (const a of adapters) {
    try {
      plans.push(await a.plan(ctx));
    } catch (err) {
      plans.push({
        surface: a.surface, steps: [],
        advisories: [{ id: `${a.surface}:plan-error`, severity: 'high', description: `planning failed: ${err instanceof Error ? err.message : String(err)}` }],
      });
    }
  }
  return plans;
}

export async function protectApply(
  ctx: ProtectContext, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS,
): Promise<{ results: SurfaceApplyResult[]; manifestPath: string }> {
  const results: SurfaceApplyResult[] = [];
  const manifest: ProtectManifest = {
    id: new Date().toISOString().replace(/[:.]/g, '-'),
    timestamp: new Date().toISOString(),
    surfaces: {},
  };
  for (const a of adapters) {
    try {
      const result = await a.apply(ctx);
      results.push(result);
      manifest.surfaces[a.surface] = result.undo;
    } catch (err) {
      results.push({
        surface: a.surface, applied: [], skipped: [], undo: {},
        errors: [err instanceof Error ? err.message : String(err)],
      });
    }
  }
  const manifestPath = writeManifest(manifest, ctx.stateDir);
  return { results, manifestPath };
}

export async function protectStatus(ctx: ProtectContext, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS): Promise<SurfaceStatus[]> {
  const statuses: SurfaceStatus[] = [];
  for (const a of adapters) {
    try {
      statuses.push(await a.status(ctx));
    } catch (err) {
      statuses.push({
        surface: a.surface, protected: false,
        summary: `status failed: ${err instanceof Error ? err.message : String(err)}`, detail: [],
      });
    }
  }
  return statuses;
}

export async function protectOff(
  ctx: ProtectContext, opts: { force?: boolean } = {}, adapters: ProtectAdapter[] = DEFAULT_ADAPTERS,
): Promise<{ results: SurfaceUndoResult[]; manifestPath: string | null }> {
  const latest = readLatestManifest(ctx.stateDir);
  const results: SurfaceUndoResult[] = [];
  for (const a of adapters) {
    const handle = latest?.manifest.surfaces[a.surface] ?? {};
    try {
      results.push(await a.undo(ctx, handle, opts));
    } catch (err) {
      results.push({
        surface: a.surface, restored: [], skipped: [],
        errors: [err instanceof Error ? err.message : String(err)],
      });
    }
  }
  return { results, manifestPath: latest?.path ?? null };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/unit/protect-orchestrator.test.ts && npm run typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: protect orchestrator — plan/apply/status/off across surface adapters"
```

---

### Task 8: CLI command + terminal reporter

**Files:**
- Create: `src/cli/commands/protect.ts`, `src/reporters/protect-terminal.ts`
- Modify: `src/cli/index.ts` (add `import { protectCommand } from './commands/protect.js';` with the other command imports, and `program.addCommand(protectCommand);` directly after the `checkCommand` line)
- Test: `tests/unit/protect-command.test.ts`

**Interfaces:**
- Consumes: Task 7 orchestrator functions; chalk (same usage as `src/reporters/check-terminal.ts`).
- Produces: `g0 protect` (dry-run default), `g0 protect --apply`, `--surfaces <list>`, `--json`, `g0 protect status [--json]`, `g0 protect off [--force] [--surfaces <list>] [--json]`. Reporter functions `reportProtectPlan(plans: SurfacePlan[])`, `reportProtectApply(results: SurfaceApplyResult[], manifestPath: string)`, `reportProtectStatus(statuses: SurfaceStatus[])`, `reportProtectUndo(results: SurfaceUndoResult[], manifestPath: string | null)`.

- [ ] **Step 1: Write the failing test**

Model process handling on `tests/unit/proxy-command.test.ts` if it exercises commander directly; otherwise use this action-level pattern:

```typescript
// tests/unit/protect-command.test.ts
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { protectCommand } from '../../src/cli/commands/protect.js';

describe('g0 protect command', () => {
  let tmpDir: string;
  let logs: string[];

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-protect-cmd-'));
    process.env.G0_STATE_DIR = tmpDir;
    logs = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.join(' ')); });
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    delete process.env.G0_STATE_DIR;
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    process.exitCode = 0;
  });

  it('default action is a dry-run that emits a plan and writes nothing', async () => {
    await protectCommand.parseAsync(['node', 'g0', '--json'], { from: 'node' });
    const out = JSON.parse(logs.join('\n'));
    expect(out.mode).toBe('plan');
    expect(Array.isArray(out.plans)).toBe(true);
    expect(fs.existsSync(path.join(tmpDir, 'protect', 'manifests'))).toBe(false);
  });

  it('rejects an unknown surface with exit code 1', async () => {
    await protectCommand.parseAsync(['node', 'g0', '--surfaces', 'nope', '--json'], { from: 'node' });
    expect(process.exitCode).toBe(1);
  });

  it('status subcommand reports surfaces', async () => {
    await protectCommand.parseAsync(['node', 'g0', 'status', '--json'], { from: 'node' });
    const out = JSON.parse(logs.join('\n'));
    expect(out.statuses[0].surface).toBe('mcp');
  });
});
```

Note: the dry-run test runs against the real machine estate via well-known paths — it asserts only shape (`mode: 'plan'`), never contents, so it is machine-independent. `commander` retains parsed state between `parseAsync` calls on the same instance; if cross-test bleed appears, build the command via an exported factory `buildProtectCommand()` and instantiate per test — keep `protectCommand` exported for the CLI.

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/unit/protect-command.test.ts`
Expected: FAIL — cannot resolve `src/cli/commands/protect.js`.

- [ ] **Step 3: Implement the reporter**

```typescript
// src/reporters/protect-terminal.ts
import chalk from 'chalk';
import type { SurfaceApplyResult, SurfacePlan, SurfaceStatus, SurfaceUndoResult } from '../protect/types.js';

export function reportProtectPlan(plans: SurfacePlan[]): void {
  for (const plan of plans) {
    console.log(chalk.bold(`\n[${plan.surface}]`));
    if (plan.steps.length === 0) {
      console.log(chalk.dim('  nothing to change — already protected, or nothing discovered'));
    }
    for (const step of plan.steps) {
      console.log(`  ${chalk.green('+')} ${step.description}`);
      for (const file of step.files) console.log(chalk.dim(`      ${file}`));
    }
    if (plan.advisories.length > 0) {
      console.log(chalk.bold('  advisories (report-only):'));
      for (const a of plan.advisories) console.log(`  ${chalk.yellow('!')} [${a.severity}] ${a.description}`);
    }
  }
  console.log(chalk.dim('\nDry-run only. Re-run with --apply to make these changes; `g0 protect off` restores them.'));
}

export function reportProtectApply(results: SurfaceApplyResult[], manifestPath: string): void {
  for (const r of results) {
    console.log(chalk.bold(`\n[${r.surface}]`));
    for (const id of r.applied) console.log(`  ${chalk.green('✓')} ${id}`);
    for (const s of r.skipped) console.log(chalk.dim(`  - skipped: ${s.reason}`));
    for (const e of r.errors) console.log(`  ${chalk.red('✗')} ${e}`);
  }
  console.log(chalk.dim(`\nSession manifest: ${manifestPath}`));
  console.log(chalk.dim('Undo everything with: g0 protect off'));
}

export function reportProtectStatus(statuses: SurfaceStatus[]): void {
  for (const s of statuses) {
    const badge = s.protected ? chalk.black.bgGreen(' PROTECTED ') : chalk.black.bgYellow(' OFF ');
    console.log(`\n${badge} ${chalk.bold(`[${s.surface}]`)} ${s.summary}`);
    for (const d of s.detail) console.log(chalk.dim(`  ${d}`));
  }
}

export function reportProtectUndo(results: SurfaceUndoResult[], manifestPath: string | null): void {
  for (const r of results) {
    console.log(chalk.bold(`\n[${r.surface}]`));
    for (const id of r.restored) console.log(`  ${chalk.green('✓')} restored: ${id}`);
    for (const s of r.skipped) console.log(chalk.dim(`  - skipped: ${s.reason}`));
    for (const e of r.errors) console.log(`  ${chalk.red('✗')} ${e}`);
  }
  if (manifestPath) console.log(chalk.dim(`\nFrom manifest: ${manifestPath}`));
}
```

Badge colors: black-on-color, matching the 2.1.0 badge-legibility fix (#188) — never white-on-red/green.

- [ ] **Step 4: Implement the command**

```typescript
// src/cli/commands/protect.ts
import chalk from 'chalk';
import { Command } from 'commander';
import {
  protectApply, protectOff, protectPlan, protectStatus, resolveSurfaces,
} from '../../protect/orchestrator.js';
import {
  reportProtectApply, reportProtectPlan, reportProtectStatus, reportProtectUndo,
} from '../../reporters/protect-terminal.js';

interface ProtectCliOptions { apply?: boolean; surfaces?: string; json?: boolean; }
interface OffCliOptions { force?: boolean; surfaces?: string; json?: boolean; }

export const protectCommand = new Command('protect')
  .description('Install g0 guardrails across this machine (dry-run by default; --apply to commit)')
  .option('--apply', 'execute the plan (default: dry-run preview only)')
  .option('--surfaces <list>', 'comma-separated surfaces (available: mcp; default: all)')
  .option('--json', 'machine-readable output')
  .action(async (options: ProtectCliOptions) => {
    let adapters;
    try {
      adapters = resolveSurfaces(options.surfaces);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (options.json) console.log(JSON.stringify({ error: message }));
      else console.error(chalk.red(message));
      process.exitCode = 1;
      return;
    }
    if (!options.apply) {
      const plans = await protectPlan({}, adapters);
      if (options.json) console.log(JSON.stringify({ mode: 'plan', plans }, null, 2));
      else reportProtectPlan(plans);
      return;
    }
    const { results, manifestPath } = await protectApply({}, adapters);
    if (options.json) console.log(JSON.stringify({ mode: 'apply', results, manifestPath }, null, 2));
    else reportProtectApply(results, manifestPath);
    if (results.some((r) => r.errors.length > 0)) process.exitCode = 1;
  });

protectCommand.addCommand(
  new Command('status')
    .description('Show what g0 protect currently guards')
    .option('--json', 'machine-readable output')
    .action(async (options: { json?: boolean }) => {
      const statuses = await protectStatus({});
      if (options.json) console.log(JSON.stringify({ statuses }, null, 2));
      else reportProtectStatus(statuses);
    }),
);

protectCommand.addCommand(
  new Command('off')
    .description('Undo protect changes from the most recent apply (restores backups)')
    .option('--force', 'restore even over configs edited since the backup')
    .option('--surfaces <list>', 'comma-separated surfaces (default: all)')
    .option('--json', 'machine-readable output')
    .action(async (options: OffCliOptions) => {
      let adapters;
      try {
        adapters = resolveSurfaces(options.surfaces);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (options.json) console.log(JSON.stringify({ error: message }));
        else console.error(chalk.red(message));
        process.exitCode = 1;
        return;
      }
      const { results, manifestPath } = await protectOff({}, { force: options.force }, adapters);
      if (options.json) console.log(JSON.stringify({ results, manifestPath }, null, 2));
      else reportProtectUndo(results, manifestPath);
      if (results.some((r) => r.errors.length > 0)) process.exitCode = 1;
    }),
);
```

Register in `src/cli/index.ts`: add the import beside the other command imports and `program.addCommand(protectCommand);` right after `program.addCommand(checkCommand);`.

- [ ] **Step 5: Run tests**

Run: `npx vitest run tests/unit/protect-command.test.ts && npm run typecheck && npm test`
Expected: PASS across the board.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: g0 protect CLI — dry-run plan, --apply, status, off"
```

---

### Task 9: End-to-end round-trip integration test

**Files:**
- Test: `tests/integration/protect-e2e.test.ts`

**Interfaces:**
- Consumes: the real CLI (`npx tsx bin/g0.ts`, per `tests/integration/proxy-e2e.test.ts`), Cursor's well-known config path `~/.cursor/mcp.json` (same on darwin/linux/win32 per `src/mcp/well-known-paths.ts`), env vars `HOME` and `G0_STATE_DIR`.
- Produces: proof of spec §12's "sandboxed-HOME round trip": plan → apply (config rewritten) → off (byte-identical HOME).

- [ ] **Step 1: Write the test**

```typescript
// tests/integration/protect-e2e.test.ts
import { execFile } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));
const G0_BIN = path.join(REPO_ROOT, 'bin', 'g0.ts');

function sha256(p: string): string {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

describe('g0 protect e2e round trip (sandboxed HOME)', () => {
  let home: string;
  let configPath: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'g0-protect-home-'));
    configPath = path.join(home, '.cursor', 'mcp.json');
    fs.mkdirSync(path.dirname(configPath), { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({
      mcpServers: { demo: { command: 'node', args: ['server.mjs'] } },
    }, null, 2));
    env = {
      ...process.env,
      HOME: home,
      USERPROFILE: home,                 // win32 parity
      G0_STATE_DIR: path.join(home, '.g0'),
      G0_NO_CTA: '1',
    };
  });
  afterEach(() => { fs.rmSync(home, { recursive: true, force: true }); });

  async function g0(...args: string[]) {
    return execFileAsync('npx', ['tsx', G0_BIN, ...args], { cwd: REPO_ROOT, env });
  }

  it('plan → apply → off leaves the config byte-identical', async () => {
    const beforeHash = sha256(configPath);

    const plan = await g0('protect', '--json');
    const planOut = JSON.parse(plan.stdout);
    expect(planOut.mode).toBe('plan');
    const mcpPlan = planOut.plans.find((p: { surface: string }) => p.surface === 'mcp');
    expect(mcpPlan.steps.some((s: { id: string }) => s.id === 'wrap:cursor/demo')).toBe(true);
    expect(sha256(configPath)).toBe(beforeHash); // dry-run wrote nothing

    const apply = await g0('protect', '--apply', '--json');
    const applyOut = JSON.parse(apply.stdout);
    expect(applyOut.mode).toBe('apply');
    const wrapped = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    expect(JSON.stringify(wrapped.mcpServers.demo)).toContain('proxy');
    expect(fs.existsSync(applyOut.manifestPath)).toBe(true);

    const status = await g0('protect', 'status', '--json');
    expect(JSON.parse(status.stdout).statuses[0].protected).toBe(true);

    await g0('protect', 'off', '--json');
    expect(sha256(configPath)).toBe(beforeHash);
  }, 120_000);
});
```

Note: the client name asserted in `wrap:cursor/demo` must match the `name` used for Cursor in `src/mcp/well-known-paths.ts` — check that file and use its exact string (it may be `Cursor`). If the installer's restore turns out not byte-exact (JSON reserialization), assert deep-equal of parsed JSON instead — mirroring whichever equivalence `tests/unit/proxy-installer.test.ts` asserts.

- [ ] **Step 2: Run the test**

Run: `npx vitest run tests/integration/protect-e2e.test.ts`
Expected: PASS. Common failures: client discovery not honoring `HOME` on darwin for Cursor (it does — path is `HOME/.cursor/mcp.json` on all three platforms), or the well-known client `name` differing from `cursor` (fix the assertion string to the real name, once, from the source).

- [ ] **Step 3: Full suite + commit**

Run: `npm test`

```bash
git add tests/integration/protect-e2e.test.ts
git commit -m "test: protect e2e — sandboxed-HOME plan/apply/off round trip"
```

---

### Task 10: Docs + changelog

**Files:**
- Create: `docs/protect.md`
- Modify: `README.md` (60-second tour + surfaces table), `CHANGELOG.md` (`[Unreleased]` section)

**Interfaces:** none — documentation of Tasks 5–9's shipped behavior.

- [ ] **Step 1: Write `docs/protect.md`**

Cover, in this order, matching the real CLI: what `g0 protect` is (the write-side pair of `g0 check`); the dry-run-first contract; each surface Phase A protects (mcp: proxy routing + quarantine + OpenClaw advisories); `status` and `off` (including `--force` semantics and the session manifest location under `~/.g0/protect/manifests/`); the safety invariants (fail-open, backups, per-user scope, no network); a short roadmap note that claude/codex/browser/watch surfaces arrive in later phases (link the spec). Every command example must be copy-paste runnable against this build.

**Positioning constraint (spec §15):** no "first/only enforcing proxy" claims, no claiming quarantine/pinning as unique, no characterization of snyk/agent-scan's proxy mode, Codex claims scoped to hardening/enforcement (not discovery). Sell the bundle + undo safety.

- [ ] **Step 2: Update README**

In the 60-second tour code block, after the `g0 proxy install` line add:

```bash
g0 protect --apply                       # one command: route MCP through proxy + quarantine known-bad
```

In the surfaces table, extend the Runtime proxy row's description or add a row:

```markdown
| 🛡️ | **[Protect](docs/protect.md)** | One command that installs the guardrails: MCP proxy routing, known-malicious quarantine, config hardening advisories — dry-run first, fully undoable. |
```

- [ ] **Step 3: Update CHANGELOG under `[Unreleased]`**

```markdown
### Added
- **`g0 protect` — enforcement, one command** — dry-run by default; `--apply` routes every stdio MCP server through the g0 proxy and quarantines known-malicious servers, with OpenClaw hardening advisories in the plan. `g0 protect status` shows what's guarded; `g0 protect off` restores every touched config from backups. Session manifests under `~/.g0/protect/`.

### Changed
- **Internal: enforcement engine extracted** — the proxy's decision stack (policy DSL, confidence fusion, detectors, EDM, provenance, sensitive-read, response inspection) moved from `src/proxy/` to `src/enforcement/` behind a transport-neutral `decide()`. Proxy behavior is unchanged (verified against the full existing proxy suite).
```

- [ ] **Step 4: Verify and commit**

Run: `npm test` (docs changes can't break it — this is the final green gate for the phase)

```bash
git add docs/protect.md README.md CHANGELOG.md
git commit -m "docs: g0 protect — command guide, README surface row, changelog"
```
