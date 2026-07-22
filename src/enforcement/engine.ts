/**
 * The enforcement engine facade — `decide(event, policy, state)`.
 *
 * This is the decision pipeline extracted verbatim from `proxy-core.ts`'s
 * `handleRequestLine`/`handleResponseLine`: evaluate → EDM scan →
 * provenance/dataflow → v2 candidate fusion → audit extras. Every guard,
 * branch, and diagnostic string is copied unchanged — the proxy's observable
 * behavior (stderr diagnostics, audit records, deny/redact/forward stream)
 * must be byte-identical before and after the extraction.
 *
 * The engine is pure with respect to transport: it never writes to a
 * stream. Mutable per-session state (provenance tags, loaded EDM indexes)
 * lives in `EngineState`, owned by the caller — the proxy holds one per
 * proxied server; the Phase B hook adapter persists one per Claude session.
 */

import {
  evaluateCall,
  evaluateResponse,
  combineDecisions,
  edmMatchCandidate,
  dataflowMatchCandidate,
  resolveDetectors,
  safeStringify,
} from './policy.js';
import type { EvalContext, ProxyPolicy } from './policy.js';
import { canonicalize } from './canonicalize.js';
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

/**
 * EDM match on the raw text plus, when canonicalization changes it, a second
 * match on the canonical form (spec §6.1: encoding-larded exfil must not slip
 * past exact-data-match). Union deduped by index name — EDM findings are
 * metadata-only, so the union is safe.
 */
function matchEdmCanonical(indexes: EdmIndex[], text: string, maxScanBytes: number): EdmMatch[] {
  if (indexes.length === 0) return [];
  const hits = matchEdmIndexes(indexes, text, { maxScanBytes });
  const canon = canonicalize(text);
  if (canon === text) return hits;
  const seen = new Set(hits.map((h) => h.indexName));
  for (const hit of matchEdmIndexes(indexes, canon, { maxScanBytes })) {
    if (!seen.has(hit.indexName)) {
      hits.push(hit);
      seen.add(hit.indexName);
    }
  }
  return hits;
}

// ─────────────────────────────────────────────────────────────────────────
// Audit-extras helpers (moved verbatim from proxy-core.ts)
// ─────────────────────────────────────────────────────────────────────────

/**
 * EDM findings never carry the matched value (see `edm.ts`'s module
 * docblock) — only these two small helpers turn a set of `EdmMatch`es into
 * the metadata-only shapes `AuditRecord` and its `findings` array already
 * support. `confidence`/`signals`/`context` mirror how `structured.ts`
 * hits eventually reach `ResponseFinding`, kept consistent across both the
 * request (args) and response (text) scan sites.
 */
function edmAuditExtras(edmHits: EdmMatch[]): Pick<AuditRecord, 'confidence' | 'signals' | 'context'> {
  if (edmHits.length === 0) return {};
  return {
    confidence: 0.99,
    signals: edmHits.map((h) => `edm:${h.indexName}`),
    context: { edmIndexes: edmHits.map((h) => h.indexName) },
  };
}

/** `EdmMatch[]` -> audit-log-safe finding labels (index name only, never the matched value). */
function edmFindingNames(edmHits: EdmMatch[]): string[] {
  return edmHits.map((h) => `EDM exact-data-match: ${h.indexName}`);
}

/**
 * `DataflowFinding[]` (see `provenance.ts`) -> `AuditRecord` extras, mirroring
 * `edmAuditExtras`'s shape/rationale exactly: metadata only (tool names +
 * category), never the tainted value or its hash.
 */
function dataflowAuditExtras(hits: DataflowFinding[]): Pick<AuditRecord, 'confidence' | 'signals' | 'context'> {
  if (hits.length === 0) return {};
  return {
    confidence: 0.9,
    signals: hits.map((h) => `dataflow:${h.originTool}->${h.destinationTool}`),
    context: {
      dataflow: hits.map((h) => ({ originTool: h.originTool, destinationTool: h.destinationTool, category: h.category })),
    },
  };
}

/** `DataflowFinding[]` -> audit-log-safe finding labels (tool names + category only, never the matched value). */
function dataflowFindingNames(hits: DataflowFinding[]): string[] {
  return hits.map((h) => `Dataflow: ${h.originTool} -> ${h.destinationTool} (${h.category})`);
}

/**
 * Merge N `{confidence?, signals?, context?}` audit-extras fragments (e.g.
 * EDM + provenance dataflow both hitting on the same call) into one:
 * signals concatenate, context keys shallow-merge, confidence takes the
 * max. Plain object-spreading two of these would silently DROP one
 * fragment's `signals`/`context` on key collision (later spread wins
 * outright) — this merges instead of overwriting, so the audit trail never
 * silently loses one detector's metadata because another also fired.
 */
export function mergeAuditExtras(
  ...parts: Array<Pick<AuditRecord, 'confidence' | 'signals' | 'context'>>
): Pick<AuditRecord, 'confidence' | 'signals' | 'context'> {
  let confidence: number | undefined;
  const signals: string[] = [];
  let context: Record<string, unknown> | undefined;
  for (const part of parts) {
    if (typeof part.confidence === 'number') {
      confidence = confidence === undefined ? part.confidence : Math.max(confidence, part.confidence);
    }
    if (Array.isArray(part.signals)) signals.push(...part.signals);
    if (part.context) context = { ...(context ?? {}), ...part.context };
  }
  const out: Pick<AuditRecord, 'confidence' | 'signals' | 'context'> = {};
  if (confidence !== undefined) out.confidence = confidence;
  // Dedup: a v2 `finalDecision` can carry the SAME slug (`dataflow:A->B`,
  // `edm:idx`) that `dataflowAuditExtras`/`edmAuditExtras` already
  // contributed for the same underlying finding — those helpers run
  // regardless of policy version, so `decisionAuditExtras` (v2-only) merges
  // a duplicate. Collapse to distinct slugs (insertion order preserved) so
  // the audit `signals` array never lists the same signal twice.
  if (signals.length > 0) out.signals = [...new Set(signals)];
  if (context !== undefined) out.context = context;
  return out;
}

/** Merge N finding-name arrays (e.g. structured/EDM/dataflow) into one, or `undefined` if all are empty — matches the `findings?: string[]` optional-field convention used throughout `AuditRecord`. */
export function mergeFindingNames(...parts: string[][]): string[] | undefined {
  const merged = parts.flat();
  return merged.length > 0 ? merged : undefined;
}

/**
 * `PolicyDecision.confidence`/`.signals` -> `AuditRecord` extras, mirroring
 * `edmAuditExtras`/`dataflowAuditExtras`'s shape exactly. Used ONLY under a
 * v2 policy (see call sites below). Note that when a v2 `finalDecision` IS
 * the dataflow-fusion / `dataflow[]`-onMatch / `edm[]`-onMatch candidate,
 * `decision.signals` carries the SAME slug (`dataflow:<origin>-><dest>`,
 * `edm:<idx>`) that `dataflowAuditExtras`/`edmAuditExtras` already
 * contributed for that finding — those helpers run regardless of policy
 * version. That overlap is real; it is deduped downstream in
 * `mergeAuditExtras` (`[...new Set(signals)]`), so the merged audit
 * `signals` array never lists a slug twice. The overlap is purely cosmetic
 * either way — no decision or leak impact — since both sources derive the
 * same slug from the same taint state.
 */
function decisionAuditExtras(decision: PolicyDecision): Pick<AuditRecord, 'confidence' | 'signals' | 'context'> {
  const out: Pick<AuditRecord, 'confidence' | 'signals' | 'context'> = {};
  if (typeof decision.confidence === 'number') out.confidence = decision.confidence;
  if (Array.isArray(decision.signals) && decision.signals.length > 0) out.signals = decision.signals;
  return out;
}

// ─────────────────────────────────────────────────────────────────────────
// decide()
// ─────────────────────────────────────────────────────────────────────────

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

  // Exact-Data-Match scan of the OUTBOUND args — a fingerprinted
  // secret/PII value being sent OUT in a tool call is the exfil case (see
  // edm.ts's module docblock). Guarded by `edmIndexes.length > 0` (rather
  // than relying solely on `matchEdmIndexes`'s own empty-array short
  // circuit) so the common case — no corpus ever fingerprinted — skips even
  // the `JSON.stringify(args)` cost, not just the matching itself.
  const edmHits =
    state.edmIndexes.length > 0
      ? matchEdmCanonical(state.edmIndexes, safeStringify(event.args), policy.limits.maxScanBytes)
      : [];
  if (edmHits.length > 0) {
    diagnostics.push(
      `EDM match: outbound arg for tools/call "${event.toolName}" matched fingerprint index(es): ${edmHits
        .map((h) => h.indexName)
        .join(', ')}`,
    );
  }

  // Provenance/dataflow scan of the OUTBOUND args (see provenance.ts).
  // This is a SECOND, independent, read-only call to `detectDataflow` —
  // `evaluateCall` above already consulted `evalCtx.provenance` once
  // internally to decide `decision`. Calling it again here is deliberate
  // (not a bug): it is what lets the finding's tool-name metadata reach the
  // audit trail/diagnostics even in the rare case where an explicit policy
  // rule ALSO fired at equal-or-higher precedence and won `decision`
  // outright (ties keep the rule's decision — see `pickHighestPrecedence`
  // in policy.ts). Cheap and bounded: it's a no-op scan
  // (`provenance.taintedCount === 0` short-circuits before any hashing)
  // whenever nothing has been tainted yet this session, and otherwise
  // bounded by `policy.limits.maxScanBytes` exactly like the EDM scan above.
  const dataflowHits =
    state.provenance.taintedCount > 0
      ? state.provenance.detectDataflow(event.toolName, event.args, policy.limits.maxScanBytes)
      : [];
  if (dataflowHits.length > 0) {
    diagnostics.push(
      `provenance: dataflow — response data from tool(s) [${dataflowHits
        .map((h) => h.originTool)
        .join(', ')}] appeared in tools/call "${event.toolName}" arguments`,
    );
  }

  const requestAuditExtras = mergeAuditExtras(edmAuditExtras(edmHits), dataflowAuditExtras(dataflowHits));
  const findingNames = mergeFindingNames(
    edmHits.length > 0 ? edmFindingNames(edmHits) : [],
    dataflowHits.length > 0 ? dataflowFindingNames(dataflowHits) : [],
  );

  // Policy DSL v2: fold `edm[]`/`dataflow[]` `onMatch` enforcement into
  // `decision`. For a v1/version-less policy `finalDecision` is `decision`
  // itself (same reference, zero extra work) — `edmMatchCandidate`/
  // `dataflowMatchCandidate` both short-circuit to `undefined` before
  // touching `policy.edm`/`policy.dataflow` (always `undefined` for v1) via
  // their own `policy.version !== 2` guard, so `combineDecisions` is not
  // even called.
  const finalDecision: PolicyDecision =
    policy.version === 2
      ? combineDecisions(decision, [
          edmMatchCandidate(policy, edmHits, 'request'),
          dataflowMatchCandidate(policy, dataflowHits, event.serverName),
        ])
      : decision;
  // For v1, `auditExtras` IS `requestAuditExtras` — the exact same object,
  // no re-derivation at all (not even a pass through `mergeAuditExtras`
  // with an empty fragment) — the strongest form of "v1 untouched."
  const auditExtras =
    policy.version === 2 ? mergeAuditExtras(requestAuditExtras, decisionAuditExtras(finalDecision)) : requestAuditExtras;

  return { decision: finalDecision, findingNames, inspectionFindings: [], auditExtras, diagnostics };
}

function decideResponse(event: EnforcementEvent, policy: ProxyPolicy, state: EngineState): EngineDecision {
  const diagnostics: string[] = [];
  const text = event.responseText ?? '';
  const inspection = inspectResponseText(text, {
    redactSecrets: policy.response.redactSecrets,
    maxScanBytes: policy.limits.maxScanBytes,
    // Policy DSL v2 `detectors:` block — `resolveDetectors` returns
    // `undefined` whenever `policy.detectors` is unset (always true for
    // v1), and `inspectResponseText` falls back to its own full default
    // detector list on `undefined`, exactly as before this option existed.
    detectors: resolveDetectors(policy),
    // §6.1 hardening: catch encoding-larded secrets (detection-only pass;
    // redaction still operates on raw-text offsets only).
    canonicalPass: true,
  });

  // Tag any sensitive ('secret'-category) findings as this tool's output
  // (see provenance.ts) — BEFORE evaluating the decision, so a
  // same-response velocity read is consistent, and regardless of what that
  // decision turns out to be: tagging just records "the server tried to
  // emit this." A dataflow finding can only ever fire later if the CLIENT
  // actually received the plaintext and echoed it into a different tool's
  // args — a redacted/denied response never reaches the client, so tagging
  // here is harmless even when this very response gets blocked.
  // `tagResponse` never throws on its own (see provenance.ts).
  state.provenance.tagResponse(event.toolName, event.serverName, inspection.findings);

  // Sensitive-path provenance slice. `event.args` is the REQUEST that
  // produced THIS response — if it pointed at a sensitive filesystem
  // location (`~/.ssh`, a `.env`, a credential store — see
  // `./sensitive-read.ts` / `../endpoint/sensitive-paths.ts`), tag this
  // response's CONTENT as sensitive-origin too, regardless of what
  // `tagResponse` above found (a private key's base64 body won't match any
  // secret regex, but its origin is the signal). Same "tag ahead of
  // `decision`, unconditionally" reasoning as the comment above.
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

  // Exact-Data-Match scan of the response text (see edm.ts's module
  // docblock). Same no-op-when-empty guarantee as the request-side scan.
  // Under a v1 policy this never changes `decision`. Under a v2 policy, a
  // configured `edm[]` `onMatch` rule CAN enforce (folded into
  // `finalDecision` below).
  const edmHits = matchEdmIndexes(state.edmIndexes, text, { maxScanBytes: policy.limits.maxScanBytes });
  const allFindingNames = edmHits.length > 0 ? [...inspectionNames, ...edmFindingNames(edmHits)] : inspectionNames;
  if (edmHits.length > 0) {
    diagnostics.push(
      `EDM match: response for "${event.toolName}" matched fingerprint index(es): ${edmHits
        .map((h) => h.indexName)
        .join(', ')}`,
    );
  }

  // Policy DSL v2: fold `edm[]` `onMatch` enforcement into `decision` for
  // the response leg too (dataflow does not apply to responses — see
  // `dataflowMatchCandidate`'s doc comment). For a v1/version-less policy
  // `finalDecision` is `decision` itself (same reference) since
  // `edmMatchCandidate` short-circuits before touching `policy.edm`
  // (always `undefined` for v1).
  const finalDecision: PolicyDecision =
    policy.version === 2 ? combineDecisions(decision, [edmMatchCandidate(policy, edmHits, 'response')]) : decision;
  // For v1, `auditExtras` is exactly `edmAuditExtras(edmHits)` — the same
  // computation as before the extraction, no re-derivation through
  // `mergeAuditExtras` with an empty fragment.
  const edmExtras = edmAuditExtras(edmHits);
  const auditExtras =
    policy.version === 2 ? mergeAuditExtras(edmExtras, decisionAuditExtras(finalDecision)) : edmExtras;

  return {
    decision: finalDecision,
    findingNames: allFindingNames.length > 0 ? allFindingNames : undefined,
    inspectionFindings: inspection.findings,
    auditExtras,
    redactedText: inspection.redactedText,
    diagnostics,
  };
}
