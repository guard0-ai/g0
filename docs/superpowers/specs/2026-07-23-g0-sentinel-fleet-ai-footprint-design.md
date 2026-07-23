# g0 sentinel — MDM-deployed AI footprint discovery, PII exposure, and governance

- **Date:** 2026-07-23
- **Status:** Approved design, pre-implementation
- **Branch:** `feat/sentinel` (proposed)
- **Driven by:** committed-POC customer (ManageEngine MDM shop, Windows + macOS all-staff)
- **Relates to:** `g0 check` (endpoint discovery), `g0 protect` (enforcement engine), `g0 fleet` (roll-up), `src/endpoint/*`, `src/flows/*`, `src/enforcement/*`

## 1. Context and goal

A committed customer wants to push a CLI to **every machine** through
**ManageEngine** (their MDM), have it **discover the entire AI footprint**, show
**what PII is exposed to each AI tool** (across email, browsers, coding agents,
desktop apps), deliver an **inventory first**, and then give them a way to
**remove the footprint or enforce a governance policy**.

This is the "shadow AI discovery + governance" category — and it is squarely in
g0's existing wheelhouse. g0 already:

- discovers 19 AI dev tools, MCP servers, agentic browsers, and the Claude
  supply chain on a machine (`src/endpoint/scanner.ts`, `claude-estate-scanner.ts`);
- detects MDM enrollment and provider (`src/endpoint/mdm-detect.ts` — already
  aware of ManageEngine-class managers);
- classifies PII-shaped data via the proxy's Exact-Data-Match / secret detectors
  and session forensics (`src/proxy/*`, `src/endpoint/session-forensics.ts`);
- analyzes toxic data flows (`src/flows/*`);
- quarantines known-malicious artifacts, dry-run by default
  (`src/endpoint/quarantine.ts`, `estate-quarantine.ts`);
- rolls results up across machines (`src/platform/fleet.ts`, `g0 fleet`).

**What is missing is not detection — it is packaging and framing.** The gap
between what g0 does today and what this customer buys is:

1. a **deployable unit** that installs through MDM with no Node prerequisite and
   runs unattended;
2. a **per-tool PII-exposure view** (g0 has the classifiers but presents them by
   finding, not by "which AI tool can see what");
3. an **org-wide inventory report** an admin sees without touching each machine;
4. a **governance/removal action** that an MDM-managed fleet can actually enact.

The deliverable of this project is a demo-able closed loop:

> Push through ManageEngine → every machine reports its AI footprint and PII
> exposure → admin sees one org inventory → admin applies a governance policy →
> footprint is removed or enforced, and the report proves it.

### Decisions already made (do not relitigate)

1. **Engagement:** committed paid POC. Plan is concrete build phases with a
   demo-able milestone in weeks, scoped to win this deal.
2. **Aggregation:** **MDM-collect first, platform later.** The sentinel writes a
   machine snapshot to a well-known path; ManageEngine's own file/script
   collection pulls it; an admin-side `g0 fleet import` + HTML org report rolls
   it up. **No new network surface in the POC.** Platform upload becomes the paid
   upgrade later. This keeps the standing "g0 does not upload results" constraint
   intact for the POC.
3. **PII depth:** **evidence-based exposure, no interception.** Per tool: what it
   *can* reach (extension permissions, OAuth scopes, add-in manifests,
   filesystem/config access) + what *did* flow (PII classifiers over local
   artifacts only). No TLS interception, no inline DLP.
4. **Fleet scope:** Windows + macOS all-staff is the target. **macOS ships first
   in the POC** (g0's endpoint depth is proven there); Windows detection depth is
   built in parallel and is the primary risk to retire early.
5. **Architecture:** **g0 core + `g0 sentinel` mode**, compiled to a single
   self-contained binary. Reuse every existing scanner. Rejected: npm+Node
   bootstrap (enterprise IT rejects Node on all-staff machines); ground-up
   Go/Rust agent (throws away the detection/classifier code — months of rewrite,
   two codebases forever).
6. **Language:** **stay in TypeScript, do not rewrite in Rust.** Rationale in §9.

## 2. Non-goals

- **No TLS interception / inline content DLP.** We prove exposure from evidence
  (permissions, scopes, local artifacts), not by reading traffic in transit.
  Content-level interception is Netskope/Zscaler territory — months of work,
  cert-store manipulation, breaks pinned apps. Out of scope even if tempting.
- **No result upload to app.guard0.ai in the POC.** Aggregation is MDM-collected
  files. Platform push is the *later paid* path, designed for but not built here.
- **No raw PII in snapshots.** Snapshots carry PII *classes and counts with
  evidence locators* (e.g. "14 email addresses, 3 credit-card-shaped strings in
  `~/.codex/history`"), never the values themselves. This is a hard invariant —
  a security tool that exfiltrates PII into a report an MDM copies around is the
  exact failure it exists to prevent.
- **No new agent process rewrite.** Sentinel is a mode of the existing binary.
- **Not a replacement for `g0 check`/`protect`/`fleet`** — sentinel composes them
  for unattended fleet use.

## 3. The deployed unit: `g0 sentinel`

A restricted, non-interactive entrypoint of the same binary, designed to be run
by a scheduler (Windows Scheduled Task / macOS LaunchDaemon) that MDM installs.

```
g0 sentinel scan     # run one collection pass, write snapshot, exit
g0 sentinel status   # last run time, next run, snapshot path, health (for MDM checks)
g0 sentinel version  # binary + detection-DB version (for MDM compliance reporting)
```

Properties:

- **Non-interactive, never blocks, never prompts.** No spinner TTY assumptions,
  no network calls on the scan path (consistent with the platform-read
  constraint: sync + never-throw).
- **Deterministic output path.** Writes an atomic snapshot to a well-known,
  MDM-collectable location:
  - Windows: `C:\ProgramData\guard0\snapshot.json` (+ `snapshot.json.sig`)
  - macOS: `/Library/Application Support/guard0/snapshot.json`
- **Bounded runtime.** Hard wall-clock cap (default 120s) with partial-result
  emission — a scan that can't finish still reports what it found and flags the
  timeout, so a slow machine never produces an empty report.
- **Config from a managed file** MDM drops next to the binary
  (`guard0.policy.yaml`): scan cadence, PII scan opt-in per artifact class,
  governance policy, snapshot path override, redaction level.
- **Self-describing health** so ManageEngine can alert on stale/failed sentinels
  (a fleet-management tool must itself be fleet-observable).

Sentinel is a thin orchestrator over existing modules — it calls the endpoint
scanner, the new footprint/PII builders (§5, §6), and the snapshot writer (§7).
No detection logic lives in the sentinel command itself.

## 4. Packaging & MDM delivery

The single largest *new* work item, and the thing that makes this "real software
pushed through MDM" rather than a dev toy.

- **Single self-contained binary.** Compile with Node SEA (Single Executable
  Applications) or `bun build --compile`. No Node/npm on the target machine.
- **Native-dependency spike is week-1, gating.** g0's scanners use tree-sitter
  (native). The compile must either bundle these or the affected scanners must
  degrade gracefully. **Fallback if the compile fights native deps:** ship an
  installer that embeds a pinned Node runtime privately (not on PATH, not
  `npm i -g`) and invokes it — still "one MDM artifact, no system Node," just
  larger. Decide by end of week 1.
- **Installers:**
  - **Windows:** signed **MSI** (WiX or `msitools`) that lays down the binary +
    policy file and registers a Scheduled Task. Code-signing cert required —
    procurement is on the critical path, start day 1.
  - **macOS:** signed + notarized **PKG** that lays down the binary + a
    **LaunchDaemon** plist. Apple Developer ID + notarization — also day-1
    procurement.
- **ManageEngine handoff:** MSI/PKG push via MDM software distribution; policy
  file via MDM config profile / file deployment; snapshot retrieval via MDM
  file-collection or a scripted pull. We provide a **ManageEngine deployment
  guide** (the artifact IT actually needs) — not custom ManageEngine code.
- **Uninstall path** that removes the scheduler entry, binary, and (optionally)
  local snapshots — clean teardown is table stakes for IT approval.

## 5. AI footprint discovery (inventory)

Reuse and reframe existing discovery; the new work is **coverage breadth on
Windows** and **grouping output by AI tool rather than by finding.**

Surfaces (extending what `src/endpoint/` already covers):

- **Desktop AI apps:** ChatGPT/Claude/Copilot desktop, IDE assistants, etc.
  (process + install detection — extend `process-detector.ts`, `fingerprints.ts`).
- **Coding agents:** Claude Code, Codex, Cursor, Windsurf, Copilot, Cline, +
  their config/estate (`agent-config-scanner.ts`, `claude-estate-scanner.ts`).
- **Browser AI extensions:** enumerate installed extensions across Chrome/Edge/
  Brave/Firefox and match against an AI-extension catalog (extend
  `browser-scanner.ts`, `agentic-browser-scanner.ts`) — **Edge on Windows is new
  depth.**
- **Email / productivity AI integrations:** Outlook add-ins (manifest scan),
  Gmail/Workspace add-ons where locally evidenced, Copilot-for-M365 signals.
  **New: `email-integration-scanner.ts`.**
- **MCP servers:** already covered (`src/mcp/*`, discovery graph).
- **OAuth grants to AI vendors:** where locally discoverable (browser-stored
  grants, app tokens) — evidence of "this identity authorized this AI tool."

Each discovered item becomes a **footprint entry** with a stable identity, a
category, evidence locators, version, and a `reach` descriptor (§6). This is the
inventory the customer asked for "first."

## 6. PII exposure engine (per-tool)

The differentiated view. For **each AI tool** in the footprint, answer two
questions from local evidence only:

1. **What can it reach?** (capability / attack surface)
   - Browser-extension declared permissions (`host_permissions`, `tabs`,
     `cookies`, `<all_urls>`, clipboard, etc.).
   - OAuth scopes granted to the tool (mail.read, drive, contacts…).
   - Add-in manifest permissions (Outlook `ReadWriteMailbox` etc.).
   - Filesystem/config reach: what paths the agent is configured to access,
     MCP servers it can call, working directories.
2. **What did flow?** (evidenced exposure)
   - Run PII classifiers (reuse the proxy's EDM/secret detectors and
     `session-forensics.ts`) over **local artifacts the tool produced or
     touched**: coding-agent session/history logs, browser history entries to AI
     domains, MCP audit logs (`~/.g0/…`), clipboard-manager stores if present.
   - Output **classes + counts + locator**, never raw values. E.g. *"Codex
     session history contains 14 email addresses, 2 access-token-shaped strings,
     1 credit-card-shaped string (`~/.codex/history/2026-07-*.jsonl`)."*

Represent per tool as an **exposure record**:

```
tool: "Cursor"
category: coding-agent
reach:      [ filesystem: workspace+home, mcp: [github, postgres], network: api.anthropic.com ]
evidenced:  { email: 14, secret: 3, credit_card: 1, person_name: 22 }
risk:       HIGH   # from reach × evidenced, mapped to existing scoring
```

Reuse `src/flows/scorer.ts` and `src/endpoint/scoring.ts` for the risk roll-up so
grading stays consistent with the rest of g0. **Redaction level is policy-driven**
(counts-only vs. redacted-sample-with-context) and defaults to counts-only.

## 7. Snapshot format & signing

- **One JSON document per machine per run**, schema-versioned. Contents: host
  identity (hostname, OS, MDM provider from `mdm-detect.ts`, machine-id hash),
  sentinel/DB versions, footprint entries (§5), exposure records (§6), governance
  policy verdict (§8), run metadata (start/end/timeout/errors).
- **Signed** (reuse `src/inventory/sign.ts` — the same signing that backs
  attestation packs) so the admin roll-up can trust snapshots weren't tampered in
  transit through file collection.
- **Content-addressed** so the org report can diff machine-over-time and
  fleet-wide drift (reuse `src/inventory/differ.ts`).
- **Size-bounded**; large evidence lists are truncated with counts preserved.

## 8. Governance & enforcement (remove or enforce)

Two tiers, matching "get rid of it **or** enforce a governance policy":

**Tier 1 — Policy verdict (report-only, ships in POC).**
`guard0.policy.yaml` declares an allow/deny/monitor stance per tool category or
specific tool (e.g. "personal ChatGPT extension = deny," "approved Copilot =
allow," "unknown MCP server = flag"). Every snapshot carries a per-tool
**compliance verdict** against this policy. The org report shows who is
compliant. This alone satisfies "enforce a governance policy" at the visibility
level and is the safe default.

**Tier 2 — Remediation actions (guarded, opt-in).** Two enactment paths, and we
deliberately prefer the first for a managed fleet:

- **MDM-enacted (recommended):** g0 *decides and reports* the required action;
  **ManageEngine enforces** it (uninstall app, remove extension via browser
  policy, block via app-control). g0 emits a machine-readable **remediation
  manifest** the MDM consumes. This respects the reality that the MDM already
  owns software lifecycle on these machines, and keeps g0 out of the destructive
  path on staff machines. `g0 sentinel remediate --plan` produces the manifest;
  MDM does the removal.
- **g0-enacted (opt-in, dry-run default):** reuse the existing quarantine engine
  (`src/endpoint/quarantine.ts`, `estate-quarantine.ts`) to neutralize
  known-malicious footprint directly, plus `g0 protect` to install runtime
  enforcement (MCP proxy, Claude hooks) where the customer wants live blocking
  rather than removal. **Never destructive without explicit policy opt-in;
  reversible; logged.**

The split — **g0 decides, MDM enforces by default; g0 enforces only where the
customer opts in** — is the safe, enterprise-legible governance model.

## 9. Language decision: TypeScript, not Rust

The customer-relayed question was "should we write this in Rust for performance?"
**No — for this workload and this timeline, Rust is the wrong trade.** Reasoning,
not reflex:

- **The workload is I/O-bound, not CPU-bound.** Sentinel enumerates files,
  parses config/JSON, reads extension manifests, greps artifacts for PII
  patterns. Wall-clock is dominated by disk and process enumeration, which a
  Rust rewrite does not speed up. The one CPU-heavy piece (tree-sitter parsing)
  already runs as native code regardless of the host language.
- **Rewriting discards the moat.** The entire value here is the *existing*
  detection DB, classifiers, scoring, quarantine, and flow analysis — thousands
  of lines of tuned TypeScript. A Rust rewrite is months, produces a second
  codebase to maintain forever, and delivers the POC late. That directly
  contradicts decision (1).
- **"Single small binary" — the real reason people reach for Rust — is already
  solved** by Node SEA / `bun --compile` (§4). We get one self-contained
  artifact without abandoning the code.
- **Where perf actually matters, fix it locally.** If a scan pass is too slow,
  the wins are algorithmic (parallelize artifact scans, cap file sizes, skip
  binary blobs, cache by mtime) — all achievable in TS. The p95 budget that
  matters (the `g0 hook` <100ms path) is unaffected; sentinel runs on a schedule,
  not in an interactive hot path.
- **Revisit only if evidence demands it.** If week-1 benchmarking shows a
  specific hot loop (e.g. PII regex over multi-GB artifacts) blows the runtime
  budget and can't be fixed in TS, port *that function* to a native addon — not
  the product. Measure first.

**Conclusion: TypeScript + compiled single binary. Do not rewrite in Rust.** Keep
this decision in the spec so it isn't relitigated under schedule pressure.

## 10. Build phasing (6 weeks to a converting demo)

Each phase ends in something demo-able. macOS leads; Windows depth is retired
early because it is the top risk.

- **Phase 0 — Spike & de-risk (week 1).** Two spikes in parallel: (a) compile the
  binary with SEA/bun, prove native-dep story or commit to the embedded-runtime
  fallback; (b) start MSI + PKG signing-cert procurement. Ship a hand-run
  `g0 sentinel scan` on macOS writing a real snapshot. *Demo: a signed snapshot
  JSON from a Mac.*
- **Phase 1 — Footprint inventory + org report (weeks 2–3).** `g0 sentinel scan`
  full macOS coverage (§5), snapshot signing (§7), `g0 fleet import` of a
  directory of snapshots, and an **HTML org inventory report**. *Demo: push to a
  handful of Macs via MDM (or manually), collect, one report showing every AI
  tool across machines.*
- **Phase 2 — PII exposure engine (weeks 3–4, overlaps).** Per-tool reach +
  evidenced exposure (§6), redaction invariant enforced, risk roll-up. *Demo: the
  report now shows "which AI tool can see what PII" per machine and fleet-wide.*
- **Phase 3 — Governance verdict + remediation manifest (weeks 4–5).**
  `guard0.policy.yaml`, per-tool compliance verdict, MDM-enacted remediation
  manifest, opt-in g0-enacted quarantine reusing existing engine (§8). *Demo:
  apply a policy, report flags non-compliant tools, generate a removal manifest.*
- **Phase 4 — Windows depth + installer hardening (weeks 5–6).** Windows
  detection paths (registry, AppData, Edge/Outlook add-ins), MSI, Scheduled Task,
  ManageEngine deployment guide, uninstall path. *Demo: the full loop on a
  Windows machine pushed through ManageEngine.*

**Critical-path items that must start on day 1** regardless of phase: code-signing
cert procurement (Windows) and Apple Developer ID + notarization (macOS); the
native-dep compile spike; and confirming the customer's actual Windows/macOS mix
and one test machine of each for the pilot.

## 11. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Native deps (tree-sitter) won't compile into SEA/bun binary | Medium | High | Week-1 spike; embedded-runtime fallback keeps "one MDM artifact" promise |
| Windows detection depth is shallow today | High | High | Retire early (Phase 4 planned, Windows paths researched in Phase 0); macOS carries the first demo |
| Code-signing / notarization procurement slips | Medium | High | Start day 1; unsigned binaries are a non-starter for MDM push |
| Snapshot accidentally carries raw PII | Low | Critical | Hard invariant (§2): classes+counts+locator only; redaction default counts-only; test asserts no raw values in output |
| ManageEngine collection/enforcement specifics differ from assumptions | Medium | Medium | We emit standard files + manifests, provide a guide; do not build ManageEngine-specific code; confirm with customer IT in Phase 0 |
| Scope creep toward inline DLP/interception | Medium | High | Explicit non-goal (§2); evidence-based only |
| Sentinel hangs/slows a staff machine | Low | High | Bounded runtime with partial emission (§3); scheduled not interactive |
| PII classifier false positives inflate risk | Medium | Medium | Reuse checksum-validated EDM/secret detectors already tuned in the proxy; show evidence locator so admin can verify |

## 12. What we reuse vs. build

**Reuse (most of it):** endpoint scanners, `mdm-detect.ts`, PII/secret/EDM
classifiers, `session-forensics.ts`, flow scorer, `fleet.ts` roll-up,
`inventory/sign.ts` + `differ.ts`, quarantine engines, `protect`/enforcement.

**Build (new):**
1. `g0 sentinel` command mode (thin orchestrator).
2. Single-binary compile + MSI/PKG installers + scheduler registration.
3. `email-integration-scanner.ts` (Outlook/Workspace add-ins) + Windows/Edge
   extension enumeration depth.
4. Per-tool PII **exposure record** builder (reframes existing classifier output
   by tool with a reach descriptor).
5. Machine **snapshot schema** + writer/signer.
6. `g0 fleet import` of snapshot directories + **HTML org inventory/exposure
   report**.
7. `guard0.policy.yaml` governance schema + per-tool compliance verdict +
   **remediation manifest** emitter.
8. ManageEngine deployment guide.

## 13. Success criteria

The POC converts if, on the customer's own fleet:

1. A signed installer pushes through ManageEngine to Windows **and** macOS with
   no Node/system prerequisite.
2. Every machine reports its full AI footprint unattended.
3. The admin sees **one org report**: every AI tool, per machine and fleet-wide,
   with per-tool PII exposure — without logging into any machine.
4. No raw PII appears in any snapshot or report.
5. Applying a governance policy flags non-compliant tools, and a remediation
   manifest (MDM-enacted) or opt-in quarantine (g0-enacted) removes/enforces the
   footprint — with proof in the next report.
