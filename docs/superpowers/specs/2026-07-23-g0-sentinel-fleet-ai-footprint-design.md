# g0 sentinel — MDM-deployed AI footprint discovery, PII exposure, and governance

- **Date:** 2026-07-23
- **Status:** Approved design (revised after internet research), pre-implementation
- **Branch:** `feat/sentinel` (proposed)
- **Driven by:** committed-POC customer (ManageEngine shop, Windows + macOS all-staff)
- **Relates to:** `g0 check`, `g0 protect`, `g0 fleet`, `src/endpoint/*`, `src/flows/*`, `src/enforcement/*`
- **Research provenance:** §16. Five sourced research passes (2026-07-23) validated or corrected
  every load-bearing assumption. Where research overturned the first draft, the change is
  called out inline with **[CORRECTED]**.

## 1. Context and goal

A committed customer wants to push a CLI to **every machine** through **ManageEngine**
(their MDM), **discover the entire AI footprint**, show **what PII is exposed to each AI
tool** (email, browsers, coding agents, desktop apps), deliver an **inventory first**, then
give a way to **remove the footprint or enforce a governance policy**.

This is the "shadow AI discovery + governance" category, and it is in g0's wheelhouse. g0
already discovers AI dev tools/MCP servers/agentic browsers/the Claude supply chain
(`src/endpoint/*`), detects MDM enrollment (`mdm-detect.ts`), classifies PII-shaped data
(proxy EDM/secret detectors, `session-forensics.ts`), analyzes toxic flows (`src/flows/*`),
quarantines malicious artifacts (`quarantine.ts`, `estate-quarantine.ts`), and rolls results
up across machines (`src/platform/fleet.ts`, `g0 fleet`).

**The gap is packaging and framing, not detection.** Four things stand between g0-today and
this deal:

1. a **deployable unit** that installs through MDM with no Node prerequisite and runs unattended;
2. a **per-tool PII-exposure view** (g0 has the classifiers but presents by finding, not by tool);
3. an **org-wide inventory report** an admin sees without touching each machine;
4. a **governance/removal action** an MDM-managed fleet can actually enact.

Deliverable: a demo-able closed loop —

> Push through ManageEngine → every machine reports its AI footprint and PII exposure →
> admin sees one org inventory → admin applies a governance policy → footprint is removed or
> enforced, and the report proves it.

### Competitive positioning (why this is worth building) — [RESEARCHED]

The shadow-AI market splits into two camps that both look **away from the machine**:
**network/proxy** (Zscaler AI Access, Netskope AI Command Center, WitnessAI, Microsoft
Defender for Cloud Apps — they see *traffic* to AI domains) and **SaaS-API/OAuth/IdP** (Nudge
Security, Wing Security, Grip Security — they see *grants and logins*). Only **Harmonic
Security** and **Lanai** ship true endpoint agents, and both are oriented to *runtime GenAI
usage monitoring / inline DLP* (what a user typed into a prompt) — not a static, per-machine
**AI-footprint asset inventory** (installed AI apps + coding agents + browser AI extensions +
MCP configs + Office add-ins) unified per device with **local PII-exposure evidence** and
governance. That combination, positioned as an independent **auditor of record** rather than
an inline proxy, is unoccupied. Defensive call-outs: Harmonic (endpoint desktop client, but
usage-monitoring not inventory) and Nudge (OAuth-grant + extension governance, but
agentless/SaaS-side). Sources in §16.

### Decisions already made (do not relitigate)

1. **Engagement:** committed paid POC. Concrete build phases, demo-able milestone in weeks.
2. **Aggregation:** **[CORRECTED] — a thin collector is required.** The first draft assumed
   ManageEngine natively pulls a snapshot file from every machine to the console. **It does
   not** (§8). The corrected model: the ME-run script POSTs each machine's snapshot to a
   **small, customer-hosted collector we ship**; `g0 fleet import` + an HTML org report roll
   it up. A **compact summary** also goes back through ManageEngine's own script-output report
   (native visibility in their console). Full snapshots never touch app.guard0.ai in the POC.
3. **PII depth:** **evidence-based exposure, no interception.** Per tool: what it *can* reach
   (extension permissions, OAuth scopes, add-in manifests, filesystem/config access) + what
   *did* flow (PII classifiers over local artifacts only). No TLS interception, no inline DLP.
4. **Fleet scope:** Windows + macOS all-staff. **macOS ships first** (proven endpoint depth);
   Windows depth is built in parallel and de-risked early.
5. **Architecture:** **g0 core + `g0 sentinel` mode**, compiled to a single self-contained
   binary. Reuse every existing scanner. Rejected: npm+Node bootstrap (enterprise IT rejects
   Node on all-staff machines); ground-up Go/Rust rewrite (discards the detection/classifier
   moat). **[RESEARCHED] we also evaluated shipping *inside* an existing fleet agent
   (osquery/Fleet, Velociraptor, Wazuh, GRR) — see §8; keep the g0 binary, borrow only the
   transport where useful.**
6. **Language:** **stay in TypeScript, do not rewrite in Rust** (§10 — strengthened by the
   packaging research: the perf worry is answered without leaving TS).
7. **Deployment posture: [USER] resident daemon, MDM-agnostic.** The agent runs in **daemon
   mode** (reusing `src/daemon/` + the resident watcher shipped in #193): installed once via any
   MDM, it stays resident, wakes on its own schedule, and reports **deltas continuously** — so
   the fleet view keeps updating without re-triggering. Default posture is a *well-behaved*
   daemon (internal scheduling + targeted watches on high-signal paths), **not** a hot
   filesystem-watch over everything (EDR-collision + resource cost — §3). Aggressive real-time
   watch + immediate blocking stays the opt-in `g0 protect` tier. The MDM is a **dumb pipe**
   (push binary + config + optional trigger); the agent never knows which MDM deployed it, so
   the same binary scales across Jamf, ManageEngine, Intune, Kandji, Workspace ONE (§4). (We
   considered wiring in a network/SSE product as a channel too — dropped: SSE tools aren't
   deployment channels, so the model stays MDM-only.)

## 2. Non-goals

- **No TLS interception / inline content DLP.** Exposure is proven from evidence, not traffic.
- **No full-snapshot upload to app.guard0.ai in the POC.** Aggregation is a **customer-hosted
  collector**. Platform push stays the *later paid* path.
- **No raw PII anywhere.** Snapshots carry PII **classes + counts + evidence locator** (e.g.
  "14 email addresses, 3 card-shaped strings in `~/.codex/history`"), never values. Hard
  invariant — now doubly important because snapshots travel over HTTP to the collector (§8).
- **No bespoke fleet-management server.** We do not rebuild what Fleet/Velociraptor give away
  (§8). The collector is a thin ingest + the existing `g0 fleet` roll-up, nothing more.
- **No endpoint scanning of surfaces that don't live on the endpoint.** **[CORRECTED]** OAuth
  grants to AI vendors and modern M365/Office **web** add-ins (incl. Copilot for M365) are
  *not* reliably discoverable on-device; they are reframed as optional SaaS admin-API
  connectors (§5), explicitly out of the endpoint sentinel.

## 3. The deployed unit: `g0 sentinel` (daemon mode) — [REVISED: DAEMON-FIRST]

The deployed unit is a **resident, MDM-agnostic agent** — the existing g0 daemon
(`src/daemon/`: `runner.ts`, `watch.ts`, `kill-switch.ts`, `alerter.ts`; resident watcher
shipped #193) run in a fleet *sentinel* profile. Installed once via any MDM, it stays resident
and keeps the fleet view fresh without re-triggering.

```
g0 sentinel start      # install/run the resident daemon (the fleet posture)
g0 sentinel scan       # one-shot delta scan for MDM-triggered runs / debugging: snapshot, POST, compact summary, exit
g0 sentinel status     # daemon health, last/next scan, snapshot path, collector reachability (for MDM checks)
g0 sentinel version    # binary + detection-DB version (for MDM compliance reporting)
```

**Default posture — a well-behaved daemon, not a hot-watch loop.** Between reports the daemon
is mostly idle: it wakes on its **own internal schedule** (so it never depends on MDM
cron-grade timing, which ManageEngine lacks — §4), runs a fast **delta** scan, and keeps
**targeted** watches only on high-signal change points (MCP config files, browser extension
dirs, new-app installs) via native OS events. It does **not** hot-watch the whole home
directory or continuously re-scan for PII — that posture collides with EDR/AV behavioral
detection (a resident process reading browser profiles + session logs + phoning home looks
exactly like an infostealer) and taxes laptop CPU/battery. This is the osquery-style posture
(resident but mostly idle, internal scheduling), not a real-time file monitor. Aggressive
real-time watch + immediate blocking is the **opt-in `g0 protect` tier**, deployed only where
the customer wants live enforcement over inventory.

Properties (unchanged): non-interactive, never prompts, never blocks; per-scan bounded runtime
(default 120s, **partial-result emission** on timeout); deterministic snapshot path (Windows
`C:\ProgramData\guard0\snapshot.json`, macOS `/Library/Application Support/guard0/snapshot.json`);
config from a managed `guard0.policy.yaml` the MDM drops beside the binary; self-describing
health so the MDM can alert on a dead/stale daemon. Thin orchestrator over existing scanners —
no detection logic lives in the command.

## 4. Packaging & MDM delivery — [MAJOR CORRECTION FROM RESEARCH]

The first draft called the native-dependency compile the top technical risk. **Research
resolved it: it is a non-issue once we migrate tree-sitter to WASM.**

- **Step 0, gating everything: replace native `tree-sitter` with `web-tree-sitter` (WASM).**
  g0 currently depends on the native N-API addon `tree-sitter@0.21.1` + five native grammars.
  `web-tree-sitter` is the official Tree-sitter core compiled to WebAssembly; each grammar
  loads as a plain `.wasm` **data file** (`Parser.Language.load('…wasm')`) — no `.node`, no
  `dlopen`, no node-gyp, no per-platform ABI. Prebuilt grammar `.wasm` for all five of g0's
  languages already exist on npm (no emscripten build needed). This removes native compilation,
  the per-OS ABI matrix, temp-file `dlopen`, the Node-24/C++20 build breakage, **and** the
  EDR/AV quarantine risk of writing-then-executing a `.node` from temp on hardened endpoints.
  The one honest cost: WASM parsing is slower than native — irrelevant for a scheduled scan,
  but **benchmark on the largest target repo in Phase 0** before committing.
- **Binary:** **Node SEA** (primary — keeps the exact runtime g0 is tested on; per-OS CI
  matrix, re-sign after postject inject) with a **one-day Bun `--compile` spike** as the
  low-effort alternative (true cross-compile from one host — attractive *now that no native
  dep remains*; cost is re-running the test suite under JavaScriptCore). Vercel `pkg` is
  archived; `nexe` is broken on Node 20+; Deno compile adds runtime-migration cost for no gain.
- **Installers:**
  - **Windows:** signed **MSI** via **WiX v6** (or GNOME `msitools`/`wixl` to build on
    Linux CI and dodge WiX's Open-Source Maintenance Fee) that lays down the binary + policy
    file and **registers a Scheduled Task** (`schtasks /create /xml` from a deferred custom
    action; `schtasks /delete` on uninstall). Authenticode-sign **both** exe and msi; EV/OV
    cert for clean SmartScreen reputation.
  - **macOS:** **PKG** via `pkgbuild`→`productbuild` laying down the binary + a **LaunchDaemon**
    plist (`StartCalendarInterval` = the schedule). Sign with **Developer ID Installer** +
    **notarize** (`notarytool --wait`) + `stapler staple`; binary signed with Developer ID
    Application. **[CORRECTED]** ManageEngine docs omit this because it's an *Apple* Gatekeeper
    requirement, not an ME one — but without it, silent install fails.
- **Scheduling — [CORRECTED]:** ManageEngine does **not** give cron-grade per-endpoint
  scheduling; its cadence is the agent refresh cycle + logon/startup triggers. So **our
  installer registers its own Scheduled Task / LaunchDaemon**; ME is used to install and to
  force ad-hoc re-runs. Do not design around an ME-provided timer.
- **ManageEngine product check — [CORRECTED]:** the script/software engine we rely on is
  **ManageEngine Endpoint Central** (agent-based, ex-Desktop Central), **not Mobile Device
  Manager Plus** (agentless/profile-based, lacks the custom-script engine). **Confirm with the
  customer which product they own before building** — this is a real risk, not a formality.
- **MDM-agnostic by design — the MDM is a dumb pipe. [USER]** The agent never knows or cares
  which MDM deployed it. The MDM does exactly three things: (1) push the signed installer,
  (2) drop `guard0.policy.yaml` at the known path, (3) optionally trigger an ad-hoc run. Scan,
  daemon, delta detection, and collector transport are identical everywhere. So supporting a new
  MDM is a **thin deployment recipe, not a code fork** — if MDM-specific logic ever creeps into
  the agent, the abstraction has broken. Recipe matrix (ship as docs):
  - **ManageEngine Endpoint Central:** Software Deployment (MSI/PKG) + Script Repository/Custom
    Script to install the daemon; Prohibited-Software + Add-on/Extension Control for remediation (§9).
  - **Jamf Pro (macOS):** signed+notarized PKG via a Policy + a LaunchDaemon Configuration
    Profile; extension/app removal via Jamf policies.
  - **Microsoft Intune:** Win32 app (`.intunewin`) + PowerShell install script + a Scheduled
    Task; extension blocklist via ADMX / settings catalog.
  - **Kandji / Mosyle / Workspace ONE / others:** the same PKG/MSI + config-profile + script
    shape — no new agent code.
- **Agent updates vs. data updates — keep them separate. [USER]** The *binary* is updated
  through the MDM (push a new signed MSI/PKG) — the daemon must **not** self-update its own
  executable on a managed fleet; IT controls that. The *detection DB / threat-intel rules*
  refresh **out-of-band** as a signed data file the daemon fetches (no re-sign needed) — the AV
  model: engine via IT, signatures auto-update. This keeps "keep receiving changes" true without
  opening a binary-autoupdate hole IT won't accept.
- **Handoff + teardown:** per-MDM deployment guides (above), Endpoint Central first for the POC.
  We ship guides, not MDM-specific code. Plus a clean **uninstall** path (daemon + scheduler
  entry + binary + optionally local snapshots).

## 5. AI footprint discovery (inventory) — [SCOPE CORRECTED FROM RESEARCH]

Reuse existing discovery; the new work is **breadth on Windows/Edge** and **grouping output
by AI tool.** Research sorted the surfaces into what is genuinely endpoint-native vs. what must
be a SaaS connector — being honest here prevents over-promising the endpoint story.

**Endpoint-native (lean in — under-served by competitors, reusable OSS exists):**

- **Browser AI extensions + permissions.** Enumerate across Chrome/Edge/Brave/Firefox. OSS to
  reuse: osquery's `chrome_extensions`/`firefox_addons` tables *as a reference*, or the trivial
  direct read of `Preferences`/`Secure Preferences` + `Extensions/<id>/<ver>/manifest.json`
  (which g0 already does in `browser-scanner.ts` — extend to Edge/Windows). Risk scoring for
  `permissions`/`host_permissions`: **adopt `crx-analyzer`'s permission→risk map** (CRITICAL=10
  … LOW=1) rather than inventing one. **AI-extension-ID catalog: build our own** (no
  security-grade `extensionID→vendor/risk` map exists OSS — a small moat, not a blocker).
- **Installed AI desktop apps.** Windows Uninstall registry keys + macOS LaunchServices/bundle
  IDs (extend `process-detector.ts`/`fingerprints.ts`). **Caveat:** registry enumeration misses
  portable/no-installer AI tools — supplement with a targeted filesystem/process scan for known
  AI binaries.
- **Coding agents + MCP configs.** Already strong in g0 (`agent-config-scanner.ts`,
  `claude-estate-scanner.ts`, `src/mcp/*`). Reuse `mcp-scan`'s config-discovery *logic* as a
  cross-check for Claude Desktop/Cursor/Windsurf paths.
- **Legacy Outlook COM add-ins.** Endpoint-local via `HKLM\…\Office\Outlook\Addins` (+
  `Wow6432Node` + `HKCU`). New: `email-integration-scanner.ts`.

**SaaS admin-API connectors (reframed — NOT endpoint scanning; separate, optional, post-POC):**

- **OAuth grants to AI vendors.** Live server-side at the IdP; discover via **Google Admin SDK
  / Microsoft Graph**, not on-device. (This is exactly where Nudge/Wing/Grip play — least
  differentiated for us on the endpoint, so it's a connector, not a sentinel feature.)
- **Modern M365/Office web add-ins + Copilot for M365.** Centrally provisioned, only cached in
  obscure per-user WEF folders; Copilot is a tenant license, not a local artifact. Discover via
  **M365 admin center / Graph**. Do not claim these as endpoint discovery.

Each endpoint-native item becomes a **footprint entry** (stable identity, category, evidence
locators, version, `reach` descriptor → §6). This is the "inventory first" deliverable.

## 6. PII exposure engine (per-tool) — [ENGINE CHOICE FROM RESEARCH]

The differentiated view. For **each AI tool**, answer from local evidence only:

1. **What can it reach?** Extension permissions (`host_permissions`, `<all_urls>`, cookies,
   clipboard…), OAuth scopes where locally evidenced, add-in manifest permissions,
   filesystem/config reach, MCP servers it can call.
2. **What did flow?** Run PII classifiers over **local artifacts the tool produced/touched**
   (coding-agent session/history logs, browser history to AI domains, MCP audit logs, clipboard
   stores). Output **classes + counts + locator**, never values.

**Classifier stack — keep it all in-process TypeScript (no Python/spaCy shipped to endpoints):**

- **Structured PII** (emails, cards, SSNs, IBANs, IPs, country IDs): vendor **OpenRedaction**
  (MIT, TS, 570+ patterns, **Luhn-validated** cards, fully local) as the base catalog + fold in
  g0's existing EDM/secret detectors. This is where regex+checksum **beats** NER, so no quality
  loss.
- **Named entities** (person names, locations): **`compromise`** (MIT, ~12k★, ~250kb, in-JS)
  for approximate counts. Accept below-spaCy recall — fine because we emit *counts as evidence*,
  not redaction; "≈22 person names" is adequate where a card count would not be.
- **Secrets:** **vendor the `gitleaks` MIT rule catalog** (regex + entropy TOML) into the TS
  engine. Avoid trufflehog (AGPL + live-network verification) and ggshield (SaaS).
- **Optional Presidio sidecar** (local Docker REST or subprocess), auto-detected and used only
  when present, for the minority who need high-quality NER — keeps the bundled binary light.

Represent per tool as an **exposure record** (reach × evidenced → risk, via
`src/flows/scorer.ts` + `src/endpoint/scoring.ts` for grading consistency). Redaction level is
policy-driven, defaults to **counts-only**.

## 7. Snapshot format & signing

One schema-versioned JSON document per machine per run: host identity (hostname, OS, MDM
provider from `mdm-detect.ts`, hashed machine-id), sentinel/DB versions, footprint entries
(§5), exposure records (§6), governance verdict (§8), run metadata (timing/timeout/errors).
**Signed** (`src/inventory/sign.ts`) so the collector can trust snapshots weren't tampered in
transit; **content-addressed** (`src/inventory/differ.ts`) for machine-over-time and fleet
drift; size-bounded (evidence lists truncated, counts preserved). A **compact summary variant**
(grade + counts + top tools) is emitted separately for the ManageEngine script-output report
(§8).

## 8. Aggregation & transport — [REWRITTEN FROM RESEARCH]

**[CORRECTED] ManageEngine Endpoint Central has no native "pull this file from every machine to
the console."** "File Scan" only counts file *types*; "Remote File Transfer" is interactive and
per-machine. The whole first-draft "MDM collects `snapshot.json`" model was wrong. Corrected
design, dual-output:

- **Full snapshot + deltas → customer-hosted collector.** The resident daemon POSTs the signed
  snapshot — and subsequent **deltas** as the footprint changes — to a **small collector we
  ship** (writes to a directory; runs on a box the customer controls — no SaaS). (A one-shot
  `g0 sentinel scan` from an MDM-triggered script uses the same POST path.) Admin-side,
  `g0 fleet import <dir>` + an **HTML org inventory/exposure report** (reuse
  `src/platform/fleet.ts`). This is the demo — and because the daemon streams deltas, the report
  stays live without re-triggering. "Coverage becomes a state" comes from the collector diffing
  snapshots over time, so the change-stream holds whether the agent is hot-resident or scheduled.
- **Compact summary → ManageEngine's own console.** `g0 sentinel scan` also prints a compact
  summary to stdout; ManageEngine captures Custom Script output into its Execution-Status
  "Remarks" (exportable CSV/XLSX). Size-limited, so this carries only grade + counts + flags —
  giving native visibility inside the tool IT already lives in, without depending on it for the
  rich data.

**Why a collector and not an off-the-shelf fleet agent — [RESEARCHED].** We evaluated shipping
inside osquery/Fleet, Velociraptor, Wazuh, and GRR. Findings: don't rewrite detection into any
of them, and don't stand up a competing management plane. osquery's **ATC** could expose a g0
SQLite snapshot as tables with zero extension code, and **Fleet** (MIT core) would give rollup +
API + UI — but Fleet's own MDM overlaps the customer's ManageEngine, and ATC flattens
everything to strings (losing PII structure). **Velociraptor** (single static binary server, a
~30-line VQL artifact that `execve`s `g0 sentinel scan` and collects the JSON) is the best
off-the-shelf fallback **if the customer wants a fleet UI/API without us hosting anything** —
note its **AGPLv3 server** (running g0 as a subprocess does not taint g0; modifying and hosting
the Velociraptor server would trigger network-copyleft). **Decision:** because the customer
already runs ManageEngine (deploy + schedule + run-script), the genuinely missing piece is only
*aggregation/reporting* — so build the **thin collector + reuse `g0 fleet`**, and keep
Velociraptor as the documented alternative if they'd rather not host the collector.

## 9. Governance & enforcement (remove or enforce) — [ENACTMENT CORRECTED]

Two tiers matching "get rid of it **or** enforce a governance policy":

**Tier 1 — Policy verdict (report-only, ships in POC).** `guard0.policy.yaml` declares
allow/deny/monitor per tool category or specific tool. Every snapshot carries a per-tool
**compliance verdict**; the org report shows who's compliant. Safe default; satisfies "enforce a
governance policy" at the visibility level.

**Tier 2 — Remediation (guarded, opt-in).** Two enactment paths:

- **MDM-enacted (recommended).** **[CORRECTED]** ManageEngine *can* uninstall apps (Prohibited
  Software auto-uninstall), remove/block browser extensions (Add-on & Extension Control — really
  Chrome/Edge enterprise force-blocklist, so semantics = disabled/blocked, not guaranteed
  filesystem delete), and block executables (Application Control). **But these are separate ME
  policy objects, not a single JSON manifest ME ingests.** So g0 *decides and reports* the
  required action, and enactment is either an **operator translating it in the ME console** or
  an **ME REST API integration** (Endpoint Central REST API v1.4; on-prem token auth, cloud
  OAuth2 — validate the specific write endpoints exist before building on them). `g0 sentinel
  remediate --plan` emits the machine-readable action list that drives either path.
- **g0-enacted (opt-in, dry-run default).** Reuse the quarantine engine (`quarantine.ts`,
  `estate-quarantine.ts`) to neutralize known-malicious footprint directly, plus `g0 protect`
  for runtime enforcement (MCP proxy, Claude hooks) where the customer wants live blocking over
  removal. Never destructive without explicit policy opt-in; reversible; logged.

Model: **g0 decides; ManageEngine enforces by default; g0 enforces only where opted in.**

## 10. Language decision: TypeScript, not Rust — [STRENGTHENED BY RESEARCH]

The customer-relayed question was "should we write this in Rust for performance?" **No.**

- **The workload is I/O-bound** (file/process enumeration, config/JSON parsing, PII regex over
  local artifacts). Wall-clock is dominated by disk and process walking; Rust doesn't speed that
  up. The one CPU-heavy piece is tree-sitter parsing — **and after §4 that runs as WASM, whose
  perf profile is language-agnostic.**
- **The "small single binary" reason people reach for Rust is already solved** without leaving
  TS: web-tree-sitter removes the native dep, and Node SEA / Bun `--compile` produce one
  self-contained artifact (§4).
- **Rewriting discards the moat** — the tuned detection DB, classifiers, scoring, quarantine,
  flow analysis are thousands of lines of TS; a rewrite is months and two codebases forever,
  landing the POC late (contradicts decision 1).
- **Where perf actually bites, fix it locally in TS** (parallelize artifact scans, cap file
  sizes, skip binary blobs, cache by mtime). Sentinel runs on a schedule, not in the `g0 hook`
  p95<100ms hot path.
- **Revisit only on evidence:** if Phase-0 benchmarks show a specific hot loop blowing the
  runtime budget and unfixable in TS, port *that function* to a native addon — not the product.

**Conclusion: TypeScript + WASM tree-sitter + compiled single binary. Do not rewrite in Rust.**

## 11. Build phasing (~6 weeks to a converting demo)

macOS leads; Windows depth and signing are de-risked first because they are the long-poles.

- **Phase 0 — De-risk (week 1).** (a) Migrate tree-sitter → web-tree-sitter and **benchmark
  parse throughput** on the largest target repo. (b) Compile the binary (Node SEA; one-day Bun
  spike). (c) **Start EV Authenticode + Apple Developer ID Installer + notarization
  procurement** — the true critical path. (d) **Confirm the customer runs Endpoint Central (not
  MDM Plus)** and secure one Windows + one macOS pilot machine. *Demo: a signed snapshot JSON
  from a Mac + a green WASM benchmark.*
- **Phase 1 — Footprint inventory + collector + org report (weeks 2–3).** Endpoint-native
  discovery (§5) on macOS, snapshot signing (§7), the **thin collector** + `g0 fleet import` +
  **HTML org report** (§8), compact-summary stdout for ME. *Demo: push to a few Macs, snapshots
  land in the collector, one report shows every AI tool across machines.*
- **Phase 2 — PII exposure engine (weeks 3–4, overlaps).** OpenRedaction + compromise + gitleaks
  rules (§6), per-tool reach + evidenced exposure, redaction invariant enforced, risk roll-up.
  *Demo: the report shows "which AI tool can see what PII" per machine and fleet-wide.*
- **Phase 3 — Governance verdict + remediation (weeks 4–5).** `guard0.policy.yaml`, per-tool
  compliance verdict, `remediate --plan` action list + the ME-console/REST enactment path,
  opt-in g0-enacted quarantine (§9). *Demo: apply a policy, report flags non-compliant tools,
  produce a removal action list.*
- **Phase 4 — Windows depth + installer hardening (weeks 5–6).** Windows/Edge detection
  (registry, AppData, Outlook COM add-ins), signed MSI + Scheduled Task, ME Endpoint Central
  deployment guide, uninstall path. *Demo: the full loop on a Windows machine pushed through
  ManageEngine.*

**Day-1 critical path regardless of phase:** code-signing/notarization procurement; the
web-tree-sitter migration + benchmark; confirming Endpoint-Central-vs-MDM-Plus and the pilot
machines; and coordinating an **EDR/AV allowlist** for the resident daemon with the customer's
security team (a resident agent that reads browser profiles will otherwise be flagged).

## 12. Risk register — [UPDATED]

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Code-signing / Apple notarization procurement slips** (now the #1 risk) | Medium | High | Start day 1; unsigned exe (SmartScreen) / un-notarized pkg (Gatekeeper) will not deploy via MDM |
| Customer owns **MDM Plus, not Endpoint Central** (no script engine) | Medium | High | Confirm in Phase 0 before building; if MDM Plus only, transport/enactment options shrink drastically |
| **Resident daemon trips EDR/AV behavioral detection** (reads browser profiles + session logs + phones home) | Medium | High | Well-behaved posture (§3: targeted watches, not hot-watch); signed binary; coordinate an EDR/AV allowlist with the customer's security team in Phase 0; scan-and-report cadence, not constant profile reads |
| **Daemon lifecycle on a fleet** (crash / leak / needs restart / self-update hole) | Medium | Medium | Reuse `src/daemon/` runner + kill-switch + watchdog; per-scan bounded runtime; MDM health check via `sentinel status`; binary updates via MDM only, DB updates out-of-band (§4) |
| ManageEngine **can't pull files** (was the buried assumption) | — (resolved) | — | Corrected: ship a thin collector + compact-summary via script output (§8) |
| WASM tree-sitter too slow for large repos | Low | Medium | Phase-0 benchmark; scheduled not interactive; cap file sizes; native-addon fallback for one hot function only |
| Windows detection depth shallow today | High | Medium | Phase 4 planned, paths researched in Phase 0; macOS carries the first demo |
| Snapshot accidentally carries raw PII (now travels over HTTP) | Low | Critical | Hard invariant (§2): classes+counts+locator only; default counts-only; test asserts no raw values in snapshot or collector payload |
| ME REST API lacks the specific write endpoints for remediation | Medium | Medium | Verify endpoints in Phase 3; fall back to operator-in-console enactment; inventory+prohibited-software endpoints confirmed to exist |
| Over-promising OAuth/M365-web-add-in discovery as "endpoint" | Medium | Medium | Reframed as SaaS connectors (§5); don't sell them as endpoint features |
| Scope creep toward inline DLP/interception | Medium | High | Explicit non-goal (§2) |
| Collector becomes an unplanned server product | Low | Medium | Keep it a thin ingest-to-directory; reuse `g0 fleet`; Velociraptor documented as the off-the-shelf alternative |

## 13. What we reuse vs. build — [UPDATED]

**Reuse:** endpoint scanners, `mdm-detect.ts`, EDM/secret classifiers, `session-forensics.ts`,
flow scorer, `fleet.ts` roll-up, `inventory/sign.ts` + `differ.ts`, quarantine engines,
`protect`/enforcement.

**Adopt (OSS, license-checked):** `web-tree-sitter` + prebuilt grammar `.wasm` (parsing),
**OpenRedaction** (MIT, structured PII), **`compromise`** (MIT, names), **gitleaks** MIT rule
catalog (secrets), **crx-analyzer** permission→risk map, `mcp-scan` config-discovery logic as
cross-check. Optional **Presidio** sidecar.

**Build (new):** `g0 sentinel` mode; single-binary compile + MSI/PKG + scheduler registration;
`email-integration-scanner.ts` (Outlook COM add-ins) + Edge/Windows extension depth; per-tool
**exposure record** builder; machine **snapshot schema** + writer/signer + compact summary;
**thin collector** + `g0 fleet import` + HTML org report; `guard0.policy.yaml` schema +
per-tool verdict + `remediate --plan`; **ManageEngine Endpoint Central deployment guide**.
Post-POC: optional Google Admin SDK / MS Graph connectors for OAuth grants + M365 web add-ins.

## 14. Success criteria

The POC converts if, on the customer's own fleet:

1. A **signed** installer pushes through **Endpoint Central** (and, by the same MDM-agnostic
   shape, any of Jamf/Intune/Kandji/etc.) to Windows **and** macOS with no Node/system prerequisite.
2. Every machine reports its full endpoint-native AI footprint unattended, and the **resident
   daemon keeps it current** as the footprint changes (streamed deltas), without re-triggering.
3. Snapshots reach the **collector**; the admin sees **one org report** (every AI tool, per
   machine and fleet-wide, with per-tool PII exposure) without logging into any machine; a
   compact summary is also visible **inside ManageEngine**.
4. **No raw PII** appears in any snapshot, collector payload, or report.
5. Applying a governance policy flags non-compliant tools, and remediation
   (ME-enacted via console/REST, or opt-in g0-enacted quarantine) removes/enforces the
   footprint — with proof in the next report.

## 15. Open questions to confirm with the customer

1. **Endpoint Central vs. MDM Plus?** (Gates the entire script/transport/enactment design.)
2. Windows/macOS mix and two pilot machines?
3. Where can the **collector** run (a box they host), or do they prefer the Velociraptor path,
   or the ManageEngine script-output summary as the only rollup for the POC?
4. Do they want the SaaS connectors (OAuth grants via Google/M365 admin APIs) in scope later,
   or is endpoint-only sufficient for the buying decision?
5. **Which EDR/AV runs on the fleet** (CrowdStrike / SentinelOne / Defender / …)? A resident
   daemon that reads browser profiles needs an allowlist entry — who owns that, and how long
   does it take? (Gates whether daemon-first is viable or we start scheduled-only.)

## 16. Research sources (2026-07-23)

Five sourced research passes underpin the corrections above. Key sources:

- **ManageEngine:** Endpoint Central (ex-Desktop Central) vs. MDM Plus; Software Deployment
  (Win MSI / mac PKG/DMG); Script Repository + Custom Script; File Scan is type-census only;
  no native file-pull; Prohibited Software auto-uninstall; Browser Add-on & Extension Control;
  REST API v1.4. `manageengine.com/products/desktop-central/{help,api}/…`, `developer.apple.com/developer-id/`.
- **OSS fleet agents:** osquery (Apache-2/GPL-2, ATC, `chrome_extensions`/`programs`/`apps`
  tables), Fleet (MIT core + MDM), Velociraptor (AGPLv3, single-binary, VQL artifacts), Wazuh
  (GPLv2), GRR (Apache-2). `github.com/{osquery/osquery,fleetdm/fleet,Velocidex/velociraptor,wazuh/wazuh,google/grr}`.
- **PII/DLP:** Microsoft Presidio (MIT, Python/spaCy), OpenRedaction (MIT, TS, Luhn),
  `compromise` (MIT), gitleaks (MIT rules), trufflehog (AGPL — avoid), Google DLP (SaaS — out).
  `github.com/{microsoft/presidio,sam247/openredaction,spencermountain/compromise,gitleaks/gitleaks}`.
- **Packaging:** Node SEA (`nodejs.org/api/single-executable-applications.html`), Bun compile
  (`bun.com/docs/bundler/executables`; tree-sitter issues #7518/#30286), web-tree-sitter
  (`npmjs.com/package/web-tree-sitter`; prebuilt `github.com/sourcegraph/tree-sitter-wasms`),
  vercel/pkg archived, WiX v6 + OSMF (`docs.firegiant.com/wix`), GNOME msitools, Apple
  pkgbuild/productbuild/notarytool.
- **Shadow-AI landscape / discovery blocks:** Nudge, Harmonic, Lanai, Prompt Security,
  WitnessAI, Zscaler, Netskope, MS Defender/Purview, Wing, Grip (positioning); osquery
  extension tables, crx-analyzer (permission risk), mcp-scan (MCP config discovery), Outlook COM
  add-in registry keys (`learn.microsoft.com/.../state-of-com-add-ins`); OAuth grants + M365 web
  add-ins confirmed SaaS-admin-API, not endpoint.
