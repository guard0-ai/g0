# g0 v2 — Definitive Product Spec (DRAFT / working doc)

> Status: **DRAFT** — strategy + engineering spec for the definitive version of g0.
> This is a working document, not final docs. Grounded in the current codebase
> (`src/`) as of v2.0.0.

## Build status (branch: docs/vision-v2-draft)

Shipped and validated end-to-end on public repos (crewAI-examples, OpenAI
Agents SDK) with tests:

- ✅ **Foundation — scoring cap.** Criticals can no longer present as a healthy
  grade (`src/scoring/engine.ts`). 16 criticals now → F, not B.
- ✅ **Foundation — real discovery.** `filterTestFiles` judged paths absolutely,
  so scanning any project under a `tests/`-like path found nothing. Fixed to be
  scan-root-relative (`src/discovery/graph.ts`).
- ✅ **Foundation — diff-based gate.** `--write-baseline` / `--baseline`
  regression mode fails only on new findings (`src/ci/baseline.ts`).
- ✅ **Pillar 2 — generalized threat feed.** Multi-ecosystem, pluggable sources,
  package matching (`src/intelligence/cve-feed.ts`); fixes a CVE false-positive
  in the pipeline.
- ✅ **Pillar 3 — signed CycloneDX AI-BOM.** `inventory --cyclonedx --sign-key`
  with content-addressed hash + ed25519 signature (`src/inventory/{cyclonedx,sign}.ts`).
- ✅ **Pillar 5 — attestation packs.** `g0 attest` produces signed,
  standards-mapped evidence packs and persists evidence records
  (`src/governance/attestation.ts`, wires up `evidence-collector.ts`).
- ✅ **Waivers + honest coverage.** Expired/expiring waivers surfaced; scan
  reports a "Coverage Gaps" section of un-analyzable files.
- ✅ **Pillar 4 — fleet control plane.** `g0 fleet scan/status/list/drift`:
  local-first estate roll-up across repos and machines, keyed by git remote +
  sub-path, with per-asset drift over time (`src/platform/fleet.ts`).

Remaining (larger, not in this branch): fleet cloud sync + dashboards (the paid
platform layer this feeds), GitHub App / IDE surfaces (Pillar 6). Runtime
enforcement proxy (Pillar 1) is intentionally out of scope — not needed.

---

## 0. North star

g0 becomes the **system of record for "can we trust this agent?"** across its
whole life — from a developer's laptop, through CI, into production, and out to
the auditor.

The background-check metaphor completes: g0 doesn't just run a one-time check, it
**issues and continuously re-validates the clearance.**

The defensible edge against free MCP scanners (Cisco MCP Scanner, Tencent
AI-Infra-Guard, Snyk ToxicSkills) is **not more rules** — it's owning the
*continuity and accountability*: the estate-wide picture, the living threat feed,
and the signed evidence trail. Point scanners structurally cannot produce those.

### Positioning shift

- **From:** "the OpenClaw security tool."
- **To:** "the agent & MCP supply-chain + posture security platform" — OpenClaw is
  one covered ecosystem among many.

Rationale: the acute OpenClaw/ClawHavoc wave crested Feb–March 2026; by mid-2026
it is a chronic concern, and the differentiators (MCP scanning, skill auditing)
are being commoditized by big-co open-source drops. The durable market is
agentic + MCP supply-chain security broadly (MCP: ~97M monthly SDK downloads,
10k+ public servers).

---

## 1. The spine: one lifecycle, not six commands

Today g0 ships six largely disconnected commands. v2 wires them into one loop
where each stage feeds the next:

```
Discover → Assess → Test → Enforce → Monitor → Attest
```

| Stage | Today | Module(s) | Gap to close |
|-------|-------|-----------|--------------|
| Discover | `inventory`/`discovery` returns `Agents: 0, Tools: 0` on real agents | `src/discovery`, `src/inventory` | Make AI-BOM real + signed |
| Assess | 1,180 rules; 16 crit → "B"; 57 findings on 2 files | `src/analyzers`, `src/scoring` | Calibrate, dedupe, reachability-first |
| Test | 1,200 payloads, `--auto` targeting | `src/testing` | Auto-target from discover output |
| Enforce | only a doc (Tetragon/Falco) | — (new) | **Runtime guardrail — missing leg** |
| Monitor | daemon + OpenClaw-only feed | `src/daemon`, `src/intelligence` | Generalize feed; fleet-wide |
| Attest | evidence-collector skeleton | `src/governance`, `src/standards` | **Productize — the moat** |

**Structural change for v2:** ship *one loop* where discover feeds assess feeds
test feeds a signed record — not six standalone tools.

---

## 2. Foundation fixes (prerequisites — must land before anything else)

The score is the product. Until it's trustworthy, nothing else matters.

### 2.1 Critical-caps-grade
- **File:** `src/scoring/engine.ts`, `src/scoring/grades.ts`
- **Problem:** per-domain scores floor at 0 then weighted-average against domains
  sitting at 100, so 16 CRITICAL findings → overall "B / 84".
- **Fix:** any unresolved CRITICAL hard-caps the grade (e.g. 1 crit → max D;
  3+ crit → F). Apply after `calculateScore` computes `overall`.
- **Size:** ~20 lines. Highest-leverage change in the repo.

### 2.2 Real discovery / AI-BOM
- **File:** `src/discovery`, `src/inventory`, unify with `src/analyzers/ast`
- **Problem:** `create_react_agent`, `AgentExecutor`, `@tool`, `ShellTool` present
  but reported as `Agents: 0, Tools: 0`. openai fixture → `0/0/0`.
- **Hypothesis:** inventory extractor is a separate, thinner code path than the
  AST analyzer (which already does reachability/taint/cross-file-exfil). Unify.
- **Acceptance:** every fixture in `tests/fixtures/*` reports non-zero, correct
  agent/tool/model counts.

### 2.3 Noise + baseline
- High-confidence findings by default; `--min-confidence low` opt-in (already
  partially there).
- Dedupe adjacent/duplicate findings (multiple `eval`/`subprocess` on nearby lines).
- **Diff-gating:** `g0 gate` fails only on findings *introduced by this change* —
  baseline existing debt. Without this, first-run's 57 findings → teams add
  `continue-on-error` and the gate is dead.

---

## 3. The six pillars to ADD (v-final)

### Pillar 1 — Runtime enforcement (the missing third leg)
- **New module:** `src/runtime/` (proxy/gateway)
- **Reuse:** `src/ai/provider.ts`, `src/ai/consensus.ts` (LLM judge),
  `docs/enforcement-integrations.md`
- A lightweight proxy in front of the agent's model + tool calls that **enforces
  the policy g0 already knows**: block prompt injection, PII exfil, unapproved
  tool calls, MCP calls to un-trusted servers.
- Closes the loop: `scan` finds → `test` proves → **runtime blocks** → block
  becomes evidence.
- Biggest platform upsell; competes with Lakera / Prompt Security / General Analysis.

### Pillar 2 — Generalize the threat feed beyond OpenClaw
- **File:** `src/intelligence/cve-feed.ts`, `src/intelligence/ioc-database.ts`
- **Problem:** hardwired to `openclaw.ai/security/advisories/feed.json` + hardcoded
  CVEs.
- **Change:** multi-ecosystem, auto-updating intel — MCP servers, ClawHub/skills.sh
  skills, model weights, npm/PyPI AI packages, CVEs across all frameworks.
- Converts g0 from point-in-time to living. Clean free→paid line (basic feed free;
  real-time + private IOC matching paid). Recurring reason to stay installed.

### Pillar 3 — AI-BOM as a signed, standard, diffable artifact
- **File:** `src/inventory`, `src/reporters`
- Emit **CycloneDX ML-BOM / SPDX-AI-compatible**, **sigstore-signed** document
  that diffs across releases.
- Goal: "send me your g0 AI-BOM" becomes a procurement/vendor-risk request (like
  SBOMs). Owning the *interchange format* is a moat a scanner can't copy.
- Forces discovery (Pillar 2.2) to be complete enough to sign.

### Pillar 4 — Fleet / estate control plane
- **Seeds:** `src/platform/machine-id.ts`, `src/platform/types.ts`,
  `src/remote/clone.ts`
- From single-repo/single-machine → **org-wide continuous inventory**: every agent,
  MCP server, model, dev tool across repos + laptops + CI + prod, with ownership,
  drift detection, trend.
- Extends `endpoint` (already the best zero-config demo — finds shadow Ollama,
  hardcoded MCP secrets in seconds).
- Cisco scans a target; g0 knows the *whole estate and how it changes*. Paid
  platform; most defensible surface.

### Pillar 5 — Attestation & evidence (productize the compliance moat)
- **File:** `src/governance/evidence-collector.ts` (already hashes + maps
  standards), `src/standards/*` (10 frameworks already mapped)
- Finish into **auto-generated, signed audit-evidence packs**: "EU AI Act Art. 15
  evidence for agent X", "ISO 42001 control coverage", continuously collected,
  timestamped, exportable.
- Scanners find issues; they don't write the regulator's evidence binder. Least
  copyable thing here → enterprise contracts.

### Pillar 6 — Fix loop + developer-native surfaces
- `g0 scan --fix` for mechanical remediations (extend the `endpoint --fix` ethos).
- **GitHub App:** PR annotations + auto-open fix PRs.
- **IDE extension** (VS Code/Cursor): flag unsafe tool definitions *as you type*.
  The daemon already watches folders — IDE is the natural next surface and the
  path into the daily dev loop ("defacto" = daily loop).

### Smaller high-leverage additions
- **Waiver/exception workflow** in policy-as-code (`src/governance/policy-engine.ts`):
  time-boxed exceptions with approver + expiry. Enterprises won't adopt a gate
  without it.
- **Honest coverage reporting:** surface `analyzability` (`src/analyzers/analyzability.ts`)
  prominently — "here's what g0 could NOT analyze." Trust comes from admitting
  blind spots.

---

## 4. Product / business layering

| Layer | Contents | Pricing |
|-------|----------|---------|
| **OSS core** | discover, assess, test, gate, endpoint, MCP | Free, viral — top of funnel. Lead with endpoint/MCP, not OpenClaw |
| **Feed** | generalized threat intel | Freemium (basic free, real-time/private paid) |
| **Platform** | fleet control plane, continuous monitoring, attestation packs, runtime enforcement, PR bot, dashboards | Paid |
| **Standard** | signed AI-BOM schema | Open, owned — give away to drive adoption |

---

## 5. What to cut / demote

- Pull the ClawHavoc panic banner off the top of the README; demote OpenClaw to
  one covered ecosystem.
- Kill hardcoded threat numbers ("1,184 IOCs / 2 CVEs") — the feed replaces them;
  already stale against 138+ CVEs.
- Curate the 1,180 regex rules toward a high-signal, reachability-weighted core.
  Rule *count* is a vanity metric competitors match in a weekend; signal-to-noise
  retains users.
- Consider collapsing six top-level commands into `g0` (smart default: detects
  repo vs machine vs URL) + subcommands — one obvious front door.

---

## 6. Sequence (don't boil the ocean)

1. **Trust (weeks):** scoring cap, discovery accuracy, dedupe, diff-gating.
   Nothing else matters until the number is believable.
2. **Re-anchor (weeks):** generalize the feed, lead with endpoint/MCP, signed
   AI-BOM v1.
3. **Loop (1–2 months):** GitHub App + `--fix` + IDE extension — daily dev flow.
4. **Moat (quarter):** fleet control plane + attestation packs — paid platform.
5. **Enforce (quarter+):** runtime guardrail proxy — third leg, biggest upsell.

**Through-line:** the hard, defensible parts are already scaffolded (feed,
evidence, fleet identity, LLM judge). v2 is finishing those skeletons,
generalizing them past OpenClaw, and wiring the six commands into one
discover→enforce→attest loop — so g0 stops being "a scanner" and becomes the
continuous trust record for an org's entire agent estate.

---

## Appendix A — Existing scaffolding referenced

| Capability | File | State |
|------------|------|-------|
| CVE/advisory feed | `src/intelligence/cve-feed.ts` | Skeleton, OpenClaw-only, hardcoded fallback |
| IOC database | `src/intelligence/ioc-database.ts` | Present |
| Evidence collection | `src/governance/evidence-collector.ts` | sha256 + standards mapping present |
| Policy engine | `src/governance/policy-engine.ts` | Present (387 lines) |
| Standards mapping | `src/standards/*` | 10 frameworks mapped |
| Machine/fleet identity | `src/platform/machine-id.ts`, `types.ts` | Seeds |
| Remote repo scan | `src/remote/clone.ts` | Present |
| LLM meta-analysis + judge | `src/ai/*` | analyzer, consensus, meta-analyzer, provider |
| Advanced static analysis | `src/analyzers/*` | reachability, pipeline-taint, cross-file-exfil, analyzability |
| Scoring | `src/scoring/engine.ts`, `grades.ts` | Needs critical-cap |
