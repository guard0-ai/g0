# g0 protect — enforcement everywhere, continuously

- **Date:** 2026-07-21
- **Status:** Approved design, pre-implementation
- **Branch:** `feat/protect`
- **Drives:** issues #66 (daemon continuity/drift), #78 (Claude Code plugin — superseded in part by hooks), #118/#9/#13 (runtime enforcement, extended), #119 (ASPM), #131 (agentic browser, hardening layer only)

## 1. Context and goal

2.1.0 shipped `g0 check` (read: one-command background check of the machine's AI
estate) and `g0 proxy` (enforce: but only on the MCP-stdio path). The coverage
map after 2.1.0: discovery is broad, assessment is uneven, enforcement exists on
exactly one transport, and everything is point-in-time.

`g0 protect` is the write-side flagship that pairs with `g0 check`:

> **`g0 check` found it. `g0 protect` stops it — and keeps it stopped.**

One command that installs guardrails across the five surfaces the user named —
Claude (Code + Desktop), Codex, devtools (Cursor/Windsurf/VS Code), agentic
browsers, and the endpoint itself — and registers a resident watcher so the
protection stays true after the terminal closes.

### Decisions already made (do not relitigate)

1. **Story shape:** enforce-everywhere (`protect`) + continuous watch, chosen
   over instruction-supply-chain-only and per-surface-parity-only.
2. **Composition:** one flagship — `protect` includes watcher registration.
   Not two separate releases.
3. **Surfaces in scope:** all four (MCP clients, Claude Code hooks, Codex,
   browser hardening) plus the watcher.
4. **Architecture:** Approach 1 — *one enforcement engine, many adapters*.
   Extract the proxy's decision stack into a shared core; every surface is an
   adapter feeding the same engine. (Rejected: thin orchestrator with a second
   simpler rule-set for hooks — codepaths diverge; daemon-centric single
   resident process — blocks all value behind the hardest component.)

## 2. Non-goals

- **No result upload to the platform.** The platform ingests via its own CLI
  (standing constraint). The watcher never phones home; the daemon's vestigial
  `upload` config/flag is removed as part of Phase D.
- **No new scan rules engine.** `.claude/` supply-chain scanning and AGENTS.md
  scanning plug into the existing threat-feed/IOC and endpoint-scanner
  machinery, not a new engine.
- **No root/system-level agents.** Everything is per-user scope: user launchd
  agents, systemd *user* units, per-user scheduled tasks.
- **No VS Code extension (#80), no TUI (#117)** — still deprioritized.
- **Browser detection/assessment depth** stays with m13v's #131 work; we build
  only the hardening/remediation layer (see Phase E).

## 3. Command surface

```
g0 protect                    # dry-run (DEFAULT): full protection plan, per surface
g0 protect --apply            # execute the plan; byte-exact backup of every file touched
g0 protect --surfaces mcp,claude,codex,browser,watch    # limit to listed surfaces
g0 protect status             # per-surface protection state + watcher health
g0 protect off [--surfaces]   # undo from backups; removes watcher persistence
g0 hook <event>               # internal: Claude Code hook entrypoint (stdin JSON in, JSON out)
```

Safety grammar is inherited from `endpoint quarantine` (the established
convention): dry-run by default, `--apply` to commit, byte-exact backups,
refuse to restore over a config edited since backup unless `--force`.

`protect` (dry-run) prints a per-surface plan: what would be installed,
which files would be rewritten, what the diff looks like (config rewrites show
exact diffs), and which servers/skills match known-malicious indicators.

## 4. Architecture — enforcement engine extraction

### 4.1 What moves

The proxy's decision stack (today ~5.8k lines under `src/proxy/`) splits:

| Moves to `src/enforcement/` (shared core) | Stays in `src/proxy/` (transport) |
|---|---|
| `policy.ts` (DSL v2, zod) | `proxy-core.ts` (stdio piping) |
| `confidence.ts` (noisy-OR fusion) | `jsonrpc.ts` (framing) |
| `detectors/` (validator-gated secrets) | `installer.ts` (client config rewrite) |
| `edm.ts` (exact-data-match) | |
| shared JSONL audit writer (extracted from `audit-log.ts` → `src/enforcement/audit.ts`) | `audit-log.ts` (proxy file-location/rotation config, delegates to the shared writer) |
| `provenance.ts` (dataflow tagging) | |
| `injection-patterns.ts` | |
| `sensitive-read.ts` | |
| content checks from `response-inspector.ts` | JSON-RPC-specific plumbing of `response-inspector.ts` |

### 4.2 Neutral event model

```ts
// src/enforcement/types.ts
interface EnforcementEvent {
  transport: 'mcp-stdio' | 'claude-hook';   // extensible: 'codex-hook' later
  direction: 'request' | 'response';
  client: string;                            // e.g. 'claude-code', 'cursor'
  toolName: string;
  payload: unknown;                          // args (request) or result (response)
  sessionId: string;                         // provenance correlation key
}

interface Decision {
  action: 'deny' | 'redact' | 'coach' | 'alert' | 'allow';
  confidence: number;
  findings: Finding[];                       // existing finding shape
  redactedPayload?: unknown;                 // present when action === 'redact'
}
```

The engine is pure and in-process: `decide(event, policy, state): Decision`.
Session state (provenance tags, EDM index handle) lives in a small state object
owned by the caller — the proxy owns one per proxied server; the hook adapter
persists one per Claude session under `~/.g0/hook-state/<session>.json`
(hook invocations are separate processes, so provenance state must survive
process exit; see 6.1).

### 4.3 Regression bar

The proxy must behave **byte-identically** after extraction. The existing proxy
e2e suite is the regression harness and must pass unchanged. Public SDK exports
keep their current names/paths (re-export from new locations).

## 5. Phase A — the `protect` orchestrator

New `src/protect/`:

- `orchestrator.ts` — resolves surfaces, runs adapters, aggregates the plan /
  apply / status / undo results, renders reporter output.
- `adapter.ts` — the surface adapter interface:

```ts
interface ProtectAdapter {
  surface: 'mcp' | 'claude' | 'codex' | 'browser' | 'watch';
  plan(ctx): Promise<PlanStep[]>;       // dry-run: exact files + diffs + reasons
  apply(ctx): Promise<ApplyResult>;     // executes, records backups in manifest
  status(ctx): Promise<SurfaceStatus>;
  undo(ctx): Promise<UndoResult>;       // restores from manifest, --force semantics
}
```

- `backup-manifest.ts` — central manifest under
  `~/.g0/protect/backups/<timestamp>/manifest.json`: every file written, its
  pre-image (byte-exact copy), pre/post hashes. `undo` refuses to restore over
  a file whose current hash matches neither pre nor post image unless `--force`.
- `src/cli/commands/protect.ts` — command registration (same pattern as
  `check.ts` / `endpoint.ts`).

**Phase A adapters wire what already exists:**

- `mcp` adapter → `proxy install` (existing installer: Claude Code, Claude
  Desktop, Cursor, Windsurf) + `endpoint quarantine` IOC matching (`--apply`
  removes known-malicious servers).
- OpenClaw hardening → existing `openclaw-config-hardener.ts` becomes part of
  the `mcp` adapter's plan.

Phase A ships user value on day one (one command instead of three) and creates
the chassis every later phase slots into.

## 6. Phase B — Claude Code adapter (the headline)

### 6.1 Runtime hooks

- `protect --apply --surfaces claude` writes PreToolUse + PostToolUse hooks
  into `~/.claude/settings.json` (user scope; file backed up via manifest).
  The hook command is `g0 hook pretooluse` / `g0 hook posttooluse`.
- `g0 hook` reads the Claude Code hook JSON on stdin, maps it to an
  `EnforcementEvent` (`transport: 'claude-hook'`, tool name/input from the
  event, session id from the hook payload), calls the engine, and answers:

| Engine action | Hook response |
|---|---|
| `deny` | `permissionDecision: "deny"` + reason (finding summary + rule id) |
| `redact` | `permissionDecision: "ask"` + reason explaining what would be redacted (hooks cannot mutate payloads in v1) |
| `coach` | `permissionDecision: "ask"` + coaching text |
| `alert` | allow + audit-log entry |
| `allow` | allow (empty output) |

- **PostToolUse** feeds tool *results* through the engine for
  response-injection detection and provenance tagging (data seen in tool A's
  response → flagged when it reappears in tool B's request args on a later
  PreToolUse — the confused-deputy pattern, now inside Claude Code).
- **Session state:** provenance tags persist under
  `~/.g0/hook-state/<sessionId>.json` (hook calls are separate processes).
  State files are pruned by age (>24h) on each invocation.
- **Fail-open, hard requirement:** any error — engine crash, malformed stdin,
  missing policy, state-file corruption — exits 0 with allow. A g0 bug must
  never break a user's Claude Code session. Same guarantee the proxy makes.
- **Latency budget: p95 < 100ms** per invocation. Engine is in-process and
  local; EDM index is loaded from its on-disk form (already a bloom filter +
  hashes, no rebuild); policy parse is cached to `~/.g0/hook-state/` keyed by
  policy file hash. A latency test enforces the budget in CI.
- **What this catches that the MCP proxy cannot:** Bash commands, file writes,
  WebFetch exfil — the built-in (non-MCP) tools where real damage happens.
  (Verified 2026-07-21: every examined MCP-layer competitor — agentgateway,
  mcp-context-protector, open-edison — architecturally cannot see these; the
  only hook-based prior art is three dormant 2–4-star single-author repos.)
- **Hardening requirements (from documented prior-art pitfalls):**
  - *Canonicalization pre-pass* in the engine (Unicode NFKC + zero-width
    strip) before detectors run, on both transports — the hook micro-projects
    self-document regex bypass via payload encoding as their top weakness.
    Lands in the Phase B train, NOT the Phase A extraction (byte-identical bar).
  - *Default shipped hook policy is coach-first*: `deny` reserved for
    known-malicious IOC matches, EDM hits (0.99), and high-confidence
    dataflow exfil; everything else coaches/alerts. Alert fatigue is Trail of
    Bits' own documented failure mode for this product class — a guard users
    uninstall protects nobody.
  - *`onError: open | closed`* policy knob on the hook path (same grammar the
    proxy already has). Fail-open stays the default; hardened setups can opt
    into fail-closed. Every hook error is audited and counted.
  - *Execution-verification backstop*: after a `deny`, a cheap post-hoc check
    (did git HEAD move / target file mtime change?) alerts loudly if a denied
    action left effects anyway — detection only, never auto-revert. Motivated
    by anthropics/claude-code#20946 (unconfirmed deny race under
    `--dangerously-skip-permissions`; generalized bypass claim refuted 0-3).
  - *Hook health surfaced*: `protect status` shows hook error rate, last
    invocation, and latency p95; the Phase D watcher alerts on error-rate
    spikes (bypass-by-induced-error presents as an error spike).
  - The p95 < 100ms budget is a hard CI gate: one dispatch process,
    in-process engine, no per-guard process spawning (a documented complaint
    against an 11-hook stack was ~13s added per interaction).

### 6.2 `.claude/` supply-chain scanning

New `src/endpoint/claude-estate-scanner.ts`, same shape as the existing
endpoint scanners:

- **Enumerates:** skills (`~/.claude/skills`, plugin cache dirs), plugins,
  hooks declared in settings files (including the commands they run),
  subagents (`.claude/agents/*.md`), Claude Desktop extensions, MCP configs
  (already covered — cross-referenced, not duplicated).
- **Checks:** threat-feed IOC matching (ClawHavoc-style indicators already flow
  through the multi-ecosystem feed) + static heuristics: obfuscated shell in
  hook commands, `curl | bash` patterns, exfil primitives in skill bodies,
  frontmatter that triggers on secrets-adjacent contexts.
- **Feeds:** `g0 check` grading (a malicious skill caps the machine grade at F,
  existing convention), `endpoint quarantine` matching (a matched skill can be
  quarantined with the same backup/undo semantics), and the Phase D watcher.

### 6.3 MCP tool/config pinning in the proxy (Phase B train)

Trust-on-first-use pinning of what each proxied server *claims to be*: hash
the server's tool list, tool descriptions, and instructions at
`initialize`/`tools/list`; on drift, take a policy action (`alert` default,
`deny` opt-in) until re-approved via `g0 proxy review-server`. Re-approval
matching is **semantic** (normalized tool-list hash), not exact command
strings — the exact-string friction is mcp-context-protector's documented
weakness. Prior art credit where due: Trail of Bits shipped TOFU pinning in
July 2025; ours differs by being policy-integrated (confidence/audit path)
and part of one-command protect. Ships in the 2.2.0 train, independent of
hooks.

## 7. Phase C — Codex first-class

Codex appears **nowhere** in `src/` today (verified 2026-07-21). Competitive
scope note: snyk/agent-scan already *discovers* Codex (skills/servers in its
supported-agents table) — our differentiation is **assessment + hardening +
enforcement + proxy routing + instruction-file scanning**, none of which any
examined project ships for Codex; claims must be scoped accordingly. Work:

- **Fingerprints:** `process-detector.ts` entry (`codex`, `@openai/codex`),
  `sensitive-paths.ts` (`~/.codex/auth.json`), artifact/forensics entries.
- **Config assessment:** parse `~/.codex/config.toml` — flag
  `approval_policy = "never"`, sandbox disabled, `--dangerously-*`-style
  bypass settings; enumerate `[mcp_servers.*]` and assess those servers with
  the same MCP assessment path as every other client.
- **Proxy routing:** `installer.ts` gains TOML config support (add a TOML
  parser dependency — `smol-toml` or equivalent, license-checked) so Codex's
  MCP servers route through `g0 proxy` like JSON-config clients. Rewrites
  preserve comments/layout if the chosen parser supports it; if not, the plan
  output shows the exact resulting file and the manifest backup covers undo.
- **Instruction-file scanning:** one rule pack, category `instruction-files`,
  scanning **AGENTS.md, CLAUDE.md, and `.cursorrules`** for injected
  instructions (exfil directives, tool-permission escalation, hidden-text
  encodings). Runs in `scan` (repo context) and `check` (home-dir context).
  This deliberately seeds the instruction-supply-chain story across all
  clients with one pack.
- **`codex` protect adapter:** hardening = proposed `config.toml` diff
  (dry-run shows it; `--apply` writes with backup).

## 8. Phase D — the watcher

Builds on the existing `src/daemon/` scaffold (config, logger, fork/pid
management, runner, alerter, notification-manager, kill-switch,
openclaw-drift, agent-watchers) — no new daemon.

Competitive framing (2026-07-21): among examined projects, the only resident
capability is agent-scan's "Background Mode" — MDM telemetry reporting into
Snyk's commercial Evo. A **local-first** watcher (OS notifications,
opt-in auto-quarantine, full undo, nothing leaves the machine) has no
examined overlap; phrase any open-field claim as "among projects examined."

- **New watch sources** (fs-watch, debounced): MCP config paths for all known
  clients, `~/.claude` (settings/skills/plugins/agents), `~/.codex`, OpenClaw
  skills dir, agentic-browser extension dirs.
- **On change:** targeted re-check of the touched surface (reuse
  `src/check/runner.ts` subsets — the runner gains a `surfaces` filter).
- **Sweep:** periodic full `check`, honoring the daemon config's existing
  `intervalMinutes` (current default: 30).
- **Actions:** `observe` (default) — audit log + OS notification via the
  existing notification-manager. `enforce` (opt-in flag in daemon config) —
  auto-quarantine known-malicious matches through the same quarantine path,
  backups included. Nothing beyond known-malicious is ever auto-removed.
- **Persistence:** `protect --apply --surfaces watch` registers per-user
  autostart: launchd agent plist (macOS), systemd user unit (Linux), scheduled
  task (Windows). `protect off` deregisters and stops the process.
  `protect status` shows watcher liveness (pid, last sweep, last event).
- **Network:** the watcher performs **no network calls** except the existing
  fail-open threat-feed refresh. The daemon's `upload` config key and
  `--no-upload` flag are **removed**: verified 2026-07-21 that the key is dead
  code — defaulted `true` in `src/daemon/config.ts` but consumed nowhere — so
  no upload has ever occurred and removal changes no behavior (changelog note
  only).

## 9. Phase E — browser hardening

- **Step 0 (before any code):** comment on #131 proposing the scope split —
  m13v continues detection/assessment depth; core adds a
  hardening/remediation layer consuming their detection output. Wait for ack;
  if no response in ~2 weeks, proceed on the hardening layer only, still
  consuming the existing `agentic-browser-scanner.ts` interface.
- **Hardening checks:** risky AI browser extensions → finding + uninstall
  guidance; agentic-browser settings audits where config files are reachable
  on disk (Atlas/Comet/Dia app-config paths); sensitive-path exposure
  (browser agent profile dirs intersecting `~/.ssh`, `.env` locations).
- **Apply policy:** auto-apply **only** where a byte-exact file backup is
  possible (config files). Extension removal and app settings that live in
  opaque stores are report + guided-fix, never auto-applied.

## 10. Safety invariants (all phases, non-negotiable)

1. **Fail-open on every runtime path.** Hook errors → allow. Proxy errors →
   forward unmodified. Watcher errors → log and continue. A g0 defect must
   never break a scan, a session, or a machine.
2. **Dry-run before every write.** Anything that writes shows the plan first;
   `--apply` is always explicit.
3. **Every write is undoable.** Byte-exact backups in the manifest;
   `protect off` restores; hash-mismatch refuses without `--force`.
4. **No network on scan/enforce paths.** Platform reads stay sync +
   never-throw (existing constraint); feed refresh stays fail-open; watcher
   never uploads.
5. **Per-user scope only.** No root, no system daemons, no other users' files.

## 11. Error handling

- **Malformed hook input:** allow + one-line stderr warning + audit entry.
- **Policy file invalid:** engine falls back to safe observe-mode defaults
  (existing DSL v2 behavior) — never "invalid policy = no protection silently";
  `protect status` surfaces the fallback loudly.
- **Backup manifest corrupt at `undo`:** refuse, print recovery instructions
  pointing at the raw backup dir (pre-images are plain files, restorable by
  hand).
- **Watcher crash-loop:** existing kill-switch semantics; `protect status`
  reports unhealthy + last error; autostart backs off (platform-native:
  launchd throttling / systemd `RestartSec`).
- **Partial `--apply` failure:** adapters are independent; a failed surface
  reports and does not roll back succeeded surfaces; the manifest records
  exactly what was applied so `off` is accurate.

## 12. Testing strategy

- **Engine extraction:** existing proxy e2e suite passes unchanged — the
  regression harness for byte-identical proxy behavior.
- **Hook adapter:** golden-file tests (recorded Claude Code hook JSON in →
  expected JSON out) per action; e2e via a scripted fake client invoking the
  real `g0 hook` binary; fail-open tests (garbage stdin, missing state,
  crashed engine → exit 0 allow); latency test enforcing p95 < 100ms;
  canonicalization corpus (encoded/zero-width/homoglyph payload variants must
  still match); a sandboxed CI e2e verifying `deny` holds under
  `--dangerously-skip-permissions` (the #20946 failure class) — run only in
  an isolated CI sandbox, never on a developer machine.
- **Orchestrator:** sandboxed-HOME e2e (same technique as `assets/demo.tape`):
  seed a fake estate → `protect` plan snapshot → `--apply` → assert configs
  rewritten + manifest complete → `off` → assert HOME byte-identical.
- **Codex:** fixture corpus of `config.toml` variants + AGENTS.md
  injection/benign pairs; TOML rewrite round-trip tests.
- **Watcher:** fs-watch integration tests against temp dirs (touch a config →
  targeted re-check fires); service-registration smoke tests gated per-OS in
  CI.
- **Instruction-file pack:** benign corpus (real-world CLAUDE.md/AGENTS.md
  samples) as the false-positive gate.

## 13. Release plan and narrative

- **2.2.0 = Phases A + B** (orchestrator + Claude hooks + `.claude/`
  supply-chain scanning). Headline: *"g0 check found it. g0 protect stops
  it."* Demo GIF: install a malicious skill → `check` flags F → `protect
  --apply` → re-install attempt denied live by the hook, notification fires.
- **2.2.x = Phase C** (Codex) and **Phase D** (watcher) as they land.
- **2.3 = Phase E** once #131 coordination resolves.
- Each phase is its own PR train off `feat/protect` (or stacked PRs, matching
  the #162/#163 precedent).
- CTA moments (existing frequency-capped system): `protect status` across a
  fleet → platform; watcher drift events → platform. No new CTA machinery.

## 14. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Engine extraction destabilizes the proxy | e2e suite as hard regression bar; extraction is its own PR, no behavior changes allowed in it |
| Hook latency annoys users → they uninstall | p95 budget in CI; `alert`-only default policy option; `protect off` is one command |
| Hook JSON contract drifts with Claude Code releases | golden files versioned; contract checked in e2e against the documented hook schema; fail-open means drift degrades to allow, never breakage |
| Auto-enforce quarantines a false positive | enforce mode is opt-in; only known-malicious IOC matches (same bar as quarantine today); backups + undo |
| TOML rewrite mangles Codex configs | round-trip tests; dry-run shows exact resulting file; manifest backup |
| Steamrolling m13v on #131 | scope comment first, 2-week window, consume their interfaces |
| Hook deny race under bypass-permissions (#20946, unconfirmed) | sandboxed dsp e2e test + post-hoc execution-verification backstop |
| False comparative claims (field has real enforcers) | §15 positioning rules; refresh competitor facts before any published comparison |

## 15. Competitive positioning (verified 2026-07-21, deep-research + first-hand corroboration)

The enforcement field is real; the breadth is not. Verified landscape:
**agentgateway** (Linux Foundation, ~4k stars, very active) enforces
deny-by-default CEL authz + inline Reject/Mask guardrails — infra-tier
(K8s/standalone gateway), no one-command client hardening, no quarantine, no
watcher. **mcp-context-protector** (Trail of Bits) enforces TOFU config
pinning + opt-in response quarantine across stdio/HTTP/SSE for six clients —
substantive development stalled Aug 2025; self-documents no-conversation-
context and alert-fatigue limits. **open-edison** enforces session-level
data-flow ACLs (SecurityError on write-downgrade) — HTTP-only client surface,
at the staleness boundary. **Hook prior art**: three dormant 2–4-star repos
prove feasibility (one layers macOS `sandbox-exec`); none has install/undo,
MCP coverage, or maintenance. **snyk/agent-scan**: discovers Codex; scan-only
(Scan Mode + commercial Background Mode); its proxy enforce-vs-detect status
is UNRESOLVED — do not characterize it either way without hands-on re-test.

**Never-claim rules (marketing + docs):**
1. Never "first/only enforcing MCP proxy" — agentgateway, ToB, open-edison enforce.
2. Never claim quarantine or config-pinning as g0-unique — ToB prior art, July 2025.
3. Never call agent-scan scan-only-in-proxy or enforcing — unresolved; re-verify hands-on first.
4. Scope Codex claims to hardening/enforcement/routing/instruction-files (agent-scan discovers Codex).
5. Phrase open-field claims (browser, watcher) as "among projects examined as of 2026-07-21"; refresh before publishing.

**What we uniquely bundle** (the honest pitch): one command, five surfaces,
byte-exact undo, built-in-tool coverage via hooks, Codex hardening,
instruction-file scanning, local-first resident watch — plus the existing
scan/red-team/AI-BOM estate. Differentiate on the bundle and the safety
grammar, not on inventing categories others already ship.

**Backlog (explicit 2.2.0 non-goals), from converged table stakes:**
- *Pluggable guardrail-provider interface* (LlamaFirewall-class, moderation
  APIs): all three enforcing peers ship one. Constraint: enforce-path
  providers must be local-only (no-network invariant); remote providers are
  opt-in, fail-open, and audit/PostToolUse-side only. Design rides the
  existing policy-DSL `detectors` seam.
- *Session-level data-flow ACLs* (open-edison's PUBLIC/PRIVATE/SECRET model)
  as a policy-DSL extension over our provenance tracker.
- Infra-tier features (JWT/RBAC/K8s gateway) remain permanent non-goals —
  agentgateway owns that lane; ours is the developer machine.
