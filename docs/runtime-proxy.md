# Runtime Proxy (`g0 proxy`)

`g0 proxy` is a policy-enforcing man-in-the-middle for MCP (Model Context
Protocol) servers. It sits between your IDE/agent client and a real MCP
server on stdio, inspects every request and response as newline-delimited
JSON-RPC traffic flows through, and allows, alerts on, redacts, coaches, or
denies each message according to a policy file.

```
client (IDE/agent)  <->  g0 proxy  <->  spawned real MCP server
       stdin/stdout                        child stdin/stdout
```

This document covers:

- the policy file itself (v1, and the v2 DSL added by this task)
- the confidence model that drives v2's decisions
- how to fingerprint data for Exact-Data-Match (EDM)
- the CLI surface

## Quick start

```
g0 proxy install                    # rewrite IDE/agent configs to route through g0 proxy
g0 proxy policy init                # write a default (observe-mode) policy file
g0 proxy status                     # show installed wraps + recent activity
g0 proxy logs --tail 50             # show recent audit records
g0 proxy fingerprint corpus.txt --name prod-secrets   # build an EDM index (see below)
```

Policy and fingerprint state live under `~/.g0/proxy/` by default
(`--policy-dir` overrides this for every subcommand):

```
~/.g0/proxy/policy.yaml              # global policy
~/.g0/proxy/policies/<server>.yaml   # per-server override, merged over the global policy
~/.g0/proxy/fingerprints/*.jsonl     # EDM indexes (see g0 proxy fingerprint)
~/.g0/proxy/logs/<server>/*.jsonl    # audit log, one JSON record per line
```

## Modes and actions

Every policy has a `mode`:

| Mode | Behavior |
|---|---|
| `observe` (default) | Log-only. Every decision is downgraded to `alert`; nothing is ever blocked. |
| `alert` | A rule's own `deny` is downgraded to `coach` — a loud, forwarded warning. Nothing is blocked. |
| `enforce` | Rules are honored as written: `deny` actually blocks, `redact` actually redacts. |

A decision's action is one of, in blocking-strength order:

```
deny > redact > coach > alert > allow
```

- **`allow`** — forward unmodified, no diagnostic.
- **`alert`** — forward unmodified, log-only.
- **`coach`** — forward unmodified, but with a loud `stderr` warning: "this
  would have been denied in enforce mode." Never blocks, never mutates the
  message. This is what `alert`-mode downgrades a would-be `deny` into.
- **`redact`** — forward the message with sensitive spans replaced by
  `[g0:redacted]`.
- **`deny`** — block the message. A denied request gets a synthesized
  JSON-RPC error back to the client instead of reaching the server; a denied
  response gets a synthesized "blocked by policy" tool result instead of
  reaching the client.

## v1 policy (unchanged, still fully supported)

A policy file with `version: 1`, or **no `version:` key at all**, is a v1
policy. Every v1 file that worked before this task continues to compile and
evaluate through the exact same code path, producing byte-identical
decisions — v2 is purely additive and opt-in.

```yaml
mode: enforce          # observe (default) | alert | enforce
onError: open           # open (default) | closed — what to do on an internal error
limits:
  maxScanBytes: 1048576 # scan budget for response inspection / EDM / dataflow
response:
  redactSecrets: false  # redact detected secrets in tool responses
  injection: alert       # off | alert | deny — what to do on injection/IOC findings
rules:
  - id: block-destructive-commands
    direction: request      # request (default) | response
    tools: ["execute_command", "run_*", "*shell*"]   # glob(s); omitted/empty = all tools
    argsRegex: '(rm\s+-rf\s+/|mkfs)'                 # tested against JSON-stringified args
    pathArgs: ["path"]                                # optional: path-arg allowlist check
    allowPaths: ["~/projects/**", "/tmp/**"]
    action: deny             # allow | deny | alert
    message: "Blocked by g0 policy: destructive command"
```

`g0 proxy policy init` writes exactly this shape (with an empty `rules: []`)
in `observe` mode.

## Policy DSL v2

Set `version: 2` at the top of the file to opt into the v2 schema. v2 is
parsed and validated with [zod](https://zod.dev) (`safeParse` — never
throws); **on any validation failure the proxy logs the error to `stderr`
and falls back to the exact same safe default policy a malformed v1 file
falls back to** (`mode: observe`, no rules, no v2 blocks). A v2 file is
never partially trusted — it's either valid and fully compiled, or the
whole document degrades to observe-mode log-only.

**`version: 2` works on the global file AND on a per-server override file** —
each file is validated and compiled according to its own declared version.
A `version: 2` per-server override on a v1 (or version-less) global cleanly
**upgrades** the merged policy to v2: the override's v2 blocks are compiled
through the real v2 schema, and the result behaves as v2. (This is a
deliberate design property — an earlier revision silently dropped a
`version: 2` override's v2 blocks when the global was v1 while still flipping
the policy into v2 mode; that class of corruption is now impossible, because
version routing is an explicit per-file decision, never a side effect of
scalar merging.) A v1-shaped override on a v2 base preserves the base's v2
blocks and applies only its v1-shaped deltas.

v2 supports every v1 field (`mode`, `onError`, `limits`, `response`,
`rules`) plus these new, entirely optional blocks:

### `thresholds`

Overrides the confidence-fusion decision boundaries (see [Confidence
model](#confidence-model) below). Any omitted field falls back to the
default.

```yaml
thresholds:
  deny: 0.95      # fused score >= this -> deny
  redact: 0.85    # fused score >= this -> redact
  coach: 0.4      # fused score >= this -> coach; below -> allow
```

### `detectors`

Enable/disable/tune the structured secret detectors (credit card, IBAN, ABA
routing number, vendor API key/JWT, context-corroborated entropy, bare
entropy — see `src/proxy/detectors/structured.ts`), keyed by detector id.

```yaml
detectors:
  credit-card:
    enabled: false        # turn a detector off entirely
  bare-entropy:
    confidence: 0.5        # report a fixed confidence instead of the detector's own tier
```

### `edm`

Wires a fingerprinted index's matches (see [Fingerprinting /
EDM](#fingerprinting--exact-data-match-edm) below) to a real enforcement
action. Without an `edm:` entry for a given index, a match is still
detected and audited (confidence `0.99`, signal `edm:<indexName>`) but never
changes the decision — the same "detect, don't enforce" behavior EDM has
always had. An `edm:` entry turns a match into a real, mode-adjusted
decision.

```yaml
edm:
  - index: prod-secrets   # matches the --name used at fingerprint time
    onMatch: deny         # allow | deny | alert | coach (default: alert)
```

There is no `redact` option here: an EDM match carries no matched-value
offset (that's the whole point of the plaintext-never-persists guarantee),
so there's no span to redact surgically — only "block the whole message"
or "let it through with a warning" are well-defined.

### `dataflow`

Wires a specific cross-tool taint flow (see
[Provenance/dataflow](#provenance--dataflow-tracking) below) to a real
enforcement action, matched by tool-name/server-name glob on either side of
the flow. Every matcher field is optional — an omitted `tool`/`server`
matches anything for that side.

```yaml
dataflow:
  - from:
      tool: "read_secrets"
      server: "vault-mcp"
    to:
      tool: "send_*"
    onMatch: deny
```

This composes with (does not replace) the general confidence-fusion
dataflow signal every v2 policy already gets — see below. **`onMatch` sets a
floor for that specific flow, not a ceiling.** The engine picks the
highest-precedence candidate across every source (base rules, EDM,
dataflow-rule `onMatch`, and the always-on confidence-fusion signal), so an
explicit `onMatch: coach` can only ESCALATE the outcome above `coach`, never
pin it there or lower it: a cross-tool flow of a high-confidence secret can
still be `deny`d by fusion alone even when the matching `dataflow[]` rule
says `onMatch: coach`. This is intended — a specific rule is a guaranteed
minimum response for a flow you already know about; it is never a ceiling
that could suppress a stronger signal the general fusion model independently
finds.

### `context`

Feeds confidence-fusion context multipliers and overrides the
volume/velocity window used to flag a tool emitting an unusual burst of
sensitive tokens.

```yaml
context:
  destinations:
    untrusted: ["*_external", "web_*"]   # escalate confidence for these destinations (factor 1.3)
    trusted: ["internal_*"]              # dampen confidence for these destinations (factor 0.7)
  volume:
    windowMs: 30000       # velocity window (default 60000)
    alertThreshold: 3     # tokens/window before an alert fires (default 5)
```

### `positiveSecurity`

An allow-list posture: any tool call whose name matches none of
`tools` gets `default`'s action (mode-adjusted). This only ever ADDS
restriction on top of whatever the rest of the policy decides — an explicit
`deny` rule still applies to an allow-listed tool, and an allow-listed tool
is not a bypass of anything else.

```yaml
positiveSecurity:
  tools: ["read_file", "search_docs", "list_items"]
  default: deny   # allow | deny | alert | coach (default: deny)
```

### `action: coach` in `rules[]`

v2 adds exactly one new rule-level action value: `action: coach`. Unlike
v1's `allow | deny | alert`, an author can write `coach` directly — it
behaves exactly like a `deny` rule that has already been downgraded by
`alert` mode: never blocks, never mutates the message, always forwards with
a loud `stderr` warning. In `enforce` mode it is honored as `coach` (still
never blocks); in `observe` mode it still collapses to plain `alert`, like
everything else in observe mode.

```yaml
rules:
  - id: flag-risky-tool
    tools: ["risky_*"]
    action: coach
    message: "risky_* tools are being watched closely"
```

### Full example

```yaml
version: 2
mode: enforce
thresholds:
  deny: 0.9
  redact: 0.7
  coach: 0.3
detectors:
  credit-card:
    enabled: false
edm:
  - index: prod-secrets
    onMatch: deny
dataflow:
  - from: { tool: "read_secrets" }
    to: { tool: "send_*" }
    onMatch: deny
context:
  destinations:
    untrusted: ["*_external"]
positiveSecurity:
  tools: ["read_file", "search_docs"]
  default: deny
rules:
  - id: flag-risky-tool
    tools: ["risky_*"]
    action: coach
```

### Per-server overrides under v2

A per-server override file (`~/.g0/proxy/policies/<server>.yaml`) is
validated and compiled according to its OWN declared version. When the
override or the base is v2, the merge uses the v2 path: scalars (`mode`,
`onError`, `limits`, `response`) override, `rules`/`edm`/`dataflow` append,
`thresholds`/`detectors`/`context` merge field-by-field, and
`positiveSecurity` (an allow-list posture with no sensible partial-merge
semantic) is wholesale replaced if the override specifies it. A `version: 2`
override on a v1/version-less global cleanly upgrades the result to v2 (its
v2 blocks are compiled through the real v2 zod schema); a v1-shaped override
on a v2 base preserves the base's v2 blocks. A malformed override is skipped
(logged to `stderr`) without touching the already-valid base. Two v1 files
merge through the unchanged v1 path.

## Confidence model

Tasks 1-4 of this proxy's build-out each produce a confidence signal on
their own scale:

| Source | Confidence | Notes |
|---|---|---|
| Structured secret detectors | `0.9` (HIGH) / `0.6` (MEDIUM) / `0.3` (LOW) | Checksum/format-validated (Luhn, IBAN, ABA, vendor key/JWT) = HIGH; context-corroborated entropy = MEDIUM; bare entropy = LOW. |
| Exact-Data-Match (EDM) | `0.99` | An exact hash match against operator-fingerprinted data — the strongest possible evidence. |
| Provenance / dataflow | `0.9` | A value tainted in one tool's response reappeared in a different tool's request arguments. |
| Injection / IOC | mapped from severity | `critical` → `0.95`, `high` → `0.85`, `medium` → `0.6`, `low` → `0.3`. |

None of these is trustworthy alone at "block traffic" strength — that's why
each is emitted at a modest confidence rather than a blanket `1.0`. Under a
**v2 policy**, `src/proxy/confidence.ts` fuses every finding on a given
request/response into one score and maps that score to an action. **Under a
v1/version-less policy this fusion code never runs at all** — v1 keeps using
its original flat rules (`response.redactSecrets`, `response.injection`,
explicit `rules[]`) exactly as before.

### Fusion: noisy-OR

Findings are treated as independent evidence for one underlying event
("this traffic is bad"). The combined score is:

```
score = 1 - Π(1 - c_i)
```

i.e. "the probability that at least one finding correctly flags the event."
This has the properties this domain needs:

- one HIGH-confidence finding (`0.9`) alone already yields a high score — a
  single strong signal is not diluted.
- two MEDIUM findings (`0.6`, `0.6`) compound to `0.84` — corroborating weak
  signals raise confidence, without simply averaging or summing past `1.0`.
- it is monotonic and bounded to `[0,1]` by construction.

A **context multiplier** (e.g. "this destination tool is on an untrusted
list", factor `1.3`) scales every finding's confidence before fusion, then
the result is clamped back to `[0,1]`. A multiplier of exactly `1` is a
no-op and is not mentioned in the audit trail. Every finding/multiplier
that actually contributed a nonzero effect emits a short, audit-safe
**signal slug** (e.g. `secret:high`, `edm:exact`, `dataflow:cross-tool`,
`context:untrusted-destination`) so the fused score is always explainable
from the audit log, without ever containing the underlying sensitive value.

### Decision: "coach on uncertainty"

The fused score (plus a coarse severity, which shifts the effective
thresholds) is mapped to `allow | coach | redact | deny` via three
thresholds. The core design rule is **coach on uncertainty**: a score that
clears the `coach` bar but not the `redact` bar produces a loud, forwarded
warning instead of either silently doing nothing or silently
blocking/mutating traffic on shaky evidence. This is what keeps precision
high — a proxy that redacted or denied on every LOW-confidence bare-entropy
hit would be unusable; a proxy that ignored them entirely would miss real
corroborated signal. `coach` is the middle path.

Default thresholds (`{ deny: 0.95, redact: 0.85, coach: 0.4 }`), and what
they mean in practice:

| Signal | Score | Default outcome |
|---|---|---|
| One HIGH structured finding alone | `0.9` | `redact` — strong enough to act on alone, not strong enough for `deny`. |
| One EDM exact match alone | `0.99` | `deny` — an exact fingerprint match is treated as definitive. |
| One MEDIUM finding alone | `0.6` | `coach` — enough to warn loudly, not enough to touch the traffic. |
| One LOW finding alone | `0.3` | `allow` — below even the `coach` bar; a single noisy low-confidence hit doesn't spam the operator. |
| Two LOW findings (corroborated) | `0.51` | `coach` — noisy-OR raised it past the bar a single LOW finding couldn't clear. |

A `severity` (critical/high/medium/low, derived from the finding's own
severity or from a dataflow finding's own high-severity classification)
shifts the effective thresholds: a `critical` finding needs LESS
corroborating confidence to reach `deny`/`redact` than a `low`-severity one
needs to reach the same bar, reflecting that the cost of a false negative
differs by what's at stake.

A `redact`/`coach` outcome from fusion is applied as-is; a `deny` outcome is
still mode-adjusted (`observe` → `alert`, `alert` → `coach`, `enforce` →
`deny`) — v2's fused confidence can never silently block traffic outside
`enforce` mode, the same invariant every other decision in this proxy
honors.

### Fusion respects the `response` toggles

Each `response` toggle keeps its exact v1 meaning under v2. Fusion is
computed **per category group** (secrets separately from injection/IOC), and
each group's fused outcome is **capped at the action that group's toggle
authorizes** — so a v1 toggle is never silently demoted to a floor fusion can
overshoot, and one category's high fused score can never push a *different*
category's action past its own ceiling. The two toggles are independent, just
as in v1:

| Toggle | Fusion participation | Action ceiling |
|---|---|---|
| `redactSecrets: false` | secret findings **excluded** (detect-only) | — |
| `redactSecrets: true` | secret findings participate | **`redact`** (never `deny`) |
| `injection: off` | injection/IOC findings **excluded** (detect-only) | — |
| `injection: alert` | injection/IOC findings participate | **`coach`** (loud warn, forwards — never `redact`/`deny`) |
| `injection: deny` | injection/IOC findings participate | **`deny`** (blocking authorized) |

Key points:

- **`injection: alert` never blocks.** Its v1 contract is "detect and warn,
  never block"; its faithful v2 form is `coach` — a loud, forwarded warning.
  A critical injection/IOC finding under `injection: alert` fuses to `coach`,
  **never** `redact` or `deny`, even in enforce mode. Only `injection: deny`
  authorizes fusion to reach `deny`.
- **`redactSecrets: true` caps secrets at `redact`.** Corroborated secrets
  never fuse past `redact` (matching v1, where a secret finding only ever
  produced a `redact` candidate).
- **Detect-only posture:** `response: { redactSecrets: false, injection: off }`
  reproduces v1's exact "detect but never touch traffic" — a high-confidence
  finding under that config produces `allow`.
- **Mixed category:** a response with both a critical IOC (under
  `injection: alert`, capped at `coach`) and a high-confidence secret (under
  `redactSecrets: true`, capped at `redact`) resolves to `redact` — the
  secret's authorized action — not `deny`. The IOC's high score cannot lift
  the outcome past its own `coach` ceiling.

Within a group, weak signals still corroborate (two low-confidence IOCs fuse
to a higher combined score, raising visibility) — the cap only bounds the
*action*, not the score.

## Fingerprinting / Exact-Data-Match (EDM)

```
g0 proxy fingerprint <corpus-file> [--name <indexName>] [--mode line|shingle] [--shingle-size <n>]
```

Fingerprints a corpus of sensitive values (API keys, a DB column dump,
confidential doc lines) into `~/.g0/proxy/fingerprints/<name>.jsonl` — a
salted-hash + Bloom-filter index. **The plaintext corpus never persists**:
only salted SHA-256 hashes and a lossy Bloom bitset are written. Once
fingerprinted, the proxy flags any of that exact data appearing in MCP
traffic — a tool response, or an outbound `tools/call` argument (the exfil
case) — with near-zero false positives (unlike the entropy/regex
detectors, EDM never "thinks something looks like a secret"; it only ever
confirms a byte-for-byte match).

By itself, an EDM match is detect-only (audited, `stderr`-visible,
`confidence: 0.99`). Add an `edm:` entry to a v2 policy (see above) to make
a match on a specific index actually enforce.

## Provenance / dataflow tracking

Because `g0 proxy` sits on both legs of every MCP call, it can tag a
sensitive value the instant it appears in tool A's response and later, in
the same session, notice that exact value reappearing in tool B's request
arguments — the classic confused-deputy / exfiltration pattern (read a
secret via tool A, then unwittingly forward it through tool B). This is
tracked automatically, with no configuration required, and (under v1)
always contributes a `deny`-wanted (mode-adjusted) decision candidate.
Under v2, this signal instead runs through confidence fusion (so
`thresholds`/`context` genuinely change the outcome), and a `dataflow:`
policy block lets an operator declare a specific from/to flow that must
always take a given action regardless of confidence thresholds.

### Sensitive-path provenance ("read a secret file -> don't let it exfiltrate")

Dataflow tracking above only tags a value the response INSPECTOR already
flagged as a validated secret (`category: 'secret'` — Luhn/IBAN/ABA
checksum, a structurally-valid vendor key, a context-corroborated
credential). That misses a real class of exfiltration: an SSH private
key's base64 body, an `.env`'s custom-format token, or a JSON credential
store's contents don't match any known secret pattern, but they are
sensitive because of WHERE they came from, not what they look like.

`g0 proxy` closes that gap with no configuration required. On every
`tools/call` response, the proxy also checks the REQUEST that produced it:
if a path-like argument (`path`, `file_path`, `filename`, or any value
shaped like `/...`/`~/...`, checked the same way `pathArgs`/`allowPaths`
rules resolve a path value) resolved into one of a canonical set of
sensitive locations — `~/.ssh`, `~/.aws`, `~/.gnupg`, a `.env` file
(`$HOME/.env` or a project-local `.env`/`.env.local`/...), a shell profile,
or a known credential store (`~/.cursor/auth.json`, `~/.claude/credentials.json`,
`~/.g0/auth.json`, ...; see `src/endpoint/sensitive-paths.ts`, the same
canonical list `g0 endpoint`'s artifact scanner uses) — the ENTIRE response
content is tagged sensitive-origin, tokenized and hashed into the same
taint LRU `tagResponse` uses (`SessionProvenance.tagSensitiveOrigin`). A
later outbound flow of any sufficiently-long substring of that content into
a DIFFERENT tool's request args is then caught by the exact same
`detectDataflow` path described above — same precedence, same v1 fixed-deny
/ v2 confidence-fusion behavior, same audit shape (tool names + a sensitive
CATEGORY label, e.g. `ssh-key`/`env-file`/`credential-store` — never the
matched value or the resolved path).

An ordinary path read (`~/projects/foo.py`, `/tmp/scratch/out.txt`) is a
no-op: no tag, no added cost beyond one cheap, bounded path check per
response.

Only **top-level** argument keys are inspected for a path: a call whose path
sits in a nested arg (e.g. `args.options.file`) is not recognized as a
sensitive read. This keeps the per-response check fixed-cost and covers the
common `read_file`/`cat`/`fs.read`-style shape (a top-level `path`/`file_path`
argument); a tool that buries the path deeper is out of scope for this slice.

**Honest ceiling.** This is a point-in-time, IN-PROXY slice, not full
data-lineage: it only sees what flows through THIS proxied MCP session,
and only tags the response to the READ call itself — if an agent reads a
secret file via one tool call and, in a SEPARATE process outside this
proxy's view (a different terminal, a different IDE session, a background
script), forwards that content elsewhere, this mechanism cannot see it.
Full cross-process data-lineage / DDR is the daemon (`src/daemon/*`) or a
separate endpoint-agent product's job, not this CLI — see
[`docs/endpoint-monitoring.md`](endpoint-monitoring.md#scope--ceiling-what-the-cli-is-and-isnt).

## CLI reference

| Command | Purpose |
|---|---|
| `g0 proxy install [--client <name>] [--server <name>] [--dry-run]` | Rewrite IDE/agent MCP configs to route stdio servers through `g0 proxy`. |
| `g0 proxy uninstall [--client <name>] [--server <name>]` | Restore configs to their pre-proxy state. |
| `g0 proxy status [--json]` | Show installed wraps and a summary of recent activity. |
| `g0 proxy logs [--server <name>] [--tail <n>] [--json]` | Show recent audit records. |
| `g0 proxy policy init [--server <name>] [--force]` | Write a default (observe-mode) policy file. |
| `g0 proxy fingerprint <file> [--name <n>] [--mode line\|shingle]` | Build an EDM fingerprint index. |
| `g0 proxy -- <command> [args...]` | Run the proxy directly, wrapping `<command>` (used internally by `install`). |

Every subcommand accepts `--policy-dir <path>` to redirect policy, audit,
and fingerprint state away from `~/.g0/proxy`.

## Design invariants (every version)

- **Never throw / fail open.** A missing policy file is silently treated as
  empty; a malformed one (v1 or v2) falls back to a safe `observe` policy
  and logs the parse/validation error to `stderr`. A single bad rule (v1 or
  v2) is dropped without invalidating the rest of the policy. Confidence
  fusion is pure and never throws — a bad input yields a safe default.
- **`stdout` carries only proxied JSON-RPC traffic.** All diagnostics go to
  `stderr`.
- **Secrets never enter logs.** Findings, signals, and audit records carry
  metadata only (names, confidence, index/tool names) — never the matched
  value.
- **Bounded work.** Every scan respects `limits.maxScanBytes`; detector,
  EDM, and dataflow finding arrays are all capped; confidence fusion is
  `O(findings)`.
- **One sensitive-path list, not two.** Sensitive-path provenance (above)
  and `g0 endpoint`'s artifact scanner both read `src/endpoint/sensitive-paths.ts`
  — there is no proxy-local, independently-maintained copy of "which
  locations are sensitive" to drift out of sync.
