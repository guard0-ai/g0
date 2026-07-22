# Claude Code hook enforcement — `g0 hook`

MCP proxies — g0's own included — architecturally cannot see Claude Code's
**built-in tools**: Bash commands, file writes, WebFetch. Those never
traverse MCP. g0 closes that gap with Claude Code's native hook system: a
PreToolUse/PostToolUse hook that pipes every tool call through the same
enforcement engine the [runtime proxy](runtime-proxy.md) uses — policy
rules, validator-gated secret detection, Exact-Data-Match, and cross-tool
dataflow provenance.

```bash
g0 protect --apply --surfaces claude   # install the hooks (backed up, undoable)
g0 protect status                      # hook health: error rate, last run, latency p95
g0 protect off --surfaces claude       # remove them, restoring settings.json byte-exact
```

## What it sees and does

On every tool call, Claude Code invokes `g0-hook` (a dedicated slim binary —
p95 decision latency is CI-gated under 100 ms including process startup):

- **PreToolUse** — the engine evaluates the call. `deny` blocks it with a
  reason; `redact`/`coach` answer *ask* so you decide; everything else
  passes silently.
- **PostToolUse** — never blocks. It inspects tool output, tags sensitive
  values (provenance), and audits. When that tagged value later reappears in
  a *different* tool's arguments — the confused-deputy exfil pattern — the
  PreToolUse leg catches it, **across separate hook processes**: session
  provenance persists under `~/.g0/hook-state/` (salted hashes only, pruned
  after 24 h).

## Coach-first by default

The installed policy (`~/.g0/hook/policy.yaml`) ships in `mode: alert`:
would-be denies surface as loud *coach* warnings and nothing blocks. A guard
that annoys you gets uninstalled — and then protects nobody. When you're
ready:

```yaml
version: 1
mode: enforce        # deny/redact become real
rules:
  - id: no-destructive-bash
    tools: ["Bash"]
    argsRegex: '(rm\s+-rf\s+/|mkfs|dd\s+if=)'
    action: deny
    message: destructive command blocked by g0
```

The full policy DSL (v1 and v2 — thresholds, detectors, EDM, dataflow) is
shared with the proxy: see [runtime-proxy.md](runtime-proxy.md).

## Fail-open, by contract

A g0 defect must never break your Claude Code session: any internal error
allows the call (exit 0, empty output) and lands in the audit log. Hardened
setups can set `onError: closed` to turn internal errors into PreToolUse
denies instead. Two backstops watch the gap:

- **Execution verification** — after a deny of a Write/Edit, g0 checks
  post-hoc whether the target file changed anyway and alerts loudly if so
  (detection only, never auto-revert).
- **Health surfacing** — `g0 protect status` reports hook error rate, last
  invocation, and decision-latency p95 from the audit trail
  (`~/.g0/hook/audit.jsonl`).

Detection is canonicalization-hardened: secret/EDM scans also run over an
NFKC-normalized, zero-width-stripped copy of each payload, so encoding
tricks don't slip past pattern matching.

## Uninstall

`g0 protect off --surfaces claude` restores `~/.claude/settings.json` from
its byte-exact backup (refusing if you've edited it since, unless
`--force`). Your own hook entries are always preserved — install merges,
never clobbers.

## The rest of the Claude estate

Runtime hooks guard what Claude *does*; `g0 check` guards what *programs*
it: skills, plugins, subagents, other settings hooks, and Desktop
extensions are enumerated and content-scanned on every check, and critical
findings cap the machine's grade. One command each way: `g0 check` to see,
`g0 protect` to enforce.
