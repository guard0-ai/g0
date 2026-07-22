# `g0 protect` — one command to install the guardrails

`g0 check` is the read side: it tells you what's on the machine and whether
any of it is known-malicious. **`g0 protect` is the write side**: one command
that installs g0's guardrails, shows you exactly what it would change before
touching anything, and can undo everything it did.

```bash
g0 protect            # dry-run (default): the full plan, per surface — changes nothing
g0 protect --apply    # execute the plan (backups taken for every file touched)
g0 protect status     # what's currently guarded
g0 protect off        # undo the most recent apply, restoring configs from backups
```

## The dry-run-first contract

`g0 protect` with no flags **never writes**. It prints, per surface:

- the exact steps `--apply` would take, with every file that would be rewritten
- advisories — findings worth acting on that protect will not auto-apply

`--apply` is always explicit. Every rewritten config is backed up first, and
the apply is recorded as a **session manifest** under
`~/.g0/protect/manifests/` so `g0 protect off` can restore the exact set of
changes from that run.

## What the `mcp` surface protects

| Step | What happens on `--apply` |
|---|---|
| **Proxy routing** | Every stdio MCP server configured in your MCP clients (Claude Code, Claude Desktop, Cursor, Windsurf) is rewritten to route through [`g0 proxy`](runtime-proxy.md), so live tool traffic gets policy enforcement, secret redaction, and audit. |
| **Quarantine** | MCP servers matching known-malicious indicators (name/command typosquats, C2 hosts) are removed from client configs — same engine as [`g0 endpoint quarantine`](endpoint-monitoring.md), with byte-exact backups. |
| **OpenClaw hardening advisories** | If OpenClaw is installed, config-hardening recommendations appear in the plan as report-only advisories. Apply them with the endpoint hardening flow. |

## What the `claude` surface protects

Installs g0's PreToolUse/PostToolUse hooks into Claude Code
(`~/.claude/settings.json`, byte-exact backup, merge-never-clobber) so
**built-in tools — Bash, file writes, WebFetch — and MCP tools** run through
the same enforcement engine as the proxy. Ships coach-first (`mode: alert`
warns, never blocks) with blocking as an explicit opt-in. Full guide:
[hooks.md](hooks.md).

## What the `watch` surface protects

Registers the g0 daemon as a **per-user autostart** (launchd agent on
macOS, systemd user unit on Linux) so coverage stays continuous: fs-watched
re-checks of your MCP configs and Claude estate with native OS
notifications, each new finding notified exactly once. Observe-only by
default; set `"enforce": true` in the daemon config to auto-quarantine
known-malicious MCP servers and flagged-critical estate components (moved
to an undoable vault under `~/.g0/quarantine/estate/`). `g0 protect off
--surfaces watch` deregisters.

`--surfaces mcp,claude,watch` limits protect to listed surfaces. Codex
hardening and agentic-browser hardening arrive in later phases — see the
[design spec](superpowers/specs/2026-07-21-g0-protect-design.md).

## `status` and `off`

```bash
g0 protect status     # per-surface: protected or not, with detail lines
g0 protect off        # restore from the most recent apply's manifest
g0 protect off --force  # restore even over configs edited since the backup
```

`off` refuses to clobber a config that changed since its backup was taken
unless you pass `--force` — the same safety rule `endpoint quarantine --undo`
follows. If a manifest is missing or corrupt, the underlying backups are
plain files (paths are printed at apply time) and can be restored by hand.

## Safety invariants

- **Fail-open everywhere.** A g0 defect must never break a scan, an MCP
  session, or your machine. The proxy forwards unmodified on any internal
  error; protect surfaces report errors instead of propagating them.
- **Dry-run before every write; every write is undoable.**
- **Per-user scope.** No root, no system daemons, no other users' files.
- **No network on scan/enforce paths.** Signing in is optional and never
  required for protect.

## JSON output

Every subcommand takes `--json` for scripts and CI:

```bash
g0 protect --json | jq '.plans[].steps[].id'
g0 protect --apply --json | jq '.manifestPath'
g0 protect status --json | jq '.statuses[].protected'
```

Exit code is `1` when an apply or undo recorded any per-surface error.
