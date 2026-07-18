# Endpoint Assessment & Monitoring

g0 provides multi-layer security assessment for AI developer endpoints:

- **`g0 endpoint`** — On-demand discovery, scanning, and scoring of AI developer tools on the machine
- **`g0 daemon`** — Background agent for continuous monitoring, drift detection, and fleet-wide visibility
- **`g0 scan . --openclaw-audit`** — Deployment audit for self-hosted OpenClaw instances (see [OpenClaw Deployment Guide](openclaw-deployment-guide.md))

## Endpoint Assessment

### Quick Start

```bash
g0 endpoint                    # Full scan: config + process + MCP + network + artifacts
g0 endpoint --json             # Structured JSON output
g0 endpoint --fix              # Auto-fix permissions and remediate
g0 endpoint --forensics        # Include conversation store metadata (opt-in)
g0 endpoint --browser          # Include browser AI service HISTORY — visited URLs (opt-in)
g0 endpoint --agentic-browser  # Detect agentic browsers + risky AI browser extensions (opt-in)
g0 endpoint --fix              # Auto-fix permissions and suggest remediation
g0 endpoint status             # Machine info, daemon health, last score
g0 endpoint quarantine         # Dry-run: list MCP servers matching malicious IOCs (opt-in, writes nothing)
```

### Scan Layers

`g0 endpoint` runs a multi-layer scan pipeline. Layers 1-4 run by default; layers 5-7b are opt-in.

| Layer | Name | Default | Flag | What It Does |
|:-----:|------|:-------:|------|-------------|
| 1 | Config Discovery | Yes | — | Finds AI tool config files across 19 tools |
| 2 | Process Detection | Yes | — | Checks which AI tools are actively running |
| 3 | MCP Security | Yes | — | Scans MCP server configurations for security issues |
| 4 | Network Discovery | Yes | `--no-network` to skip | Enumerates listening ports, fingerprints AI services, detects shadow services |
| 5 | Artifact Scanning | Yes | `--no-artifacts` to skip | Finds plaintext API keys, credential files, unencrypted data stores |
| 6 | Forensics | No | `--forensics` | Scans conversation stores (SQLite, JSON, LevelDB) for metadata |
| 7 | Browser History | No | `--browser` | Scans browser **history** for AI service usage patterns (visited URLs) |
| 7b | Agentic Browsers | No | `--agentic-browser` | Detects installed/running agentic browsers and risky AI browser extensions (point-in-time, not history) |

After all layers complete, g0 cross-references results across layers and computes a composite score.

### What It Discovers

`g0 endpoint` scans the machine for 19 AI developer tools:

| Tool | Config Location (macOS) |
|------|------------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| VS Code | `~/Library/Application Support/Code/User/settings.json` |
| Zed | `~/.config/zed/settings.json` |
| JetBrains (Junie) | `~/.junie/mcp/mcp.json` |
| Gemini CLI | `~/.gemini/settings.json` |
| Amazon Q Developer | `~/.aws/amazonq/mcp.json` |
| Cline | `~/.cline/mcp_settings.json` |
| Roo Code | `~/.roo-code/mcp_settings.json` |
| Copilot CLI | `~/.copilot/mcp-config.json` |
| Kiro | `~/.kiro/settings/mcp.json` |
| Continue | `~/.continue/config.json` |
| Augment Code | `~/.augment/settings.json` |
| Neovim (mcphub) | `~/.config/mcphub/servers.json` |
| BoltAI | `~/.boltai/mcp.json` |
| 5ire | `~/Library/Application Support/5ire/mcp.json` |
| OpenClaw | `~/.openclaw/openclaw.json` or `/data/.openclaw/openclaw.json` |

For each tool, g0 checks:
- **Installation** — Does the config file exist?
- **Running status** — Is the process currently active?
- **MCP servers** — What MCP servers are configured in this tool?
- **Security findings** — Hardcoded secrets, unsafe configurations, etc.

### Network Discovery

The network scanner enumerates all listening TCP ports and fingerprints AI-related services:

- **Service types detected**: MCP SSE, MCP Streamable HTTP, OpenAI-compatible, A2A, Ollama, LM Studio, vLLM, llama.cpp, Jan, OpenClaw
- **Shadow service detection** — Identifies AI services listening on ports that aren't declared in any config file
- **Security checks** — Unauthenticated endpoints, services bound to 0.0.0.0 (network-exposed), missing TLS, wildcard CORS

### Artifact Scanning

Scans for credentials and data stores left on disk by AI tools:

- **API key detection** — Anthropic, OpenAI, Google, AWS, GitHub, Azure, Hugging Face keys in config files, env files, and shell histories
- **Credential issues** — Plaintext storage, bad file permissions, env variable leaks, config-embedded secrets
- **Data store inventory** — SQLite databases, JSON stores, model caches, and log files with size, permissions, and encryption status

### Forensics (opt-in)

With `--forensics`, g0 scans conversation stores for metadata:

- Discovers SQLite, JSON, and LevelDB stores across Claude Desktop, ChatGPT Desktop, Cursor, and other tools
- Reports conversation count, message count, date range, file size, and encryption status
- Does **not** read conversation content — only metadata

### Browser History (opt-in)

With `--browser`, g0 scans browser history databases for AI service usage:

- Detects visits to ChatGPT, Claude, Gemini, Copilot, Perplexity, and other AI services
- Reports visit counts, date ranges, and which browsers are in use
- Supports Chrome, Safari, Firefox, Arc, Edge, and Brave

### Agentic Browsers (opt-in)

With `--agentic-browser`, g0 detects **agentic browsers** — browsers that can autonomously
navigate, click, and submit forms on the web using the signed-in user's session cookies — and
**risky AI browser extensions** with dangerous permission combinations. This is distinct from
`--browser` above: `--browser` mines browsing *history* (visited URLs); `--agentic-browser` is a
point-in-time detector for installed/running software and extension manifests, and touches no
browsing history.

**Agentic browsers detected** (macOS today): ChatGPT Atlas, Perplexity Comet, Dia, Arc, each
classified by capability:

| Capability | Meaning |
|------------|---------|
| `full-agent` | Can autonomously navigate, click, and submit forms using the user's logged-in sessions (e.g. ChatGPT Atlas, Perplexity Comet) |
| `agent-mode` | Ships agent-mode features that can act on the user's behalf within the browser (e.g. Dia) |
| `ai-assistant` | Includes AI-assistant features that read/summarize page content (e.g. Arc) |

For each detected browser, g0 reports installed/running status and severity-rated findings
(`critical`/`high`/`medium`/`low`/`info`) — e.g. a **running** `full-agent` browser is flagged
`high` as a high-value target for prompt-injection-driven data exfiltration; an installed-but-not-running
one is flagged `info`.

**Risky extension sweep**: g0 also sweeps Chromium-family extension manifests (Chrome, Chrome
Beta/Canary, Edge, Brave, Arc) and flags an extension as risky only when **all three** signals
co-occur: broad host access (`<all_urls>` or equivalent), a powerful capability
(`debugger`, `scripting`, `tabs`, `webNavigation`, `nativeMessaging`, or `cookies`), and an
AI/agent-related signal in its name or description. Severity is `critical` when `debugger` is
present, `high` for `scripting`/`nativeMessaging`, otherwise `medium`.

This layer is best-effort and macOS-only today; on other platforms (or on any internal error) it
returns an empty result rather than failing the scan.

### Cross-Reference Analysis

After individual layers complete, g0 cross-references results to detect inconsistencies:

| Status | Meaning |
|--------|---------|
| `fully-tracked` | Config + process + network all agree |
| `stdio-expected` | Config + process, no port (expected for stdio MCP servers) |
| `configured-inactive` | In config, not running |
| `shadow-service` | On network, not in any config |
| `config-mismatch` | Config vs reality divergence |
| `orphaned-config` | In config, process gone, port gone |

### Endpoint Scoring

Every scan produces a **0-100 score** with a letter grade (A-F) across four categories:

| Category | Max Points | What It Measures |
|----------|:----------:|-----------------|
| Configuration | 30 | MCP config issues, cross-reference mismatches, AI exposure surface (opt-in) |
| Credentials | 30 | Plaintext keys, bad permissions, data store exposure |
| Network | 25 | Shadow services, unauthenticated ports, exposed bindings |
| Discovery | 15 | Daemon running, tools detected |

**Severity deductions**: critical (-15), high (-10), medium (-5), low (-2)

**Grading**: A (90+), B (75-89), C (60-74), D (40-59), F (<40)

**AI exposure surface (opt-in, folded into Configuration)**: when `--agentic-browser` runs, its
findings are scored as part of the existing 30-point Configuration bucket — no new category, no
change to the 100-point total. Two rules, using the same severity-deduction table as everything
else in that bucket:

| Condition | Severity | Deduction |
|-----------|:--------:|:---------:|
| A `full-agent` browser (ChatGPT Atlas, Perplexity Comet) is **running** | high | -10 |
| A **critical**-severity risky AI browser extension is present | critical | -15 |

An installed-but-not-running `full-agent` browser, an `agent-mode`/`ai-assistant` browser, or a
non-critical risky extension does **not** deduct — those are surfaced only as informational
findings in the report. When `--agentic-browser` is not passed, this rule never runs: the
Configuration score (and the overall score) is byte-identical to a scan without the flag.

### Remediation (opt-in)

With `--fix`, g0 automatically applies safe fixes and suggests manual steps:

| Action | Description |
|--------|-------------|
| `fix-permissions` | Fixes file permissions on credential and auth files |
| `add-gitignore` | Suggests `.gitignore` entries for sensitive files |
| `rotate-key` | Flags plaintext credentials for key rotation |
| `bind-localhost` | Suggests binding exposed services to 127.0.0.1 |
| `enable-auth` | Suggests enabling authentication on open endpoints |
| `enable-tls` | Suggests enabling TLS on unencrypted services |

### Output Sections

```
  AI Developer Tools       — Each tool with running/installed status and MCP count
  MCP Servers              — All servers with severity badge and command
  Network Services         — Listening AI services with type, auth, and bind status
  Credentials              — API key exposures with redacted values
  Data Stores              — AI data files with size and encryption status
  Cross-Reference          — Config vs reality mismatches
  Score                    — 0-100 composite score with letter grade
  Findings                 — All security issues across all layers
  Summary                  — Overall status with severity breakdown
```

### JSON Output

```bash
g0 endpoint --json | jq '.score'
g0 endpoint --json | jq '.network.services[] | select(.type == "shadow-service")'
g0 endpoint --json | jq '.artifacts.credentials[] | .keyType'
```

Returns structured data with `tools[]`, `mcp`, `network`, `artifacts`, `crossReference`, `score`, and `summary` fields. Opt-in layers add `forensics`, `browser`, `agenticBrowsers`, and `remediation` when enabled — each key is omitted entirely (not `null`) when its layer didn't run.

### Drift Detection

g0 saves each scan result to `~/.g0/last-endpoint-scan.json` and compares against the previous scan to detect changes:

- **New shadow services** — AI services appearing on ports not in any config
- **New credential exposures** — Keys that weren't there before
- **Score drops** — Security posture degradation between scans
- **New tools installed** — AI developer tools added to the machine
- **Findings resolved** — Issues that have been fixed
- **Services secured** — Previously exposed services that are now locked down

### MCP-Server Quarantine (opt-in)

`g0 endpoint quarantine` is a **separate, opt-in command** — it is **never** run as part of
`g0 endpoint` / `g0 endpoint scan`. It enumerates the MCP servers configured across every
detected client (Claude Desktop, Cursor, VS Code, Zed, etc.), matches each against the local
IOC database, and — only when you explicitly ask — removes the matched entries from the owning
client's config file, with a byte-exact backup and a reversible undo.

**What gets matched.** For each configured server, g0 checks:

- **Name → typosquat** — the IOC typosquat patterns (e.g. `clawhub-official`, `0penclaw`) are
  checked against the server's config key **and** its `command` and every non-flag `args` token —
  because a malicious package's identity lives in the package specifier passed to
  `npx`/`uvx`/`pipx`/`node` (e.g. `npx -y clawhub-official-connector`), not in the friendly key the
  user typed.
- **Domain / IP** — hostnames and IPv4 addresses extracted from the server's `command`, `args`,
  and `env` values, matched against known C2 IPs and malicious/exfil domains (e.g. `webhook.site`).
- **Dangerous prerequisites** — the server's stringified config scanned for install/execution
  patterns like `curl … | sh`, base64-decode-to-shell, forced global installs, etc.

The IOC database is entirely **local** — quarantine makes no network calls.

```bash
g0 endpoint quarantine                 # DRY RUN (default) — prints the plan, writes nothing
g0 endpoint quarantine --json          # Same, machine-readable
g0 endpoint quarantine --apply         # Back up each affected config + remove ONLY matched servers
g0 endpoint quarantine --undo          # Restore configs from the latest manifest
g0 endpoint quarantine --undo <path>   # Restore from a specific manifest
g0 endpoint quarantine --undo --force  # Restore even if a config was edited since --apply
```

**Safety model.** This command rewrites client config files, so reversibility is the whole point:

1. **Dry-run by default.** Bare `g0 endpoint quarantine` only *reads* configs and prints which
   servers would be removed, from which files, and which IOC each one matched. It writes nothing.
   You must pass `--apply` to make any change.
2. **Backup before write, always.** Before modifying a config, `--apply` copies it byte-for-byte
   (a raw file copy, not a re-serialization) to `<configPath>.backup.<timestamp>`. If the backup
   fails for any reason, the write is skipped — a config is never rewritten without a good backup.
3. **Scope discipline.** Only the server entries that actually matched an IOC are deleted from the
   client's server map. Every other server, and every other key in the file, is left untouched. A
   config with zero matches is never backed up or rewritten.
4. **Manifest + undo.** Each `--apply` records a manifest under `~/.g0/quarantine/` (timestamp,
   each config path, its backup path, the server names removed, and a sha256 of the post-apply
   config). `--undo` reads the latest manifest (or a path you give it) and restores each config
   from its backup, verifying the restored bytes are **identical** to the backup — so `--apply`
   then `--undo` returns every touched config to its exact pre-quarantine state.
5. **Staleness guard on undo.** Before overwriting, `--undo` compares each config's current bytes
   to the post-apply sha256 in the manifest. If you edited the config after `--apply` (added a
   legit server, changed a setting), undo **refuses to clobber those edits** — it skips that config
   and tells you to re-run with `--force` if you really want to restore the backup over your
   changes.
6. **Fail-safe.** A malformed config, a missing file, a permission error, or a locking conflict on
   any single client is skipped and reported — it never aborts the run or leaves a config
   half-written. Every read-modify-write is guarded by a file lock so a concurrent writer can't
   corrupt the config.

### Scope & Ceiling (what the CLI is and isn't)

`g0 endpoint` — including quarantine — is a **point-in-time** tool: it inspects the machine's
current state when you run it and, for quarantine, makes a one-shot, reversible config change. It
is deliberately not a runtime enforcement layer. Be honest about where the boundaries are:

- **Continuous monitoring and enforcement is the daemon's job**, not the CLI's. `g0 daemon`
  (below) re-scans on an interval, tracks drift, and reports to the fleet; the CLI only sees the
  moment you invoke it. Quarantine removes a malicious server *now* — it does not prevent one from
  being re-added a minute later.
- **Kernel- and network-level enforcement is rule *generation*, not live blocking.** g0 can emit
  auditd / Falco / Tetragon / egress rules for you to load into the appropriate enforcement
  engine; g0 itself does not sit in the kernel or on the wire and block syscalls or packets.
- **Real-time browser DLP, cross-app data-flow, and cross-process lineage are a separate platform
  product**, not something a point-in-time endpoint CLI can deliver. The agentic-browser and
  extension detectors surface *risk*; they do not intercept a running browser agent's actions in
  real time. That live, cross-surface enforcement lives in the Guard0 Platform, not in this CLI.
- **`g0 proxy`'s sensitive-path provenance is an in-session, in-proxy slice, not full
  data-lineage.** When an MCP tool call reads `~/.ssh`, a `.env`, or a credential store (see
  `src/endpoint/sensitive-paths.ts`, the same canonical list this scanner's artifact layer uses),
  the proxy tags that call's response and flags a LATER outbound flow of that content into a
  different tool call — but only within that ONE proxied session, on that ONE machine, for that
  ONE MCP connection. It cannot see a secret read in one process reappear in an unrelated
  process (a different terminal, a different IDE session, a background script) — that is
  cross-process data-lineage / DDR (data detection and response), which is the daemon's
  continuous-monitoring job at best, and genuinely belongs to a separate endpoint-agent product,
  not this point-in-time CLI. See [`docs/runtime-proxy.md`](runtime-proxy.md#sensitive-path-provenance-read-a-secret-file---dont-let-it-exfiltrate)
  for the mechanism.

---

## Continuous Monitoring

### Why Endpoint Monitoring

AI agents run on developer machines through tools like Claude Desktop, Cursor, and custom MCP setups. These configurations change frequently and exist outside of version control. Without endpoint monitoring:

- MCP server tool descriptions can change silently (rug-pull attacks)
- New AI components appear on developer machines without review
- There's no fleet-wide visibility into what AI tools developers are using
- Configuration drift between machines goes undetected
- Shadow AI services can listen on open ports without anyone knowing

### Quick Start

```bash
# 1. Authenticate
# Platform features → guard0.ai/signup

# 2. Start the daemon
g0 daemon start

# 3. Verify it's running
g0 daemon status
```

The daemon registers your machine with Guard0 Platform and begins periodic monitoring.

## How It Works

On each tick (default: every 30 minutes), the daemon:

1. **MCP Config Scan** - Scans all local MCP configurations
2. **Network Scan** - Enumerates listening ports and detects shadow AI services
3. **Artifact Scan** - Checks for credential exposures
4. **Pin Check** - Verifies MCP tool descriptions against pinned hashes
5. **Inventory Diff** - Scans watched project paths
6. **Host Hardening** - Audits OS-level security (firewall, encryption, SSH)
7. **OpenClaw Deployment Audit** - 27 deployment + container checks
8. **Agent Watcher** - Detects running AI agents (Claude Code, Cursor, OpenClaw, etc.)
9. **Fleet Registration** - Reports machine scores and status
10. **Drift Detection** - Compares current scan against previous
11. **Heartbeat** - Reports machine health to Guard0 Platform

### Endpoint Registration

On first start, the daemon registers the machine:

```
Machine ID:  a3f8c2d1-...     (stable per machine, stored in ~/.g0/machine-id)
Hostname:    jayesh-mbp
Platform:    darwin / arm64
g0 Version:  2.0.0
Watch Paths: ~/projects
```

Guard0 Platform tracks each endpoint and displays fleet-wide status.

## Commands

### Start

```bash
g0 daemon start                           # Start with defaults
g0 daemon start --interval 15             # Scan every 15 minutes
g0 daemon start --watch ~/projects,~/work # Watch specific paths
g0 daemon start --no-upload               # Run locally without uploading
```

### Stop

```bash
g0 daemon stop
```

### Status

```bash
g0 daemon status
```

Shows PID, uptime, last tick, last endpoint score/grade, and configuration.

### Logs

```bash
g0 daemon logs              # View recent logs
g0 daemon logs --follow     # Tail logs
```

## Configuration

The daemon stores its configuration in `~/.g0/daemon.json`:

```json
{
  "intervalMinutes": 30,
  "watchPaths": [],
  "upload": true,
  "mcpScan": true,
  "mcpPinCheck": true,
  "inventoryDiff": true,
  "networkScan": true,
  "artifactScan": true,
  "killSwitch": {
    "autoEnabled": true
  },
  "costMonitor": {
    "enabled": true,
    "dailyLimitUsd": 100,
    "circuitBreakerEnabled": true
  },
  "fleet": {
    "enabled": true,
    "group": "engineering",
    "tags": ["dev"],
    "reportAgents": true,
    "reportHostHardening": true
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `intervalMinutes` | 30 | Minutes between scan ticks |
| `watchPaths` | `[]` | Project directories to monitor for inventory changes |
| `upload` | `true` | Upload results to Guard0 Platform |
| `mcpScan` | `true` | Scan local MCP configurations each tick |
| `mcpPinCheck` | `true` | Verify MCP tool descriptions against pins |
| `inventoryDiff` | `true` | Diff AI inventories on watched paths |
| `networkScan` | `true` | Enumerate listening ports and detect shadow services |
| `artifactScan` | `true` | Scan for credential exposures and data stores |

### Plugin Security Event Notifications

When the daemon receives security events from plugins (injection, tool-blocked, PII), you can opt into Slack/Discord/PagerDuty notifications by adding `notifications` to `alerting`:

```json
{
  "alerting": {
    "webhookUrl": "https://hooks.slack.com/services/...",
    "format": "slack",
    "notifications": {
      "mode": "interval",
      "intervalMinutes": 5
    }
  }
}
```

| Mode | Behavior |
|------|----------|
| `off` | Default. No extra notifications — events still logged and fed to kill switch / correlation. |
| `interval` | Accumulates events, sends a single digest every `intervalMinutes` (default: 5). |
| `realtime` | Alerts per-event with rate limiting — max 1 alert per category per `rateLimitSeconds` (default: 60). |

| Setting | Default | Description |
|---------|---------|-------------|
| `notifications.mode` | `off` | Notification mode: `realtime`, `interval`, or `off` |
| `notifications.intervalMinutes` | `5` | Digest interval in minutes (interval mode) |
| `notifications.rateLimitSeconds` | `60` | Min seconds between alerts per category (realtime mode) |

**Event categories**: `injection`, `tool-blocked`, `pii`, `message-blocked`, `subagent-blocked`, `correlation`.

## What Gets Monitored

### MCP Configuration Scanning

Every tick, the daemon scans MCP config files in standard locations:

- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `~/.cursor/mcp.json`
- Project-level `.mcp.json` files in watched paths

Findings are uploaded to Guard0 Platform with the machine context, so you can see which developer machines have risky MCP configurations.

### Rug-Pull Detection

If a `.g0-pins.json` file exists, the daemon compares current MCP tool descriptions against pinned hashes. Any mismatch triggers a warning in the logs and an alert on Guard0 Platform.

```
[WARN] Pin check: 1 mismatches detected!
[WARN]   MISMATCH: filesystem/write_file - description changed
```

### AI Inventory Drift

For watched paths, the daemon builds an AI inventory each tick and uploads it. Guard0 Platform tracks changes over time:

- New models, tools, or agents added
- Framework version changes
- MCP server configuration changes
- Vector database connection changes

### Host Hardening

Every tick, the daemon audits OS-level security:

**macOS** (8 checks): Firewall, FileVault, SIP, Gatekeeper, remote login, screen sharing, auto-login, AirDrop

**Linux** (5 checks): UFW/iptables, LUKS encryption, SSH hardening, auto-updates, open ports

Results are uploaded to Guard0 Platform for fleet-wide host posture tracking.

### Fleet Management

When `fleet.enabled` is set in daemon.json, the daemon:

- Registers the machine with scores and metadata
- Prunes stale members not seen in 72 hours
- Computes aggregate fleet scores across all machines
- Detects cross-machine common failures
- Reports running AI agents per machine

Fleet state is stored at `~/.g0/fleet-state.json`.

### Heartbeats

The daemon sends periodic heartbeats with status:

| Status | Meaning |
|--------|---------|
| `healthy` | All checks passed |
| `degraded` | Some checks failed but daemon is running |
| `error` | Daemon encountered a critical error |

Guard0 Platform uses heartbeats to show endpoint status and alert on machines that go offline.

## Fleet Management on Guard0 Platform

With daemons running across your team's machines, Guard0 Platform provides:

- **Endpoint inventory** - All registered machines with OS, platform, and g0 version
- **Fleet-wide MCP visibility** - Which MCP servers are installed across the fleet
- **Endpoint scores** - Track security posture (0-100) across all machines
- **Shadow service alerts** - AI services running outside of declared configurations
- **Credential exposure alerts** - Plaintext API keys detected on developer machines
- **Rug-pull alerts** - Notifications when tool descriptions change on any machine
- **Component drift** - Track AI inventory changes across all watched projects
- **Health monitoring** - See which endpoints are healthy, degraded, or offline
- **Policy enforcement** - Set fleet-wide policies for allowed MCP servers and tools

## Deploying Across a Team

### Manual

Each developer runs:

```bash
npm install -g @guard0/g0
# Platform features → guard0.ai/signup
g0 daemon start --watch ~/projects
```

### MDM / Script

For automated deployment across machines:

```bash
#!/bin/bash
npm install -g @guard0/g0
echo '{"intervalMinutes":30,"watchPaths":["~/projects"],"upload":true}' > ~/.g0/daemon.json
G0_API_KEY="$FLEET_API_KEY" g0 daemon start
```

### Verify Fleet Status

On Guard0 Platform, the endpoints dashboard shows all registered machines and their last heartbeat time.

## Files

| Path | Purpose |
|------|---------|
| `~/.g0/daemon.json` | Daemon configuration |
| `~/.g0/daemon.pid` | PID file for the running daemon |
| `~/.g0/daemon.log` | Daemon log output |
| `~/.g0/machine-id` | Stable machine identifier (UUID) |
| `~/.g0/auth.json` | Guard0 Platform authentication tokens |
| `~/.g0/last-endpoint-scan.json` | Last scan result for drift detection |
| `~/.g0/quarantine/manifest-<ts>.json` | MCP-server quarantine manifests (config paths, backups, removed servers) used by `--undo` |
| `~/.g0/fleet-state.json` | Fleet member registry and scores |
| `~/.g0/evidence/` | Evidence records for governance compliance |
| `~/.g0/events.jsonl` | Persisted security events from event receiver |
| `~/.g0/cognitive-baselines.json` | Cognitive file integrity baselines |
| `~/.g0/.killswitch` | Kill switch state file |
