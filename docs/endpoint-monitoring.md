# Endpoint Assessment & Monitoring

g0 provides multi-layer security assessment for AI developer endpoints:

- **`g0 endpoint`** — On-demand discovery, scanning, and scoring of AI developer tools on the machine
- **`g0 daemon`** — Background agent for continuous monitoring, drift detection, and fleet-wide visibility

## Endpoint Assessment

### Quick Start

```bash
g0 endpoint              # Full scan: config + process + MCP + network + artifacts
g0 endpoint --json       # Structured JSON output
g0 endpoint --upload     # Upload results to Guard0 Cloud
g0 endpoint --forensics  # Include conversation store metadata (opt-in)
g0 endpoint --browser    # Include browser AI service history (opt-in)
g0 endpoint --fix        # Auto-fix permissions and suggest remediation
g0 endpoint status       # Machine info, daemon health, last score
```

### Scan Layers

`g0 endpoint` runs a multi-layer scan pipeline. Layers 1-4 run by default; layers 5-7 are opt-in.

| Layer | Name | Default | Flag | What It Does |
|:-----:|------|:-------:|------|-------------|
| 1 | Config Discovery | Yes | — | Finds AI tool config files across 18 tools |
| 2 | Process Detection | Yes | — | Checks which AI tools are actively running |
| 3 | MCP Security | Yes | — | Scans MCP server configurations for security issues |
| 4 | Network Discovery | Yes | `--no-network` to skip | Enumerates listening ports, fingerprints AI services, detects shadow services |
| 5 | Artifact Scanning | Yes | `--no-artifacts` to skip | Finds plaintext API keys, credential files, unencrypted data stores |
| 6 | Forensics | No | `--forensics` | Scans conversation stores (SQLite, JSON, LevelDB) for metadata |
| 7 | Browser History | No | `--browser` | Scans browser history for AI service usage patterns |

After all layers complete, g0 cross-references results across layers and computes a composite score.

### What It Discovers

`g0 endpoint` scans the machine for 18 AI developer tools:

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

For each tool, g0 checks:
- **Installation** — Does the config file exist?
- **Running status** — Is the process currently active?
- **MCP servers** — What MCP servers are configured in this tool?
- **Security findings** — Hardcoded secrets, unsafe configurations, etc.

### Network Discovery

The network scanner enumerates all listening TCP ports and fingerprints AI-related services:

- **Service types detected**: MCP SSE, MCP Streamable HTTP, OpenAI-compatible, A2A, Ollama, LM Studio, vLLM, llama.cpp, Jan
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
| Configuration | 30 | MCP config issues, cross-reference mismatches |
| Credentials | 30 | Plaintext keys, bad permissions, data store exposure |
| Network | 25 | Shadow services, unauthenticated ports, exposed bindings |
| Discovery | 15 | Daemon running, tools detected |

**Severity deductions**: critical (-15), high (-10), medium (-5), low (-2)

**Grading**: A (90+), B (75-89), C (60-74), D (40-59), F (<40)

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

Returns structured data with `tools[]`, `mcp`, `network`, `artifacts`, `crossReference`, `score`, and `summary` fields. Opt-in layers add `forensics`, `browser`, and `remediation` when enabled.

### Drift Detection

g0 saves each scan result to `~/.g0/last-endpoint-scan.json` and compares against the previous scan to detect changes:

- **New shadow services** — AI services appearing on ports not in any config
- **New credential exposures** — Keys that weren't there before
- **Score drops** — Security posture degradation between scans
- **New tools installed** — AI developer tools added to the machine
- **Findings resolved** — Issues that have been fixed
- **Services secured** — Previously exposed services that are now locked down

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
g0 auth login

# 2. Start the daemon
g0 daemon start

# 3. Verify it's running
g0 daemon status
```

The daemon registers your machine with Guard0 Cloud and begins periodic monitoring.

## How It Works

On each tick (default: every 30 minutes), the daemon:

1. **MCP Config Scan** - Scans all local MCP configurations (Claude Desktop, Cursor, etc.) for security issues
2. **Network Scan** - Enumerates listening ports and detects shadow AI services
3. **Artifact Scan** - Checks for new credential exposures and data stores
4. **Pin Check** - Verifies MCP tool descriptions against pinned hashes to detect rug-pulls
5. **Inventory Diff** - Scans watched project paths and detects AI component changes
6. **Drift Detection** - Compares current scan against previous to detect changes
7. **Heartbeat** - Reports machine health status and endpoint score to Guard0 Cloud

### Endpoint Registration

On first start, the daemon registers the machine:

```
Machine ID:  a3f8c2d1-...     (stable per machine, stored in ~/.g0/machine-id)
Hostname:    jayesh-mbp
Platform:    darwin / arm64
g0 Version:  1.1.2
Watch Paths: ~/projects
```

Guard0 Cloud tracks each endpoint and displays fleet-wide status.

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
  "artifactScan": true
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `intervalMinutes` | 30 | Minutes between scan ticks |
| `watchPaths` | `[]` | Project directories to monitor for inventory changes |
| `upload` | `true` | Upload results to Guard0 Cloud |
| `mcpScan` | `true` | Scan local MCP configurations each tick |
| `mcpPinCheck` | `true` | Verify MCP tool descriptions against pins |
| `inventoryDiff` | `true` | Diff AI inventories on watched paths |
| `networkScan` | `true` | Enumerate listening ports and detect shadow services |
| `artifactScan` | `true` | Scan for credential exposures and data stores |

## What Gets Monitored

### MCP Configuration Scanning

Every tick, the daemon scans MCP config files in standard locations:

- `~/Library/Application Support/Claude/claude_desktop_config.json`
- `~/.cursor/mcp.json`
- Project-level `.mcp.json` files in watched paths

Findings are uploaded to Guard0 Cloud with the machine context, so you can see which developer machines have risky MCP configurations.

### Rug-Pull Detection

If a `.g0-pins.json` file exists, the daemon compares current MCP tool descriptions against pinned hashes. Any mismatch triggers a warning in the logs and an alert on Guard0 Cloud.

```
[WARN] Pin check: 1 mismatches detected!
[WARN]   MISMATCH: filesystem/write_file - description changed
```

### AI Inventory Drift

For watched paths, the daemon builds an AI inventory each tick and uploads it. Guard0 Cloud tracks changes over time:

- New models, tools, or agents added
- Framework version changes
- MCP server configuration changes
- Vector database connection changes

### Heartbeats

The daemon sends periodic heartbeats with status:

| Status | Meaning |
|--------|---------|
| `healthy` | All checks passed |
| `degraded` | Some checks failed but daemon is running |
| `error` | Daemon encountered a critical error |

Guard0 Cloud uses heartbeats to show endpoint status and alert on machines that go offline.

## Fleet Management on Guard0 Cloud

With daemons running across your team's machines, Guard0 Cloud provides:

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
g0 auth login
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

On Guard0 Cloud, the endpoints dashboard shows all registered machines and their last heartbeat time.

## Files

| Path | Purpose |
|------|---------|
| `~/.g0/daemon.json` | Daemon configuration |
| `~/.g0/daemon.pid` | PID file for the running daemon |
| `~/.g0/daemon.log` | Daemon log output |
| `~/.g0/machine-id` | Stable machine identifier (UUID) |
| `~/.g0/auth.json` | Guard0 Cloud authentication tokens |
| `~/.g0/last-endpoint-scan.json` | Last scan result for drift detection |
