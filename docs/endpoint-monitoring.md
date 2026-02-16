# Endpoint Monitoring

The `g0 daemon` command runs a background agent on developer machines (endpoints) for fleet-wide AI security visibility. It continuously monitors MCP configurations, detects tool description rug-pulls, tracks AI component drift, and reports health to Guard0 Cloud.

## Why Endpoint Monitoring

AI agents run on developer machines through tools like Claude Desktop, Cursor, and custom MCP setups. These configurations change frequently and exist outside of version control. Without endpoint monitoring:

- MCP server tool descriptions can change silently (rug-pull attacks)
- New AI components appear on developer machines without review
- There's no fleet-wide visibility into what AI tools developers are using
- Configuration drift between machines goes undetected

## Quick Start

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
2. **Pin Check** - Verifies MCP tool descriptions against pinned hashes to detect rug-pulls
3. **Inventory Diff** - Scans watched project paths and detects AI component changes
4. **Heartbeat** - Reports machine health status to Guard0 Cloud

### Endpoint Registration

On first start, the daemon registers the machine:

```
Machine ID:  a3f8c2d1-...     (stable per machine, stored in ~/.g0/machine-id)
Hostname:    jayesh-mbp
Platform:    darwin / arm64
g0 Version:  1.0.0
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

Shows PID, uptime, last tick, and configuration.

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
  "inventoryDiff": true
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
