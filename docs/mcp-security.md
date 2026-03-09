# MCP Security

The `g0 mcp` command assesses Model Context Protocol (MCP) server configurations and source code for security issues, including rug-pull detection via tool description hash pinning.

## What g0 MCP Scans

| Target | How |
|--------|-----|
| **Local MCP configs** | Scans Claude Desktop, Cursor, and other MCP config files on your system |
| **Project source code** | Analyzes MCP server implementations in a project directory |
| **Remote repositories** | Clones and scans MCP server repos |

## Basic Usage

### Scan Local MCP Configurations

```bash
# Scan all local MCP configs (Claude Desktop, Cursor, etc.)
g0 mcp
```

g0 automatically discovers MCP configuration files in standard locations:
- `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- `~/.config/Claude/claude_desktop_config.json` (Linux)
- `~/.cursor/mcp.json`
- `.mcp.json` / `.mcp/config.json` in project directories

### Scan a Project

```bash
# Scan MCP server source code in a directory
g0 mcp ./my-mcp-server

# Scan a remote MCP server repo
g0 mcp https://github.com/org/mcp-server
```

### Output Formats

```bash
g0 mcp --json                    # JSON output
g0 mcp --json -o mcp-report.json # JSON to file
```

## Multi-Language Source Scanning

When scanning MCP server source code, g0 extracts tool declarations across three languages:

| Language | Patterns Detected |
|----------|------------------|
| **Python** | `@server.tool()`, `server.add_tool()`, FastMCP patterns |
| **TypeScript/JavaScript** | `server.tool("name", ...)`, `createTool({ name })`, `new Tool(...)` |
| **Go** | `mcp.NewTool("name", ...)`, `server.AddTool(...)` |

For each extracted tool, g0 detects capabilities (filesystem, network, shell, database, code-execution, email) and checks for input validation and sandboxing.

### Description-Behavior Alignment

g0 compares what a tool's description claims vs what its code actually does:

- A tool described as "read-only" that has write or shell capabilities
- A tool claiming "no network access" that makes HTTP calls
- Overprivileged descriptions using language like "any file", "full access", "all permissions"

Mismatches generate findings with severity based on the undisclosed capability (shell/code-execution = high).

### Manifest Consistency

g0 compares tools found in MCP source code against tools declared in MCP configuration:

- **Undeclared tools** — present in code but not in config (shadow tools)
- **Phantom tools** — declared in config but not found in code (stale/suspicious entries)

## MCP Server Discovery

When scanning local configs, g0 discovers:

- **Server name** — The key in the MCP config
- **Command** — What executable runs the server (`npx`, `python`, `node`, etc.)
- **Arguments** — Command-line arguments passed to the server
- **Environment variables** — Env vars configured for the server
- **Tools** — Tool names and descriptions exposed by the server

## MCP-Specific Security Rules

g0 evaluates MCP configurations against security rules including:

| Category | What g0 Checks |
|----------|---------------|
| **Permissions** | Filesystem access scope, network capabilities, shell execution |
| **Supply Chain** | Unpinned package versions, unverified packages |
| **Configuration** | Exposed secrets in env vars, overly broad paths |
| **Tool Capabilities** | Dangerous tool descriptions, write/delete operations |
| **Transport** | Transport security (stdio vs SSE vs HTTP) |

## Rug-Pull Detection

A "rug-pull" attack occurs when an MCP server changes its tool descriptions after initial approval — potentially tricking the AI into performing unintended actions.

### How It Works

1. **Pin** — g0 hashes every tool description from your MCP servers
2. **Check** — On subsequent runs, g0 compares current descriptions against pins
3. **Alert** — If a description changed, g0 flags it for review

### Pin Tool Descriptions

```bash
# Generate pins for all local MCP servers
g0 mcp --pin

# Save pins to a specific file
g0 mcp --pin my-pins.json
```

This creates a `.g0-pins.json` file:

```json
{
  "version": 1,
  "pins": {
    "filesystem": {
      "read_file": "sha256:a1b2c3...",
      "write_file": "sha256:d4e5f6...",
      "list_directory": "sha256:g7h8i9..."
    },
    "github": {
      "create_issue": "sha256:j0k1l2...",
      "search_repos": "sha256:m3n4o5..."
    }
  }
}
```

### Check Against Pins

```bash
# Verify tools match pinned descriptions
g0 mcp --check

# Check against a specific pin file
g0 mcp --check my-pins.json
```

If a tool description has changed:

```
  CHANGED  filesystem/write_file
           Pin:     sha256:d4e5f6...
           Current: sha256:x9y8z7...
           Description changed — review for rug-pull

  NEW      filesystem/delete_file
           Tool added since last pin — review permissions
```

### CI Integration

Add pin checking to your CI pipeline:

```yaml
- name: Check MCP tool descriptions
  run: npx @guard0/g0 mcp --check
```

Commit `.g0-pins.json` to your repository so changes are tracked in version control.

## Watch Mode

Monitor MCP config files for changes in real time:

```bash
g0 mcp --watch
```

g0 watches for file changes and re-scans automatically, useful during development.

## Example: Scanning Claude Desktop Config

```bash
$ g0 mcp

  MCP Security Assessment
  ───────────────────────

  Config: ~/Library/Application Support/Claude/claude_desktop_config.json

  Servers (3)
  ┌──────────────┬─────────┬───────┬──────────┐
  │ Server       │ Command │ Tools │ Findings │
  ├──────────────┼─────────┼───────┼──────────┤
  │ filesystem   │ npx     │ 5     │ 2 high   │
  │ github       │ npx     │ 12    │ 1 medium │
  │ slack        │ npx     │ 8     │ 3 high   │
  └──────────────┴─────────┴───────┴──────────┘

  Findings (6)

    HIGH  filesystem: Server has write access to home directory
    HIGH  filesystem: Unpinned package version (@modelcontextprotocol/server-filesystem)
    HIGH  slack: Server can send messages to any channel
    HIGH  slack: API token in environment variable without rotation
    HIGH  slack: Unpinned package version
    MED   github: Server has repository write permissions
```

## Example: Scanning Cursor Config

```bash
$ g0 mcp ~/.cursor/mcp.json

  MCP Security Assessment
  ───────────────────────

  Config: ~/.cursor/mcp.json
  ...
```

## Uploading Results

```bash
g0 mcp --upload
g0 mcp ./my-mcp-server --upload
```

Guard0 Cloud provides MCP-specific dashboards showing tool permissions, description change history, and supply chain risk.
