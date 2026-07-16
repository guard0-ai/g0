# g0 as an MCP Server

`g0 mcp serve` runs g0 itself as a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so agent hosts — Claude Code, Cursor, Windsurf, and anything else that speaks MCP — can call g0's scanner, inventory builder, and MCP-supply-chain checks directly, in-process, without shelling out.

This is the mirror image of [MCP Security](mcp-security.md) (`g0 mcp [path]`, which scans *other* MCP servers). Here, **g0 is the MCP server** your agent talks to.

## Why

If you're pairing with an agent inside Claude Code, Cursor, or Windsurf, it can now ask "is this project secure?", "is this npm package safe to install as an MCP server?", or "what's my current score?" as a tool call — no context-switching to a terminal, no copy-pasting scan output back into the chat.

## Quick start

```bash
g0 mcp serve --project-root .
```

This starts a stdio MCP server confined to the current directory. It's meant to be launched by an MCP-aware host (see registration below), not run interactively — it reads/writes JSON-RPC on stdin/stdout and blocks until the host disconnects or the process is signaled (`SIGINT`/`SIGTERM`).

`--project-root <path>` confines every path-accepting tool to that directory tree — a tool call asking to scan or read a path outside it (e.g. via `../../`) is rejected. **Always pass `--project-root`** when registering g0 with an agent host; without it, tools can resolve any path the OS user running `g0` can reach.

## Tools

All 6 tools are **read-only** (`annotations.readOnlyHint: true`) — none of them write, modify, or delete files, and `g0 test` (live adversarial/red-team testing) is intentionally **not** exposed here.

| Tool | Input | What it does |
|------|-------|---------------|
| `scan_project` | `path?` (default `.`), `ruleset?` (`recommended`\|`extended`\|`all`), `min_severity?` (`critical`\|`high`\|`medium`\|`low`), `max_findings?` (number) | Runs g0's full scan (1,120+ rules, 12 domains) and returns a scored, graded summary with the top findings. Caches the result for this session so `get_score`/`explain_finding` can reuse it. |
| `scan_mcp_server` | `path` (required) | Assesses an MCP server's source code for supply-chain / tool-safety findings (the same engine as `g0 mcp <path>`). |
| `verify_mcp_package` | `package` (required) | Checks whether an npm package is safe to install as an MCP server — install scripts, package age, download counts, maintainers, repository. **Makes a network call** to the npm registry (`registry.npmjs.org` / `api.npmjs.org`) — the one exception to "local only" in this tool set. Returns a `recommendation` of `safe-to-install`, `review`, or `do-not-install`. |
| `inventory` | `path?` (default `.`), `format?` (`summary`\|`cyclonedx`) | Builds an AI Asset Inventory (models, frameworks, tools, MCP servers, agents, vector DBs). `cyclonedx` returns a full CycloneDX 1.6 AI-BOM document — **unsigned** (signing needs an ed25519 private key via `g0 inventory --sign-key`, which is out of scope for an MCP tool call). |
| `explain_finding` | `rule_id?`, `finding_id?`, `path?` | Explains a g0 rule (description, remediation, standards mapping) and/or a specific finding from a prior `scan_project` call in this session. |
| `get_score` | `path?` (default `.`) | Returns the score, grade, and per-domain breakdown for a project — reuses the cached `scan_project` result for that path in this session when available, instead of rescanning. |

Every tool returns both a markdown summary (`content[0].text`) and a `structuredContent` object with the same data in a form an agent can reason about programmatically.

## Safety model

- **Read-only.** No tool in this set writes files, modifies state, or executes anything beyond static analysis. `g0 test` (dynamic/adversarial testing against a live target) is deliberately excluded from v1 of the MCP surface.
- **Confined to local paths.** With `--project-root` set, every path-accepting tool rejects paths that resolve outside it (defends against a `../../` traversal from a careless or compromised MCP client).
- **One network exception.** `verify_mcp_package` calls the public npm registry to check package metadata — no other tool makes network requests.
- **No stdout pollution.** The stdio transport owns stdout for JSON-RPC framing; g0's banner, spinners, and terminal chrome are suppressed on this code path, and diagnostics go to stderr only.
- **Subtle, capped signup nudge.** `scan_project` and `get_score` results may carry a single-line footer pointing at guard0.ai — at most once per server session, and it respects the same opt-outs as the CLI (`G0_NO_CTA=1`, `.g0.yaml`'s `cta: false`, and it never shows for logged-in paid accounts).

## Registering g0 as an MCP server

### Claude Code

```bash
claude mcp add g0 -- npx -y @guard0/g0 mcp serve --project-root .
```

### Cursor (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "g0": {
      "command": "npx",
      "args": ["-y", "@guard0/g0", "mcp", "serve", "--project-root", "."]
    }
  }
}
```

### Windsurf (`mcp_config.json`)

```json
{
  "mcpServers": {
    "g0": {
      "command": "npx",
      "args": ["-y", "@guard0/g0", "mcp", "serve", "--project-root", "."]
    }
  }
}
```

> Replace `"."` with an absolute path to the project you want g0 confined to if your host doesn't run the server with the right working directory.

## See also

- [MCP Security](mcp-security.md) — using g0 to scan *other* MCP servers and configs (the reverse direction of this doc).
- [Programmatic API](api.md) — `createG0McpServer()` is also exported from `@guard0/g0` for embedding the MCP server in your own process.
