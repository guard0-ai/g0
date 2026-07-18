# MCP remediation guide

This guide maps common g0 MCP findings to concrete remediation patterns. It
focuses on tool validation, least privilege, transport hardening, and audit
evidence for agent tool calls.

## Findings covered

| Finding class | Relevant g0 area | Remediation pattern |
| --- | --- | --- |
| Tool lacks input validation | Tool safety | Add `inputSchema` with bounded JSON Schema |
| Filesystem access is too broad | Tool safety | Scope roots to explicit read/write directories |
| MCP package version is unpinned | Supply chain | Pin package versions or use a reviewed local server |
| Shell execution is exposed | Code execution | Remove shell tools or require human review |
| Remote transport has weak controls | Identity and access | Use authenticated HTTPS/SSE with explicit allowlists |
| Tool description changed unexpectedly | Tool safety | Pin and diff tool descriptions before use |

## 1. Add input schema validation

Before:

```json
{
  "name": "search_docs",
  "description": "Search company documents"
}
```

After:

```json
{
  "name": "search_docs",
  "description": "Search approved company documents",
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["query"],
    "properties": {
      "query": {
        "type": "string",
        "minLength": 3,
        "maxLength": 300
      },
      "limit": {
        "type": "integer",
        "minimum": 1,
        "maximum": 10,
        "default": 5
      }
    }
  }
}
```

Why this helps:

- agents cannot pass unbounded or unexpected arguments
- downstream tools receive typed inputs
- audit records can show which schema was enforced

## 2. Scope filesystem servers

Before:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    }
  }
}
```

After:

```json
{
  "mcpServers": {
    "filesystem-readonly-docs": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@2026.1.14",
        "./docs"
      ]
    }
  }
}
```

Prefer separate read-only and write-capable servers. Route write-capable tools
through human review for production workspaces.

## 3. Pin server packages

Before:

```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-github"]
}
```

After:

```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-github@2025.4.8"]
}
```

Pinning reduces package rug-pull risk and makes tool description drift easier
to review in CI.

## 4. Gate shell or deploy tools

Before:

```json
{
  "name": "run_shell",
  "description": "Run any shell command",
  "inputSchema": {
    "type": "object",
    "properties": {
      "command": { "type": "string" }
    }
  }
}
```

After:

```json
{
  "name": "run_checked_command",
  "description": "Run an allowlisted read-only diagnostic command",
  "inputSchema": {
    "type": "object",
    "additionalProperties": false,
    "required": ["command"],
    "properties": {
      "command": {
        "type": "string",
        "enum": ["git status --short", "npm test", "pytest"]
      }
    }
  }
}
```

Shell, deploy, delete, permission-changing, export, and payment tools should
produce an audit record and require explicit approval before execution.

## 5. Record a minimal tool-call audit event

Use a redacted audit event when a tool call is allowed, denied, modified, or
routed to review:

```json
{
  "event_id": "mcp_tool_evt_001",
  "server": "filesystem-readonly-docs",
  "tool": "search_docs",
  "decision": "allow",
  "args_hash": "sha256:example-argument-fingerprint",
  "policy": "mcp-tool-policy-v1",
  "review_required": false,
  "redacted_fields": ["arguments.query"]
}
```

Store hashes, policy identifiers, and decisions instead of raw prompts, secrets,
credentials, or private document text.

## g0 review checklist

- [ ] Tool has an `inputSchema` with `additionalProperties: false`.
- [ ] Unbounded strings, arrays, and numeric limits are capped.
- [ ] MCP package versions are pinned.
- [ ] Filesystem, shell, network, deploy, and data-export tools are scoped.
- [ ] Human review is required for destructive or irreversible tools.
- [ ] Tool descriptions are pinned or diffed before use.
- [ ] Audit records store hashes and redacted metadata, not raw sensitive data.
