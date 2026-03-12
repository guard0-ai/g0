# @guard0/g0-openclaw-plugin

In-process security monitoring for OpenClaw agents. Hooks into the OpenClaw plugin API to detect prompt injection, block dangerous tools, scan for PII leakage, gate sensitive commands/files, monitor LLM I/O, track sessions, guard subagent spawning, and stream security events to the g0 daemon.

## Installation

```bash
# Via OpenClaw plugin manager
openclaw plugins install @guard0/g0-openclaw-plugin

# Or link for development
openclaw plugins install --link /path/to/g0/packages/g0-openclaw-plugin
```

## Configuration

Add to your `openclaw.json` plugins section:

```json
{
  "plugins": {
    "allow": ["g0-openclaw-plugin"],
    "entries": {
      "g0-openclaw-plugin": {
        "enabled": true,
        "config": {
          "webhookUrl": "http://localhost:6040/events",
          "blockedTools": ["dangerous_tool"],
          "authToken": "your-daemon-token"
        }
      }
    }
  }
}
```

```bash
# Start the g0 daemon to receive events
g0 daemon start

# Restart OpenClaw to load the plugin
openclaw restart
```

## Hook Architecture

The plugin registers 17 hooks across 3 execution models + 1 agent-callable tool:

### Modifying Hooks (sequential, can block/modify)

| Hook | Priority | Action |
|------|----------|--------|
| `before_agent_start` | 10 | Injects Guard0 security policy into agent context via `prependContext` |
| `before_tool_call` | 10 | Blocks denied tools, detects injection in params, logs high-risk tool calls |
| `message_sending` | 10 | Blocks outbound messages containing sensitive PII (SSN, CC, API keys) |
| `subagent_spawning` | 10 | Gates subagent creation, can block spawning of denied agents |

### Synchronous Hooks (sync only — async returns ignored by OpenClaw)

| Hook | Priority | Action |
|------|----------|--------|
| `tool_result_persist` | 10 | Scans tool output for PII, redacts before persistence to session JSONL |
| `before_message_write` | 10 | Redacts PII from any message before it's written to session JSONL |

### Void Hooks (parallel, fire-and-forget)

| Hook | Priority | Action |
|------|----------|--------|
| `message_received` | 10 | Scans inbound messages for injection patterns |
| `after_tool_call` | 50 | Logs high-risk tool results and errors |
| `llm_input` | 50 | Detects late-stage injection in LLM history context |
| `llm_output` | 50 | Detects PII/credential leakage in model responses |
| `session_start` | 100 | Tracks session lifecycle for daemon correlation |
| `session_end` | 100 | Flushes final session telemetry |
| `agent_end` | 100 | Logs agent run metadata (success, duration, message count) |
| `subagent_spawned` | 50 | Tracks subagent creation for daemon correlation |
| `subagent_ended` | 50 | Tracks subagent termination, warns on abnormal outcomes |
| `gateway_start` | 100 | Logs gateway lifecycle |
| `gateway_stop` | 100 | Logs gateway shutdown |

### Registered Tool

| Tool | Action |
|------|--------|
| `g0_security_check` | Agent-callable gate — checks commands against destructive patterns and file paths against sensitive patterns. Returns ALLOWED/DENIED with reasoning. |

## Security Layers

**L1 - Policy Injection** (`before_agent_start`): Prepends a security policy instructing the agent to use `g0_security_check` before destructive commands or sensitive file access.

**L2 - Injection Detection** (`message_received`, `llm_input`, `before_tool_call`): 17 injection patterns across 3 hook points — inbound messages, LLM history context, and tool arguments. High-severity injection in tool args triggers blocking.

**L3 - Tool Gating** (`before_tool_call`): Blocks tools in `blockedTools` list. Logs high-risk tool calls with argument details. Sends `tool.blocked` / `tool.executed` / `injection.detected` webhooks.

**L4 - PII Redaction** (`tool_result_persist`, `before_message_write`): Scans for 7 PII types in tool output and messages. Redacts before persistence — PII never reaches session JSONL. Handles both string content and content block arrays.

**L5 - LLM I/O Monitoring** (`llm_input`, `llm_output`): Inspects assembled prompts for late-stage injection that survived earlier filters. Detects PII/credential leakage in model responses with model/provider/usage metadata.

**L6 - Outbound Protection** (`message_sending`): Blocks outbound messages containing sensitive PII (SSN, credit card, API key) before they reach chat channels.

**L7 - Post-Execution Telemetry** (`after_tool_call`): Captures tool execution timing and errors for high-risk tools.

**L8 - Lifecycle Tracking** (`session_start/end`, `agent_end`, `gateway_start/stop`): Session and agent lifecycle events for daemon correlation, behavioral baseline, and fleet monitoring.

**L9 - Subagent Management** (`subagent_spawning/spawned/ended`): Gates subagent creation (can block), tracks spawn lifecycle, warns on abnormal termination.

**L10 - Security Gate Tool** (`g0_security_check`): Agent-callable tool that checks commands against 14 destructive patterns and file paths against 15 sensitive patterns.

## Event Flow

```
Inbound Message
  │
  ├─ message_received ──── injection? ──── webhook ──→ g0 daemon
  │
  ▼
before_agent_start ──── inject security policy
  │
  ▼
LLM Input
  │
  ├─ llm_input ──── injection in history? ──── webhook ──→ g0 daemon
  │
  ▼
LLM Output
  │
  ├─ llm_output ──── PII in response? ──── webhook ──→ g0 daemon
  │
  ▼
Tool Call
  │
  ├─ before_tool_call ──── blocked? inject? high-risk? ──── webhook ──→ g0 daemon
  │                        │ (block if denied/injection)
  ▼                        ▼
Tool Executes         [BLOCKED]
  │
  ├─ after_tool_call ──── high-risk/error? ──── webhook ──→ g0 daemon
  │
  ▼
Tool Result
  │
  ├─ tool_result_persist ──── PII? ──── redact + webhook ──→ g0 daemon
  │
  ▼
Message Write
  │
  ├─ before_message_write ──── PII? ──── redact (no webhook)
  │
  ▼
Outbound Message
  │
  ├─ message_sending ──── sensitive PII? ──── cancel + webhook ──→ g0 daemon
  │
  ▼
Session JSONL (PII-free)
```

## Configuration Reference

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `webhookUrl` | string | `http://localhost:6040/events` | g0 daemon event receiver URL |
| `logToolCalls` | boolean | `true` | Log high-risk tool executions |
| `detectInjection` | boolean | `true` | Scan for injection patterns |
| `scanPii` | boolean | `true` | Scan and redact PII in tool output |
| `blockedTools` | string[] | `[]` | Tools to block at gateway level |
| `highRiskTools` | string[] | 15 defaults | Tools that get detailed logging |
| `maxArgSize` | number | `10000` | Max bytes to log per tool argument |
| `quietWebhook` | boolean | `false` | Suppress webhook errors in logs |
| `injectPolicy` | boolean | `true` | Inject security policy on agent start |
| `registerGateTool` | boolean | `true` | Register g0_security_check tool |
| `authToken` | string | - | Bearer token for webhook auth |
| `blockOutboundPii` | boolean | `true` | Block outbound messages with sensitive PII |
| `monitorLlm` | boolean | `true` | Enable LLM input/output monitoring |
| `trackSessions` | boolean | `true` | Enable session lifecycle tracking |

## Webhook Event Types

| Event | Source Hook | When |
|-------|-----------|------|
| `tool.blocked` | `before_tool_call` | Denied tool blocked |
| `tool.executed` | `before_tool_call` | High-risk tool allowed |
| `tool.result` | `after_tool_call` | High-risk tool completed or error |
| `injection.detected` | `message_received` / `before_tool_call` / `llm_input` | Injection pattern found |
| `pii.redacted` | `tool_result_persist` | PII found and redacted in tool output |
| `pii.detected` | `llm_output` | PII found in model response |
| `pii.blocked_outbound` | `message_sending` | Outbound message blocked for PII |
| `security.gate` | `g0_security_check` tool | Gate tool invoked |
| `session.start` | `session_start` | New session created |
| `session.end` | `session_end` | Session closed |
| `agent.end` | `agent_end` | Agent run completed |
| `subagent.spawning` | `subagent_spawning` | Subagent spawn requested |
| `subagent.blocked` | `subagent_spawning` | Subagent spawn blocked |
| `subagent.spawned` | `subagent_spawned` | Subagent created |
| `subagent.ended` | `subagent_ended` | Subagent terminated |
| `gateway.start` | `gateway_start` | Gateway started |
| `gateway.stop` | `gateway_stop` | Gateway stopped |

## Requirements

- OpenClaw v2026.3.x+
- g0 v1.3.0+ (for daemon event receiver)
- Node.js 20+

## Full Documentation

See the [OpenClaw Deployment Hardening Guide](https://github.com/guard0-ai/g0/blob/main/docs/openclaw-deployment-guide.md) for the complete setup including daemon configuration, egress filtering, Falco integration, and auto-remediation.
