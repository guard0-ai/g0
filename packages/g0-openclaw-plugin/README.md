# @guard0/openclaw-plugin

In-process security monitoring for OpenClaw gateway. Hooks into the real OpenClaw plugin API to detect prompt injection, block dangerous tools, scan for PII leakage, gate sensitive commands/files, and stream security events to the g0 daemon.

## Installation

```bash
# Via OpenClaw plugin manager
openclaw plugins install @guard0/openclaw-plugin

# Or manually
cd /opt/openclaw
npm install @guard0/openclaw-plugin
```

## Configuration

Add to your `openclaw.json` plugins section:

```json
{
  "plugins": {
    "allow": ["@guard0/openclaw-plugin"],
    "entries": {
      "@guard0/openclaw-plugin": {
        "config": {
          "webhookUrl": "http://localhost:6040/events",
          "logToolCalls": true,
          "detectInjection": true,
          "scanPii": true,
          "injectPolicy": true,
          "registerGateTool": true,
          "blockedTools": ["bash", "shell", "exec"],
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

The plugin registers four lifecycle hooks and one agent-callable tool:

| Hook | Priority | Action |
|------|----------|--------|
| `before_agent_start` | 10 | Injects Guard0 security policy into agent context via `prependContext` |
| `message_received` | 10 | Scans inbound user/tool messages for injection patterns (fire-and-forget) |
| `before_tool_call` | 10 | Blocks denied tools (`{ block: true }`), detects injection in arguments, blocks high-severity injection |
| `tool_result_persist` | 10 | Scans tool output for PII, returns `{ message: redacted }` with PII replaced by `[TYPE_REDACTED]` labels |

Additionally, `g0_security_check` is registered as an agent-callable tool via `api.registerTool()` for command/file-path gating.

## Security Layers

**L1 - Policy Injection** (`before_agent_start`): Prepends a security policy into the agent context. The policy instructs the agent to use `g0_security_check` before running destructive commands or accessing sensitive files, and to never output raw credentials.

**L2 - Injection Detection** (`message_received`): Scans inbound user and tool messages for 17 injection pattern types. Fires webhook events but does not block (fire-and-forget hook).

**L3 - Tool Gating** (`before_tool_call`): Blocks tools in the `blockedTools` list by returning `{ block: true, blockReason }`. Also scans tool arguments for injection patterns and blocks high-severity matches. Logs high-risk tool calls with argument details.

**L4 - PII Redaction** (`tool_result_persist`): Scans tool output for 7 PII types (email, phone, SSN, credit card, API key, JWT, private IP). Returns `{ message: redacted }` with PII replaced by `[TYPE_REDACTED]` labels before the result is persisted.

**L5 - Security Gate Tool** (`registerTool`): The `g0_security_check` tool accepts `command` or `file_path` parameters and checks against destructive command patterns (rm -rf, chmod 777, etc.) and sensitive file patterns (.env, .ssh, credentials, etc.). Returns `STATUS: ALLOWED` or `STATUS: DENIED` with reasoning.

## Injection Detection

17 pattern types with severity-based scoring:

- **High**: instruction override, role-play attacks, jailbreak markers, delimiter injection, HTML comment injection (`<!-- SYSTEM: ... -->`), script/iframe injection, constraint removal
- **Medium**: system prompt extraction, developer mode, encoded payloads, zero-width character obfuscation

A single high-severity pattern match in tool arguments triggers blocking in L3.

## PII Scanning

Scans tool output for 7 PII types: email addresses, US phone numbers, SSNs, credit card numbers, API keys (OpenAI, AWS, GitHub), JWTs, and private IP addresses. Detected PII is redacted before persistence.

## Event Flow

```
User Message
  |
  v
message_received (L2) ---- webhook ----> g0 daemon
  |                                         |
  v                                         v
before_tool_call (L3)                  EventReceiver
  |  (block / allow)                       |
  v                                    +---+---+
Tool Executes                          |       |
  |                              events.jsonl  alerting
  v                                          (Slack, etc.)
tool_result_persist (L4)
  |  (redact PII)
  v
Result Persisted
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

## Requirements

- OpenClaw v2026.2.23+
- g0 v1.3.0+ (for daemon event receiver)
- Node.js 20+

## Full Documentation

See the [OpenClaw Deployment Hardening Guide](https://github.com/guard0/g0/blob/main/docs/openclaw-deployment-guide.md) for the complete setup including daemon configuration, egress filtering, Falco integration, and auto-remediation.
