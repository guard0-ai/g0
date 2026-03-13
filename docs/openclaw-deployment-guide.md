# OpenClaw Deployment Hardening Guide

A complete guide for securing self-hosted OpenClaw deployments with g0. Covers every finding from a typical security audit, with step-by-step instructions for configuration, monitoring, and enforcement.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Deployment Audit Checks](#deployment-audit-checks)
4. [Step 1: Initial Assessment](#step-1-initial-assessment)
5. [Step 2: Config Hardening](#step-2-config-hardening)
6. [Step 3: Risk Acceptance](#step-3-risk-acceptance)
7. [Step 4: Egress Filtering (NET)](#step-4-egress-filtering)
8. [Step 5: Secret Management (CRED)](#step-5-secret-management)
9. [Step 6: Docker Socket Isolation (DOCK)](#step-6-docker-socket-isolation)
10. [Step 7: Data Privacy Boundaries (DATA)](#step-7-data-privacy-boundaries)
11. [Step 8: Observability (O11Y)](#step-8-observability)
12. [Step 9: Container Hardening (DOCK)](#step-9-container-hardening)
13. [Step 10: Network Isolation (DOCK)](#step-10-network-isolation)
14. [Step 11: Log Rotation (DOCK)](#step-11-log-rotation)
15. [Step 12: Additional Checks (DATA/DOCK)](#step-12-additional-checks)
16. [Step 13: g0 OpenClaw Plugin](#step-13-g0-openclaw-plugin)
17. [Step 14: Continuous Monitoring with g0 Daemon](#step-14-continuous-monitoring-with-g0-daemon)
18. [Step 15: Falco Runtime Detection (Optional)](#step-15-falco-runtime-detection-optional)
19. [Step 16: Tetragon Enforcement (Optional)](#step-16-tetragon-enforcement-optional)
20. [Architecture Overview](#architecture-overview)
21. [Configuration Reference](#configuration-reference)
22. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **OpenClaw** v2026.2.23+ (patched for CVE-2026-25253 and CVE-2026-28363)
- **g0** v1.5.0+ (`npm install -g @guard0/g0`)
- **Docker** and **Docker Compose** (for containerized deployments)
- **Linux host** (for iptables, auditd — macOS supported for scanning only)
- Root/sudo access (for iptables and auditd rule installation)

```bash
# Install g0
npm install -g @guard0/g0

# Verify
g0 --version    # Should show >= 1.3.0
```

---

## Quick Start

Run the full deployment audit in under 60 seconds:

```bash
# 1. Full deployment audit (deployment checks + hardening probes)
g0 scan ./your-openclaw-project \
  --openclaw-audit \
  --openclaw-hardening http://localhost:18789

# 2. Generate hardened config
g0 scan . --openclaw-audit --fix

# 3. Start continuous monitoring
g0 daemon start
```

---

## Deployment Audit Checks

g0 performs 36 deployment-level checks across 7 categories:

| g0 Check | Category | Description | Severity |
|----------|----------|-------------|----------|
| **OC-H-019** | NET | No egress filtering — agents can reach any destination | Critical |
| **OC-H-020** | CRED | Shared API keys across agents | Critical |
| **OC-H-021** | DOCK | Docker socket mounted in agent containers | Critical |
| **OC-H-022** | DATA | No data privacy boundaries between agents | Critical |
| **OC-H-023** | O11Y | No per-agent observability or audit trail | High |
| **OC-H-024** | DATA | No automated backup mechanism | Medium |
| **OC-H-025** | DOCK | Containers running as root | High |
| **OC-H-026** | DOCK | Docker log rotation not configured | Medium |
| **OC-H-027** | DOCK | Agents share default bridge network | Medium |
| **OC-H-028** | DATA | Session transcripts stored unencrypted | Medium |
| **OC-H-029** | DOCK | No Docker image scanning in CI | Low |
| **OC-H-030** | CRED | Overprivileged environment variable injection | Low |
| **OC-H-031** | O11Y | Per-agent tool call logging | High |
| **OC-H-032** | O11Y | Per-agent file access auditing | Medium |
| **OC-H-033** | O11Y | Per-agent network connection logging | High |
| **OC-H-034** | DATA | Backup encryption and retention policy | High |
| **OC-H-035** | SYS | Kernel reboot pending (security patches) | Medium |
| **OC-H-036** | NET | Tailscale account type and ACL configuration | Medium |
| **OC-H-037** | FORNS | Session transcript forensics (shells, exfil, escalation) | Critical |

**Categories**: NET (network), CRED (credentials), DOCK (Docker/container), DATA (data protection), O11Y (observability), SYS (system), FORNS (forensics)

### Container Deep Audit (OC-H-056..064)

g0 performs deep inspection of running Docker containers:

| g0 Check | Category | Description | Severity |
|----------|----------|-------------|----------|
| **OC-H-056** | DOCK | Containers should drop all capabilities (cap_drop: ALL) | High |
| **OC-H-057** | DOCK | Containers should set no-new-privileges | High |
| **OC-H-058** | DOCK | Root filesystem should be read-only | Medium |
| **OC-H-059** | DOCK | Memory and CPU resource limits should be set | Medium |
| **OC-H-060** | DOCK | Container should not use host network mode | High |
| **OC-H-061** | DOCK | OPENCLAW_DISABLE_BONJOUR should be set | Low |
| **OC-H-062** | DOCK | Sensitive host paths should not be mounted | High |
| **OC-H-063** | DOCK | Container images should be verified/signed | Medium |
| **OC-H-064** | CRED | Secrets passed via `-e` flags are visible in `ps aux` | Critical |

---

## Step 1: Initial Assessment

Run the deployment audit to understand your current security posture:

```bash
g0 scan ./your-openclaw-project --openclaw-audit
```

Output shows each check with PASS/FAIL status, severity, and finding ID:

```
  OpenClaw Deployment Audit
  ──────────────────────────────────────────────────────────────────────────────
  C1    OC-H-019    Egress filtering (iptables)            [CRITICAL]  FAIL
        No DOCKER-USER iptables rules found
  C2    OC-H-020    Secret duplication                     [CRITICAL]  FAIL
        3 duplicate credential groups found across 5 agents
  C3    OC-H-021    Docker socket mount                    [CRITICAL]  PASS
  C4    OC-H-022    Data privacy boundaries                [CRITICAL]  FAIL
        Agent data dirs have 755 permissions (should be 700)
  C5    OC-H-023    Per-agent observability (infra)        [HIGH]      FAIL
        No auditd rules or log forwarder detected
  ...

  Summary
  ──────────────────────────────────────────────────────────────────────────────
  Overall: CRITICAL  (15 checks)
  Passed: 4  Failed: 9  Errors: 0  Skipped: 2
```

For JSON output (CI/CD integration):

```bash
g0 scan . --openclaw-audit --json > audit-results.json
```

---

## Step 2: Config Hardening

g0 analyzes your `openclaw.json` and generates a hardened configuration with 20 security recommendations.

### Automatic Hardening

```bash
# Generate hardened config (creates backup of original)
g0 scan . --openclaw-audit --fix
```

This creates `openclaw.json.backup.<timestamp>` and writes the hardened config.

### What Gets Hardened

| Config Path | Default | Hardened | Finding |
|-------------|---------|---------|---------|
| `gateway.bind` | `"lan"` | `"loopback"` or `"tailnet"` | C1 |
| `gateway.auth.mode` | `"password"` | `"token"` | C3 |
| `gateway.auth.token` | _(empty)_ | `${OPENCLAW_AUTH_TOKEN}` | C3 |
| `gateway.controlUi.enabled` | _(unset)_ | `false` | — |
| `gateway.trustedProxies` | _(unset)_ | `[]` (set when not loopback) | — |
| `agents.defaults.sandbox.mode` | `"off"` | `"all"` | C4 |
| `agents.defaults.sandbox.docker.network` | _(shared)_ | `"isolated"` | M6 |
| `tools.exec.safeBins` | `true` | `true` (enforced) | CVE-2026-28363 |
| `tools.exec.host` | _(unset)_ | `"sandbox"` | C4 |
| `tools.elevated.enabled` | _(unset)_ | `false` | — |
| `tools.fs.workspaceOnly` | _(unset)_ | `true` | — |
| `tools.deny` | _(unset)_ | `["group:automation", "group:runtime", "group:fs"]` | — |
| `discovery.mdns.mode` | _(unset)_ | `"off"` | — |
| `logging.level` | `"info"` | `"verbose"` | C5 |
| `logging.redactSensitive` | _(unset)_ | `"tools"` | C5 |
| `session.dmScope` | _(unset)_ | `"per-channel-peer"` | — |
| `requireMention` | _(unset)_ | `true` | — |
| `plugins.allow` | _(unset)_ | `[]` (explicit allowlist) | — |
| `registry` | _(unset)_ | `"https://clawhub.ai"` | — |

### Tailscale Detection

g0 automatically detects Tailscale and adjusts recommendations:

- **Tailscale detected**: `gateway.bind` → `"tailnet"` (binds to Tailscale interface)
- **No Tailscale**: `gateway.bind` → `"loopback"` (localhost only)

### Manual Review

View recommendations without applying:

```bash
g0 scan . --openclaw-audit 2>&1 | grep -A3 "Recommendation"
```

### Hardened openclaw.json Example

```json
{
  "gateway": {
    "port": 18789,
    "bind": "tailnet",
    "auth": {
      "mode": "token",
      "token": "${OPENCLAW_AUTH_TOKEN}"
    },
    "controlUi": {
      "enabled": false
    },
    "trustedProxies": []
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "docker": {
          "network": "isolated"
        }
      }
    }
  },
  "tools": {
    "exec": {
      "safeBins": true,
      "host": "sandbox"
    },
    "elevated": {
      "enabled": false
    },
    "fs": {
      "workspaceOnly": true
    },
    "deny": ["group:automation", "group:runtime", "group:fs"]
  },
  "logging": {
    "level": "verbose",
    "redactSensitive": "tools"
  },
  "discovery": {
    "mdns": {
      "mode": "off"
    }
  },
  "session": {
    "dmScope": "per-channel-peer"
  },
  "requireMention": true,
  "plugins": {
    "allow": ["@guard0/openclaw-plugin"],
    "entries": {
      "@guard0/openclaw-plugin": {
        "config": {
          "webhookUrl": "http://localhost:6040/events",
          "detectInjection": true,
          "scanPii": true
        }
      }
    }
  },
  "registry": "https://clawhub.ai"
}
```

---

## Step 3: Risk Acceptance

Some findings may be expected in your environment (e.g., Tailscale handles TLS). Use risk acceptance to acknowledge these without failing the audit.

### Configure .g0.yaml

Create or edit `.g0.yaml` in your project root:

```yaml
# .g0.yaml — g0 configuration
preset: balanced

risk_accepted:
  # Tailscale handles network-level auth
  - rule: OC-H-003
    reason: "Control UI accessed only via Tailscale — device pairing not needed"

  # Tailscale provides TLS
  - rule: OC-H-009
    reason: "TLS terminated by Tailscale tunnel"

  # Note: OC-H-001 and OC-H-002 no longer need risk acceptance — g0 automatically
  # detects SPA catch-all responses and marks them as PASS (not a real health endpoint).

  # Temporary acceptance with expiry
  - rule: OC-H-028
    reason: "Session encryption planned for Q2 2026"
    expires: "2026-07-01"
```

### How It Works

- Accepted findings show as **ACCEPTED** (green badge) instead of FAIL
- Accepted findings are excluded from the failure count
- Expired acceptances automatically revert to FAIL
- The `reason` field is shown in the audit output for transparency

### Output with Risk Acceptance

```
  C3    OC-H-003    Control UI without device pairing      [CRITICAL]  ACCEPTED
        Control UI accessed only via Tailscale — device pairing not needed
  C9    OC-H-009    TLS enforcement absent                 [HIGH]      ACCEPTED
        TLS terminated by Tailscale tunnel

  Summary
  ──────────────────────────────────────────────────────────────────────────────
  Overall: WARN  (15 checks)
  Passed: 4  Failed: 5  Accepted: 4  Errors: 0  Skipped: 2
```

---

## Step 4: Egress Filtering

**Finding:** Agents can make outbound connections to any destination without restriction.

### Configure Egress Allowlist

Add allowed destinations to your daemon config:

```json
// ~/.g0/daemon.json
{
  "openclaw": {
    "enabled": true,
    "agentDataPath": "/data/.openclaw/agents",
    "egressAllowlist": [
      "api.openai.com",
      "api.anthropic.com",
      "api.notion.com",
      "100.64.0.0/10",
      "10.0.0.0/8"
    ],
    "egressIntervalSeconds": 60
  },
  "enforcement": {
    "applyEgressRules": true
  }
}
```

### How It Works

1. **g0 generates iptables rules** from your `egressAllowlist`
2. Rules are applied to the `DOCKER-USER` chain (affects all Docker containers)
3. DNS resolution happens at rule generation time for hostname entries
4. The fast egress loop checks every 60 seconds for violations
5. Violations trigger immediate webhook alerts

### Generated iptables Rules

```bash
# Allow established connections
iptables -I DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow DNS
iptables -I DOCKER-USER -p udp --dport 53 -j ACCEPT

# Allow specific destinations
iptables -I DOCKER-USER -d 104.18.6.192 -j ACCEPT   # api.openai.com
iptables -I DOCKER-USER -d 160.79.104.16 -j ACCEPT   # api.anthropic.com
iptables -I DOCKER-USER -d 10.0.0.0/8 -j ACCEPT      # Internal

# Default deny
iptables -I DOCKER-USER -j DROP
```

### Manual Application

If you prefer to apply rules manually:

```bash
# Generate rules as a script
g0 scan . --openclaw-audit --json | jq -r '.egressRules.script' > egress-rules.sh

# Review and apply
chmod +x egress-rules.sh
sudo ./egress-rules.sh
```

---

## Step 5: Secret Management

**Finding:** Multiple agents share the same API keys.

### Fix

1. **Issue unique API keys per agent** — each agent should have its own credential set
2. **Use a secret manager** instead of `.env` files:

```yaml
# docker-compose.yml
services:
  agent-1:
    environment:
      - OPENAI_API_KEY_FILE=/run/secrets/agent1_openai_key
    secrets:
      - agent1_openai_key

secrets:
  agent1_openai_key:
    external: true  # From Docker Swarm secrets, Vault, or AWS SSM
```

3. **Set file permissions** on any `.env` files:

```bash
chmod 600 /data/.openclaw/agents/*/.env
```

g0 detects duplicate credential groups automatically during the deployment audit.

### Never Pass Secrets via `-e` Flags (OC-H-064)

**Finding:** Secrets passed as `docker run -e SECRET_KEY=value` are visible to **every user on the host** via `ps aux` or `/proc/{pid}/cmdline`. This is a critical exposure that g0 now detects automatically.

**Bad — visible in process list:**

```bash
# Anyone on the host can see this secret:
docker run -e OPENAI_API_KEY=sk-proj-abc123... openclaw-agent
```

**Good — use Docker secrets or `--env-file`:**

```bash
# Option 1: Docker secrets (Swarm mode)
echo "sk-proj-abc123..." | docker secret create agent1_openai_key -

# Option 2: env-file with restricted permissions
echo "OPENAI_API_KEY=sk-proj-abc123..." > /data/.openclaw/agents/agent-1/.env
chmod 600 /data/.openclaw/agents/agent-1/.env
docker run --env-file /data/.openclaw/agents/agent-1/.env openclaw-agent

# Option 3: Mount secret as a file
docker run -v /data/secrets/openai_key:/run/secrets/openai_key:ro openclaw-agent
```

g0 inspects running container environment variables and flags any sensitive values (API keys, tokens, passwords, credentials) that are passed inline rather than via files or secret stores.

---

## Step 6: Docker Socket Isolation

**Finding:** Docker socket (`/var/run/docker.sock`) is mounted in agent containers.

### Fix

Remove the Docker socket mount from your `docker-compose.yml`:

```yaml
# BEFORE (vulnerable)
services:
  agent:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # REMOVE THIS

# AFTER (hardened)
services:
  agent:
    volumes:
      - agent-data:/data
    # No docker.sock mount
```

If Docker API access is genuinely needed, use a read-only socket proxy:

```yaml
services:
  docker-proxy:
    image: tecnativa/docker-socket-proxy
    environment:
      - CONTAINERS=1
      - IMAGES=0
      - EXEC=0
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "127.0.0.1:2375:2375"
```

---

## Step 7: Data Privacy Boundaries

**Finding:** Agent containers can read each other's data directories.

### Fix

1. **Set file permissions:**

```bash
chmod 700 /data/.openclaw/agents/*/
chmod 600 /data/.openclaw/agents/*/.env
```

2. **Use separate Docker volumes per agent:**

```yaml
services:
  agent-1:
    volumes:
      - agent1-data:/data/.openclaw/agents/agent-1
  agent-2:
    volumes:
      - agent2-data:/data/.openclaw/agents/agent-2

volumes:
  agent1-data:
  agent2-data:
```

3. **Enable sandbox mode** in `openclaw.json`:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "docker": {
          "network": "isolated"
        }
      }
    }
  }
}
```

---

## Step 8: Observability

**Finding:** No per-agent audit trail — tool calls, file access, and network connections are not logged.

This is the most comprehensive finding. g0 addresses it with four layers:

### Layer 1: OpenClaw Built-in Logging

In `openclaw.json`:

```json
{
  "logging": {
    "level": "verbose",
    "toolCalls": true,
    "style": "json"
  }
}
```

### Layer 2: OpenTelemetry

OpenClaw v2026.2+ has native OTEL support:

```json
{
  "diagnostics": {
    "otel": {
      "endpoint": "http://localhost:4318",
      "protocol": "http/protobuf",
      "serviceName": "openclaw-gateway",
      "sampleRate": 1.0,
      "logs": true
    }
  }
}
```

Run an OTEL collector with your preferred backend (Jaeger, Grafana, Datadog):

```yaml
# docker-compose.yml addition
services:
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.96.0
    volumes:
      - ./otel-config.yaml:/etc/otelcol-contrib/config.yaml
    ports:
      - "4318:4318"   # OTLP HTTP
```

### Layer 3: auditd Rules

g0 generates Linux audit rules for kernel-level file and network monitoring:

```bash
# g0 generates rules automatically during audit
# Manual install:
sudo cp g0-openclaw.rules /etc/audit/rules.d/
sudo augenrules --load
sudo systemctl restart auditd
```

Generated rules cover:
- File access monitoring on agent data directories
- Docker socket and config access
- Network syscalls (connect, bind, accept)
- Process execution monitoring (sensitive binaries)
- Credential and identity file access

### Layer 4: g0 OpenClaw Plugin

See [Step 13](#step-13-g0-openclaw-plugin) for in-process tool call logging, injection detection, and PII scanning.

---

## Step 9: Container Hardening

**Finding:** Agent containers run as root (UID 0).

### Fix

Add a non-root user to your Dockerfile:

```dockerfile
# At the end of your Dockerfile
RUN addgroup --gid 1000 openclaw && \
    adduser --uid 1000 --gid 1000 --disabled-password openclaw
USER 1000:1000
```

Or in `docker-compose.yml`:

```yaml
services:
  agent:
    user: "1000:1000"
```

Ensure data directories are owned by the new user:

```bash
sudo chown -R 1000:1000 /data/.openclaw/agents/
```

---

## Step 10: Network Isolation

**Finding:** All agent containers share the default Docker bridge network.

### Fix

Create isolated networks per agent:

```yaml
services:
  agent-1:
    networks:
      - agent1-net
  agent-2:
    networks:
      - agent2-net
  gateway:
    networks:
      - agent1-net
      - agent2-net
      - external

networks:
  agent1-net:
    internal: true
  agent2-net:
    internal: true
  external:
```

The `internal: true` flag prevents containers on that network from reaching the internet directly — all external traffic must go through the gateway.

---

## Step 11: Log Rotation

**Finding:** Docker log rotation is not configured.

### Fix

Add to `/etc/docker/daemon.json`:

```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Then restart Docker:

```bash
sudo systemctl restart docker
```

---

## Step 12: Additional Checks

### C7: Backups

Set up automated backups with cron:

```bash
# /etc/cron.d/openclaw-backup
0 2 * * * root tar czf /backup/openclaw-$(date +\%Y\%m\%d).tar.gz \
  /data/.openclaw/agents/ \
  /opt/openclaw/openclaw.json \
  /data/.openclaw/sessions/
```

### L1: Session Transcript Encryption

Enable encryption-at-rest for session `.jsonl` files:

```bash
# Option 1: LUKS encrypted volume
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup luksOpen /dev/sdX openclaw-sessions
sudo mkfs.ext4 /dev/mapper/openclaw-sessions
sudo mount /dev/mapper/openclaw-sessions /data/.openclaw/sessions

# Option 2: Application-level (future OpenClaw feature)
# Set in openclaw.json when available:
# { "sessions": { "encryption": "aes-256-gcm" } }
```

### L2: Docker Image Scanning

Add Trivy to your CI pipeline:

```yaml
# .github/workflows/image-scan.yml
- name: Scan Docker image
  run: |
    trivy image --severity CRITICAL,HIGH --exit-code 1 openclaw:latest
```

### L3: Overprivileged Environment Variables

Audit environment variables per agent and remove unused keys:

```bash
# Use env_file with minimal scoped credentials
# agent-1.env — only the keys this agent needs
OPENAI_API_KEY=sk-...
NOTION_TOKEN=ntn_...
# Do NOT include: SLACK_TOKEN, AWS_ACCESS_KEY, etc.
```

### Backup Encryption & Retention (OC-H-034)

If a backup tool is detected (restic, borg), g0 verifies encryption is enabled and a retention policy exists:

```bash
# restic: encryption is on by default, but verify
restic cat config

# borg: use repokey encryption
borg init --encryption=repokey-blake2 /backup/openclaw

# Add retention to crontab
0 3 * * * restic backup /data/.openclaw --keep-daily 7 --keep-weekly 4 --prune
```

### Kernel Reboot Pending (OC-H-035)

g0 checks whether the host needs a reboot for pending kernel security patches:

```bash
# Debian/Ubuntu: check for reboot-required
test -f /var/run/reboot-required && echo "Reboot needed"

# RHEL/CentOS
needs-restarting -r

# Add to CI/CD pipeline as a gate
test ! -f /var/run/reboot-required || (echo "FAIL: reboot required" && exit 1)
```

### Tailscale Account & ACL (OC-H-036)

For deployments using Tailscale, g0 checks whether you're using an organization account (not personal email) and whether ACLs are configured:

```bash
# Check current account type
tailscale status --json | jq '.CurrentTailnet.Name'
# personal email (user@gmail.com) = warning
# organization domain (corp.com) = OK

# Configure ACLs in Tailscale admin console to restrict gateway access
```

### Auto-Fix (`--fix`)

g0 can automatically fix certain failed checks:

```bash
g0 scan . --openclaw-audit --fix
```

| Failed Check | Auto-Fix Action |
|---|---|
| OC-H-022 (file permissions) | `chmod 600` on all `.env`/credential files (creates backup first) |
| OC-H-026 (log rotation) | Writes log rotation config to `/etc/docker/daemon.json` |
| OC-H-028 (session encryption) | Guidance only (requires manual LUKS/dm-crypt setup) |

### AI Attack Chain Analysis (`--ai`)

Add `--ai` to get AI-powered attack chain correlation and prioritized remediation:

```bash
g0 scan . --openclaw-audit --ai
```

The AI analyzes all failed checks together and identifies:
- **Attack chains**: how multiple failures combine to enable real attacks
- **Prioritized remediation**: which fix to apply first to break the most chains
- **Risk narrative**: overall deployment risk assessment

---

## Step 13: g0 OpenClaw Plugin

The `@guard0/g0-openclaw-plugin` package runs inside the OpenClaw gateway process, hooking into the plugin lifecycle to provide real-time security enforcement — blocking, redaction, and event streaming happen inline with zero latency.

### Install

```bash
# Via OpenClaw plugin manager (recommended)
openclaw plugins install @guard0/g0-openclaw-plugin

# Or via npm
npm install @guard0/g0-openclaw-plugin
```

### Configure

Add to `openclaw.json`:

```json
{
  "plugins": {
    "allow": ["g0-openclaw-plugin"],
    "entries": {
      "g0-openclaw-plugin": {
        "enabled": true,
        "config": {
          "webhookUrl": "http://localhost:6040/events",
          "blockedTools": [],
          "highRiskTools": ["bash", "exec", "write_file", "http_request", "sql_query", "send_email"],
          "logToolCalls": true,
          "detectInjection": true,
          "scanPii": true,
          "injectPolicy": true,
          "registerGateTool": true,
          "blockOutboundPii": true,
          "monitorLlm": true,
          "trackSessions": true,
          "authToken": "your-daemon-token"
        }
      }
    }
  }
}
```

Restart OpenClaw after configuration:

```bash
openclaw restart
# Verify plugin is loaded
openclaw plugins doctor
```

### What It Does

The plugin registers 17 hooks across 3 execution models + 1 agent-callable tool:

**Security hooks (can block/modify):**

| Hook | Action |
|------|--------|
| `before_tool_call` | Blocks denied tools (`{ block: true }`), detects injection in tool arguments, logs high-risk tool calls |
| `message_sending` | Blocks outbound messages containing sensitive PII (SSN, credit card, API key) |
| `subagent_spawning` | Gates subagent creation, can block spawning of denied agents |
| `before_agent_start` | Injects Guard0 security policy into agent context |

**PII redaction hooks (synchronous, inline):**

| Hook | Action |
|------|--------|
| `tool_result_persist` | Scans tool output for PII, redacts before persistence to session JSONL |
| `before_message_write` | Redacts PII from any message before it's written to session storage |

**Detection hooks (observe, fire-and-forget):**

| Hook | Action |
|------|--------|
| `message_received` | Scans inbound chat messages for injection patterns |
| `llm_input` | Detects late-stage injection in assembled LLM history context |
| `llm_output` | Detects PII/credential leakage in model responses |
| `after_tool_call` | Logs high-risk tool results and errors with timing |

**Lifecycle hooks (telemetry):**

| Hook | Action |
|------|--------|
| `session_start` / `session_end` | Session lifecycle tracking for daemon correlation |
| `agent_end` | Agent run metadata (success, duration, message count) |
| `subagent_spawned` / `subagent_ended` | Subagent lifecycle tracking |
| `gateway_start` / `gateway_stop` | Gateway lifecycle |

**Registered tool:**

| Tool | Action |
|------|--------|
| `g0_security_check` | Agent-callable gate — checks commands against 14 destructive patterns and file paths against 15 sensitive patterns. Returns ALLOWED/DENIED with reasoning. |

### Injection Detection

17 patterns with severity-based scoring:

- **High**: instruction override, role-play attacks, jailbreak markers, delimiter injection, HTML comment injection, script/iframe injection, constraint removal
- **Medium**: system prompt extraction, developer mode, encoded payloads, zero-width character obfuscation

Detection runs at 3 hook points: inbound messages, LLM history context, and tool arguments. High-severity injection in tool arguments triggers automatic blocking.

### PII Redaction

7 PII types detected and redacted before persistence:

| Type | Example | Redaction |
|------|---------|-----------|
| Email | `user@example.com` | `[EMAIL_REDACTED]` |
| Phone (US) | `555-123-4567` | `[PHONE_US_REDACTED]` |
| SSN | `123-45-6789` | `[SSN_REDACTED]` |
| Credit Card | `4111111111111111` | `[CREDIT_CARD_REDACTED]` |
| API Key | `sk-...`, `AKIA...`, `ghp_...` | `[API_KEY_REDACTED]` |
| JWT | `eyJ...` | `[JWT_REDACTED]` |
| Private IP | `10.x.x.x`, `192.168.x.x` | `[IPV4_PRIVATE_REDACTED]` |

PII is redacted at two points: tool output (before the agent sees it) and message persistence (before it reaches disk). Outbound messages with sensitive PII (SSN, CC, API key) are blocked entirely.

### Tool Blocking

Tools in `blockedTools` are denied at the gateway level — the tool execution never happens. The plugin returns `{ block: true, blockReason: "..." }` from `before_tool_call`, and OpenClaw prevents execution. A `tool.blocked` event is sent to the daemon.

### Verify

After installation, confirm the plugin is working:

```bash
# Check plugin is loaded
openclaw plugins doctor

# Send a test agent message that triggers the security gate
openclaw agent --agent main --message "Use g0_security_check to check if 'rm -rf /' is safe"

# Check daemon received events
curl http://localhost:6040/events
```

You should see `security.gate` and `agent.end` events in the daemon.

---

## Step 14: Continuous Monitoring with g0 Daemon

The g0 daemon runs in the background and continuously monitors your OpenClaw deployment.

### Configure

```json
// ~/.g0/daemon.json
{
  "intervalMinutes": 30,
  "upload": true,
  "openclaw": {
    "enabled": true,
    "agentDataPath": "/data/.openclaw/agents",
    "gatewayUrl": "http://localhost:18789",
    "egressAllowlist": [
      "api.openai.com",
      "api.anthropic.com",
      "10.0.0.0/8"
    ],
    "egressIntervalSeconds": 60,
    "composePath": "/opt/openclaw/docker-compose.yml",
    "dockerDaemonConfigPath": "/etc/docker/daemon.json"
  },
  "alerting": {
    "webhookUrl": "https://hooks.slack.com/services/T.../B.../xxx",
    "format": "slack",
    "minSeverity": "high",
    "onChangeOnly": true,
    "notifications": {
      "mode": "interval",
      "intervalMinutes": 5
    }
  },
  "enforcement": {
    "applyEgressRules": true,
    "applyAuditdRules": true,
    "stopContainersOnCritical": false,
    "criticalThreshold": 2,
    "protectedContainers": ["openclaw-gateway"]
  },
  "eventReceiver": {
    "enabled": true,
    "port": 6040,
    "bind": "127.0.0.1",
    "authToken": "your-secret-token-here"
  },
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
    "group": "engineering"
  }
}
```

### Start the Daemon

```bash
g0 daemon start
g0 daemon status    # Check it's running
g0 daemon logs      # View recent logs
```

### What the Daemon Does

| Feature | Interval | Description |
|---------|----------|-------------|
| Full deployment audit | Every 30 min | All 18 OC-H checks |
| Fast egress scan | Every 60 sec | Outbound connections vs allowlist |
| Drift detection | Every tick | Detects status changes since last audit |
| Webhook alerting | On change | Sends alerts to Slack/Discord/PagerDuty |
| Plugin notifications | Configurable | Security event digests (interval) or per-event alerts (realtime) |
| Event receiver | Always on | HTTP server on port 6040 for plugin events |
| Enforcement | On violation | iptables rules, auditd rules, container stop |
| Platform upload | Every tick | Sends results to Guard0 Cloud dashboard |
| Host hardening | Every tick | OS-level security audit (firewall, encryption, SSH) |
| Agent watcher | Every tick | Detects running AI agents (Claude Code, Cursor, OpenClaw) |
| Fleet management | Every tick | Registers machine, aggregates scores, cross-machine correlation |
| Kill switch | Always on | Auto-activates on event pattern thresholds |
| Cost monitoring | Always on | Tracks token usage, trips circuit breaker at limits |
| Behavioral baseline | Always on | Learns normal patterns, detects anomalies |
| Correlation engine | On events | Cross-source attack chain detection (6 rules) |

### Event Receiver

The daemon runs an HTTP event receiver that accepts events from:

- **g0 OpenClaw Plugin** → `POST /events`
- **Falcosidekick** → `POST /falco`
- **Custom sources** → `POST /events` with `source` field

```bash
# Health check
curl http://localhost:6040/health

# View stats
curl http://localhost:6040/stats
```

Events are persisted to a JSONL file (default: `~/.g0/events.jsonl`) for post-incident analysis. The file automatically rotates at 100MB. Configure with:

```json
{
  "eventReceiver": {
    "enabled": true,
    "logFile": "/var/log/g0/events.jsonl"
  }
}
```

### Alerting Formats

| Format | Webhook URL Pattern |
|--------|-------------------|
| `slack` | `https://hooks.slack.com/services/...` |
| `discord` | `https://discord.com/api/webhooks/...` |
| `pagerduty` | `https://events.pagerduty.com/v2/enqueue` |
| `generic` | Any HTTP endpoint accepting JSON POST |

### Plugin Security Event Notifications

When the g0 OpenClaw plugin sends security events to the daemon (injection, tool-blocked, PII redaction), you can opt into notifications by adding `notifications` to your `alerting` config. By default, notifications are **off** — events are still logged and processed by the kill switch, behavioral baseline, and correlation engine.

#### Notification Modes

| Mode | Behavior | Use case |
|------|----------|----------|
| `off` | Default. No extra notifications. | Only want daemon-level alerts (existing behavior). |
| `interval` | Accumulates events, sends a single digest every `intervalMinutes` (default: 5). | Observe mode — periodic summary without noise. |
| `realtime` | Alerts on each event with rate limiting — max 1 alert per category per `rateLimitSeconds` (default: 60). Suppressed events are counted and included in the next alert. | Security teams who want immediate visibility. |

#### Interval Mode (Recommended)

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

Sends a single digest every 5 minutes grouping events by category:

```
🛡️ g0 Security Digest
─────────────────────────────
Period: 14:00–14:05 UTC   |  Total: 23 events
Host: prod-agent-1        |  Categories: 4
─────────────────────────────
🔴 injection.detected (7) — agents: canvas, workspace
  > Tool args injection: bash...
🟠 tool.blocked (3) — agents: canvas
  > curl blocked by security policy
🟡 pii (12) — agents: canvas, workspace, reports
  > 8 redacted, 4 blocked outbound
─────────────────────────────
🚨 Correlated Threats
  CT-001: Confirmed Injection (95% confidence)
```

#### Realtime Mode

```json
{
  "alerting": {
    "webhookUrl": "https://hooks.slack.com/services/...",
    "format": "slack",
    "notifications": {
      "mode": "realtime",
      "rateLimitSeconds": 60
    }
  }
}
```

Sends one alert per event, rate-limited per category. If 5 injections fire within the 60s cooldown, only the first sends immediately — the next alert after the cooldown includes "4 more since last alert".

#### Event Categories

| Category | Event Types | Default Severity |
|----------|-------------|------------------|
| `injection` | `injection.detected` | critical |
| `tool-blocked` | `tool.blocked` | high |
| `pii` | `pii.redacted`, `pii.blocked_outbound`, `pii.detected` | medium |
| `message-blocked` | `message.blocked` | high |
| `subagent-blocked` | `subagent.blocked` | high |
| `correlation` | CT-001..006 correlated threats | critical/high |

#### Settings Reference

| Setting | Default | Description |
|---------|---------|-------------|
| `notifications.mode` | `off` | `realtime`, `interval`, or `off` |
| `notifications.intervalMinutes` | `5` | Digest interval in minutes (interval mode) |
| `notifications.rateLimitSeconds` | `60` | Min seconds between alerts per category (realtime mode) |

---

## Step 15: Falco Runtime Detection (Optional)

g0 generates Falco rules for runtime container monitoring. Falco uses eBPF to observe syscalls without modifying your containers.

### Install Falco

```yaml
# Add to docker-compose.yml
services:
  falco:
    image: falcosecurity/falco:0.38.0
    privileged: true
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock:ro
      - /dev:/host/dev:ro
      - /proc:/host/proc:ro
      - /boot:/host/boot:ro
      - /lib/modules:/host/lib/modules:ro
      - ./falco-rules:/etc/falco/rules.d:ro
    depends_on:
      - falcosidekick

  falcosidekick:
    image: falcosecurity/falcosidekick:2.29.0
    environment:
      - WEBHOOK_ADDRESS=http://host.docker.internal:6040/falco
    ports:
      - "2801:2801"
```

### Generate Rules

g0 generates 9 Falco rules covering:

| Rule | Finding | What It Detects |
|------|---------|----------------|
| Unexpected egress | C1 | Outbound connections to non-allowlisted destinations |
| Cross-agent access | C4 | File reads across agent data boundaries |
| Credential access | C2/C4 | Reads of .env files in agent directories |
| Session access | L1 | Access to session transcript files |
| Root container | H1 | Processes running as UID 0 in OpenClaw containers |
| Sensitive binary | C5 | Execution of curl, wget, nc, ssh, etc. |
| Docker socket | C3 | Access to /var/run/docker.sock |
| Gateway exposure | — | Gateway bound to 0.0.0.0 (all interfaces) |
| Log tampering | C5 | Deletion or truncation of log files |

### Deploy Rules

```bash
# Rules are generated during g0 scan --openclaw-audit
# Copy to Falco rules directory:
cp g0-openclaw-falco.yaml /path/to/falco-rules/

# Falco picks up new rules automatically (hot-reload)
```

### Event Flow

```
Container syscall → Falco (eBPF) → Alert → Falcosidekick → g0 daemon (:6040/falco)
                                                          → Slack/PagerDuty
```

---

## Step 16: Tetragon Enforcement (Optional)

Tetragon provides eBPF-based **enforcement** — it can observe AND kill processes at the kernel level. Unlike Falco (detection-only), Tetragon can actively block violations.

### When to Use Tetragon

- You need to **prevent** (not just detect) unauthorized actions
- You want kernel-level enforcement that can't be bypassed from userspace
- You're comfortable running a privileged container

### Install Tetragon

```yaml
# Add to docker-compose.yml
services:
  tetragon:
    image: quay.io/cilium/tetragon:v1.3
    container_name: g0-tetragon
    restart: unless-stopped
    pid: host
    privileged: true
    volumes:
      - /sys/kernel:/sys/kernel:ro
      - /proc:/procHost:ro
      - ./tetragon-policies:/etc/tetragon/tetragon.tp.d:ro
```

### Generate Policies

g0 generates 6 Tetragon TracingPolicies:

| Policy | Finding | Syscall | Action |
|--------|---------|---------|--------|
| Egress enforcement | C1 | `sys_connect` | Block unauthorized outbound |
| Cross-agent access | C4 | `sys_openat` | Block file reads across boundaries |
| Docker socket | C3 | `sys_openat` + `sys_connect` | Block docker.sock access |
| Sensitive binary | C5 | `sys_execve` | Block curl/wget/nc/ssh |
| Credential protection | C2 | `sys_openat` | Block .env file reads |
| Log tampering | C5 | `sys_unlinkat` + `sys_truncate` | Block log deletion |

### Observe vs Enforce Mode

**Observe mode** (default — safe to start with):
```bash
# Events are logged but nothing is blocked
# Events forwarded to g0 daemon via webhook
```

**Enforce mode** (SIGKILL on violation):
```bash
# Processes are killed at the kernel level when violations occur
# Use with caution — test in observe mode first
```

Configure mode in daemon.json — g0 generates policies accordingly.

### Deploy Policies

```bash
# Policies are generated during g0 scan --openclaw-audit
# Copy to Tetragon policy directory:
cp g0-openclaw-*.yaml /path/to/tetragon-policies/

# Tetragon loads policies on startup
docker-compose restart tetragon
```

### Event Forwarding

Forward Tetragon events to the g0 daemon:

```bash
# In a separate container or sidecar:
tetra getevents -o json | while read line; do
  curl -s -X POST http://localhost:6040/events \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer your-secret-token" \
    -d "{\"source\":\"tetragon\",\"type\":\"tetragon.event\",\"data\":$line}"
done
```

---

## Architecture Overview

After implementing all steps, your deployment looks like this:

```
┌─────────────────────────────────────────────────────────┐
│  Customer Host                                          │
│                                                         │
│  ┌─────────────────────────────────────────────┐       │
│  │  OpenClaw Gateway (port 18789)              │       │
│  │  └── @guard0/openclaw-plugin (in-process)   │       │
│  │      ├── preToolExecution → block + log     │       │
│  │      ├── preRequest → injection detection   │       │
│  │      ├── postToolExecution → PII scan       │       │
│  │      └── webhook ──────────────────────────────┐    │
│  └─────────────────────────────────────────────┘  │    │
│                                                    │    │
│  ┌─────────────────────────────────────────────┐  │    │
│  │  g0 Daemon                                  │  │    │
│  │  ├── Full audit tick (30m)                  │◄─┘    │
│  │  ├── Fast egress loop (60s)                 │       │
│  │  ├── Event receiver (:6040)  ◄── Falco ─────────┐  │
│  │  ├── Drift detection                        │    │  │
│  │  ├── Webhook alerting → Slack/PagerDuty     │    │  │
│  │  ├── Enforcement (iptables, auditd)         │    │  │
│  │  ├── Kill switch (auto-activation)             │       │
│  │  ├── Cost monitor (circuit breaker)             │       │
│  │  ├── Behavioral baseline (anomaly detection)    │       │
│  │  ├── Correlation engine (6 attack chain rules)  │       │
│  │  ├── Host hardening audit                       │       │
│  │  ├── Agent watcher (Claude, Cursor, OpenClaw)   │       │
│  │  ├── Fleet management                           │       │
│  └─────────────────────────────────────────────┘    │  │
│                                                      │  │
│  ┌──────────────────┐  ┌────────────────────────┐   │  │
│  │  iptables        │  │  auditd                │   │  │
│  │  DOCKER-USER     │  │  g0-openclaw.rules     │   │  │
│  │  (generated)     │  │  (generated)           │   │  │
│  └──────────────────┘  └────────────────────────┘   │  │
│                                                      │  │
│  ┌──────────────────┐  ┌────────────────────────┐   │  │
│  │  Falco (eBPF)    │──┤  Falcosidekick        │───┘  │
│  │  9 rules         │  │  webhook → :6040       │      │
│  │  (generated)     │  └────────────────────────┘      │
│  └──────────────────┘                                   │
│                                                         │
│  ┌──────────────────┐  (Optional)                      │
│  │  Tetragon (eBPF) │                                  │
│  │  6 policies      │  ← Observe or Enforce mode       │
│  │  (generated)     │                                  │
│  └──────────────────┘                                   │
└─────────────────────────────────────────────────────────┘
```

### Finding Coverage Matrix

| Finding | Detection | Prevention | Tool |
|---------|-----------|------------|------|
| C1 Egress | g0 egress monitor (60s) | iptables DOCKER-USER + Tetragon | g0 daemon |
| C2 Secrets | g0 deployment audit | Per-agent credentials | g0 scan |
| C3 Docker socket | g0 audit + Falco | Remove mount + Tetragon | g0 + Falco |
| C4 Data privacy | g0 audit + Falco | Sandbox mode + volumes + Tetragon | g0 + config |
| C5 Observability | Plugin + auditd + OTEL | N/A (detection) | Full stack |
| C7 Backups | g0 audit | cron/systemd timer | g0 scan |
| H1 Root container | g0 audit + Falco | USER directive | g0 + config |
| M1 Log rotation | g0 audit | daemon.json config | g0 scan |
| M6 Shared network | g0 audit | Isolated Docker networks | g0 + config |
| L1 Sessions | g0 audit | LUKS/dm-crypt | g0 scan |
| L2 Image scanning | g0 audit | Trivy in CI | g0 scan |
| L3 Overprivileged env | g0 audit + Plugin | env_file scoping | g0 + config |
| FORNS Session forensics | g0 deployment audit | N/A | g0 scan |
| Container deep audit | g0 audit (8 checks) | Docker config | g0 scan |
| Host hardening | g0 daemon + scan | OS config | g0 endpoint |

---

## Configuration Reference

### .g0.yaml

```yaml
# Scan preset
preset: balanced           # strict | balanced | permissive

# Minimum confidence level for findings
min_confidence: medium     # low | medium | high

# Risk acceptance
risk_accepted:
  - rule: OC-H-003
    reason: "Tailscale-only access"
  - rule: OC-H-009
    reason: "TLS via Tailscale"
    expires: "2027-01-01"

# Exclude paths from scanning
exclude_paths:
  - tests/
  - node_modules/

# Exclude specific rules
exclude_rules:
  - AA-TS-065
```

### ~/.g0/daemon.json

```json
{
  "intervalMinutes": 30,
  "upload": true,
  "watchPaths": ["/opt/openclaw"],

  "openclaw": {
    "enabled": true,
    "agentDataPath": "/data/.openclaw/agents",
    "gatewayUrl": "http://localhost:18789",
    "egressAllowlist": ["api.openai.com", "api.anthropic.com"],
    "egressIntervalSeconds": 60,
    "composePath": "/opt/openclaw/docker-compose.yml",
    "dockerDaemonConfigPath": "/etc/docker/daemon.json"
  },

  "alerting": {
    "webhookUrl": "https://hooks.slack.com/services/...",
    "format": "slack",
    "minSeverity": "high",
    "onChangeOnly": true
  },

  "enforcement": {
    "applyEgressRules": true,
    "applyAuditdRules": true,
    "stopContainersOnCritical": false,
    "criticalThreshold": 2,
    "protectedContainers": ["openclaw-gateway"]
  },

  "eventReceiver": {
    "enabled": true,
    "port": 6040,
    "bind": "127.0.0.1",
    "authToken": "generate-a-strong-token-here"
  }
}
```

### openclaw.json (Security-Relevant Fields)

```json
{
  "gateway": {
    "port": 18789,
    "bind": "tailnet",
    "auth": { "mode": "token", "token": "${OPENCLAW_AUTH_TOKEN}" }
  },
  "agents": {
    "defaults": {
      "sandbox": { "mode": "all", "docker": { "network": "isolated" } }
    }
  },
  "tools": {
    "exec": { "safeBins": true, "host": "sandbox" },
    "elevated": { "enabled": false },
    "fs": { "workspaceOnly": true },
    "deny": ["group:automation", "group:runtime", "group:fs"]
  },
  "logging": { "level": "verbose", "redactSensitive": "tools" },
  "discovery": { "mdns": { "mode": "off" } },
  "session": { "dmScope": "per-channel-peer" },
  "requireMention": true,
  "plugins": {
    "allow": ["@guard0/openclaw-plugin"],
    "entries": {
      "@guard0/openclaw-plugin": {
        "config": { "webhookUrl": "http://localhost:6040/events" }
      }
    }
  },
  "registry": "https://clawhub.ai"
}
```

---

## Troubleshooting

### "No OpenClaw deployment detected"

g0 looks for OpenClaw indicators in these locations:
- `openclaw.json` in the project directory
- Docker containers matching `openclaw-*` or `oc-agent-*`
- Agent data directory specified in `daemon.json`

Ensure your `agentDataPath` is correct in `~/.g0/daemon.json`.

### Daemon won't stay alive / exits immediately

If `g0 daemon start` reports a PID but the process dies immediately:

1. **Check the startup log** — errors during early initialization are captured here:

```bash
cat ~/.g0/daemon-startup.log
```

2. **Check the daemon log** — if the daemon survived past initial startup:

```bash
g0 daemon logs
```

3. **Common causes:**
   - Missing Node.js modules — reinstall g0: `npm install -g @guard0/g0`
   - Corrupt `daemon.json` — validate: `cat ~/.g0/daemon.json | python3 -m json.tool`
   - No swap + high memory pressure — the OOM killer may be terminating the process. Check `dmesg | grep -i oom`

4. If the startup log is empty, the runner script could not be located. Verify the installation:

```bash
ls $(dirname $(which g0))/../lib/node_modules/@guard0/g0/dist/src/daemon/runner.js
```

### "iptables: Permission denied"

Egress rule application requires root/sudo. Either:
- Run the daemon as root
- Use `enforcement.applyEgressRules: false` and apply rules manually

### "Event receiver: Address already in use"

Port 6040 is already in use. Change the port in daemon.json:

```json
{ "eventReceiver": { "port": 6041 } }
```

Update the webhook URL in `openclaw.json` plugin config accordingly.

### "Falco: No matching rules"

Ensure the generated Falco rules file is in Falco's rules directory:

```bash
ls /etc/falco/rules.d/g0-openclaw-falco.yaml
```

Falco hot-reloads rules — no restart needed after placing the file.

### "auditd: No rules loaded"

After copying rules, reload auditd:

```bash
sudo augenrules --load
sudo systemctl restart auditd
sudo auditctl -l    # Verify rules are loaded
```

### False Positives in Static Scan

If you see false positives like SQL injection on logger lines:
1. g0 v1.5.0+ includes fixes for common FPs (e.g., AA-CE-012 on Python f-string logging)
2. Add specific rules to `exclude_rules` in `.g0.yaml`
3. Use `--min-confidence medium` (default) to hide low-confidence generic findings

---

## Related Documentation

- [OpenClaw Security Guide](openclaw-security.md) — Static scanning, supply-chain auditing, adversarial testing, live hardening
- [Endpoint Monitoring](endpoint-monitoring.md) — Developer endpoint assessment and fleet monitoring
- [Dynamic Testing](dynamic-testing.md) — Adversarial testing with OpenClaw-specific payloads
- [Compliance Mapping](compliance.md) — OWASP, NIST, ISO standards mapping
