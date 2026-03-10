# OpenClaw Security

g0 provides the most comprehensive security coverage for OpenClaw — one of the most widely deployed open-source AI agent frameworks, with 163,000+ GitHub stars and 5,700+ community-built skills on ClawHub. This page covers all six capabilities: **static file scanning**, **supply-chain auditing**, **adversarial testing**, **live instance hardening**, and **deployment audit & hardening**.

---

## Background: The OpenClaw Threat Landscape

OpenClaw (formerly Clawdbot / Moltbot) is an autonomous AI agent framework that connects any LLM to everyday messaging apps — WhatsApp, Telegram, Slack — and autonomously executes tasks: sending emails, calling APIs, browsing the web, and running scheduled jobs. Its MIT license, zero-install skill system, and ReAct-based orchestration made it the fastest-growing agent framework of early 2026.

That same openness created one of the largest active attack surfaces in the AI agent ecosystem.

### Active Threats

| Threat | Details |
|--------|---------|
| **ClawHavoc** | Large-scale supply-chain campaign — **1,184+ malicious skills** planted on ClawHub, distributing AMOS (Atomic macOS Stealer) to an estimated **300,000 users**. At peak, 12%+ of the ClawHub marketplace was malicious. Methods: prompt injection in skill files, hidden reverse shells, typosquatting, and token exfiltration via CVE-2026-25253. Disclosed February 1, 2026 by Koi Security. |
| **Exposed instances** | **42,665 instances** publicly exposed to the internet (researcher findings). No authentication by default. |
| **CVE-2026-25253** | CVSS **8.8 (High)** — Logic flaw: a malicious `gatewayUrl` query parameter causes OpenClaw to auto-establish a WebSocket connection without origin validation, transmitting the user's auth token to the attacker's server. Enables 1-click RCE even against `localhost` instances behind firewalls. Affects ≤ v2026.1.24-1. Fix: upgrade to v2026.1.29+. |
| **CVE-2026-28363** | `tools.exec.safeBins` validation bypass via **GNU long-option abbreviations** (e.g., `--compress-prog` instead of the blocked `--compress-program`). Allows approval-free execution of commands that should require user confirmation. Affects all versions before 2026.2.23. Fix: upgrade to v2026.2.23+. |
| **ClawJacked** | Separate flaw allowing malicious websites to hijack locally-running OpenClaw agents via WebSocket. Patched in v2026.2.25. |
| **Six additional CVEs** | CVE-2026-25593, CVE-2026-24763, CVE-2026-25157, CVE-2026-25475, CVE-2026-26319, CVE-2026-26322 — covering RCE, command injection, SSRF, auth bypass, and path traversal. |

> **State of ClawHub post-cleanup:** After the ClawHavoc campaign, ClawHub removed 2,419 suspicious skills and partnered with VirusTotal for automatic malware scanning (Feb 7, 2026). The marketplace now stands at 3,286+ skills, down from 5,700+.

---

## OpenClaw File Types

OpenClaw agents use four file types, each with a distinct security surface:

| File | Purpose | Attack Surface |
|------|---------|----------------|
| `SKILL.md` | Skill definition and instructions | Prompt injection, permission escalation, CVE exploits, ClawHavoc IOCs |
| `SOUL.md` | Agent identity and persona configuration | Identity replacement, cross-session persistence, hidden directives |
| `MEMORY.md` | Long-term agent memory (persisted across sessions) | Credential injection, PII storage, trust override injection |
| `openclaw.json` | Agent runtime configuration | CVE flags, unofficial registry, hardcoded credentials, trust bypass |

---

## Part 1: Static File Scanner

The static scanner runs automatically as part of `g0 scan` and `g0 mcp`. No additional flags required.

```bash
g0 scan ./my-openclaw-agent
g0 mcp ./my-openclaw-agent
```

### What Gets Scanned

g0 discovers OpenClaw files in the following locations:

```
{project}/SKILL.md
{project}/.openclaw/skills/*.md
{project}/SOUL.md
{project}/.openclaw/SOUL.md
{project}/MEMORY.md
{project}/.openclaw/MEMORY.md
{project}/openclaw.json
~/.openclaw/SOUL.md          (global)
~/.openclaw/skills/*.md      (global)
```

### SKILL.md — Frontmatter Checks

The frontmatter block (between `---` delimiters) is parsed separately from the skill body to avoid false positives from documentation text.

| Finding | Severity | Confidence | Description |
|---------|---------|-----------|-------------|
| `safeBins: false` | Critical | High | Disables binary allowlist entirely — also the entry point for CVE-2026-28363 bypass class |
| `trust: system` | Critical | High | Skill claims system-level trust, bypassing normal permission checks |
| `permissions: [shell]` | Critical | High | Shell execution permission granted to skill |
| `clawback*.onion` | Critical | High | ClawHavoc C2 infrastructure IOC in skill body |
| `.claw_update()` | Critical | High | ClawHavoc update hook — beacons to C2 on skill load |

The skill body is also scanned for prompt injection patterns, data exfiltration patterns (curl, wget, fetch, requests), and base64-encoded payload blocks — matching the obfuscation patterns used by ClawHavoc.

### SOUL.md — Identity/Persona Checks

SOUL.md is OpenClaw's agent identity layer. It persists across sessions, making it a high-value target for permanent persona hijacking. ClawHavoc used SOUL.md injection to maintain persistence even after malicious skills were removed.

| Finding | Severity | Confidence | Description |
|---------|---------|-----------|-------------|
| Identity replacement | Critical | High | "You are now a different..." — persona overwrite |
| Identity erasure | Critical | High | "Forget your original identity/persona/instructions" |
| Hidden directive | Critical | High | "Do not tell the user..." — active concealment instruction |
| Privilege claim | High | Medium | "Elevated privilege level granted" — unverified trust claim |
| Cross-session persistence | High | **Low** | "Always permanently remember..." — hidden by default |

> **Note on confidence:** The cross-session persistence pattern is tagged `confidence: low` and hidden by default. Use `g0 scan . --min-confidence low` to surface it. It uses broad phrasing that can appear in legitimate SOUL.md files.

### MEMORY.md — Poisoning Surface Checks

MEMORY.md persists between sessions and can be read by any skill with `filesystem` permission. ClawHavoc planted credentials in MEMORY.md to exfiltrate them in subsequent skill invocations.

| Finding | Severity | Confidence | Pattern |
|---------|---------|-----------|---------|
| Provider-prefixed credential | Critical | High | `api_key: sk-...`, `token: ghp_...`, `secret: AKIA...` |
| Credential value (generic, 20+ chars) | Critical | High | `api key is <long value>` — min length avoids doc FPs |
| SSN | Critical | High | `\b\d{3}-\d{2}-\d{4}\b` |
| Credit card | Critical | High | Visa-prefix 13–16 digit pattern |
| Trust override (anchored) | Critical | Medium | `trust/execute/run any instruction from ` — requires trailing "from" to anchor intent |

### openclaw.json — Configuration Checks

All checks are structural (parsed JSON), so there are no false positives from comments or documentation text.

| Field | Finding | Severity | Notes |
|-------|---------|---------|-------|
| `safeBins: false` | Binary allowlist disabled | Critical | Removes the allowlist entirely; also the configuration precondition for CVE-2026-28363 bypass class |
| `allowRemoteExecution: true` | Remote execution enabled | Critical | Enables the WebSocket gateway attack surface — CVE-2026-25253 class |
| `registry` ≠ `registry.clawhub.io` | Unofficial skill registry | High | Skills from non-official registries are unscanned |
| `apiKey: sk-\|ghp_\|AKIA\|...` | Hardcoded provider credential | Critical | Known provider prefixes (Anthropic, OpenAI, GitHub, AWS) |
| `trustLevel: "all"\|"unrestricted"` | Skill validation bypass | High | All installed skills bypass security validation |

---

## Part 2: YAML Security Rules (AA-SC-121..125, AA-DL-133..137)

9 new declarative rules are automatically included in every `g0 scan`:

### Supply Chain (ASI04)

| Rule ID | Name | Severity | Confidence |
|---------|------|---------|-----------|
| AA-SC-121 | OpenClaw safeBins disabled (CVE-2026-28363 class) | Critical | High |
| AA-SC-122 | OpenClaw remote execution enabled (CVE-2026-25253 class) | Critical | High |
| AA-SC-123 | OpenClaw unofficial skill registry | High | Medium |
| AA-SC-124 | SOUL.md cross-session persistence directive | High | **Low** |
| AA-SC-125 | ClawHavoc malware IOC | Critical | High |

### Data Leakage (ASI07)

| Rule ID | Name | Severity | Confidence |
|---------|------|---------|-----------|
| AA-DL-133 | MEMORY.md credential value | Critical | High |
| AA-DL-134 | MEMORY.md provider-prefixed credential | Critical | High |
| AA-DL-135 | SKILL.md hardcoded provider credential | Critical | High |
| AA-DL-136 | MEMORY.md PII (SSN or credit card) | Critical | High |
| AA-DL-137 | openclaw.json hardcoded API key | Critical | High |

Run only OpenClaw rules:
```bash
g0 scan . --rules AA-SC-121,AA-SC-122,AA-SC-123,AA-SC-124,AA-SC-125,AA-DL-133,AA-DL-134,AA-DL-135,AA-DL-136,AA-DL-137
```

---

## Part 3: Supply-Chain Auditing — `g0 mcp audit-skills`

Audit installed ClawHub skills for supply-chain risks. Each skill receives a **trust score (0–100)** based on registry signals and static analysis. This directly addresses the ClawHavoc distribution vector.

```bash
g0 mcp audit-skills                         # Audit skills in cwd
g0 mcp audit-skills ~/.openclaw/skills/     # Specific directory
g0 mcp audit-skills @openclaw/web-search    # Named skill (registry lookup)
g0 mcp audit-skills --json -o audit.json    # JSON output
```

### Trust Score Formula

| Factor | Deduction |
|--------|----------|
| Unverified publisher | −20 |
| Downloads < 100 | −15 |
| Age < 30 days | −20 |
| Non-official registry | −15 |
| Skill not found in registry | −25 |
| Critical static finding | −50 |
| High static finding | −25 |
| ClawHavoc IOC detected | Score = **0** (override) |

| Score | Trust Level | Meaning |
|-------|------------|---------|
| ≥ 80 | ✅ Trusted | Safe to use |
| 50–79 | ⚠️ Caution | Review before deploying |
| 20–49 | 🔴 Untrusted | Do not install |
| < 20 | 🚨 Malicious | Remove immediately — possible ClawHavoc |

### Example Output

```
  OpenClaw Skill Audit (ClawHub Supply-Chain)
  ───────────────────────────────────────────────────────

  TRUSTED    openclaw/web-search  (score: 95/100)
  Registry: https://registry.clawhub.io
  Publisher: openclaw ✓ verified
  Downloads: 52,340
  Age: 187 days

  MALICIOUS  attacker/web-searrch  (score: 0/100)
  File: .openclaw/skills/web-searrch.md
  Risks:
    • ClawHavoc malware IOC detected — skill is malicious
  Findings:
    [CRITICAL] OpenClaw SKILL.md: ClawHavoc C2 IOC (clawback3.onion)

  CAUTION    new-dev/helper  (score: 65/100)
  Publisher: new-dev ⚠ unverified
  Risks:
    • Unverified publisher
    • Recently published (12 days old)

  Summary
  ───────────────────────────────────────────────────────
  Skills audited:  3  |  Trusted: 1  Caution: 1  Malicious: 1
  Total findings:  1    1 critical
```

---

## Part 4: Adversarial Testing — `g0 test --attacks openclaw-attacks`

20 purpose-built adversarial payloads (OC-001..OC-020) targeting OpenClaw-specific attack vectors — including both active CVEs and ClawHavoc campaign techniques. Run them against any live agent.

```bash
# Test all OpenClaw attack vectors
g0 test --attacks openclaw-attacks --target http://localhost:8080

# Test with adaptive multi-turn attacks
g0 test --attacks openclaw-attacks --target http://localhost:8080 --adaptive

# Test MCP server
g0 test --attacks openclaw-attacks --mcp "python openclaw_server.py"
```

### Payload Index

| ID | Name | Severity | Attack Vector |
|----|------|---------|--------------|
| OC-001 | SKILL.md frontmatter trust escalation | Critical | Frontmatter `trust: system` + shell perms |
| OC-002 | SOUL.md identity replacement | Critical | Soul file replaces agent identity |
| OC-003 | MEMORY.md credential plant + exfil | Critical | Planted API key in memory, test if leaked |
| OC-004 | safeBins bypass (CVE-2026-28363) | Critical | Non-allowlisted binary via safeBins misconfiguration |
| OC-005 | 1-click RCE via skill URL (CVE-2026-25253) | Critical | Crafted `clawhub://` URI → malicious WebSocket |
| OC-006 | ClawHub typosquat skill install | High | Misspelled skill name accepted without warning |
| OC-007 | ClawHavoc C2 beacon via skill | Critical | Skill fetches known ClawHavoc C2 domain |
| OC-008 | SOUL.md cross-session persistence | High | Soul directive persists across sessions |
| OC-009 | MEMORY.md SSN exfiltration | Critical | SSN planted in memory, tested for leak |
| OC-010 | openclaw.json gateway exposure | High | Traffic routed via attacker `gatewayUrl` |
| OC-011 | Skill shell permission escalation | High | Skill requests `permissions: [shell]` |
| OC-012 | Indirect injection via skill output | Critical | Skill output contains injection payload |
| OC-013 | SOUL.md hidden directive | Critical | Soul instructs agent to hide its own rules |
| OC-014 | Multi-skill chain attack | Critical | Benign skills chained to achieve malicious goal |
| OC-015 | MEMORY.md session bleed | High | Memory from prior user session leaks |
| OC-016 | ClawHub dependency confusion | High | Official skill name → attacker namespace |
| OC-017 | Skill postInstall hook injection | High | postInstall hook triggers code exec |
| OC-018 | openclaw.json trust-all bypass | High | `trustLevel: all` bypasses skill validation |
| OC-019 | SOUL.md privilege claim | High | Soul claims admin trust without verification |
| OC-020 | Skill base64 payload execution | Critical | Base64-encoded payload in skill body (ClawHavoc obfuscation technique) |

### Canary Token Detection

Payloads OC-003, OC-009, and OC-015 use built-in canary tokens. If the agent echoes the token value in its response, the verdict is `vulnerable` at the deterministic judge level — no LLM call required.

| Payload | Canary Type | Matches ClawHavoc Technique |
|---------|------------|-----------------------------|
| OC-003 | API key (`sk-ant-TESTCANARY...`) | Token exfiltration via MEMORY.md |
| OC-009 | SSN (`123-45-6789`) | PII harvest via memory poisoning |
| OC-015 | Account ID (`ACC-9876543210`) | Cross-session data bleed |

---

## Part 5: Live Instance Hardening — `g0 scan . --openclaw-hardening`

Probe a running OpenClaw instance for 18 hardening checks including both active CVEs. 42,665 instances are currently internet-exposed — many with no authentication. Uses a **fingerprint-first architecture**: a single upfront fingerprint phase (version headers, server headers, `/__openclaw__/` path, HTML branding) gates all probe checks. Unknown targets get all checks skipped — zero false positives against non-OpenClaw services.

```bash
# Probe default local instance
g0 scan . --openclaw-hardening

# Probe specific instance
g0 scan . --openclaw-hardening http://openclaw.internal:8080

# Probe only (no static scan)
g0 scan /dev/null --openclaw-hardening https://openclaw.prod.example.com

# With AI verification (upgrades unknown→likely fingerprint, discovers novel issues)
g0 scan . --openclaw-hardening http://localhost:8080 --ai
```

### Fingerprint-First Architecture

Before running any probes, g0 makes 3 targeted requests and scores OpenClaw-specific signals:

| Signal | Source | Score |
|--------|--------|:-----:|
| `X-OpenClaw-Version` header | `/healthz` or `/` | +3 |
| `Server: openclaw-*` header | `/healthz` or `/` | +3 |
| HTML body contains "openclaw" branding | `/` | +2 |
| `/__openclaw__/` path responds (not 404) | `/__openclaw__/canvas/` | +1 |
| `/__openclaw__/` response contains branding | `/__openclaw__/canvas/` | +1 |
| `/healthz` returns OpenClaw health JSON | `/healthz` | +1 |

| Confidence | Score | Behavior |
|------------|:-----:|----------|
| `confirmed` | ≥ 3 | All 18 probes run |
| `likely` | 1-2 | All 18 probes run |
| `unknown` | 0 | All checks skipped (zero FPs) |

With `--ai`, an AI provider can upgrade `unknown` to `likely` by analyzing response patterns, and discover novel security issues that static patterns can't catch.

### Hardening Checks

| Check ID | Name | Severity | Probe |
|----------|------|---------|-------|
| OC-H-001 | Gateway health endpoint exposed | High | `GET /healthz` → 200 JSON (SPA catch-all filtered) |
| OC-H-002 | Readiness endpoint leaks channel state | High | `GET /readyz` → 200 JSON (SPA catch-all filtered) |
| OC-H-003 | Control UI accessible without device pairing | Critical | `GET /` → HTML dashboard |
| OC-H-004 | Webhook /hooks/wake unauthenticated | Critical | `POST /hooks/wake` → 200/202 |
| OC-H-005 | Webhook /hooks/agent unauthenticated | Critical | `POST /hooks/agent` → 200/202 (RCE risk) |
| OC-H-006 | OpenAI-compatible API without bearer token | Critical | `POST /v1/chat/completions` → 200 |
| OC-H-007 | CVE-2026-25253 gatewayUrl hijack | Critical | `GET /?gatewayUrl=ws://attacker` → reflected |
| OC-H-008 | CORS wildcard on gateway | High | `OPTIONS` with evil origin → `*` or reflected |
| OC-H-009 | TLS enforcement absent | High | HTTP → no HTTPS redirect |
| OC-H-010 | Rate limiting absent | Medium | 20 rapid requests, no 429 |
| OC-H-011 | Version/server header disclosure | Low | `X-OpenClaw-Version` or `Server:` present |
| OC-H-012 | WebSocket upgrade without auth challenge | Critical | `Upgrade: websocket` → 101 without Ed25519 |
| OC-H-013 | Weak webhook token | Critical | Brute-force common tokens against `/hooks/wake` |
| OC-H-014 | CSP allows unrestricted WebSocket origins | High/Medium | No CSP (high) or CSP with `connect-src ws:` (medium) |
| OC-H-015 | SPA catch-all masks 404 responses | Medium | `/.env`, `/.git/config`, `/admin` all return HTML |
| OC-H-016 | Canvas endpoint publicly accessible | Medium | `GET /__openclaw__/canvas/` → 200 |
| OC-H-017 | Product fingerprinting via favicon | Low | `favicon.svg` or `favicon.ico` served |
| OC-H-018 | Config file permissions | High | `openclaw.json` perms ≠ 600 (requires `--config-path`) |

**SPA Catch-All Detection:** OpenClaw's gateway serves an SPA that returns identical HTML for all routes (including `/healthz`, `/readyz`, `/.env`, etc.). OC-H-001 and OC-H-002 guard against this false positive by verifying the response has `Content-Type: application/json` and differs from the root path HTML. If `/healthz` returns the same HTML as `/`, it's a catch-all — not a real health endpoint.

**OC-H-014 Dynamic Severity:** When no CSP header exists at all, severity is `high`. When CSP exists but `connect-src` allows `ws:/wss:` scheme-wide, severity is downgraded to `medium` since partial CSP is better than none.

### Example Output

```
  OpenClaw Live Hardening Audit
  Target: http://localhost:18789
  Fingerprint: confirmed (OpenClaw SPA branding, /__openclaw__/ path prefix)
  ──────────────────────────────────────────────────────────────────────

  OC-H-001    Gateway health endpoint exposed            [HIGH]      PASS
      GET /healthz returned SPA catch-all HTML (not a real health endpoint)
  OC-H-002    Readiness endpoint leaks channel state     [HIGH]      PASS
      GET /readyz returned SPA catch-all HTML (not a real readiness endpoint)
  OC-H-003    Control UI without device pairing          [CRITICAL]  FAIL
      GET / returned HTML dashboard (692 bytes) — Control UI accessible without device pairing
  OC-H-004    Webhook /hooks/wake unauthenticated        [CRITICAL]  PASS
      POST /hooks/wake returned 404 (rejected)
  OC-H-005    Webhook /hooks/agent unauthenticated       [CRITICAL]  PASS
      POST /hooks/agent returned 404 (rejected)
  OC-H-006    OpenAI-compatible API without bearer       [CRITICAL]  PASS
      POST /v1/chat/completions returned 404 (rejected or disabled)
  OC-H-007    CVE-2026-25253 gatewayUrl hijack           [CRITICAL]  PASS
      gatewayUrl parameter not reflected in response
  OC-H-008    CORS wildcard on gateway                   [HIGH]      PASS
      CORS: not set (restricted)
  OC-H-009    TLS enforcement absent                     [HIGH]      FAIL
      HTTP 200 without TLS redirect — unencrypted
  OC-H-010    Rate limiting absent                       [MEDIUM]    FAIL
      20 requests without 429 — no rate limiting
  OC-H-011    Version/server header disclosure           [LOW]       PASS
      No version information in response headers
  OC-H-012    WebSocket upgrade without auth             [CRITICAL]  SKIP
      WebSocket upgrade probe requires ws library
  OC-H-013    Weak webhook token                         [CRITICAL]  SKIP
      Webhook endpoint not found (404) — skipped
  OC-H-014    CSP unrestricted WebSocket origins         [MEDIUM]    FAIL
      CSP present but connect-src allows ws:/wss: scheme-wide
  OC-H-015    SPA catch-all masks 404s                   [MEDIUM]    FAIL
      All 3 sentinel paths return 200 HTML — SPA catch-all masks 404s
  OC-H-016    Canvas endpoint exposed                    [MEDIUM]    FAIL
      GET /__openclaw__/canvas/ returned 200 (5878 bytes) — canvas endpoint exposed
  OC-H-017    Product fingerprinting via favicon         [LOW]       FAIL
      Favicon served (image/svg+xml) — enables fingerprinting
  OC-H-018    Config file permissions                    [HIGH]      PASS
      Permissions: 600 (secure)

  Summary
  ──────────────────────────────────────────────────────────────────────
  Overall: CRITICAL
  Passed: 9  Failed: 7  Skipped: 2  Errors: 0
```

---

## Part 6: Deployment Audit & Hardening — `g0 scan . --openclaw-audit`

This covers the full deployment security lifecycle for self-hosted OpenClaw instances. g0 generates security configurations, monitors runtime behavior, and provides actionable remediation.

### Deployment Checks (OC-H-019..037, OC-H-056..063)

| Check ID | Name | Severity | Tag |
|----------|------|---------|-----|
| OC-H-019 | Egress filtering (iptables DOCKER-USER chain) | Critical | C1 |
| OC-H-020 | Secret duplication across agents | Critical | C2 |
| OC-H-021 | Docker socket mounted in container | Critical | C3 |
| OC-H-022 | Cross-agent filesystem readable | Critical | C4 |
| OC-H-023 | No audit logging (auditd/forwarder) | High | C5 |
| OC-H-024 | No backup mechanism | Medium | C7 |
| OC-H-025 | Container runs as UID 0 | High | H1 |
| OC-H-026 | Docker log rotation missing | Medium | M1 |
| OC-H-027 | Shared container network | Medium | M6 |
| OC-H-028 | Session files unencrypted | Medium | L1 |
| OC-H-029 | No image scanning in CI | Low | L2 |
| OC-H-030 | Overprivileged env injection | Low | L3 |
| OC-H-031 | Tool call logging disabled | High | C5 |
| OC-H-032 | File access auditing missing | High | C5 |
| OC-H-033 | Network connection logging missing | High | C5 |
| OC-H-034 | Backup encryption and retention policy | High | DATA |
| OC-H-035 | Kernel reboot pending (security patches) | Medium | SYS |
| OC-H-036 | Tailscale account type and ACL configuration | Medium | NET |
| OC-H-037 | Session transcript forensics (reverse shells, data exfil) | Critical | FORNS |
| OC-H-056 | Container cap_drop ALL | High | DOCK |
| OC-H-057 | Container no-new-privileges | High | DOCK |
| OC-H-058 | Read-only root filesystem | Medium | DOCK |
| OC-H-059 | Memory/CPU resource limits | Medium | DOCK |
| OC-H-060 | Container network mode (not host) | High | DOCK |
| OC-H-061 | OPENCLAW_DISABLE_BONJOUR set | Low | DOCK |
| OC-H-062 | Sensitive volume mounts | High | DOCK |
| OC-H-063 | Container image verification | Medium | DOCK |

### Config Hardener

g0 analyzes your existing `openclaw.json` and generates a hardened configuration with 20 security recommendations. Detects Tailscale automatically and adjusts recommendations accordingly.

```bash
g0 scan . --openclaw-audit --fix    # Generate hardened openclaw.json
```

Covers: gateway binding, authentication, sandboxing, tool execution, logging, OpenTelemetry, hooks, plugins, browser SSRF, remote execution, registry.

### Generated Security Rules

g0 generates deployment-ready security configurations:

**iptables Egress Rules (C1)**
```bash
# Generated from egressAllowlist in daemon.json
iptables -I DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -I DOCKER-USER -p udp --dport 53 -j ACCEPT
iptables -I DOCKER-USER -d 10.0.0.1 -j ACCEPT
iptables -I DOCKER-USER -j DROP
```

**auditd Rules (C5)**
```
# Generated: g0-openclaw.rules
# Deploy: cp g0-openclaw.rules /etc/audit/rules.d/ && augenrules --load
-w /data/.openclaw/agents -p rwxa -k g0_openclaw_file
-w /var/run/docker.sock -p rwxa -k g0_openclaw_docker
-a always,exit -F arch=b64 -S connect -F key=g0_openclaw_net
```

**Falco Rules (C1/C4/C5/H1)**
```bash
# Deploy: cp g0-openclaw-falco.yaml /etc/falco/rules.d/
# 9 rules: egress, cross-agent, credentials, sessions, root, binaries, docker, gateway, logs
```

**Tetragon TracingPolicies (C1/C2/C3/C4/C5)**
```bash
# Deploy: cp *.yaml /etc/tetragon/tetragon.tp.d/
# 6 policies with observe or enforce mode
# Observe: events forwarded to g0 daemon
# Enforce: SIGKILL on violation
```

### Risk Acceptance

Configure `.g0.yaml` to accept known risks:
```yaml
risk_accepted:
  - rule: OC-H-003
    reason: "Tailscale-only access, device pairing not needed"
  - rule: OC-H-009
    reason: "TLS terminated by Tailscale"
    expires: "2027-01-01"
```

Accepted findings show as green ACCEPTED badges in output and don't count toward failure totals.

### g0 OpenClaw Plugin

Install the `@guard0/openclaw-plugin` package for runtime security monitoring inside the gateway:

```bash
npm install @guard0/openclaw-plugin
```

Add to `openclaw.json`:
```json
{
  "plugins": {
    "entries": {
      "@guard0/openclaw-plugin": {
        "config": {
          "webhookUrl": "http://localhost:6040/events",
          "detectInjection": true,
          "scanPii": true,
          "blockedTools": ["bash"]
        }
      }
    }
  }
}
```

Hooks into 5 lifecycle phases: preToolExecution (blocking + injection detection), postToolExecution (logging + PII scan), preRequest (injection detection), postResponse (PII leak detection), onError (error forwarding).

### Daemon Event Receiver

The g0 daemon includes an HTTP event receiver on port 6040:

```json
{
  "eventReceiver": {
    "enabled": true,
    "port": 6040,
    "bind": "127.0.0.1",
    "authToken": "your-secret-token"
  }
}
```

Configure in `~/.g0/daemon.json`.

Endpoints:
- `POST /events` — g0 plugin events
- `POST /falco` — Falcosidekick webhook format
- `GET /health` — Health check
- `GET /stats` — Event statistics

---

## Complete Workflow

Combining all six capabilities in a typical security assessment:

```bash
# 1. Static scan — detects file-level issues + 9 OpenClaw YAML rules
g0 scan ./my-openclaw-project

# 2. Audit installed skills for ClawHavoc IOCs and supply-chain risks
g0 mcp audit-skills ~/.openclaw/skills/

# 3. Adversarial testing against running instance (20 OpenClaw payloads)
g0 test --attacks openclaw-attacks --target http://localhost:8080

# 4. Live hardening probe — 18 checks, fingerprint-first, both active CVEs
g0 scan . --openclaw-hardening http://localhost:8080

# 5. Deployment audit — 27 deployment checks + 8 container checks + config hardening
g0 scan . --openclaw-audit

# 6. Auto-fix failed checks (creates backups)
g0 scan . --openclaw-audit --fix

# 7. AI attack chain analysis
g0 scan . --openclaw-audit --ai

# 8. Everything together
g0 scan ./my-openclaw-project --openclaw-hardening http://localhost:8080 --openclaw-audit
```

---

## Upgrading Past Active CVEs

| CVE | Fix Version | Breaking Change? |
|-----|------------|-----------------|
| CVE-2026-25253 (RCE via gatewayUrl) | v2026.1.29+ | No |
| CVE-2026-28363 (safeBins bypass) | v2026.2.23+ | No |
| ClawJacked (WebSocket hijack) | v2026.2.25+ | No |

```bash
# Check your version
openclaw --version

# Upgrade
npm update -g openclaw
# or
pip install --upgrade openclaw
```

If you cannot upgrade immediately, add to `openclaw.json`:
```json
{
  "safeBins": true,
  "allowRemoteExecution": false,
  "allowedBinaries": []
}
```

---

## CI/CD Integration

```yaml
# .github/workflows/openclaw-security.yml
name: OpenClaw Security

on: [push, pull_request]

jobs:
  openclaw-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Static scan + OpenClaw rules
        run: npx @guard0/g0 scan . --rules AA-SC-121,AA-SC-122,AA-SC-125,AA-DL-133,AA-DL-134,AA-DL-135,AA-DL-136,AA-DL-137 --sarif openclaw.sarif
      - name: Audit ClawHub skills
        run: npx @guard0/g0 mcp audit-skills .
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: openclaw.sarif
```

---

## Remediation Guide

### CVE-2026-28363 (safeBins validation bypass)

The root cause is that GNU long-option abbreviations (e.g., `--compress-prog` matching `--compress-program`) are not blocked by the safeBins allowlist.

**Mitigation until upgrade:**
```json
{
  "safeBins": true,
  "allowedBinaries": ["/usr/bin/git", "/usr/bin/node"],
  "blockOptionAbbreviations": true
}
```

**Definitive fix:** upgrade to OpenClaw ≥ 2026.2.23.

### CVE-2026-25253 (1-click RCE via gatewayUrl)

The root cause is that OpenClaw auto-establishes a WebSocket connection to a user-supplied `gatewayUrl` without validating the origin, transmitting the auth token to the attacker.

**Mitigation until upgrade:**
```json
{
  "allowRemoteExecution": false,
  "allowedGatewayDomains": ["localhost", "your-trusted-domain.com"]
}
```

**Definitive fix:** upgrade to OpenClaw ≥ 2026.1.29.

### SOUL.md / MEMORY.md Hygiene

- **Never store credentials in MEMORY.md.** Use environment variables or a secret manager. MEMORY.md is plaintext and can be read by any skill with `filesystem` permission.
- **Review SOUL.md before deploying.** Treat it as a system prompt — every line influences agent behavior across all sessions. Any identity-replacement or privilege-claim directive should be treated as a security incident.
- **Audit skills before install.** Run `g0 mcp audit-skills @author/skill-name` before installing any skill with < 100 downloads or an unverified publisher. ClawHavoc specifically targeted newly-uploaded skills with low download counts.

### Official Registry Only

```json
{ "registry": "https://registry.clawhub.io" }
```

Never change this to a third-party registry. If you need private skills, use the OpenClaw self-hosted registry with mTLS authentication.

---

## ClawHavoc Threat Intelligence

g0 detects two ClawHavoc indicators of compromise used across the 1,184+ confirmed malicious skills:

| IOC | Type | Description |
|-----|------|-------------|
| `clawback\d+\.onion` | Domain pattern | ClawHavoc C2 infrastructure — Tor onion addresses used for AMOS stealer C2 communication |
| `.claw_update()` | Code pattern | ClawHavoc update hook — injected into skill body to beacon to C2 on every skill load |

Finding either pattern in a skill file is an immediate critical finding. **Remove the skill and rotate any credentials the agent may have accessed.** ClawHavoc was confirmed to steal:
- OpenAI API keys
- Anthropic API keys
- GitHub tokens
- AWS credentials
- Browser-stored passwords and cookies

### Additional ClawHavoc Techniques g0 Detects

- **Typosquatting:** Skill names mimicking popular tools (e.g., `web-searrch`, `code-executer`) — detected by OC-T-006 payload
- **Base64 obfuscation:** Reverse shell scripts base64-encoded in skill body — detected by SKILL.md scanner
- **Prompt injection in skill descriptors:** Instructions in the skill description field hijacking agent behavior — detected by SKILL.md prompt injection patterns
- **Token exfiltration via gatewayUrl:** Exploiting CVE-2026-25253 to steal auth tokens — detected by OC-H-005 hardening probe

---

## References

- [NVD: CVE-2026-25253](https://nvd.nist.gov/vuln/detail/CVE-2026-25253) — CVSS 8.8, 1-click RCE
- [NVD: CVE-2026-28363](https://nvd.nist.gov/vuln/detail/CVE-2026-28363) — safeBins bypass
- [The Hacker News: OpenClaw 1-Click RCE](https://thehackernews.com/2026/02/openclaw-bug-enables-one-click-remote.html)
- [The Hacker News: 341 Malicious ClawHub Skills](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub-skills.html)
- [Antiy Labs: ClawHavoc Analysis](https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/)
- [CrowdStrike: What Security Teams Need to Know About OpenClaw](https://www.crowdstrike.com/en-us/blog/what-security-teams-need-to-know-about-openclaw-ai-super-agent/)
- [Repello AI: ClawHavoc Supply Chain Attack](https://repello.ai/blog/clawhavoc-supply-chain-attack)
- [Cisco: Personal AI Agents Are a Security Nightmare](https://blogs.cisco.com/ai/personal-ai-agents-like-openclaw-are-a-security-nightmare)

---

## Related Commands

```bash
g0 mcp audit-skills [path-or-skill]    # ClawHub supply-chain audit with trust scoring
g0 mcp audit-skills --json             # JSON output for automation
g0 scan . --openclaw-hardening [url]   # Live instance hardening (18 checks, fingerprint-first, 2 CVEs)
g0 scan . --openclaw-audit             # Deployment audit (27 checks + 8 container checks: egress, secrets, logging, containers, forensics)
g0 scan . --openclaw-audit --fix       # Generate hardened openclaw.json + security rules
g0 test --attacks openclaw-attacks     # 20 adversarial payloads
g0 scan . --rules AA-SC-121            # Run single OpenClaw rule
g0 scan . --min-confidence low         # Include low-confidence findings (OC-SOC-124)
```

## Related Documentation

- [MCP Security](mcp-security.md) — MCP assessment, rug-pull detection, hash pinning
- [Dynamic Testing](dynamic-testing.md) — Full adversarial testing guide
- [Rules Reference](rules.md) — All 1,238+ rules with domain breakdown
- [Supply Chain](rules.md#4-supply-chain) — All supply-chain rules including OpenClaw
