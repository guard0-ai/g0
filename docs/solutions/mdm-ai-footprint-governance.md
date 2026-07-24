# Solution brief — MDM-deployed AI footprint discovery, PII exposure & governance

> **Audience:** security / IT leaders evaluating g0 for fleet-wide shadow-AI
> governance. **Companion docs:** [`g0 sentinel`](../sentinel.md) (the command),
> and the engineering design in
> [`docs/superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md`](../superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md).

## The problem

AI tools now install themselves on employee machines faster than security teams can
track them: desktop assistants, coding agents (Claude Code, Cursor, Codex, Copilot),
browser AI extensions, MCP servers, and email/productivity add-ins. Each one can
reach real data — files, mailboxes, credentials, browser sessions — and much of that
usage is invisible to the tools most orgs already own.

Leaders are left without answers to three questions:

1. **Inventory** — what AI tooling is actually on every machine in the fleet?
2. **Exposure** — for each tool, what PII can it reach, and what has flowed to it?
3. **Governance** — how do we remove what shouldn't be there, or enforce a policy?

## The solution in one paragraph

Push the **g0 sentinel** — one signed binary, deployed through the MDM you already
run — to every machine. It discovers the full AI footprint on the endpoint, builds a
per-tool **evidence-based PII-exposure** view from local artifacts (never raw PII),
and reports a machine snapshot that rolls up into **one org-wide inventory**. From
there, a governance policy flags non-compliant tools and drives removal — with the
MDM doing the enforcing by default. Inventory first; governance next; enforcement
where you opt in.

## Why endpoint-native

The shadow-AI market mostly looks *away* from the machine. **Network/proxy** tools
(Zscaler, Netskope, Microsoft Defender for Cloud Apps) see *traffic* to AI domains;
**SaaS-API/OAuth** tools (Nudge, Wing, Grip) see *grants and logins*. Both are
useful, and g0 is complementary to them — but neither gives you a per-machine
**asset inventory** of installed AI apps + coding agents + browser extensions + MCP
configs, unified with **local PII-exposure evidence** and governance. That endpoint,
local-first view — positioned as an independent auditor of your estate rather than an
inline proxy — is where the sentinel sits.

## How it works

```
  Your MDM (ManageEngine / Jamf / Intune / Kandji / Workspace ONE)
        │  push signed binary  ·  drop config  ·  (optional) trigger run
        ▼
  g0 sentinel on every machine  ── the SAME binary everywhere ──
        ├─ Discover AI footprint (apps, coding agents, browser extensions, MCP, add-ins)
        ├─ Per-tool PII exposure  (what it CAN reach × what DID flow — classes + counts only)
        ├─ Governance verdict     (allow / deny / monitor, per policy)
        └─ Write signed machine snapshot  (NO raw PII)
        │
        ▼  transport (the MDM is a "dumb pipe"; snapshot POSTed to a collector you host)
  Customer-hosted collector  ──►  g0 fleet import  ──►  ONE org-wide HTML report
        │
        ▼  remediation
  g0 DECIDES → your MDM ENFORCES  (uninstall app / block extension / block exe)
        └─ or g0-enacted quarantine where you opt in
```

### 1. One MDM-agnostic unit

The sentinel is the g0 binary in a restricted, non-interactive mode. It runs as a
**well-behaved resident daemon** — installed once, mostly idle, waking on its own
schedule to run a fast delta scan and watch a few high-signal paths (MCP configs,
extension dirs, new-app installs). It deliberately does **not** hot-watch the whole
disk: that collides with EDR/AV behavioral detection and taxes laptops. Real-time
watching + live blocking is a separate, opt-in tier ([`g0 protect`](../protect.md)).

The MDM only pushes the binary, drops a config file, and optionally triggers a run —
so the same binary scales across every MDM with no per-MDM code.

### 2. Footprint discovery (inventory first)

Endpoint-native surfaces g0 discovers on the machine:

- **Browser AI extensions** across Chrome/Edge/Brave/Firefox, with their declared
  permissions and a risk score.
- **Installed AI desktop apps** (registry / LaunchServices / process detection).
- **Coding agents and MCP configs** (Claude Code, Cursor, Windsurf, Codex, …).
- **Legacy Outlook COM add-ins**.

Surfaces that genuinely live server-side — **OAuth grants** to AI vendors and modern
**M365 / Copilot web add-ins** — are handled as optional admin-API connectors
(Google Admin SDK / Microsoft Graph), not claimed as endpoint discovery.

### 3. PII exposure, from evidence — not interception

For each tool, the sentinel answers two questions from **local evidence only**:

- **What can it reach?** Extension permissions, OAuth scopes, add-in manifest
  permissions, filesystem/config reach, callable MCP servers.
- **What did flow?** PII classifiers run over local artifacts the tool touched
  (coding-agent session logs, browser history to AI domains, MCP audit logs).

The output is **classes + counts + an evidence locator** — e.g. *"Codex history
contains 14 email addresses, 2 access-token-shaped strings"* — **never the raw
values**, and with no traffic interception. This is the correct scope for an
inventory/governance product: it proves exposure without becoming an inline DLP proxy
or shipping sensitive data around in a report.

### 4. One org-wide view

Each machine writes a **signed** snapshot. ManageEngine (and most MDMs) can't natively
pull a file to the console, so the run script POSTs the snapshot to a small
**collector you host** — no SaaS required for the pilot — and [`g0 fleet`](../fleet.md)
rolls the snapshots into one HTML report of every AI tool, per machine and
fleet-wide, with per-tool exposure. A **compact summary** is also captured in the
MDM's own script-output report, so the result is visible inside the tool your IT team
already lives in. Because the daemon streams deltas, the report stays current without
re-triggering.

### 5. Governance — get rid of it, or enforce a policy

Two tiers:

- **Policy verdict (report-only).** A `guard0.policy.yaml` declares allow / deny /
  monitor per tool or category. Every snapshot carries a per-tool compliance verdict;
  the org report shows who's compliant.
- **Remediation (opt-in).** g0 **decides** the required action and, by default, your
  **MDM enforces** it — uninstall an app (ManageEngine Prohibited Software), remove or
  block a browser extension (Add-on & Extension Control), block an executable
  (Application Control). Where you want g0 to act directly, it can quarantine
  known-malicious footprint itself (reversible, dry-run by default) and install live
  runtime enforcement via [`g0 protect`](../protect.md).

The model: **g0 decides; the MDM enforces by default; g0 enforces only where you opt
in.**

## Data handling & privacy

- **No raw PII** in any snapshot, collector payload, or report — classes and counts
  with an evidence locator only.
- **Local-first.** For the pilot, snapshots go to a collector *you* host; nothing is
  sent to a Guard0 SaaS. Platform sync (org dashboards) is an optional later upgrade.
- **Signed snapshots** so the roll-up can trust they weren't tampered in transit.

## Deploying it (per-MDM recipes)

The agent is identical everywhere; each MDM just needs a thin recipe:

| MDM | Deploy | Schedule | Remediate |
|---|---|---|---|
| **ManageEngine Endpoint Central** | Software Deployment (MSI/PKG) | Custom Script + installer-registered task | Prohibited Software · Add-on/Extension Control · Application Control |
| **Jamf Pro (macOS)** | Policy + notarized PKG | LaunchDaemon config profile | Jamf policies |
| **Microsoft Intune** | Win32 app (`.intunewin`) + PowerShell | Scheduled Task | ADMX / settings-catalog blocklist |
| **Kandji / Mosyle / Workspace ONE** | Same PKG/MSI + config profile | Config profile / script | Vendor policy equivalents |

> **ManageEngine note:** confirm you run **Endpoint Central** (agent-based), not
> **Mobile Device Manager Plus** — only Endpoint Central has the custom-script engine
> the transport relies on.

Binary updates go through the MDM (IT controls them); the detection database refreshes
out-of-band as a signed data file — the antivirus model.

## What's shipped today vs. roadmap

| Capability | Status |
|---|---|
| `g0 sentinel scan` — machine snapshot | **Shipped** |
| Single self-contained binary, no Node prerequisite | **Shipped** |
| AI-footprint discovery (apps, coding agents, MCP, AI browser extensions) | **Shipped** |
| Per-tool PII-exposure evidence (classes + counts, no raw PII) | **Shipped** |
| Customer-hosted collector (`g0 sentinel collect`) | **Shipped** |
| HTML org report (`g0 sentinel report`) | **Shipped** |
| Governance policy + per-tool compliance verdict | **Shipped** |
| Resident daemon with streamed deltas | In progress |
| Snapshot signing + MDM-enacted remediation manifest | In progress |
| Signed MSI / notarized PKG + deployment guides + Windows runtime | In progress (needs signing certs + a Windows host) |

## Suggested pilot success criteria

1. A signed installer pushes through your MDM to Windows **and** macOS with no Node
   prerequisite.
2. Every machine reports its full AI footprint unattended.
3. You see **one org report** — every AI tool, per machine and fleet-wide, with
   per-tool PII exposure — without logging into any machine.
4. No raw PII appears in any snapshot or report.
5. A governance policy flags non-compliant tools, and remediation removes/enforces the
   footprint — with proof in the next report.

## Learn more

- [`g0 sentinel` command reference](../sentinel.md)
- [Endpoint Assessment & Monitoring](../endpoint-monitoring.md) · [Fleet Control Plane](../fleet.md) · [`g0 protect`](../protect.md)
- [Full engineering design & sourced research](../superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md)
