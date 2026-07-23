# `g0 sentinel` — fleet-deployed AI-footprint snapshots

Point scans answer "is this machine safe right now?" **The sentinel answers the
fleet question: "what AI footprint is on every machine, and how is it changing?"**
— by running unattended on each endpoint and emitting a machine snapshot that a
central roll-up can collect.

It is the same g0 binary run in a restricted, non-interactive mode, designed to be
pushed to every machine through your MDM (ManageEngine Endpoint Central, Jamf,
Intune, Kandji, Workspace ONE — the sentinel never knows which one deployed it).

> **Status:** `g0 sentinel scan` (one-shot snapshot) ships today. The resident
> daemon, per-tool PII-exposure evidence, the central collector + org report, and
> governance/remediation are designed and in progress — see
> [Status & roadmap](#status--roadmap) and the
> [solution brief](solutions/mdm-ai-footprint-governance.md).

## Commands

```bash
g0 sentinel scan [--out <path>]   # one collection pass: write a machine snapshot, print a compact summary
```

`g0 sentinel scan` is **non-interactive and never prompts** — safe to run from an
MDM custom-script / scheduled task. With no `--out`, it writes to a platform
well-known path:

| Platform | Default snapshot path |
|---|---|
| Windows | `C:\ProgramData\guard0\snapshot.json` |
| macOS | `/Library/Application Support/guard0/snapshot.json` |
| Linux | `/var/lib/guard0/snapshot.json` |

The snapshot is written atomically (temp file + rename), so a collector never reads
a half-written file. The command also prints a one-line **compact summary** to
stdout so an MDM that captures script output surfaces the result in its own console:

```
g0 sentinel: 18 AI tools (4 running), score 50 -> /Library/Application Support/guard0/snapshot.json
```

## Snapshot format

A single schema-versioned JSON document per machine per run. Reuses the endpoint
scanner (see [Endpoint Assessment](endpoint-monitoring.md)) to discover the AI
tools and MCP servers installed on the host.

```json
{
  "schemaVersion": 1,
  "generatedAtMs": 1784831012019,
  "sentinelVersion": "2.1.0",
  "host": { "hostname": "mac-1", "platform": "darwin", "arch": "arm64" },
  "tools": [
    { "name": "Claude Desktop", "installed": true, "running": true, "mcpServerCount": 1 },
    { "name": "Cursor", "installed": true, "running": false, "mcpServerCount": 0 }
  ],
  "endpointScore": 50
}
```

- `host` — hostname, OS platform, and architecture.
- `sentinelVersion` — the g0 build version, for MDM compliance reporting.
- `tools` — every discovered AI tool with install/running state and MCP server count.
- `endpointScore` — the 0–100 endpoint posture score.

**No raw PII is ever written to a snapshot.** As the per-tool exposure engine lands
(roadmap below), snapshots carry PII **classes and counts with an evidence locator**
— e.g. "14 email addresses in `~/.codex/history`" — never the values themselves.

## Deploying through an MDM

The sentinel is **MDM-agnostic**: the MDM only pushes the binary, drops a config
file, and optionally triggers a run. Everything else (scan, snapshot, transport) is
identical everywhere, so supporting a new MDM is a deployment recipe, not new code.

A typical ManageEngine Endpoint Central deployment:

1. **Deploy** the signed installer (MSI on Windows, notarized PKG on macOS) via
   Software Deployment.
2. **Schedule** `g0 sentinel scan` via a Custom Script configuration (or let the
   installer register a Scheduled Task / LaunchDaemon for precise cadence — MDM
   refresh-cycle timing is coarse).
3. **Collect** the snapshot. ManageEngine has no native file-pull, so the run
   script POSTs the snapshot to a small customer-hosted collector; the compact
   summary is also captured in ManageEngine's own script-output report.
4. **Roll up** with [`g0 fleet`](fleet.md) into one org-wide report.

Full deployment recipes for Jamf, Intune, Kandji, and Workspace ONE — plus the
collector and governance model — are in the
[solution brief](solutions/mdm-ai-footprint-governance.md).

## How it relates to the rest of g0

- [`g0 check`](../README.md) / [Endpoint Assessment](endpoint-monitoring.md) — the
  interactive, single-machine version of the discovery the sentinel runs unattended.
- [`g0 fleet`](fleet.md) — the roll-up the collected snapshots feed into.
- [`g0 protect`](protect.md) — the opt-in enforcement tier for machines that need
  live blocking rather than inventory + governance.

## Status & roadmap

| Capability | Status |
|---|---|
| `g0 sentinel scan` — one-shot machine snapshot | **Shipped** |
| Single self-contained binary (no Node prerequisite) | **Shipped** (via `bun build --compile`) |
| Resident daemon (streamed deltas, well-behaved) | Designed — reuses `src/daemon/` + the resident watcher |
| Per-tool PII-exposure evidence (classes + counts, no raw PII) | Designed |
| Customer-hosted collector + HTML org report | Designed |
| Governance policy + remediation manifest | Designed |
| Signed MSI / notarized PKG + MDM deployment guides | Designed |

The full design, phasing, and sourced research behind these is in
[`docs/superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md`](superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md).
