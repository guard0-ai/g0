# `g0 sentinel` — fleet-deployed AI-footprint snapshots

Point scans answer "is this machine safe right now?" **The sentinel answers the
fleet question: "what AI footprint is on every machine, and how is it changing?"**
— by running unattended on each endpoint and emitting a machine snapshot that a
central roll-up can collect.

It is the same g0 binary run in a restricted, non-interactive mode, designed to be
pushed to every machine through your MDM (ManageEngine Endpoint Central, Jamf,
Intune, Kandji, Workspace ONE — the sentinel never knows which one deployed it).

> **See also:** [Sentinel Architecture & Overview](sentinel-architecture.md) — deployment
> topology, scan-pipeline and module diagrams, the snapshot data model, and real customer
> scenarios with examples.
>
> **Status:** the full **inventory → per-tool PII exposure → collector → org report
> → governance** chain ships today. The resident daemon, signed MSI/PKG installers,
> and Windows runtime are still in progress — see [Status & roadmap](#status--roadmap)
> and the [solution brief](solutions/mdm-ai-footprint-governance.md).

## Commands

```bash
g0 sentinel scan [--out <path>] [--post <url>] [--policy <file>] [--no-pii]
                                  # one collection pass: footprint + per-tool PII exposure
                                  # + AI browser extensions + optional governance verdict;
                                  # writes a snapshot, optionally POSTs it to a collector
g0 sentinel collect --dir <dir> [--port 8787]
                                  # thin HTTP collector: receives POSTed snapshots -> dir
g0 sentinel report --dir <dir> [--out report.html]
                                  # roll a directory of snapshots into one org-wide HTML report
```

The end-to-end fleet flow:

```bash
# on a central box you control:
g0 sentinel collect --dir /var/guard0/snapshots --port 8787

# pushed to every machine via MDM (scheduled):
g0 sentinel scan --post http://collector.internal:8787/ --policy /etc/guard0/policy.yaml

# any time, to see the whole fleet:
g0 sentinel report --dir /var/guard0/snapshots --out fleet.html
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
| `g0 sentinel scan` — machine snapshot (footprint) | **Shipped** |
| Single self-contained binary (no Node prerequisite) | **Shipped** (via `bun build --compile`) |
| Per-tool PII-exposure evidence (classes + counts, no raw PII) | **Shipped** |
| AI browser-extension discovery (permissions + risk) | **Shipped** |
| Customer-hosted collector (`g0 sentinel collect`) | **Shipped** |
| HTML org report (`g0 sentinel report`) | **Shipped** |
| Governance policy + per-tool verdict (`--policy`) | **Shipped** |
| Resident daemon (streamed deltas, well-behaved) | In progress — reuses `src/daemon/` + the resident watcher |
| Snapshot signing + content-addressed drift | In progress |
| MDM-enacted remediation manifest | In progress |
| Signed MSI / notarized PKG + MDM deployment guides + Windows runtime | In progress (needs signing certs + a Windows host) |

The full design, phasing, and sourced research behind these is in
[`docs/superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md`](superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md).
