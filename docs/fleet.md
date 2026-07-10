# Fleet Control Plane

Point scans answer "is this target safe?" The fleet control plane answers **"what
does our whole agent estate look like, who owns it, and how is it changing?"** —
a local-first roll-up across every repo and machine you track.

Snapshots accumulate under `~/.g0/fleet` (override with `--fleet-dir` or the
`G0_FLEET_DIR` env var). It is local-first — no backend required — and structured
to later sync to the [Guard0 Platform](https://guard0.ai/early-access) for
org-wide dashboards and history.

## Commands

```bash
g0 fleet scan <paths...> [--owner <team>]   # scan projects and record snapshots
g0 fleet status                             # estate roll-up (worst-first)
g0 fleet drift [assetId]                    # change since the previous snapshot
g0 fleet list                               # tracked assets, last-seen, grade
```

`g0 fleet status` and `g0 fleet drift` support `--json`.

## Recording assets

```bash
g0 fleet scan ./agent-a ./agent-b ./agent-c --owner platform-team
```

Each project is scanned and a timestamped snapshot is written, capturing: score,
grade, finding fingerprints, inventory counts (agents/tools/models/MCP servers),
git metadata, machine metadata, and owner. The owner may also come from an
`owner:` field in `.g0.yaml`.

### Asset identity

Assets are keyed by **git remote + sub-path within the repo**, so:

- The same repo checked out on two machines is one asset.
- Each project in a monorepo (e.g. `examples/agent-a`, `examples/agent-b`) is a
  distinct asset rather than collapsing onto the shared remote.
- A target that is not in a git repo is keyed by its absolute path.

## Estate roll-up

```
  Fleet Status
  ────────────────────────────────────────────────────────────
  Assets: 3   Agents: 25   Tools: 9   Models: 11   MCP: 0
  Findings: 154   Critical: 9   High: 79
  Ecosystems: crewai (2), langchain (1)
  Owners:     platform-team (3)

  Assets (worst first)
  ────────────────────────────────────────────────────────────
  F  tools               105 findings 4 crit · platform-team
  F  starter_template     27 findings 3 crit · platform-team
  D  prep-for-a-meeting   22 findings 2 crit · platform-team
```

Totals aggregate the latest snapshot of every asset; assets are sorted worst-first
(lowest score, then most criticals).

## Drift

`g0 fleet drift` compares the two most recent snapshots per asset:

```
  Fleet Drift
  ────────────────────────────────────────────────────────────
  my-agent  score -14 (D→F)
    +1 new findings
```

It reports the score delta, grade change, new/resolved findings (via finding
fingerprints), and inventory deltas (agents/tools/models/MCP). Record at least
two snapshots of an asset to get drift.

## Typical CI usage

Run `g0 fleet scan .` in each project's pipeline (or a nightly job across a set of
repos) to keep the estate view current, then `g0 fleet status --json` /
`g0 fleet drift --json` to feed dashboards or alerts.
