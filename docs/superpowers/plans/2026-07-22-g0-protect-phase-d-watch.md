# g0 protect Phase D — Resident Watcher + Estate Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn coverage from a snapshot into a state: fs-watched targeted re-checks + periodic sweeps with OS notifications (observe default), opt-in auto-quarantine of known-malicious MCP servers AND flagged-critical estate files (closing B2's report-only gap), registered as a per-user autostart via the `watch` protect surface.

**Architecture:** Builds on `src/daemon/` (config/logger/process/runner/kill-switch stay; the dead `upload` key goes). New: `os-notify.ts` (best-effort native notifications), `watch.ts` (watch-path builder + debounced fs watchers + targeted re-check with delta vs a state snapshot), `estate-quarantine.ts` (file-level move-to-vault with manifest/undo, same safety grammar as MCP quarantine), a `watch` ProtectAdapter (launchd/systemd-user/schtasks persistence). Hook-health spike alerts tie in B1's audit trail.

**Tech Stack:** TypeScript ESM, `fs.watch`, vitest. No new dependencies. Constraints as always: fail-open, never-throw on watch paths, no network beyond the existing fail-open feed refresh, per-user scope only, baseline 163 files / 2,456+1 green + perf gate.

---

### Task 1: `src/daemon/os-notify.ts`
`notifyOS(title: string, body: string, execFn?: typeof execFile): void` — macOS `osascript -e 'display notification …'`, Linux `notify-send`, Windows PowerShell toast; args passed as ARRAYS (no shell interpolation of finding text); never-throws; silently no-ops when the binary is missing. Test: inject a fake `execFn`, assert argv arrays for darwin/linux + injection-safety (title containing `"'; rm -rf` stays a single argv element); missing binary → no throw.
Commit: `feat: best-effort native OS notifications for the watcher`

### Task 2: `src/endpoint/estate-quarantine.ts`
Closes B2's report-only gap with quarantine semantics matching `quarantine.ts`:
```typescript
export interface EstateQuarantinePlan { candidates: ClaudeEstateComponent[]; }   // findings with severity critical only
export interface EstateQuarantineManifest { id: string; timestamp: string; entries: { kind: string; name: string; originalPath: string; storedPath: string; sha256: string }[]; }
export function planEstateQuarantine(estate: ClaudeEstateResult): EstateQuarantinePlan;
export function applyEstateQuarantine(plan: EstateQuarantinePlan, opts?: { quarantineDir?: string }): { manifestPath: string | null; applied: EstateQuarantineManifest['entries']; skipped: { name: string; reason: string }[] };
export function undoEstateQuarantine(opts?: { manifestPath?: string; quarantineDir?: string; force?: boolean }): { restored: string[]; skipped: { reason: string }[] };
```
Apply MOVES the component's path (dir or file) into `<quarantineDir ?? ~/.g0/quarantine>/estate/<ts>/<n>/` recording sha256 (dir → sha256 of sorted relative-path+file-hash lines); `hook` components are skipped with reason `settings-entry — remove via protect off/manual review` (never edit settings here). Undo restores by move-back, refusing when the vault copy's hash mismatches its manifest entry unless `force`. Tests: tmp estate fixture → plan picks only criticals; apply moves + manifest; undo round-trips; hook component skipped; drifted vault refuses without force.
Commit: `feat: estate quarantine — move flagged-critical claude components to a vault, undoable`

### Task 3: `src/daemon/watch.ts`
```typescript
export function buildWatchPaths(homeDir?: string): string[];   // dedup: resolveClientPaths() config dirs, <home>/.claude/{settings.json,settings.local.json,skills,plugins,agents}, OpenClaw skills dir if present
export interface WatchDelta { newCriticalComponents: ClaudeEstateComponent[]; newMaliciousServers: QuarantineCandidate[]; hookErrorSpike?: { errors: number; total: number }; }
export function runTargetedCheck(opts?: { homeDir?: string; stateFile?: string; hookConfigDir?: string }): WatchDelta;
export function startWatchers(paths: string[], onChange: () => void, opts?: { debounceMs?: number }): () => void; // returns stop()
```
`runTargetedCheck` = `scanClaudeEstate` + `planQuarantine()` + hook-audit error-rate (last 100 records; spike = >20% errors && ≥5 errors), diffed against `<stateFile ?? ~/.g0/watch/state.json>` (keyed by component path+finding rules / server name) so each finding notifies ONCE; state updated after diff; corrupt state → treat all as new. `startWatchers`: `fs.watch` per existing path (files and dirs), shared debounce timer, never-throw per watcher, stop() closes all. Tests: tmp home — first run reports the planted critical, second run reports none (delta), new skill dropped → reported; debounce collapses burst events (fake timers or 50ms debounce + real fs writes); buildWatchPaths includes .claude paths and dedups.
Commit: `feat: watch core — watch paths, debounced fs watchers, once-only delta re-checks`

### Task 4: watcher loop + enforce mode (`src/daemon/runner.ts`, `src/daemon/config.ts`)
Config: add `enforce: boolean` (default false) and DELETE the dead `upload` key; delete `--no-upload` from `src/cli/commands/daemon.ts` (verified dead 2026-07-21; changelog note). Runner: alongside the existing interval loop — `startWatchers(buildWatchPaths(), debounced → handleDelta(runTargetedCheck()))` plus `handleDelta` on each periodic sweep. `handleDelta`: for each new critical/malicious → logger + `notifyOS('g0: <headline>', …)` + audit line (`appendJsonlLine` to `~/.g0/watch/audit.jsonl`); when `config.enforce`: `applyQuarantine({ plan })` for servers + `applyEstateQuarantine` for components, notifying what was quarantined (with undo pointer). Hook spike → notify only. Everything wrapped: a watcher failure degrades to the periodic sweep. Tests: unit-test `handleDelta` with injected fakes (notify/quarantine fns) — observe mode notifies only; enforce quarantines; empty delta silent.
Commit: `feat: daemon watch loop — once-only notifications, opt-in auto-quarantine; drop dead upload key`

### Task 5: `watch` protect surface (`src/protect/adapters/watch.ts`)
`ProtectSurface` += `'watch'`; `UndoHandle` += `{ watchUnitPath?: string | null }`; ctx += `{ launchctl?: ExecLike; systemctl?: ExecLike }` test seams. plan(): one step (`register autostart: <unit path>`) + advisory when `enforce` off ("watcher will notify, not quarantine — set enforce: true in daemon config to auto-quarantine"). apply(): darwin → write `~/Library/LaunchAgents/ai.guard0.g0-watch.plist` (ProgramArguments: [g0Bin ?? 'g0', 'daemon', 'start', '--no-banner'], RunAtLoad, KeepAlive false) + `launchctl bootstrap gui/$UID <plist>` best-effort; linux → `~/.config/systemd/user/g0-watch.service` + `systemctl --user enable --now`; win32 → skipped with reason (schtasks deferred, documented). status(): unit file present + daemon pid liveness (`readPid`) + last watch-audit timestamp. undo(): bootout/disable + remove unit file (hash-check not needed — we own the file; refuse only if content isn't ours unless force). Tests: fake exec seams, temp HOME — plist/unit content snapshot (argv array, no shell strings), apply→undo removes, status reflects.
Commit: `feat: watch protect surface — per-user autostart registration with undo`

### Task 6: e2e + gates
`tests/integration/watch-e2e.test.ts` (sandboxed HOME): in-process — build paths, start watchers, drop a `curl|bash` skill → `waitFor` delta notification record in watch audit; enforce mode → component dir moved into the vault, undo restores. Then `npm test` + `npm run test:perf` full green.
Commit: `test: watch e2e — live fs-watch detect, enforce quarantine, undo`

### Task 7: docs + changelog
`docs/protect.md` watch surface section; `docs/endpoint-monitoring.md` daemon/watch update (remove upload references); `docs/hooks.md` cross-link (error-spike alerts); CHANGELOG: watcher + estate quarantine + upload-key removal bullets; README Protect row += "resident watcher". Full suite green, commit `docs: resident watcher + estate quarantine`.
