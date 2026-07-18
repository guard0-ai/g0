# Platform & Authentication

g0 is **offline-first**. Scanning, testing, inventory, fleet, endpoint, and attestation all run entirely on your machine with no account and no network dependency. Signing in is **optional** — it connects the CLI to your [Guard0](https://guard0.ai/signup) account to unlock premium threat intelligence and platform entitlements.

> **Signing in never changes how scanning works.** `g0 login` only touches the network when you run it (and `whoami --verify`). Every other command reads your session from disk synchronously and never blocks, retries, or fails because the platform is unreachable. If you never log in, nothing is gated except the premium feed.

## Commands

```bash
g0 login              # Sign in via the browser (OAuth device flow)
g0 login --api-key <key>   # Sign in with an API key (headless / CI)
g0 whoami             # Show the current account, plan, and auth source
g0 whoami --verify    # Confirm the session is live against the platform
g0 logout             # Revoke and remove the local session
```

## Signing in

### Browser (device flow)

`g0 login` uses the OAuth 2.0 Device Authorization Grant (RFC 8628), which works everywhere a CLI runs — laptops, SSH sessions, containers, and headless boxes — with no local callback port.

```
$ g0 login
  To sign in, visit https://app.guard0.ai/activate
  and enter the code:  ABCD-1234

  ⠹ Waiting for approval…
  ✓ Signed in as you@example.com (Pro plan)
```

g0 tries to open your browser automatically. Pass `--no-browser` (or run in a non-interactive shell) to just print the URL and code so you can approve on another device.

### API key (headless / CI)

For machines with no browser at all, mint an API key on your account settings page and pass it directly or via the environment:

```bash
g0 login --api-key g0_live_xxxxxxxx
# or, without persisting a session:
export G0_API_KEY=g0_live_xxxxxxxx
```

`G0_API_KEY` is read fresh on every command and is never written to disk — ideal for CI runners.

## Session storage

Tokens are stored in `~/.g0/auth.json` with `0600` permissions (owner read/write only), and cached entitlements in `~/.g0/entitlements.json`. OAuth access tokens refresh automatically when they near expiry; a revoked or invalid session is cleared silently and the CLI degrades to the free tier — it never crashes a scan.

`g0 logout` makes a best-effort revoke call to the platform and deletes both files.

### Pointing at a different environment

Set `G0_PLATFORM_URL` to target a staging or self-hosted platform (default: `https://app.guard0.ai`):

```bash
G0_PLATFORM_URL=https://staging.guard0.ai g0 login
```

## Entitlements & the premium threat feed

After you sign in, g0 fetches your **entitlements** (plan + feature flags) once and caches them for 24 hours. Entitlements unlock platform-backed capabilities in the CLI. Today that includes the **premium threat feed**:

- The free build ships a bundled advisory set plus a public OpenClaw advisory feed; the multi-ecosystem feed (`feeds.guard0.ai`) is defined but off by default until the endpoint is live, and can be enabled via `~/.g0/feeds.json` or `G0_THREAT_FEED_URL`.
- Accounts with the `premium-feed` entitlement additionally pull a private, higher-frequency IOC/advisory feed, authenticated with a per-account feed token. It rides the same fail-open path as every other feed source, so a bad token or an offline machine never breaks a scan — g0 falls back to cache, then to the bundled advisories.

Entitlement reads are synchronous and disk-only on scan paths; only `g0 login` and `g0 whoami` fetch fresh entitlements over the network.

## Free vs. platform

Everything local and single-scan stays free and fully featured. The platform adds the cross-time, cross-repo, and org-wide layer.

| Capability | Free CLI | Guard0 Platform |
|---|---|---|
| Scanning, testing, inventory, MCP assessment, endpoint, attestation | ✅ | ✅ |
| Signed AI-BOM, local fleet roll-up & drift | ✅ | ✅ |
| SARIF, JSON, Markdown output | ✅ | ✅ |
| Public multi-ecosystem threat feed | ✅ | ✅ |
| Premium real-time threat feed | — | ✅ (`g0 login`) |
| Org-wide dashboards, history & trends | — | ✅ |
| Compliance reports (EU AI Act, NIST, ISO 42001) | mapping shown inline | full reports |
| Team collaboration & governance workflows | — | ✅ |
| Adaptive red teaming (GOAT, Crescendo, SIMBA) | — | ✅ |

> **Note on data.** `g0 login` links your CLI to your account and unlocks entitlements — it does **not** upload your scan results. The Guard0 Platform ingests data through its own connectors, not from the g0 CLI. Your scans stay local unless you deliberately send them somewhere.

## Contextual prompts (and turning them off)

When a scan surfaces something worth acting on across your estate — critical findings, fleet drift, exposed endpoint secrets — g0 may print a one-line pointer to the platform. These are frequency-capped, shown at most once per run, and **never appear in machine output or CI**:

- automatically suppressed when output is not a TTY, when `CI` is set, and in `--json` / `--sarif` / `--output` modes;
- suppressed for signed-in users on a paid plan;
- disabled entirely with `G0_NO_CTA=1` or by setting `cta: false` in your `.g0.yaml`.

```bash
export G0_NO_CTA=1          # never show platform prompts
```

```yaml
# .g0.yaml
cta: false
```

## See also

- [Getting Started](getting-started.md)
- [g0 as an MCP Server](mcp-server.md)
- [CI/CD Integration](ci-cd.md)
- [Fleet Control Plane](fleet.md)
