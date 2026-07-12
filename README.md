<div align="center">

<img src="assets/logo.png" alt="g0" width="180">

# Background Check for AI Agents

**Discover, assess, red-team, and now _enforce_ security across your AI agents —
and the MCP supply chain behind them.**
Local-first. No account required.

[![npm](https://img.shields.io/npm/v/@guard0/g0.svg?color=1f6feb)](https://www.npmjs.com/package/@guard0/g0)
[![node](https://img.shields.io/badge/node-%3E%3D20-1f6feb.svg)](https://nodejs.org)
[![license](https://img.shields.io/badge/license-AGPL--3.0-1f6feb.svg)](LICENSE)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010-orange.svg)](https://owasp.org/www-project-agentic-security/)
[![CI](https://github.com/guard0-ai/g0/actions/workflows/ci.yml/badge.svg)](https://github.com/guard0-ai/g0/actions)

</div>

> **You wouldn't hire someone without a background check.**
> **Why would you deploy an AI agent without one?**

```bash
npx @guard0/g0 endpoint     # what AI tools & MCP servers are on this machine?
npx @guard0/g0 scan .       # background-check an agent codebase
```

AI agents — and the **tools, MCP servers, and models** behind them — ship faster than anyone can track. g0 background-checks the whole estate: it discovers every component **on a laptop, in a repo, in CI, and across a fleet**, grades it against 1,128 rules in 12 domains, red-teams behavior with 1,200+ payloads, **enforces policy on live MCP traffic**, and hands you a signed, standards-mapped record you can give an auditor.

## The report card

Every scan ends in a grade you can act on — not a wall of findings:

```
  ./my-banking-agent  ·  langchain (+mcp)  ·  14 files  ·  1.2s

  CRITICAL  Shared memory between users            main.py:8   [AA-DL-046]
            Fix: isolate memory per user_id/session.  OWASP:ASI07
  HIGH      System prompt has no scope boundaries   main.py:21  [AA-GI-001]
            Fix: add role, task boundaries, output constraints.
  HIGH      Database tool without input validation  tools.py:34 [AA-TS-002]
  + 18 more across 12 domains

  CRIT 2   HIGH 5   MED 6   LOW 6   INFO 2         Total: 21

  Goal Integrity   ██████████████████░░░░░░░░░░  60
  Code Execution   ████████████████░░░░░░░░░░░░  52
  Data Leakage     █████████████████████████░░  82

  ─────────────────────────────────────────────────────
  C   ████████████████████████████░░░░░░░░  68
  ⚠  Grade capped: 2 critical findings present
```

The grade is **capped** when criticals are present, so a project with serious issues can never read as healthy — no matter how clean the rest looks. Every finding carries a one-line fix and maps to **OWASP, NIST, ISO 42001, and the EU AI Act**.

## What a background check covers

Point scanners check one repo. g0 covers the surfaces attackers actually use — the developer endpoint, the MCP supply chain, and the whole fleet — and keeps re-validating as things change.

|  | Surface | What it does |
|---|---|---|
| 🖥️ | **[Endpoint](docs/endpoint-monitoring.md)** | Discover the 19 AI dev tools & MCP servers on a machine; flag exposed secrets and unpinned servers. No server-side scanner can see this. |
| 🔬 | **[Scan](docs/rules.md)** | 1,128 rules across 12 domains, taint tracking, cross-file exfil analysis, and an A–F grade — for Python, TS/JS, Java, and Go. |
| 🧪 | **[Red-team](docs/dynamic-testing.md)** | 1,200+ adversarial payloads, a 4-level judge cascade, and CVSS scoring against a live agent, HTTP endpoint, or MCP server. |
| 🔌 | **[MCP supply chain](docs/mcp-security.md)** | Assess MCP servers from config + source, score per-skill trust, detect rug-pulls, and verify a package before you install it. |
| 🛡️ | **[Runtime proxy](docs/runtime-proxy.md)** — _new_ | Sit in the live path: deny dangerous tool calls, redact secrets, and block prompt-injection in tool output before your model reads it. |
| 📦 | **[Inventory](docs/inventory.md)** | A signed **CycloneDX 1.6 AI-BOM** of every model, tool, agent, and MCP server — content-addressed so it diffs across releases. |
| 🛰️ | **[Fleet](docs/fleet.md)** | Estate roll-up and drift across every repo and machine you track, with signed **[attestation packs](docs/attestation.md)** for audit. |
| 🧩 | **[Inside your IDE](docs/mcp-server.md)** | Run g0 _as_ an MCP server (`g0 mcp serve`) so Claude Code, Cursor, and Windsurf can scan and vet servers from the chat. |

## 60-second tour

```bash
g0 endpoint                              # audit AI tools & MCP configs on this machine
g0 scan ./my-agent                       # graded security assessment (1,128 rules)
g0 proxy install                         # route your IDE's MCP servers through g0
g0 test --target http://localhost:3000/api/chat   # red-team a live agent
g0 inventory . --cyclonedx --sign-key k  # signed AI Bill of Materials
g0 gate . --min-score 80                 # fail CI on policy violations
```

## 🛡️ Runtime MCP proxy

Static scanning tells you a server _looks_ risky. The runtime proxy sits in the live path and **enforces**: it wraps an MCP server as a man-in-the-middle over stdio, so every tool call and response flows through g0's policy engine.

```bash
g0 proxy install                 # rewrite IDE MCP configs to route through g0 (backs up configs)
g0 proxy -- npx -y server-x      # or wrap a single server directly
g0 proxy status                  # proxied servers + denied / redacted / alerted (24h)
```

It can **deny** a dangerous call (`rm -rf /`, writes outside an allowlist), **redact** secrets echoed in a response, and **catch prompt-injection in tool output before your model reads it** — the attack class a static scan can't stop. YAML policy with `observe` / `alert` / `enforce` modes, a local-first audit log, and **fail-open by design so it never bricks your IDE**. → **[docs/runtime-proxy.md](docs/runtime-proxy.md)**

## Coverage

<table>
<tr>
<td width="50%">

**12 Security Domains**

Goal Integrity · Tool Safety · Identity & Access · Supply Chain · Code Execution · Memory & Context · Data Leakage · Cascading Failures · Human Oversight · Inter-Agent · Reliability Bounds · Rogue Agent

</td>
<td width="50%">

**10 Compliance Standards**

OWASP Agentic Top 10 · NIST AI RMF · ISO 42001 · ISO 23894 · OWASP AIVSS · OWASP Agentic AI Top 10 · AIUC-1 · EU AI Act · MITRE ATLAS · OWASP LLM Top 10

</td>
</tr>
<tr>
<td>

**10 Framework Parsers** (+ generic fallback)

LangChain/LangGraph · CrewAI · OpenAI Agents SDK · MCP · Vercel AI SDK · Amazon Bedrock · AutoGen · LangChain4j · Spring AI · Go AI

</td>
<td>

**Deep analysis**

Pipeline taint tracking · cross-tool correlation · cross-file exfiltration · analyzability scoring · description-behavior alignment · multi-ecosystem threat feed

</td>
</tr>
</table>

<table align="center">
<tr>
<td align="center"><strong>1,128</strong><br><sub>Security Rules</sub></td>
<td align="center"><strong>1,200+</strong><br><sub>Attack Payloads</sub></td>
<td align="center"><strong>25</strong><br><sub>Attack Categories</sub></td>
<td align="center"><strong>19</strong><br><sub>Dev Tools Detected</sub></td>
<td align="center"><strong>5</strong><br><sub>Languages</sub></td>
</tr>
</table>

## Use it in CI & your IDE

**GitHub Actions** — scan, gate, upload SARIF, and post a sticky PR comment with a severity table and score delta:

```yaml
- uses: guard0-ai/g0@v2
  with:
    path: '.'
    min-score: '70'
    fail-on: 'high'
```

**Claude Code / Cursor / Windsurf** — let your agent run g0 directly:

```bash
claude mcp add g0 -- npx -y @guard0/g0 mcp serve
```

See [docs/ci-cd.md](docs/ci-cd.md) and [docs/mcp-server.md](docs/mcp-server.md).

## Connect to the Guard0 Platform

g0 is offline-first — everything above runs locally with no account. Signing in is optional (`g0 login`) and unlocks a **premium real-time threat feed** plus org-wide dashboards on the [Guard0 Platform](https://guard0.ai/signup). It never uploads your scans and never blocks a scan. → [docs/platform.md](docs/platform.md)

## Commands

| Command | Purpose |
|---|---|
| `g0 endpoint` | Discover AI dev tools & MCP server configs on this machine |
| `g0 scan [path]` | Security assessment with scoring and A–F grading |
| `g0 test` | Adversarial red-teaming — 1,200+ payloads, CVSS scoring |
| `g0 proxy [install/status/logs]` | Runtime MCP proxy — enforce/deny/redact/audit live tool calls |
| `g0 mcp [path]` / `mcp serve` | Assess MCP servers · run g0 as an MCP server |
| `g0 inventory [path]` | Signed CycloneDX 1.6 AI-BOM |
| `g0 fleet scan/status/drift` | Estate roll-up and drift across repos & machines |
| `g0 attest [path]` | Signed, standards-mapped attestation pack |
| `g0 flows [path]` | Execution-path mapping and toxic-flow detection |
| `g0 gate [path]` | CI/CD gate — thresholds + diff-based regression mode |
| `g0 daemon` | Continuous monitoring — MCP/skill drift, IOC alerts |
| `g0 login` / `logout` / `whoami` | Connect the CLI to your guard0.ai account (optional) |
| `g0 init` | Create a `.g0.yaml` config in the current project |

Every command supports `--json`. Full reference in [the docs](docs/).

## Documentation

| | |
|---|---|
| [Getting Started](docs/getting-started.md) | [Runtime MCP Proxy](docs/runtime-proxy.md) |
| [Rules Reference](docs/rules.md) · [Custom Rules](docs/custom-rules.md) | [MCP Security](docs/mcp-security.md) · [g0 as an MCP Server](docs/mcp-server.md) |
| [Scoring](docs/scoring.md) · [Findings](docs/findings.md) | [Endpoint Assessment](docs/endpoint-monitoring.md) |
| [AI Inventory](docs/inventory.md) · [Attestation](docs/attestation.md) | [Fleet Control Plane](docs/fleet.md) |
| [Dynamic Testing](docs/dynamic-testing.md) | [CI/CD Integration](docs/ci-cd.md) |
| [Compliance Mapping](docs/compliance.md) | [Platform & Authentication](docs/platform.md) |
| [Programmatic API](docs/api.md) · [Architecture](docs/architecture.md) | [FAQ](docs/faq.md) · [Glossary](docs/glossary.md) |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for adding rules, framework parsers, and submitting PRs.

```bash
git clone https://github.com/guard0-ai/g0.git && cd g0
npm install && npm test && npm run build
```

---

<div align="center">
<sub>An open-source project by <a href="https://guard0.ai/signup">Guard0</a>. The background check is just the beginning — for complete accountability across your fleet, see the <a href="https://guard0.ai/signup">Guard0 Platform</a>.</sub>
</div>
