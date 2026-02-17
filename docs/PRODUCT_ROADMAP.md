# Guard0 Product Roadmap: 3-Stage Shipping Plan

> From CLI scanner to enterprise control plane. Developer-first, standards-mapped, agent-native.

---

## Current State Assessment

### What's Built (g0 v0.1.0)
- **46 security rules** across 7 domains, all mapped to OWASP Agentic Top 10
- **4 framework parsers**: LangChain, CrewAI, MCP, OpenAI
- **Tree-Sitter AST** integration with regex fallback (Python, TypeScript, JavaScript)
- **3 output formats**: Terminal (colored), JSON, HTML (dark theme, Handlebars)
- **CI/CD gate command** (`g0 gate --min-score 80 --no-critical`)
- **Scoring engine** with weighted domains, severity deductions, letter grades (A-F)
- **80+ tests** (unit + integration), 5 test fixtures
- **Clean architecture**: discovery -> graph -> analysis -> scoring -> reporting

### What's Specified (test-agent-assess/docs)
- **1,140+ controls** across 12 domains with full detection logic, test procedures, remediation
- **7 standards mappings**: OWASP Agentic, AIUC-1, ISO 42001, NIST AI RMF, AIVSS, A2AS, ISO 23894
- **Dynamic analysis architecture**: adversarial payloads, LLM-as-judge, provider adapters
- **AI-BOM specification**: models, tools, MCP servers, agents, vector DBs
- **Developer guide**, contributing guide, methodology doc

### Gap Analysis vs. Snyk Evo

| Capability | Snyk Evo | Guard0 Today | Guard0 Target |
|---|---|---|---|
| Static analysis of agent code | No (BOM only) | 46 rules | 200+ rules |
| AI-BOM / Inventory | Yes (repos, models, MCP) | No | Full inventory CLI + UI |
| Threat modeling (STRIDE) | Yes (visual) | No | Agent graph visualization |
| Red teaming / Dynamic | Yes (API endpoints) | No | Static-informed dynamic |
| MCP endpoint scanning | Yes (fleet-wide) | Partial (config parsing) | Full MCP security |
| OWASP mapping | LLM Top 10 only | Agentic Top 10 | 7 standards |
| AIUC-1 coverage | None | Spec complete | Full control-by-control |
| Standards count per finding | 1 | 1 | 7 |
| Control count | ~14 vuln types | 46 rules | 1,140+ controls |
| Pricing model | Enterprise SaaS | Free CLI | Free CLI + paid platform |
| AI assistant | Evo chat (agentic) | None | g0 interactive shell |
| Deployment | Cloud SaaS | Local CLI | CLI + self-host + SaaS |
| Setup friction | Auth + org setup | `npx g0 scan .` | Zero to 60 seconds |

**Guard0's strategic advantages**:
1. Only tool doing static analysis of agent source code
2. 1,140 controls vs Evo's ~14 vulnerability types
3. AIUC-1 control-by-control coverage (mandates quarterly testing - we are the tool)
4. 7-standard mapping on every finding vs single-standard
5. Zero friction (no auth, no API keys, works offline)
6. Open source (community trust, contribution, transparency)
7. Agent-native from day 1 (not LLM-retrofitted)

---

## Stage 1: g0 CLI - The Developer Tool

> **Goal**: Be the security scanner every developer building agents runs before pushing code. The `eslint` of agent security.
>
> **Timeline**: 6-8 weeks
>
> **Success metric**: 1,000 npm weekly downloads, 500 GitHub stars, used in 50+ CI pipelines

### 1.1 Core Scanner Hardening

**Expand rule coverage: 46 -> 200+ controls**

Priority controls to implement from the spec (highest developer impact):

| Domain | Current | Target | Key Additions |
|---|---|---|---|
| Goal Integrity (AA-GI) | 8 | 25 | Multi-turn drift, cross-agent propagation, scope boundary leakage |
| Tool Safety (AA-TS) | 10 | 30 | SSRF via tool, file traversal, API mutation without confirmation |
| Identity & Access (AA-IA) | 8 | 25 | OAuth misconfiguration, token scope analysis, service account abuse |
| Supply Chain (AA-SC) | 5 | 15 | MCP server verification, model provenance, slopsquatting detection |
| Code Execution (AA-CE) | 6 | 20 | Sandbox escape, generated code analysis, template injection |
| Memory & Context (AA-MP) | 4 | 15 | Cross-session leakage, RAG poisoning, context window overflow |
| Data Leakage (AA-DL) | 5 | 30 | PII patterns (30 sub-controls), system prompt extraction, tool-mediated exfil |
| Inter-Agent Comms (AA-IC) | 0 | 15 | Delegation chain analysis, trust boundary violations |
| Cascading Failures (AA-CF) | 0 | 10 | Error propagation, circuit breaker absence, resource exhaustion |
| Human Oversight (AA-HO) | 0 | 10 | Missing approval gates, irreversible action detection |
| Rogue Agent (AA-RA) | 0 | 5 | Behavioral anomaly patterns in code |

**Additional parser support**:
- AWS Bedrock agent definitions (JSON/YAML)
- AutoGen conversation patterns
- Vercel AI SDK
- Generic Python/TS agent detection improvements

**Config file consumption**: Make `.g0.yaml` actually drive behavior:
```yaml
# .g0.yaml
version: 1
scan:
  exclude_rules: [AA-DL-001]
  exclude_paths: [tests/, docs/, __pycache__/]
  min_confidence: medium        # suppress LOW confidence findings
  frameworks: [langchain, mcp]  # explicit framework hints
gate:
  min_score: 80
  min_grade: B
  fail_on: [critical, high]
scope:                          # agent scope declaration
  name: "Customer Support Bot"
  allowed_tools: [search, lookup_order]
  allowed_data: [order_history, faq]
  denied_actions: [delete, modify_payment]
```

### 1.2 AI-BOM / Inventory Command

```bash
g0 inventory [path]              # Detect all AI components
g0 inventory --format json       # Machine-readable
g0 inventory --format cyclonedx  # CycloneDX SBOM
g0 inventory --format table      # Terminal table
```

**Detects**:
- **Models**: OpenAI (gpt-4, gpt-4o), Anthropic (claude-*), AWS Bedrock, local models (ollama, llama.cpp)
- **Frameworks**: LangChain, LangGraph, CrewAI, AutoGen, Vercel AI SDK, Haystack
- **Tools**: @tool decorators, function_tool schemas, MCP tool definitions, API integrations
- **MCP Servers**: claude_desktop_config.json, .cursor/mcp.json, cline_mcp_settings.json
- **Vector DBs**: Pinecone, Chroma, Weaviate, pgvector, FAISS
- **Agents**: Named agent instances, delegation chains, supervisor hierarchies

**Output** (terminal):
```
AI Bill of Materials
====================
Models:        3  (gpt-4o, claude-sonnet, text-embedding-3-small)
Frameworks:    2  (langchain@0.3.x, langgraph@0.2.x)
Agents:        4  (router, researcher, writer, reviewer)
Tools:         12 (3 custom, 9 built-in)
MCP Servers:   2  (github, filesystem)
Vector DBs:    1  (chroma)
Prompts:       6  (4 system, 2 user templates)
```

### 1.3 MCP Security Command

```bash
g0 mcp [config-path]            # Scan MCP configuration
g0 mcp --auto                   # Auto-detect config files
g0 mcp --verify                 # Verify server integrity
```

**Scans**:
- `claude_desktop_config.json` (Claude Desktop)
- `.cursor/mcp.json` (Cursor)
- `cline_mcp_settings.json` (Cline)
- `.vscode/mcp.json` (VS Code)
- Custom config paths

**Checks**:
- Hardcoded secrets in env vars
- `npx -y` usage (supply chain risk - runs unverified packages)
- Unverified remote servers (no checksum/signature)
- Over-permissioned tool descriptions (tool poisoning vectors)
- Missing authentication on server endpoints
- Excessive tool count per server
- Known vulnerable MCP packages

### 1.4 Output Format Expansion

**SARIF 2.1.0** (GitHub/GitLab code scanning integration):
```bash
g0 scan . --sarif results.sarif
# Upload to GitHub:
# gh api repos/{owner}/{repo}/code-scanning/sarifs -f sarif=@results.sarif
```

**Markdown** (PR comments):
```bash
g0 scan . --format markdown > comment.md
```

**CI exit code reporter** (structured):
```bash
g0 gate . --min-score 80 --output ci
# Exit 0 = pass, Exit 1 = fail, Exit 2 = error
# Prints single-line summary for CI logs
```

### 1.5 CI/CD Integrations

**GitHub Action** (`guard0/agent-assess-action`):
```yaml
# .github/workflows/agent-security.yml
name: Agent Security
on: [push, pull_request]
jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: guard0/agent-assess-action@v1
        with:
          path: ./src/agents
          min-score: 80
          fail-on: critical
          sarif: true           # Upload to GitHub Code Scanning
          comment: true         # Post PR comment with findings
```

**GitLab CI template**:
```yaml
# .gitlab-ci.yml
include:
  - remote: 'https://raw.githubusercontent.com/guard0/g0/main/.gitlab/agent-security.yml'
agent-security:
  variables:
    G0_MIN_SCORE: "80"
    G0_FAIL_ON: "critical"
```

**Pre-commit hook**:
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/guard0/g0
    rev: v1.0.0
    hooks:
      - id: agent-assess
        args: [--min-score, "70", --quiet]
```

### 1.6 IDE Integration - VS Code Extension

**guard0-vscode** extension:
- Inline diagnostics (squiggly lines on findings, like ESLint)
- Severity-colored gutters (red=critical, orange=high, yellow=medium)
- Quick-fix suggestions with remediation code
- Status bar showing agent security score
- Command palette: "Guard0: Scan Agent", "Guard0: Show AI-BOM"
- File save auto-scan (configurable)
- Problems panel integration

Architecture: Extension spawns `g0 scan --json` subprocess, parses JSON output, maps findings to VS Code diagnostics.

### 1.7 Interactive Shell

```bash
g0 shell                        # Enter interactive mode
g0>                             # REPL prompt
```

**Commands in shell**:
```
g0> scan .                       # Run scan
g0> inventory                    # Show AI-BOM
g0> mcp                          # Scan MCP configs
g0> findings                     # List current findings
g0> finding AA-TS-001            # Detail on specific finding
g0> explain AA-GI-003            # Explain a control
g0> fix AA-IA-001                # Show remediation for finding
g0> compare last                 # Compare with last scan
g0> export json report.json      # Export current results
g0> watch .                      # Watch mode (re-scan on file change)
g0> config                       # Show current config
g0> help                         # Available commands
```

Implementation: Use `readline` or `inquirer` for the REPL. Maintain scan state in memory. Support command history and tab completion.

### 1.8 Package & Distribution

```bash
# Zero-config usage (no install)
npx g0 scan .
npx g0 inventory .
npx g0 mcp --auto

# Global install
npm install -g g0

# Programmatic API
import { scan, inventory } from 'g0';
const result = await scan('./my-agent');
```

**npm package**: `g0` (short, memorable, matches brand)
**Binary name**: `g0`
**License**: AGPL-3.0 (commercial license available)

### 1.9 Launch Content

- "We scanned 100 open-source AI agents. Here's what we found." (blog post with data)
- Agent security benchmark dataset (open)
- AIUC-1 implementation guide (positions Guard0 as the standard)
- "Is your MCP server secure?" scan of top 50 MCP servers

### Stage 1 Deliverables Summary

| Deliverable | Priority | Effort |
|---|---|---|
| Expand to 200+ controls | P0 | Large |
| `g0 inventory` (AI-BOM) | P0 | Medium |
| `g0 mcp` security scanning | P0 | Medium |
| SARIF output format | P0 | Small |
| GitHub Action | P0 | Medium |
| .g0.yaml config consumption | P1 | Medium |
| VS Code extension | P1 | Medium |
| Interactive shell | P1 | Medium |
| Pre-commit hook | P1 | Small |
| GitLab CI template | P2 | Small |
| Markdown output (PR comments) | P2 | Small |
| CycloneDX SBOM output | P2 | Medium |
| Additional parsers (Bedrock, AutoGen) | P2 | Medium |

---

## Stage 2: Guard0 Web Platform - The Dashboard

> **Goal**: Self-service web platform where developers and teams see aggregate scan results, track trends, manage compliance, and collaborate.
>
> **Timeline**: 8-12 weeks (parallel with Stage 1 later items)
>
> **Success metric**: 500 registered users, 100 active teams, 10 paid conversions
>
> **Design**: IBM Carbon Design System, dark theme (g90/g100), responsive

### 2.1 Tech Stack

| Layer | Technology | Rationale |
|---|---|---|
| **Frontend** | Next.js 15 (App Router) | SSR, API routes, React Server Components |
| **UI Components** | IBM Carbon Design System (React) | Dark theme native, enterprise-grade, accessible |
| **Theme** | Carbon g100 (dark) | Matches Evo aesthetic but differentiated by design system |
| **Charts** | Carbon Charts / Recharts | Severity bars, trend lines, radar charts |
| **State** | Zustand + React Query | Lightweight, server-state caching |
| **Backend** | Next.js API Routes + tRPC | Type-safe API, co-located with frontend |
| **Database** | PostgreSQL (Neon/Supabase) | Scan results, users, orgs, findings |
| **Auth** | Clerk or NextAuth.js | GitHub/Google SSO, org management |
| **Storage** | S3-compatible (R2/S3) | HTML reports, SARIF files, scan artifacts |
| **Queue** | Inngest or BullMQ | Async scan processing, webhook delivery |
| **Hosting** | Vercel (frontend) + Fly.io (workers) | Edge-fast UI, isolated scan workers |
| **Monorepo** | Turborepo | Share types between CLI and web |

### 2.2 Information Architecture

```
guard0.dev/
├── / (Landing + marketing)
├── /login
├── /dashboard                    # Overview: risk posture, trends, quick actions
├── /scans                        # Scan history list
│   └── /scans/:id                # Individual scan detail
├── /inventory                    # AI-BOM across all scans
│   ├── /inventory/models
│   ├── /inventory/frameworks
│   ├── /inventory/tools
│   ├── /inventory/mcp-servers
│   └── /inventory/agents
├── /findings                     # All findings across scans
│   └── /findings/:id             # Finding detail with remediation
├── /compliance                   # Standards compliance view
│   ├── /compliance/owasp-agentic
│   ├── /compliance/aiuc-1
│   ├── /compliance/iso-42001
│   └── /compliance/nist-ai-rmf
├── /mcp                          # MCP security dashboard
│   └── /mcp/:server              # Individual server detail
├── /policies                     # Policy definitions (what passes/fails)
├── /integrations                 # GitHub, GitLab, Slack, Jira connections
├── /settings                     # Org, team, billing, API keys
└── /docs                         # Embedded documentation
```

### 2.3 Dashboard (Home)

**Top metrics bar**:
```
[Agent Risk Score: 72/100 C] [Scans (7d): 847] [Critical: 12] [MCP Servers: 23]
```

**Risk trend chart**: 30-day line chart of aggregate risk score across all scans
**Findings by severity**: Stacked bar chart (Critical/High/Medium/Low) over time
**Recent scans table**: Last 20 scans with score, grade, findings count, framework, repo
**Quick actions**: "Scan a repo", "Check MCP config", "View compliance report"
**Top risks**: Highest-severity open findings across all projects

### 2.4 Scan Results View

**Individual scan detail** (`/scans/:id`):
- Score gauge (0-100) with letter grade
- Domain scores radar chart (7 axes)
- Findings table with severity badges, sortable/filterable
- Agent graph visualization (nodes = agents/tools/prompts, edges = relationships)
- AI-BOM summary for this scan
- Standards coverage heatmap (which OWASP/AIUC controls pass/fail)
- Download: JSON, SARIF, HTML, PDF
- Comparison with previous scan (diff view)

### 2.5 AI-BOM / Inventory View

Similar to Evo's inventory but deeper:
- **Repositories**: Which repos contain AI components
- **Models**: All detected models with vendor, version, source repo
- **Frameworks**: Detected frameworks with versions
- **Tools**: All agent tools with type (custom/built-in), permissions
- **MCP Servers**: All detected servers with security status
- **Agents**: All detected agents with delegation chains
- **Vector DBs**: Detected vector stores
- **Dependencies**: AI-related package dependencies with version status

Each item links to findings that reference it.

### 2.6 Compliance View

**Per-standard dashboard**:
- OWASP Agentic Top 10: 10 risk categories, pass/fail/partial per category
- AIUC-1: 6 domains, 50+ controls, control-by-control status
- ISO 42001: Annex A mapping, 42 control objectives
- NIST AI RMF: 4 functions, sub-category coverage

**Compliance report generator**:
- Export as PDF or HTML
- Include evidence (findings, scan results, remediation status)
- Suitable for audit submissions
- Quarterly report template (aligns with AIUC-1 quarterly testing mandate)

### 2.7 CLI-to-Platform Bridge

```bash
# Authenticate CLI with platform
g0 auth login                    # Opens browser for OAuth

# Upload scan results
g0 scan . --upload               # Scan and upload to platform
g0 scan . --json | g0 upload -   # Pipe JSON to upload

# Pull policies from platform
g0 scan . --policy org-default   # Apply org policy during scan

# View results on web
g0 scan . --upload --open        # Opens scan result in browser
```

**API endpoints**:
```
POST /api/v1/scans               # Upload scan result
GET  /api/v1/scans               # List scans
GET  /api/v1/scans/:id           # Get scan detail
GET  /api/v1/inventory           # Get AI-BOM
GET  /api/v1/findings            # Get findings
POST /api/v1/policies            # Create policy
GET  /api/v1/compliance/:standard # Get compliance status
```

### 2.8 GitHub/GitLab Integration

- **Repository connection**: Connect repos, auto-scan on push/PR
- **PR checks**: Report scan results as GitHub Check with annotations
- **Code scanning**: Upload SARIF to GitHub Code Scanning alerts
- **PR comments**: Post finding summary as PR comment
- **Issue creation**: Create GitHub/GitLab issues from findings
- **Webhook events**: Notify on new critical findings

### 2.9 Pricing Model

| Tier | Price | Limits |
|---|---|---|
| **Free** | $0 | 3 projects, 100 scans/month, 1 user, community support |
| **Team** | $49/month | 20 projects, unlimited scans, 10 users, compliance reports, Slack/email alerts |
| **Business** | $199/month | Unlimited projects, unlimited scans, 50 users, SSO, priority support, SLA |
| **Enterprise** | Custom | Everything + on-prem, runtime control, custom integrations, dedicated support |

Free tier is generous enough that individual developers never hit limits. Team tier kicks in when you need compliance reports or team collaboration.

### Stage 2 Deliverables Summary

| Deliverable | Priority | Effort |
|---|---|---|
| Next.js app with Carbon dark theme | P0 | Large |
| Auth (GitHub SSO) + org management | P0 | Medium |
| Scan result upload + storage | P0 | Medium |
| Dashboard with risk metrics + trends | P0 | Large |
| Individual scan detail view | P0 | Large |
| AI-BOM inventory view | P0 | Medium |
| CLI auth + upload commands | P0 | Medium |
| Findings list with filters | P1 | Medium |
| Compliance views (OWASP, AIUC-1) | P1 | Large |
| GitHub integration (checks, SARIF) | P1 | Medium |
| MCP security dashboard | P1 | Medium |
| Agent graph visualization | P2 | Large |
| PDF compliance report export | P2 | Medium |
| Slack/email notifications | P2 | Small |
| Billing (Stripe) | P2 | Medium |

---

## Stage 3: Enterprise Platform - The Control Plane

> **Goal**: Full enterprise agent governance: discovery, access control, runtime monitoring, policy enforcement, compliance automation.
>
> **Timeline**: 12-16 weeks (starts after Stage 2 core is live)
>
> **Success metric**: 5 enterprise POVs, 2 closed deals, $200K pipeline

### 3.1 Agent Discovery Engine

**Multi-source discovery** (what Evo calls "Inventory Agent"):

| Source | Method | Discovers |
|---|---|---|
| **Source Code** | g0 scan (existing) | Agents, tools, prompts, models, configs |
| **GitHub/GitLab Org** | API crawler | All repos with AI code, PR activity, contributors |
| **AWS Bedrock** | AWS API | Bedrock agents, knowledge bases, guardrails |
| **Salesforce** | Metadata API | Agentforce agents, flows, permissions |
| **MCP Endpoints** | Fleet scanner | MCP servers on developer machines (opt-in agent) |
| **CI/CD Pipelines** | Webhook ingestion | Agent deployments, scan results, build artifacts |
| **Package Registries** | npm/PyPI monitoring | AI dependencies, version drift, known vulns |

**Discovery output**: Unified agent registry - the "system of record" from the vision doc.

### 3.2 Access Governance

**Per-agent blast radius mapping**:
- What data does this agent read? (databases, APIs, files, vector stores)
- What systems does this agent write to? (APIs, databases, email, Slack)
- What tools can this agent invoke? (with permission analysis)
- What credentials does this agent hold? (with scope analysis)
- Who can trigger this agent? (authentication requirements)

**Least privilege analysis**:
- Compare actual permissions vs. required permissions
- Flag over-permissioned agents
- Suggest permission reduction
- Track permission changes over time

**Unified access view**: Single dashboard showing all agent access across all platforms.

### 3.3 Runtime Monitoring

**Behavioral baselines**:
- Learn normal agent behavior patterns (tool calls, data access, response times)
- Detect anomalies (unusual tool calls, data access spikes, latency changes)
- Alert on drift from baseline

**Real-time event stream**:
- Agent invocations with timing
- Tool calls with parameters
- Data access events
- Error events
- Policy violations

**Integration points**:
- OpenTelemetry collector for agent traces
- Webhook receivers for platform events
- Log aggregation (Datadog, Splunk, etc.)
- SIEM integration (Splunk, Sentinel, QRadar)

### 3.4 Policy Engine

**Policy-as-code**:
```yaml
# guard0-policy.yaml
version: 1
policies:
  - name: "No hardcoded secrets"
    severity: critical
    action: block
    controls: [AA-IA-001, AA-IA-002, AA-IA-003]

  - name: "Require human approval for payments"
    severity: high
    action: alert
    scope:
      tools: ["process_payment", "transfer_funds"]
    require: human_approval

  - name: "Block shell execution in production"
    severity: critical
    action: block
    environments: [production, staging]
    controls: [AA-TS-001, AA-CE-001]

  - name: "Maximum tool permissions"
    severity: high
    action: warn
    max_tools_per_agent: 10
    denied_tools: ["rm", "drop_table", "delete_user"]
```

**Enforcement modes**:
- **Monitor**: Log violations, no blocking
- **Warn**: Alert on violations, allow execution
- **Block**: Prevent deployment/execution on violation
- **Kill**: Terminate running agent on violation (the "kill switch")

### 3.5 Compliance Automation

**Continuous compliance**:
- Auto-generate quarterly AIUC-1 assessment reports
- Track ISO 42001 control evidence over time
- Map findings to regulatory requirements (EU AI Act, NIST, etc.)
- Audit trail for all agent changes, policy updates, scan results
- Exportable evidence packages for auditors

**Compliance dashboard**:
- Overall compliance score per standard
- Control-by-control status across all agents
- Gap analysis with remediation priorities
- Historical compliance trends
- Upcoming assessment deadlines

### 3.6 Multi-Tenant Architecture

```
Guard0 Platform
├── Org (Company)
│   ├── Teams
│   │   ├── Projects (repos, agents)
│   │   └── Members (RBAC: admin, editor, viewer)
│   ├── Policies (org-wide + team-level)
│   ├── Integrations (GitHub, AWS, Salesforce)
│   └── Settings (SSO, billing, audit log)
```

**Deployment options**:
- **SaaS**: Multi-tenant cloud (default)
- **Single-tenant**: Dedicated cloud instance
- **On-prem**: Self-hosted (Docker Compose / Kubernetes)
- **Hybrid**: CLI scans locally, results uploaded to cloud

### 3.7 Enterprise Features

| Feature | Description |
|---|---|
| **SSO/SAML** | Okta, Azure AD, Google Workspace |
| **RBAC** | Role-based access (org admin, team lead, developer, viewer) |
| **Audit log** | Every action logged with user, timestamp, details |
| **API keys** | Scoped API keys for CI/CD and automation |
| **Webhooks** | Event notifications to external systems |
| **SLA** | 99.9% uptime, 4-hour response for critical |
| **Data residency** | US, EU, APAC deployment regions |
| **Encryption** | AES-256 at rest, TLS 1.3 in transit |
| **SOC 2** | Type II compliance for the platform itself |
| **White-label** | Custom branding for SI partners |

### Stage 3 Deliverables Summary

| Deliverable | Priority | Effort |
|---|---|---|
| Multi-source discovery engine | P0 | Very Large |
| Access governance / blast radius | P0 | Large |
| Policy engine with enforcement modes | P0 | Large |
| Runtime event ingestion | P0 | Large |
| Multi-tenant architecture | P0 | Large |
| Compliance report automation | P1 | Large |
| SSO/SAML + RBAC | P1 | Medium |
| Kill switch / emergency controls | P1 | Medium |
| SIEM integration (Splunk, Datadog) | P1 | Medium |
| Audit logging | P1 | Medium |
| On-prem deployment (Docker/K8s) | P2 | Large |
| White-label for partners | P2 | Medium |
| AWS Bedrock connector | P2 | Medium |
| Salesforce Agentforce connector | P2 | Medium |

---

## Cross-Stage: What Beats Snyk Evo

### 1. Depth of Analysis (Not Just Inventory)

Evo scans repos for AI components (BOM). Guard0 scans agent **logic** for vulnerabilities. The difference:

- Evo tells you "this repo uses LangChain with GPT-4o and has 2 tools"
- Guard0 tells you "this agent's search tool has an SSRF vulnerability because user input flows into the URL parameter at line 47, which maps to OWASP ASI02 and AIUC-1 B012"

### 2. Standards Coverage

Evo maps to OWASP LLM Top 10 (generic LLM risks). Guard0 maps every finding to 7 standards simultaneously, including AIUC-1 which mandates quarterly testing. When an enterprise needs to demonstrate compliance, Guard0 generates the actual evidence.

### 3. Open Source Trust

Developers trust open-source security tools (Snyk started this way). Evo is closed-source SaaS. Guard0's CLI is AGPL-3.0 - developers can read the rules, contribute controls, and verify there's no telemetry.

### 4. Zero Friction

Evo requires: account creation -> org setup -> repo connection -> agent onboarding -> scan configuration.
Guard0 requires: `npx g0 scan .`

### 5. MCP-First Security

Evo treats MCP as one component in inventory. Guard0 has a dedicated `g0 mcp` command that deeply analyzes MCP server configurations, detects tool poisoning vectors, and scans endpoint security across developer machines. This matters because MCP is where agent risk is concentrating fastest.

### 6. Static + Dynamic (Not Just One)

Evo's red teaming is API-endpoint dynamic testing only. Guard0 combines static analysis (finds the vulnerability in code) with static-informed dynamic testing (generates targeted payloads based on what the static scan found). This produces higher-quality findings with lower false positive rates.

### 7. Developer Experience

Evo is a dashboard you log into. Guard0 is a tool in your terminal, your IDE, your CI pipeline, and (optionally) a dashboard. The developer never has to leave their workflow.

---

## Implementation Sequence

### Weeks 1-4: Stage 1 Core
1. Expand controls to 200+ (P0 - parallel implementation across domains)
2. Implement `g0 inventory` command
3. Implement `g0 mcp` command
4. Add SARIF output format
5. Consume `.g0.yaml` configuration
6. Ship npm package as `g0`

### Weeks 4-8: Stage 1 Integrations + Stage 2 Foundation
1. GitHub Action
2. VS Code extension (basic)
3. Pre-commit hook
4. Interactive shell (basic REPL)
5. Next.js app scaffold with Carbon dark theme
6. Auth + database schema
7. Scan upload endpoint

### Weeks 8-12: Stage 2 Core
1. Dashboard with risk metrics
2. Scan detail view
3. AI-BOM web view
4. Findings management
5. CLI auth + upload
6. GitHub integration

### Weeks 12-16: Stage 2 Complete + Stage 3 Foundation
1. Compliance views
2. MCP dashboard
3. Agent graph visualization
4. Pricing + billing
5. Discovery engine architecture
6. Policy engine design

### Weeks 16-24: Stage 3 Core
1. Multi-source discovery
2. Access governance
3. Runtime monitoring
4. Policy enforcement
5. Enterprise features (SSO, RBAC, audit)
6. On-prem deployment

---

## Monorepo Structure

```
guard0/
├── packages/
│   ├── cli/                     # g0 CLI (current g0/ codebase)
│   │   ├── src/
│   │   ├── tests/
│   │   └── package.json         # "g0" on npm
│   ├── core/                    # Shared analysis engine
│   │   ├── src/
│   │   │   ├── analyzers/       # Rules, parsers, AST
│   │   │   ├── scoring/
│   │   │   ├── standards/
│   │   │   └── types/
│   │   └── package.json         # "@guard0/core"
│   ├── web/                     # Next.js web platform
│   │   ├── app/                 # App Router pages
│   │   ├── components/          # Carbon-based components
│   │   ├── lib/                 # Server utilities
│   │   └── package.json
│   ├── vscode/                  # VS Code extension
│   │   ├── src/
│   │   └── package.json
│   ├── github-action/           # GitHub Action
│   │   ├── action.yml
│   │   └── src/
│   └── shared/                  # Shared types & utilities
│       ├── src/
│       └── package.json         # "@guard0/shared"
├── controls/                    # Control definitions (YAML)
├── data/                        # Payloads, benchmarks
├── docs/                        # Documentation
├── turbo.json
├── package.json
└── pnpm-workspace.yaml
```

---

## Key Decisions to Make

1. **npm package name**: Is `g0` available on npm? Fallback: `guard0`, `agent-assess`
2. **Monorepo timing**: Restructure now or after Stage 1 ships?
3. **Dynamic testing scope**: Include in Stage 1 or defer entirely to Stage 2?
4. **Pricing validation**: Test pricing with early users before building billing
5. **Cloud provider**: Vercel + Neon vs. AWS vs. self-hosted from day 1?
6. **Open-source scope**: Just CLI? Or also web platform (open core model)?
