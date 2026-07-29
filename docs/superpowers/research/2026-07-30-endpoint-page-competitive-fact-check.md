# Competitive fact-check — endpoint page & sentinel spec (2026-07-30)

**Scope.** Every competitive claim in
[`docs/solutions/mdm-ai-footprint-governance.md`](../../solutions/mdm-ai-footprint-governance.md)
("Why endpoint-native", per-MDM recipes) and the researched positioning section of
[`docs/superpowers/specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md`](../specs/2026-07-23-g0-sentinel-fleet-ai-footprint-design.md)
(§"Competitive positioning", §16 sources), verified against live vendor sources on
2026-07-29/30 by five parallel research passes.

**Headline verdicts.**

1. The two-camp taxonomy (network/proxy vs SaaS-API) was accurate when researched but was
   **overtaken by events in June–July 2026**, partly *before* the spec's 2026-07-23 date.
2. **"Only Harmonic Security and Lanai ship true endpoint agents" is WRONG as written.**
   Nightfall, Cyberhaven, SentinelOne/Prompt (Aug 2025), Koi→Palo Alto (Apr 2026), and
   CrowdStrike (announced Mar 2026) all shipped or announced endpoint agents with AI
   visibility before the claim date.
3. **"The inventory positioning is unoccupied" is false in its strong form** — Koi/PANW
   branded the category "Agentic Endpoint Security" — but a *narrower* wedge survives
   (see "What survives" below).
4. All seven ManageEngine Endpoint Central capability claims are **accurate**; the Jamf and
   Intune recipe rows need corrections.

---

## 1. Network/proxy camp ("they see traffic to AI domains")

### Zscaler — claimed "Zscaler AI Access" · PARTIALLY ACCURATE
- Correct current name: **AI Access Security** (siblings: AI Asset Management/AI-SPM, AI
  Guardrails, AI Red Teaming; umbrella "AI Protect").
  https://www.zscaler.com/products-and-solutions/ai-access-security ·
  https://www.zscaler.com/resources/data-sheets/zscaler-gen-ai-security-at-a-glance.pdf ·
  https://www.zscaler.com/products-and-solutions/ai-security
- Mechanism claim (SSE inline inspection, traffic-based GenAI discovery) accurate for the
  core product. https://www.zscaler.com/blogs/product-insights/shadow-ai-shadow-agents-visibility-control
- **Overtaken:** June 9, 2026 (Zenith Live) Zscaler announced **"Endpoint AI Security"** —
  "AI-related threats on employee devices, including risks hidden in browsers, plugins,
  extensions, and local AI tools" — plus AI Asset Management endpoint visibility, AI Broker
  (MCP/A2A + Agent Registry), AI Access Graph. **No GA dates in the release** — announced,
  not proven shipping.
  https://www.zscaler.com/press/zscaler-unveils-new-product-innovations-secure-agentic-ai ·
  https://www.globenewswire.com/news-release/2026/06/09/3309070/0/en/Zscaler-Unveils-New-Product-Innovations-to-Secure-Agentic-AI.html ·
  https://siliconangle.com/2026/06/09/zscaler-launches-ai-broker-endpoint-ai-security-ai-agents/ ·
  https://futurumgroup.com/insights/zscaler-bets-on-agentic-ai-security-at-zenith-live-2026/
- Client Connector itself remains traffic forwarding + posture checks, not AI inventory.
  https://help.zscaler.com/zscaler-client-connector/about-device-posture-profiles

### Netskope — claimed "AI Command Center" · NAME ACCURATE; "traffic-only" framing WRONG
- **Netskope One AI Command Center** exists — announced and GA **June 2, 2026** (predates
  the spec). https://www.netskope.com/products/ai-command-center ·
  https://www.netskope.com/press-releases/netskope-unveils-ai-command-center-delivering-comprehensive-ai-discovery-and-correlated-risk-intelligence-with-fully-coordinated-agentic-response ·
  https://www.networkworld.com/article/4180200/netskope-introduces-ai-command-center-to-monitor-and-secure-enterprise-ai-sprawl.html
- Three discovery mechanisms, two of them NOT proxy: inline NewEdge SSE; an eBPF agent for
  VMs/K8s; and **"Netskope One Client … scanning installed applications, running processes,
  and listening ports on managed endpoints to identify known AI agents, local models, and
  browser extensions."** The endpoint-blind framing was already wrong at write time.
  https://www.helpnetsecurity.com/2026/06/03/netskope-one-ai-command-center/
- Background: CCI risk-scores 370+ genAI apps. https://docs.netskope.com/en/evaluate-apps/ ·
  https://www.netskope.com/products/securing-generative-ai

### WitnessAI · ACCURATE
- Network-level, deliberately agentless ("without requiring endpoint agents or browser
  extensions"); Observe/Control/Protect modules; prompt+response visibility; Jan 2026 agent
  activity monitoring. https://witness.ai/ · https://witness.ai/product/ ·
  https://witness.ai/blog/introducing-witnessai-agentic-security-extending-the-confidence-layer-to-ai-agents/ ·
  https://witness.ai/blog/best-zscaler-alternatives-ai-security-governance/
- Status: independent; $58M round Jan 13, 2026 (total $85.5M).
  https://www.prnewswire.com/news-releases/witnessai-raises-58-million-for-global-expansion-and-announces-new-ways-to-secure-ai-agents-302659319.html

### Microsoft Defender for Cloud Apps · ACCURATE on discovery; framing needs precision
- Shadow-AI discovery is traffic-based (firewall/proxy logs + Defender for Endpoint
  *network transaction* logs — telemetry, not installed-software enumeration).
  https://learn.microsoft.com/en-us/defender-cloud-apps/mde-integration ·
  https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/discover-monitor-and-protect-the-use-of-generative-ai-apps/3999228
- **But** Defender Vulnerability Management ships installed-software inventory AND a
  browser-extension assessment (permissions, risk, hunting tables) — generic, with **no
  AI classification layer**. Blanket "Microsoft sees traffic, not installed inventory" is
  wrong; "Microsoft's shadow-AI *feature* is traffic-based" is right.
  https://learn.microsoft.com/en-us/defender-vulnerability-management/tvm-browser-extensions
- Purview DSPM for AI monitors AI usage incl. on endpoints via the Purview **browser
  extension** + onboarded devices; Endpoint DLP does paste/upload controls for AI sites
  (data-flow, not inventory). https://learn.microsoft.com/en-us/purview/dspm-for-ai ·
  https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about ·
  https://learn.microsoft.com/en-us/purview/ai-microsoft-purview-supported-sites
- Missed: Entra Global Secure Access "Shadow AI discovery" (June 2026 doc) — network-based
  GenAI/MCP/model-API discovery + Generative AI Insights (TLS inspection, prompt logging).
  https://learn.microsoft.com/en-us/entra/global-secure-access/concept-shadow-ai-discovery ·
  https://learn.microsoft.com/en-us/entra/global-secure-access/concept-generative-ai-insights

---

## 2. SaaS-API/OAuth camp ("agentless — they see grants and logins")

### Nudge Security · PARTIALLY ACCURATE (browser-blind framing outdated)
- Core agentless email/OAuth/IdP discovery accurate.
  https://www.nudgesecurity.com/features/how-it-works ·
  https://www.nudgesecurity.com/features/saas-discovery
- **But Nudge ships a first-party browser extension since June 11, 2025** (MDM-deployable;
  logins, OAuth grants, file uploads, in-browser blocking/AI policy) — its extension
  governance depends on it. https://www.nudgesecurity.com/features/browser-extension ·
  https://www.prnewswire.com/news-releases/nudge-security-extends-saas-and-generative-ai-security-governance-to-the-browser-302478264.html
- July 15, 2026: "Browser Extension Risk Analyst" + "OAuth Grant Risk Analyst" agents —
  surfaces risky third-party extensions on employee devices.
  https://www.nudgesecurity.com/press/nudge-security-unveils-ai-agents-to-mitigate-escalating-risks-from-hidden-oauth-grants-and-browser-extensions
- AI agent discovery (Agentforce, Copilot Studio, MCP connections, Cursor automations…):
  https://www.nudgesecurity.com/features/ai-agent-discovery ·
  https://www.helpnetsecurity.com/2026/05/28/nudge-browser-based-agentic-ai-security/
- $22.5M Series A Nov 18, 2025; still independent.
  https://www.nudgesecurity.com/press/nudge-security-raises-22-5m-series-a-to-secure-workforce-ai-and-saas
- Endpoint reach stops at the browser; no OS-level agent, no installed-software inventory.

### Wing Security · ACCURATE
- Agentless API-first ("no endpoint agents, no browser extensions"); AI discovery of tools,
  agents, embedded AI. https://wing.security/platform/ · https://wing.security/home/ ·
  https://wing.security/use-cases/ai-discovery/
- Sept 30, 2025: repositioned AI-security-centric. Still independent, last round 2022.
  https://www.globenewswire.com/news-release/2025/09/30/3158498/0/en/Wing-Security-Evolves-into-an-AI-Security-Centric-Company-Extends-Platform-to-Govern-and-Protect-SaaS-AI-Applications.html ·
  https://www.crunchbase.com/organization/wing-security

### Grip Security · PARTIALLY ACCURATE
- Email/IdP-based SaaS discovery accurate.
  https://community.sailpoint.com/t5/Connector-Directory/Grip-Security-Connector-Extending-SaaS-Identity-Risk-Management/ta-p/261514
- **But "Grip Extend" first-party browser extension exists** (cookies, requests, hidden-SaaS
  discovery). https://grip3818.zendesk.com/hc/en-us/articles/24305903062685-Grip-Extend-Security-and-Data-Architecture ·
  https://addons.mozilla.org/en-US/firefox/addon/grip-extend/
- AI governance limited; ITDR 2.0 (June 3, 2025) adds malicious-extension detection.
  https://www.reco.ai/compare/grip-security-vs-obsidian-security ·
  https://securityboulevard.com/2025/06/stay-ahead-of-identity-threats-with-grip-itdr-2-0-grip/
- Independent; $66M total (Series B Aug 2023).
  https://techcrunch.com/2023/08/22/grip-security-raises-41m-to-help-enterprises-manage-their-saas-identity-risk/

**Camp verdict:** none deploys an OS-level agent or inventories installed desktop AI
tooling — the core differentiation holds — but "agentless/SaaS-side" is now wrong for
Nudge and Grip at the browser layer.

---

## 3. Endpoint camp ("only Harmonic and Lanai; usage-monitoring, not inventory")

### Harmonic Security · PARTIALLY ACCURATE, then overtaken within days
- Historically a **browser extension**, not an endpoint agent ("Harmonic Protect is a
  lightweight browser extension…", Jan 2026 snapshot:
  https://web.archive.org/web/20260120114456/https://www.harmonic.security/products/harmonic-protect).
  So "endpoint desktop client" overstated the past; inline-DLP characterization accurate.
- Now four surfaces (extension, native desktop client, MCP gateway, embedded-SaaS
  detection), rebranded Explore/Guide/Command. https://www.harmonic.security/
- **"Not inventory" is now WRONG:** Harmonic's Endpoint Agent page — first archived
  **2026-07-26**, the week the spec was written — inventories "every native AI app,
  AI-first IDE, CLI tool, locally hosted model, and direct inference API call" (Claude
  Desktop, Cursor, Claude Code, Ollama, MCP servers; OpenAI/Anthropic/Bedrock/Azure calls
  tied to process+user). https://www.harmonic.security/solutions/endpoint-ai-security
  (CDX: sole snapshot 20260726045451) · https://aisecurityplatform.com/reviews/harmonic/
- Funding unchanged: $17.5M Series A Oct 2024.
  https://www.harmonic.security/resources/harmonic-security-raises-17-5-million-series-a-to-accelerate-zero-touch-data-protection-to-market

### Lanai · ACCURATE
- Edge-based AI Observability Agent, MDM-deployed <24h, on-device models, prompt-level
  visibility; runtime-derived (not static inventory).
  https://www.prnewswire.com/news-releases/new-platform-discovers-89-of-enterprise-ai-use-is-invisible-to-it-teams-as-lanai-launches-edge-based-ai-observability-agent-302552910.html ·
  https://siliconangle.com/2025/09/10/lanais-edge-based-observability-agents-aim-shut-shadow-ai/
- April 2026 pivot to "AI @ Work Operating System" (ROI-first).
  https://finance.yahoo.com/sectors/technology/articles/lanai-launches-ai-operating-system-133000943.html ·
  live site https://www.withlanai.com/ (note: lanai.ai is a dead Wix 404 — fix any links).
- Seed-stage ($11.5M total); no Series A found.

### Prompt Security · listing it as an independent startup is STALE
- **Acquired by SentinelOne**: announced Aug 5, 2025, closed Sept 5, 2025, ~$250M
  (~$133.6M cash + stock, per 10-Q).
  https://www.sentinelone.com/press/sentinelone-to-acquire-prompt-security-to-advance-genai-security/ ·
  https://www.sec.gov/Archives/edgar/data/1583708/000158370825000159/s-20251031.htm ·
  https://www.darkreading.com/endpoint-security/sentinelone-acquires-ai-startup-prompt-security
- Deploys browser extensions + a lightweight endpoint agent (IDE sync) + gateway/SDK + MCP
  gateway. Markets "Inventory every AI tool and code assistant in use" (15,000+ services),
  shadow MCP discovery, Copilot/Cursor/Claude Code governance — on an EDR install base.
  https://www.sentinelone.com/platform/securing-ai-prompt/ ·
  https://prompt.security/solutions/employees ·
  https://www.sentinelone.com/blog/a-new-chapter-for-ai-and-cybersecurity-sentinelone-acquires-prompt-security/

---

## 4. Adversarial pass — endpoint agents the page doesn't name

Direct refutations of "only Harmonic and Lanai" (all pre-2026-07-23):

| Vendor | Device footprint | AI visibility | Key sources |
|---|---|---|---|
| **CrowdStrike** "Shadow AI Discovery for Endpoint" (ann. Mar 23, 2026; GA unverified — future-products disclaimer) | Falcon sensor | "AI applications, agents, LLM runtimes, MCP servers, and development tools running across endpoints" + EDR AI Runtime Protection | https://www.crowdstrike.com/en-us/press-releases/crowdstrike-establishes-the-endpoint-as-the-epicenter-for-ai-security/ · https://siliconangle.com/2026/03/23/crowdstrike-targets-ai-security-gap-falcon-platform-expansion-rsac-conference/ |
| **Koi Security → Palo Alto** (intent Feb 17, 2026; closed Apr 14, 2026, ~$400M; category branded "Agentic Endpoint Security") | Endpoint platform, macOS/Win/Linux | Tracks "every application, code or OS package, extension, AI model, AI agent, and MCP the moment it shows up"; browser + VS Code/OpenVSX extensions; allow/block/remediate | https://www.koi.ai/platform · https://www.paloaltonetworks.com/company/press/2026/palo-alto-networks-completes-acquisition-of-koi-to-secure-the-agentic-endpoint · https://www.calcalistech.com/ctechnews/article/nu6ccmpyw |
| **Cyberhaven** "Agentic AI Security" (PR Mar 24, 2026; sensor long-shipping) | Endpoint data-lineage sensor | "Discover and inventory AI agents, MCP servers, and connections"; shadow AI across endpoints, browsers, CLIs, IDEs incl. Claude Code/Codex; Risk IQ | https://www.cyberhaven.com/press-releases/cyberhaven-closes-the-ai-security-gap-amid-the-meteoric-rise-of-agentic-ai · https://www.cyberhaven.com/product/ai-security · https://www.cyberhaven.com/blog/endpoint-ai-agents-blind-spot |
| **SentinelOne/Prompt** (Aug–Sept 2025) | Agent + browser extensions | See §3 above | (see §3) |
| **Nightfall AI** | Endpoint agent + browser plugin | Real-time exfil blocking to AI apps (DLP, not inventory) — still falsifies "only two endpoint agents" | https://www.nightfall.ai/integrations/browser-dlp-and-endpoint-dlp · https://www.prnewswire.com/news-releases/nightfall-unveils-ai-browser-security-solution-to-stop-data-exfiltration-in-real-time-302666771.html |
| **Snyk Agent Scan / mcp-scan** | MDM-deployable scanner | Reads local MCP/agent configs (Claude Code/Desktop, Cursor, Gemini CLI, Windsurf); risk analysis; "MDM-based deployment … with observability on Snyk EVO" — the closest philosophical twin to `g0 sentinel`, dev-tool-scoped | https://github.com/snyk/agent-scan · https://invariantlabs-ai.github.io/docs/mcp-scan/ |

Partial overlaps (device-resident but usage/DLP-centric or single-surface): **LayerX**
(extension-only AI app + AI-extension inventory: https://layerxsecurity.com/ ·
https://layerxsecurity.com/genai-dlp/), **Island AI Protect** (Mar 17, 2026; browser +
desktop-app visibility: https://www.island.io/ai), **Lasso Security** (extension + IDE
plugin + CrowdStrike Falcon telemetry integration Jan 26, 2026:
https://www.lasso.security/blog/ai-agents-discovery-lasso-crowdstrike-falcon), **Microsoft
stack** (usage-DLP; raw inventory unmerged/un-AI-tagged — see §1), **Fleet/osquery** (MCP
query pack + `mcp_listening_servers` table; primitives, not a governance product:
https://fleetdm.com/reports/get-mcp-client-configurations ·
https://fleetdm.com/tables/mcp_listening_servers), **Cato+Aim** (Sept 3, 2025; network
flows, client is a tunnel: https://www.catonetworks.com/news/cato-acquires-aim-security-to-extend-sase-leadership-and-secure-enterprise-ai-transformation/),
**1Password XAM/Kolide** (access-based shadow-AI: https://1password.com/blog/discover-and-secure-shadow-it-with-1password-extended-access-management),
**Archipelo** (dev-scoped AI tool tracking: https://archipelo.com/developer-attribution).
MDMs themselves (Jamf/Kandji): generic app inventory, no AI-tagged product found.
(Chrome Enterprise Premium: not verified this pass.)

### What survives — the defensible wedge

1. **Inventory × local PII-exposure evidence is still unoccupied.** No vendor found pairs
   per-machine AI-footprint inventory with static, local evidence of what PII sits in AI
   tool artifacts (histories/configs/reachable files). DLP rivals inspect data in flight.
2. **Office add-ins**: no AI-inventory competitor covers them. Narrow but unique.
3. **MDM-pushed, non-resident-platform audit**: contested only by Snyk Agent Scan
   (MCP-configs, dev-focused) — everyone else is a persistent agent platform.
4. **Independent auditor-of-record + OSS + local-first**: every direct competitor is an
   EDR/DLP/SSE platform grading its own estate; none are open source; none are local-first.
5. CrowdStrike's capability is announced-not-GA; Zscaler's has no GA date — a shipping
   window exists, measured in months.

**Required rewrite:** drop "only Harmonic and Lanai" entirely; stop describing Harmonic as
usage-only; update Nudge/Grip browser-extension reality; position explicitly against
"Agentic Endpoint Security" platforms: *"Multiple endpoint agents now discover AI apps,
coding agents, and MCP servers (CrowdStrike, Cyberhaven, SentinelOne/Prompt, Koi/Palo
Alto) — all persistent-agent platforms doing runtime governance or supply-chain risk. None
ship an MDM-pushed, per-machine AI-footprint audit spanning installed AI apps, coding
agents, browser AI extensions, MCP configs, AND Office add-ins, with local PII-exposure
evidence attached to each finding, from an independent open-source auditor."*

---

## 5. MDM capability claims (deployment table)

All ManageEngine Endpoint Central claims verified ACCURATE against vendor docs:

| Claim | Verdict | Key source |
|---|---|---|
| EC-only custom-script engine; MDM Plus lacks scripts (has custom *profiles* only) | ACCURATE | https://www.manageengine.com/products/desktop-central/help/configuration_templates/script_repository.html · https://www.manageengine.com/mobile-device-management/faq.html |
| Software Deployment: MSI + PKG/DMG (and more) | ACCURATE | https://www.manageengine.com/products/desktop-central/software-installation-supported-executables-how-to.html |
| No native fleet-wide file-pull; File Scan = type census (manual per-device transfer via remote control exists) | ACCURATE | https://www.manageengine.com/products/desktop-central/demo/inventory/file-scan.html · https://www.manageengine.com/products/desktop-central/api/ |
| Prohibited Software auto-uninstall (MSI default; EXE needs silent switches; ~90-min cycle) | ACCURATE | https://www.manageengine.com/products/desktop-central/help/inventory/configure_prohibited_software.html |
| Browser Add-on Restriction blocks AND removes extensions (native EC module, not external integration) | ACCURATE | https://www.manageengine.com/products/desktop-central/help/browser-security/addon-restriction.html |
| Application Control blocks executables (Security-edition licensing) | ACCURATE | https://www.manageengine.com/products/desktop-central/help/application-control/ac-overview.html |
| REST API v1.4 (newer modules under parallel `/dcapi/`) | ACCURATE | https://www.manageengine.com/products/desktop-central/api/ |

Corrections needed in the per-MDM recipe table:

- **Jamf**: notarization is NOT required for policy-based PKG installs (only for
  PreStage/DEP or user-run installs; notarizing is still good practice); a config profile
  does not install/schedule a LaunchDaemon — the PKG lays down the plist, and the Service
  Management (Managed Login Items) profile only tamper-protects it (no built-in Jamf editor).
  https://docs.jamf.com/10.42.0/jamf-pro/documentation/Execution_Frequency_for_Policies.html ·
  https://learn.jamf.com/en-US/bundle/technical-articles/page/Uploading_a_Configuration_Profile_for_Managed_Login_Items.html ·
  https://community.jamf.com/general-discussions-2/unsigned-package-deployment-30013
- **Intune**: no native scheduled-task payload — either the deployed script registers a
  Windows Scheduled Task, or use Remediations (Ent/Edu/VDA licensing; Once/Hourly/Daily).
  .intunewin + PowerShell + Edge/Chrome extension blocklists via Settings Catalog accurate.
  https://learn.microsoft.com/en-us/intune/app-management/deployment/create-win32-package ·
  https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations ·
  https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/extensioninstallblocklist

---

*Method note: five parallel research passes (network camp, SaaS camp, endpoint camp,
adversarial counterexample hunt, MDM claims) run 2026-07-29/30 with live web verification;
vendor primary sources preferred, Wayback CDX used for launch-timing evidence.*
