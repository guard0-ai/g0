# AA-SC: Supply Chain Security Controls

**Domain:** Supply Chain Security  
**OWASP Mapping:** ASI04 — Supply Chain & Dependency Vulnerabilities  
**Control Range:** AA-SC-001 through AA-SC-090  
**Total Controls:** 90  
**Last Updated:** 2026-02-13  
**Status:** Active

---

## Overview

AI agent supply chains are uniquely vulnerable because agents depend on a multi-layered ecosystem of models, tools, plugins, MCP servers, framework libraries, vector databases, and runtime dependencies — each introducing trust boundaries that attackers can exploit. Unlike traditional software supply chains where the primary risk is malicious code execution, AI agent supply chains also face model poisoning, tool description tampering, prompt injection through dependencies, and semantic attacks that alter agent behavior without changing executable code.

Supply chain compromise in agentic systems can be particularly devastating because a single poisoned dependency can affect every interaction an agent has with users and other systems. MCP server supply chain attacks are especially concerning as they can modify tool descriptions, alter parameter schemas, or inject hidden instructions that cause the agent to behave maliciously while appearing to function normally. The "slopsquatting" attack vector — where attackers register packages with names commonly hallucinated by LLMs — represents a novel supply chain threat unique to AI-assisted development.

These controls address the full lifecycle of supply chain security: from initial dependency selection and verification through ongoing monitoring, integrity checking, and incident response. They cover package registries, model repositories, MCP server ecosystems, plugin marketplaces, and build pipelines, requiring defense-in-depth across every layer of the agent's dependency graph.

---

## Applicable Standards

| Standard | Sections |
|----------|----------|
| OWASP Agentic Security | ASI04 — Supply Chain & Dependency Vulnerabilities |
| NIST AI RMF | GOVERN-1.4, MAP-3.3, MEASURE-2.7 |
| ISO 42001 | A.6 — Supply Chain Management, A.7 — Third Party |
| ISO 23894 | Clause 6.3 — Supply Chain Risk |
| MITRE ATLAS | AML.T0018 — Backdoor ML Model, AML.T0019 — Publish Poisoned Datasets |
| OWASP Agentic AI Top 10 | Principle 3 — Dependency Verification |
| OWASP AIVSS | Vectors: AV:S (Supply Chain) |

---

## Sub-Categories Summary

| # | Sub-Category | Controls | Range |
|---|-------------|----------|-------|
| 1 | Dependency Poisoning | 10 | AA-SC-001 – AA-SC-010 |
| 2 | MCP Server Supply Chain | 10 | AA-SC-011 – AA-SC-020 |
| 3 | Model Supply Chain | 10 | AA-SC-021 – AA-SC-030 |
| 4 | Plugin & Extension Risks | 10 | AA-SC-031 – AA-SC-040 |
| 5 | Package Integrity | 10 | AA-SC-041 – AA-SC-050 |
| 6 | Registry Attacks | 10 | AA-SC-051 – AA-SC-060 |
| 7 | Build Pipeline Compromise | 10 | AA-SC-061 – AA-SC-070 |
| 8 | Update Mechanism Abuse | 10 | AA-SC-071 – AA-SC-080 |
| 9 | Slopsquatting | 10 | AA-SC-081 – AA-SC-090 |

---

## 1. Dependency Poisoning (AA-SC-001 – AA-SC-010)

**Threat:** Attackers inject malicious code into legitimate dependencies through typosquatting, account takeover, or direct package compromise, causing agents to execute attacker-controlled code during installation or runtime.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-001 | No dependency pinning for agent packages | CRITICAL | static | stable | langchain, crewai, openai, autogen |
| AA-SC-002 | Lockfile absent or stale | CRITICAL | static | stable | langchain, crewai, openai, vercel-ai |
| AA-SC-003 | Install scripts not audited | HIGH | static | stable | langchain, openai, mcp |
| AA-SC-004 | Transitive dependency not scanned | HIGH | static | stable | langchain, crewai, autogen |
| AA-SC-005 | Known vulnerability in agent dependency | HIGH | static | stable | langchain, crewai, openai, bedrock |
| AA-SC-006 | Typosquatting risk in dependency name | HIGH | static | stable | langchain, openai, mcp |
| AA-SC-007 | Dependency from untrusted registry | MEDIUM | static | stable | mcp, langchain, openai |
| AA-SC-008 | No dependency allowlist enforced | MEDIUM | static | stable | crewai, autogen, langchain |
| AA-SC-009 | Dependency version range too broad | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-SC-010 | No automated dependency audit in CI | MEDIUM | both | stable | langchain, crewai, openai, autogen |

### Standards Mapping

- **ASI04:** Direct dependency poisoning is the primary supply chain attack vector
- **NIST AI RMF GOVERN-1.4:** Dependency governance and approval processes
- **ISO 42001 A.6:** Supply chain management for AI system components

### Detailed Descriptions

**AA-SC-001: No dependency pinning for agent packages**
- **Description:** Agent framework dependencies use floating version ranges (^, ~, >=) instead of exact pinned versions, allowing automatic resolution to potentially compromised newer versions.
- **Rationale:** Pinned versions ensure reproducible builds and prevent silent introduction of malicious code through upstream compromises. Every agent dependency should be locked to a verified hash.

**AA-SC-002: Lockfile absent or stale**
- **Description:** The project lacks a lockfile (package-lock.json, yarn.lock, poetry.lock) or the lockfile is not committed to version control, meaning dependency resolution is non-deterministic across environments.
- **Rationale:** Lockfiles provide cryptographic integrity guarantees for the entire dependency tree. Without them, the same install command can yield different packages on different machines.

**AA-SC-003: Install scripts not audited**
- **Description:** Dependencies include preinstall, postinstall, or other lifecycle scripts that execute arbitrary code during installation without review or sandboxing.
- **Rationale:** Install scripts are the most common vector for npm supply chain attacks. Agent projects should audit and ideally disable lifecycle scripts for non-essential dependencies.

**AA-SC-004: Transitive dependency not scanned**
- **Description:** Security scanning covers only direct dependencies, leaving transitive (indirect) dependencies unexamined for vulnerabilities or malicious code.
- **Rationale:** Most supply chain attacks target deep transitive dependencies that receive less scrutiny. The full dependency tree must be analyzed for security issues.

**AA-SC-005: Known vulnerability in agent dependency**
- **Description:** An agent framework dependency has a published CVE or security advisory that has not been patched or mitigated.
- **Rationale:** Known vulnerabilities in agent dependencies can be exploited to compromise agent behavior, extract sensitive data, or gain unauthorized access to connected systems.

**AA-SC-006: Typosquatting risk in dependency name**
- **Description:** A dependency name is visually similar to a popular package, suggesting potential typosquatting that could lead to installing a malicious impersonator package.
- **Rationale:** Typosquatting is a prevalent attack where malicious packages mimic legitimate ones through character substitution, transposition, or homoglyph attacks.

**AA-SC-007: Dependency from untrusted registry**
- **Description:** Agent dependencies are resolved from non-standard or private registries without integrity verification, allowing man-in-the-middle or registry compromise attacks.
- **Rationale:** Only verified, reputable registries should serve agent dependencies. Custom registries must enforce authentication, TLS, and package signing.

**AA-SC-008: No dependency allowlist enforced**
- **Description:** There is no curated list of approved dependencies for the agent project, allowing developers to introduce arbitrary packages without security review.
- **Rationale:** An allowlist reduces attack surface by limiting dependencies to those that have been vetted for security, license compliance, and maintenance status.

**AA-SC-009: Dependency version range too broad**
- **Description:** Dependencies specify overly permissive version ranges (e.g., >=1.0.0) that could resolve to major versions with breaking or malicious changes.
- **Rationale:** Broad version ranges increase the window of exposure to supply chain attacks by allowing resolution to any future version that might be compromised.

**AA-SC-010: No automated dependency audit in CI**
- **Description:** The CI/CD pipeline does not include automated dependency auditing (npm audit, pip-audit, safety) to catch known vulnerabilities before deployment.
- **Rationale:** Automated auditing in CI ensures that every build is checked against current vulnerability databases, preventing deployment of agents with known dependency issues.

---

## 2. MCP Server Supply Chain (AA-SC-011 – AA-SC-020)

**Threat:** MCP servers are installed from npm or other registries and granted tool-level access to agent systems. A compromised MCP server can manipulate tool descriptions, alter responses, and inject malicious instructions — all while appearing to function normally.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-011 | MCP server package not verified | CRITICAL | static | stable | mcp |
| AA-SC-012 | MCP server publisher identity unverified | CRITICAL | static | stable | mcp |
| AA-SC-013 | MCP server auto-update without review | HIGH | static | stable | mcp |
| AA-SC-014 | MCP server tool description hash not pinned | HIGH | static | stable | mcp |
| AA-SC-015 | MCP server npm install scripts present | HIGH | static | stable | mcp |
| AA-SC-016 | MCP server no minimum download threshold | MEDIUM | static | stable | mcp |
| AA-SC-017 | MCP server single maintainer risk | MEDIUM | static | stable | mcp |
| AA-SC-018 | MCP server dependency tree unaudited | MEDIUM | static | stable | mcp |
| AA-SC-019 | MCP server no source code repository link | MEDIUM | static | stable | mcp |
| AA-SC-020 | MCP server version rollback undetected | MEDIUM | dynamic | stable | mcp |

### Standards Mapping

- **ASI04:** MCP servers are a unique supply chain vector for agentic systems
- **OWASP Agentic AI Top 10 Principle 3:** All agent dependencies including tool servers must be verified
- **ISO 42001 A.7:** Third-party MCP servers require risk assessment

### Detailed Descriptions

**AA-SC-011: MCP server package not verified**
- **Description:** MCP server packages are installed from npm or other registries without verifying package integrity, signatures, or provenance attestations.
- **Rationale:** MCP servers have direct tool-level access to agent capabilities. Installing unverified packages risks introducing backdoored tools that can manipulate agent behavior.

**AA-SC-012: MCP server publisher identity unverified**
- **Description:** The npm publisher of an MCP server package has not been verified as the legitimate maintainer, risking installation of impersonator packages.
- **Rationale:** Account takeover of MCP server publishers can allow attackers to publish malicious updates that are automatically trusted by existing installations.

**AA-SC-013: MCP server auto-update without review**
- **Description:** MCP server packages are configured to auto-update to new versions without human review or automated security checks between versions.
- **Rationale:** Auto-updates bypass the review process, allowing a compromised update to silently alter tool behavior — the "rug pull" attack vector.

**AA-SC-014: MCP server tool description hash not pinned**
- **Description:** Tool descriptions served by MCP servers are not hashed and pinned, allowing the server to silently change tool semantics between invocations.
- **Rationale:** Tool description tampering (rug pull) can inject hidden instructions that change how the agent uses tools, enabling data exfiltration or unauthorized actions.

**AA-SC-015: MCP server npm install scripts present**
- **Description:** The MCP server npm package contains preinstall or postinstall scripts that execute code during installation.
- **Rationale:** Install scripts in MCP packages can execute arbitrary code with the installing user's permissions, potentially compromising the host system before the server is even started.

**AA-SC-016: MCP server no minimum download threshold**
- **Description:** An MCP server package has very low download counts, suggesting it may be newly created, abandoned, or a typosquatting attempt.
- **Rationale:** Low-download packages receive less community scrutiny and are more likely to be malicious or unmaintained, increasing supply chain risk.

**AA-SC-017: MCP server single maintainer risk**
- **Description:** The MCP server package has only one npm maintainer, creating a single point of failure if that account is compromised.
- **Rationale:** Single-maintainer packages are high-value targets for account takeover. Critical MCP servers should have multiple verified maintainers.

**AA-SC-018: MCP server dependency tree unaudited**
- **Description:** The MCP server's own dependencies have not been audited for vulnerabilities, malicious code, or excessive permissions.
- **Rationale:** An MCP server's transitive dependencies run with the same privileges as the server itself. A compromised sub-dependency can intercept or manipulate tool calls.

**AA-SC-019: MCP server no source code repository link**
- **Description:** The MCP server npm package does not link to a public source code repository, preventing verification that the published code matches the source.
- **Rationale:** Without a source repository, there is no way to audit the code, review changes between versions, or verify that the published artifact matches the source.

**AA-SC-020: MCP server version rollback undetected**
- **Description:** MCP server package downgrades to older versions are not detected, allowing attackers to roll back to versions with known vulnerabilities.
- **Rationale:** Version rollback attacks reintroduce patched vulnerabilities. Monitoring should alert when an MCP server version decreases unexpectedly.

---

## 3. Model Supply Chain (AA-SC-021 – AA-SC-030)

**Threat:** AI models downloaded from public repositories (Hugging Face, model zoos) may contain backdoors, poisoned weights, or malicious serialized objects that execute code on load, compromising the agent from the foundation up.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-021 | Model loaded from unverified source | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-SC-022 | Model file integrity not verified | CRITICAL | static | stable | langchain, bedrock, autogen |
| AA-SC-023 | Pickle deserialization in model loading | CRITICAL | static | stable | langchain, autogen |
| AA-SC-024 | Model provenance metadata absent | HIGH | static | stable | langchain, bedrock, openai |
| AA-SC-025 | Model card security review missing | HIGH | static | stable | langchain, bedrock |
| AA-SC-026 | Fine-tuned model training data unaudited | HIGH | dynamic | experimental | langchain, openai, bedrock |
| AA-SC-027 | Model version pinning absent | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-SC-028 | Model download over insecure channel | MEDIUM | static | stable | langchain, bedrock |
| AA-SC-029 | Model cache directory permissions too broad | MEDIUM | static | stable | langchain, autogen |
| AA-SC-030 | No model behavioral baseline comparison | MEDIUM | dynamic | experimental | langchain, openai, bedrock |

### Standards Mapping

- **MITRE ATLAS AML.T0018:** Backdoor ML Model — injecting malicious behavior into model weights
- **NIST AI RMF MAP-3.3:** Model provenance and integrity verification
- **ISO 23894 Clause 6.3:** AI-specific supply chain risk management

### Detailed Descriptions

**AA-SC-021: Model loaded from unverified source**
- **Description:** The agent loads AI models from URLs, file paths, or repositories without verifying the source's authenticity or the model's integrity.
- **Rationale:** Loading models from unverified sources risks executing backdoored models that behave normally on benchmarks but contain hidden malicious behaviors triggered by specific inputs.

**AA-SC-022: Model file integrity not verified**
- **Description:** Model files are loaded without checksum or hash verification, allowing tampered models to be substituted without detection.
- **Rationale:** Integrity verification ensures the model file has not been modified in transit or at rest. Without it, file system access or MITM attacks can substitute malicious models.

**AA-SC-023: Pickle deserialization in model loading**
- **Description:** The agent uses Python pickle (or similar unsafe deserialization) to load model files, enabling arbitrary code execution through crafted pickle payloads.
- **Rationale:** Pickle deserialization is a well-known remote code execution vector. Attackers can craft model files that execute arbitrary code when loaded, fully compromising the host.

**AA-SC-024: Model provenance metadata absent**
- **Description:** Downloaded models lack provenance metadata (training data sources, training infrastructure, fine-tuning history) needed to assess trustworthiness.
- **Rationale:** Provenance metadata enables risk assessment and audit. Without it, there is no way to evaluate whether the model was trained on poisoned data or by a trusted party.

**AA-SC-025: Model card security review missing**
- **Description:** The model is used without reviewing its model card for known limitations, biases, security considerations, and intended use scope.
- **Rationale:** Model cards document known security properties and limitations. Deploying a model outside its documented scope increases the risk of unexpected or exploitable behavior.

**AA-SC-026: Fine-tuned model training data unaudited**
- **Description:** Fine-tuned models are deployed without auditing the training data for poisoning, bias injection, or inclusion of sensitive information.
- **Rationale:** Training data poisoning can embed backdoors that cause specific inputs to trigger malicious outputs, making the attack difficult to detect through normal testing.

**AA-SC-027: Model version pinning absent**
- **Description:** The agent references model names without version pinning, causing automatic resolution to the latest version which may have degraded safety properties.
- **Rationale:** Model updates can change safety alignment, capabilities, and behavior. Unpinned versions may introduce regressions in security-critical behavior.

**AA-SC-028: Model download over insecure channel**
- **Description:** Model files are downloaded over HTTP or other unencrypted channels, allowing network attackers to substitute malicious models.
- **Rationale:** MITM attacks on model downloads can replace legitimate models with backdoored versions. All model downloads must use TLS with certificate verification.

**AA-SC-029: Model cache directory permissions too broad**
- **Description:** The local model cache directory has overly permissive file permissions, allowing other users or processes to tamper with cached model files.
- **Rationale:** Cached models with broad permissions can be replaced by local attackers. Cache directories should restrict access to the agent process owner only.

**AA-SC-030: No model behavioral baseline comparison**
- **Description:** No behavioral baseline exists for the model, preventing detection of behavior changes between model versions or after fine-tuning.
- **Rationale:** Behavioral baselines enable detection of model poisoning or degradation by comparing current outputs against expected behavior on reference inputs.

---

## 4. Plugin & Extension Risks (AA-SC-031 – AA-SC-040)

**Threat:** Agent frameworks support plugins, extensions, and custom tools that execute with the agent's full permissions. Malicious or poorly coded plugins can compromise agent security, exfiltrate data, or escalate privileges.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-031 | Plugin loaded without signature verification | CRITICAL | static | stable | langchain, crewai, autogen |
| AA-SC-032 | Plugin from unverified marketplace | HIGH | static | stable | langchain, openai, crewai |
| AA-SC-033 | Plugin permission scope not restricted | HIGH | static | stable | langchain, crewai, autogen |
| AA-SC-034 | Plugin code review not performed | HIGH | static | stable | langchain, crewai, openai |
| AA-SC-035 | Plugin sandbox isolation absent | HIGH | static | stable | langchain, autogen, crewai |
| AA-SC-036 | Plugin auto-update without approval | MEDIUM | static | stable | langchain, crewai, openai |
| AA-SC-037 | Plugin dependency isolation missing | MEDIUM | static | stable | langchain, autogen |
| AA-SC-038 | Plugin version compatibility unchecked | MEDIUM | static | stable | langchain, crewai, vercel-ai |
| AA-SC-039 | Plugin telemetry data collection undisclosed | MEDIUM | static | stable | langchain, openai, crewai |
| AA-SC-040 | Third-party plugin license incompatibility | MEDIUM | static | stable | langchain, crewai, autogen |

### Standards Mapping

- **ASI04:** Plugins are a primary vector for supply chain compromise in agent systems
- **ISO 42001 A.7:** Third-party plugin management and risk assessment
- **NIST AI RMF GOVERN-1.4:** Plugin governance and approval workflows

### Detailed Descriptions

**AA-SC-031: Plugin loaded without signature verification**
- **Description:** Agent plugins or extensions are loaded and executed without verifying digital signatures or integrity checksums.
- **Rationale:** Unsigned plugins can be tampered with between distribution and execution. Signature verification ensures plugins originate from trusted publishers and haven't been modified.

**AA-SC-032: Plugin from unverified marketplace**
- **Description:** Plugins are sourced from community marketplaces or repositories without vetting the marketplace's security practices or the plugin publisher's identity.
- **Rationale:** Unverified marketplaces may host malicious plugins disguised as legitimate tools. Only curated, security-reviewed sources should provide agent plugins.

**AA-SC-033: Plugin permission scope not restricted**
- **Description:** Plugins are granted the agent's full permission set instead of the minimum permissions needed for their stated functionality.
- **Rationale:** Excessive plugin permissions increase blast radius. A file-reading plugin should not have network access; a search plugin should not have file write capabilities.

**AA-SC-034: Plugin code review not performed**
- **Description:** Third-party plugin source code has not been reviewed for malicious behavior, security vulnerabilities, or unsafe patterns before deployment.
- **Rationale:** Code review is the most effective defense against supply chain attacks. All plugins should undergo security review proportional to their permission scope.

**AA-SC-035: Plugin sandbox isolation absent**
- **Description:** Plugins execute in the same process and security context as the agent without sandboxing, containment, or resource isolation.
- **Rationale:** Sandbox isolation limits the damage a compromised plugin can cause. Without it, a malicious plugin can access all agent memory, credentials, and system resources.

**AA-SC-036: Plugin auto-update without approval**
- **Description:** Installed plugins update automatically without requiring review or approval of the new version's changes.
- **Rationale:** Auto-updates can silently introduce malicious code. Plugin updates should require explicit approval after security review of the changes.

**AA-SC-037: Plugin dependency isolation missing**
- **Description:** Plugin dependencies are installed into the shared dependency tree rather than being isolated, allowing dependency confusion between plugins.
- **Rationale:** Shared dependencies create cross-plugin attack vectors. One plugin's malicious dependency can affect other plugins and the agent core through shared resolution.

**AA-SC-038: Plugin version compatibility unchecked**
- **Description:** Plugin version compatibility with the agent framework version is not verified, risking runtime errors or security bypasses from API mismatches.
- **Rationale:** Version mismatches can cause security checks to be silently skipped or error handling to fail, creating exploitable gaps in the agent's defenses.

**AA-SC-039: Plugin telemetry data collection undisclosed**
- **Description:** Third-party plugins collect and transmit telemetry data (usage patterns, input content, agent configuration) without disclosure or user consent.
- **Rationale:** Undisclosed telemetry can exfiltrate sensitive data processed by the agent. All data collection by plugins must be documented and opt-in.

**AA-SC-040: Third-party plugin license incompatibility**
- **Description:** Plugin licenses have not been checked for compatibility with the agent's license and deployment requirements, risking legal or compliance issues.
- **Rationale:** License incompatibility can force removal of critical plugins or expose the organization to legal liability, impacting agent availability and compliance.

---

## 5. Package Integrity (AA-SC-041 – AA-SC-050)

**Threat:** Package integrity failures allow attackers to substitute, modify, or tamper with agent dependencies between build and deployment, introducing malicious code that circumvents source-level security reviews.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-041 | Package checksum verification absent | CRITICAL | static | stable | langchain, crewai, openai |
| AA-SC-042 | Provenance attestation not required | HIGH | static | stable | langchain, openai, mcp |
| AA-SC-043 | Package signing not enforced | HIGH | static | stable | langchain, crewai, mcp |
| AA-SC-044 | Source-to-package mapping unverified | HIGH | static | experimental | langchain, openai, autogen |
| AA-SC-045 | Reproducible build not enforced | MEDIUM | static | experimental | langchain, crewai, openai |
| AA-SC-046 | Package manifest tamper detection absent | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-SC-047 | SBOM not generated for agent dependencies | MEDIUM | static | stable | langchain, crewai, autogen |
| AA-SC-048 | Package mirror integrity unverified | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-SC-049 | Vendored dependency drift undetected | MEDIUM | static | stable | langchain, autogen |
| AA-SC-050 | Package metadata inconsistency undetected | MEDIUM | static | stable | langchain, openai, mcp |

### Standards Mapping

- **ASI04:** Package integrity is foundational to supply chain security
- **OWASP Agentic AI Top 10 Principle 3:** Cryptographic verification of all dependencies
- **NIST AI RMF MEASURE-2.7:** Integrity measurement for AI system components

### Detailed Descriptions

**AA-SC-041: Package checksum verification absent**
- **Description:** Downloaded packages are not verified against known-good checksums (SHA-256/SHA-512) before installation or use.
- **Rationale:** Checksum verification is the minimum bar for package integrity. Without it, corrupted or tampered packages can be installed silently.

**AA-SC-042: Provenance attestation not required**
- **Description:** Package installations do not require SLSA provenance attestations that cryptographically prove where and how packages were built.
- **Rationale:** Provenance attestations provide verifiable evidence of build origin, preventing supply chain attacks that substitute packages built on compromised infrastructure.

**AA-SC-043: Package signing not enforced**
- **Description:** Agent packages are installed without requiring valid cryptographic signatures from trusted maintainers.
- **Rationale:** Package signing binds packages to verified publisher identities. Without enforcement, anyone who gains registry access can publish packages under legitimate names.

**AA-SC-044: Source-to-package mapping unverified**
- **Description:** There is no verification that the published package binary or bundle was built from the corresponding source code in the linked repository.
- **Rationale:** Attackers can publish packages with clean source repositories but inject malicious code during the build process that only appears in the distributed artifact.

**AA-SC-045: Reproducible build not enforced**
- **Description:** The agent project does not use reproducible builds, making it impossible to verify that the distributed artifact matches the source code.
- **Rationale:** Reproducible builds allow independent verification that a binary was built from specific source code, detecting build-time supply chain attacks.

**AA-SC-046: Package manifest tamper detection absent**
- **Description:** Package manifest files (package.json, pyproject.toml) lack tamper detection mechanisms to identify unauthorized modifications.
- **Rationale:** Manifest tampering can redirect dependency resolution to malicious packages or alter build scripts. Integrity monitoring must cover manifest files.

**AA-SC-047: SBOM not generated for agent dependencies**
- **Description:** No Software Bill of Materials (SBOM) is generated or maintained for the agent's dependency tree, limiting vulnerability tracking and incident response.
- **Rationale:** SBOMs enable rapid identification of affected systems when a dependency vulnerability is disclosed, reducing mean time to remediation.

**AA-SC-048: Package mirror integrity unverified**
- **Description:** Packages are fetched from mirrors or caches without verifying that the mirror's content matches the authoritative registry.
- **Rationale:** Compromised mirrors can serve tampered packages. Mirror integrity must be verified against the primary registry's checksums.

**AA-SC-049: Vendored dependency drift undetected**
- **Description:** Vendored (locally copied) dependencies diverge from their upstream sources without tracking, allowing patches and security fixes to be missed.
- **Rationale:** Vendored dependencies must be tracked against upstream to ensure security patches are applied and no unauthorized local modifications exist.

**AA-SC-050: Package metadata inconsistency undetected**
- **Description:** Inconsistencies between package metadata (declared dependencies, entry points, scripts) and actual package contents are not detected.
- **Rationale:** Metadata manipulation can hide malicious dependencies, extra files, or code that isn't declared in the package manifest.

---

## 6. Registry Attacks (AA-SC-051 – AA-SC-060)

**Threat:** Package registries (npm, PyPI, Hugging Face Hub) are centralized trust anchors. Registry compromise, confusion attacks, or namespace hijacking can deliver malicious packages to agent systems at scale.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-051 | Dependency confusion attack possible | CRITICAL | static | stable | langchain, openai, autogen |
| AA-SC-052 | Namespace squatting not monitored | HIGH | static | stable | langchain, mcp, openai |
| AA-SC-053 | Registry authentication not enforced | HIGH | static | stable | langchain, crewai, openai |
| AA-SC-054 | Private registry fallback to public | HIGH | static | stable | langchain, openai, autogen |
| AA-SC-055 | Package scope not restricted | MEDIUM | static | stable | langchain, mcp, openai |
| AA-SC-056 | Registry token in source code | MEDIUM | static | stable | langchain, crewai, openai |
| AA-SC-057 | No registry allow-listing | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-SC-058 | Star jacking on registry undetected | MEDIUM | static | stable | langchain, openai, mcp |
| AA-SC-059 | Abandoned package takeover unmonitored | MEDIUM | dynamic | stable | langchain, crewai, mcp |
| AA-SC-060 | Registry API rate limiting absent | MEDIUM | dynamic | experimental | langchain, openai, mcp |

### Standards Mapping

- **ASI04:** Registry attacks are a primary supply chain threat
- **NIST AI RMF GOVERN-1.4:** Registry governance and access controls
- **MITRE ATLAS AML.T0019:** Publishing poisoned artifacts to public repositories

### Detailed Descriptions

**AA-SC-051: Dependency confusion attack possible**
- **Description:** The project configuration allows private package names to be resolved from public registries, enabling dependency confusion attacks where a public package with the same name as an internal package is installed.
- **Rationale:** Dependency confusion is a high-impact attack that has successfully targeted major organizations. Registry scoping and resolution order must prevent public packages from shadowing private ones.

**AA-SC-052: Namespace squatting not monitored**
- **Description:** Related package namespaces on public registries are not monitored for squatting by potential attackers who register similar names to intercept installations.
- **Rationale:** Attackers register packages with names similar to popular agent libraries. Monitoring related namespaces enables early detection of impersonation attempts.

**AA-SC-053: Registry authentication not enforced**
- **Description:** Package registry interactions (install, publish) do not require authentication, allowing anonymous access that bypasses audit trails.
- **Rationale:** Authenticated registry access enables audit logging and restricts who can publish packages. Anonymous access removes accountability.

**AA-SC-054: Private registry fallback to public**
- **Description:** When a package is not found in the private registry, the package manager falls back to the public registry without explicit configuration to prevent this behavior.
- **Rationale:** Public registry fallback is the mechanism that enables dependency confusion attacks. Private registries should never silently fall back to public resolution.

**AA-SC-055: Package scope not restricted**
- **Description:** Packages are installed without scope restrictions, allowing unscoped packages to be installed from any registry source.
- **Rationale:** Scoped packages (@org/package) provide namespace protection that unscoped packages lack. Agent dependencies should prefer scoped packages to prevent name collision attacks.

**AA-SC-056: Registry token in source code**
- **Description:** Registry authentication tokens or API keys are hardcoded in source code, configuration files, or environment variable defaults accessible in the repository.
- **Rationale:** Leaked registry tokens allow attackers to publish malicious packages under the organization's namespace, bypassing trust relationships.

**AA-SC-057: No registry allow-listing**
- **Description:** The project does not restrict which registries packages can be fetched from, allowing resolution from arbitrary untrusted sources.
- **Rationale:** Registry allow-listing limits the attack surface to vetted registries. Without it, misconfiguration or .npmrc manipulation can redirect resolution to malicious registries.

**AA-SC-058: Star jacking on registry undetected**
- **Description:** Packages claim repository URLs that don't match their actual source (star jacking), borrowing the credibility of popular projects.
- **Rationale:** Star jacking misleads users into trusting malicious packages by associating them with popular, well-starred repositories they have no connection to.

**AA-SC-059: Abandoned package takeover unmonitored**
- **Description:** Dependencies on abandoned or unmaintained packages are not monitored, leaving the project vulnerable to maintainer account takeover or package hijacking.
- **Rationale:** Abandoned packages are prime targets for takeover. Monitoring maintenance status enables proactive migration before packages are compromised.

**AA-SC-060: Registry API rate limiting absent**
- **Description:** Registry API interactions are not rate-limited, allowing automated attacks to enumerate, scrape, or abuse registry services.
- **Rationale:** Rate limiting prevents automated abuse including brute-force credential attacks, package enumeration, and denial-of-service against registry infrastructure.

---

## 7. Build Pipeline Compromise (AA-SC-061 – AA-SC-070)

**Threat:** CI/CD pipelines that build and deploy agent systems are high-value targets. Compromising the build pipeline allows attackers to inject malicious code into the final artifact even when source code is clean.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-061 | Build environment not isolated | CRITICAL | static | stable | langchain, crewai, openai |
| AA-SC-062 | Build secrets accessible to dependencies | CRITICAL | static | stable | langchain, openai, autogen |
| AA-SC-063 | CI pipeline configuration not reviewed | HIGH | static | stable | langchain, crewai, openai |
| AA-SC-064 | Build artifact provenance not recorded | HIGH | static | stable | langchain, openai, mcp |
| AA-SC-065 | Third-party CI actions not pinned | HIGH | static | stable | langchain, crewai, openai |
| AA-SC-066 | Build cache poisoning possible | MEDIUM | static | stable | langchain, autogen, openai |
| AA-SC-067 | Build log sensitive data exposure | MEDIUM | static | stable | langchain, crewai, bedrock |
| AA-SC-068 | No multi-party approval for deployments | MEDIUM | both | stable | langchain, crewai, openai |
| AA-SC-069 | Build environment drift unmonitored | MEDIUM | dynamic | experimental | langchain, openai, autogen |
| AA-SC-070 | CI runner self-hosted without hardening | MEDIUM | static | stable | langchain, crewai, openai |

### Standards Mapping

- **ASI04:** Build pipeline security for AI agent deployment
- **NIST AI RMF GOVERN-1.4:** Build and deployment governance
- **ISO 42001 A.6:** Supply chain security for build infrastructure

### Detailed Descriptions

**AA-SC-061: Build environment not isolated**
- **Description:** Agent build environments share resources, network access, or file systems with other projects, allowing cross-contamination between builds.
- **Rationale:** Isolated build environments prevent one compromised build from affecting others. Each agent build should run in a fresh, ephemeral environment.

**AA-SC-062: Build secrets accessible to dependencies**
- **Description:** Build-time secrets (API keys, deploy tokens, signing keys) are accessible to dependency install scripts and build plugins.
- **Rationale:** Secrets exposed during dependency installation can be exfiltrated by malicious packages. Build secrets should only be accessible during explicitly trusted build phases.

**AA-SC-063: CI pipeline configuration not reviewed**
- **Description:** Changes to CI/CD pipeline configuration files (.github/workflows, Jenkinsfile, etc.) are not subject to the same review requirements as source code.
- **Rationale:** Pipeline modifications can subvert all other security controls. Pipeline changes must receive at least the same level of review as application code.

**AA-SC-064: Build artifact provenance not recorded**
- **Description:** Build artifacts (agent binaries, container images) do not include provenance metadata recording the build environment, inputs, and process.
- **Rationale:** Build provenance enables verification that artifacts were produced by trusted infrastructure from reviewed source code, detecting build-time tampering.

**AA-SC-065: Third-party CI actions not pinned**
- **Description:** CI pipeline uses third-party GitHub Actions, CircleCI orbs, or similar referenced by mutable tags (v1, latest) instead of immutable SHA hashes.
- **Rationale:** Mutable references allow third-party action maintainers to push malicious updates that execute in your build environment. Pin to full commit SHAs.

**AA-SC-066: Build cache poisoning possible**
- **Description:** Build caches are shared between untrusted sources (e.g., pull request builds can populate caches used by main branch builds).
- **Rationale:** Cache poisoning inserts malicious content that is later consumed by trusted builds. Cache boundaries must match trust boundaries.

**AA-SC-067: Build log sensitive data exposure**
- **Description:** CI build logs expose sensitive information such as API keys, credentials, internal URLs, or security scan results in plaintext.
- **Rationale:** Build logs are often accessible to a broader audience than the build environment itself. Sensitive data in logs enables credential theft and reconnaissance.

**AA-SC-068: No multi-party approval for deployments**
- **Description:** Production deployments of agent systems can be triggered by a single person without requiring approval from a second authorized party.
- **Rationale:** Multi-party approval prevents a single compromised or malicious insider from deploying malicious agent code. Critical deployments require at least two approvers.

**AA-SC-069: Build environment drift unmonitored**
- **Description:** Build environment configurations (OS packages, tool versions, system libraries) are not monitored for unauthorized changes between builds.
- **Rationale:** Build environment drift can introduce vulnerabilities or be indicative of compromise. Environment specifications should be versioned and verified before each build.

**AA-SC-070: CI runner self-hosted without hardening**
- **Description:** Self-hosted CI runners are used for agent builds without security hardening, isolation, or regular rotation.
- **Rationale:** Self-hosted runners persist state between builds and may accumulate credentials, cached data, or malware. They require hardening, isolation, and periodic reprovisioning.

---

## 8. Update Mechanism Abuse (AA-SC-071 – AA-SC-080)

**Threat:** Agent update mechanisms (auto-update, remote configuration, dynamic tool loading) can be hijacked to deliver malicious payloads, bypass version pinning, or silently modify agent behavior without deployment.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-071 | Update channel not authenticated | CRITICAL | static | stable | langchain, openai, mcp |
| AA-SC-072 | Update payload integrity not verified | CRITICAL | static | stable | langchain, crewai, openai |
| AA-SC-073 | Remote configuration override unprotected | HIGH | static | stable | langchain, openai, bedrock |
| AA-SC-074 | Dynamic tool loading without verification | HIGH | static | stable | langchain, crewai, mcp |
| AA-SC-075 | Rollback to vulnerable version possible | HIGH | dynamic | stable | langchain, openai, autogen |
| AA-SC-076 | Update notification spoofing possible | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-SC-077 | Staged rollout not used for updates | MEDIUM | both | stable | langchain, crewai, openai |
| AA-SC-078 | Update frequency anomaly undetected | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-SC-079 | No update changelog review requirement | MEDIUM | static | stable | langchain, crewai, autogen |
| AA-SC-080 | Update mechanism privilege not minimized | MEDIUM | static | stable | langchain, openai, bedrock |

### Standards Mapping

- **ASI04:** Update mechanisms are a supply chain attack surface
- **NIST AI RMF MEASURE-2.7:** Update integrity and verification
- **ISO 42001 A.6:** Controlled update processes for AI systems

### Detailed Descriptions

**AA-SC-071: Update channel not authenticated**
- **Description:** The agent update mechanism does not authenticate the update server, allowing MITM attackers to serve malicious updates from impersonated servers.
- **Rationale:** Authenticated update channels (mutual TLS, signed responses) prevent attackers from intercepting and replacing legitimate updates with malicious ones.

**AA-SC-072: Update payload integrity not verified**
- **Description:** Update payloads are applied without verifying digital signatures or checksums against a trusted authority.
- **Rationale:** Unverified updates can contain arbitrary code. Every update payload must be cryptographically verified before application.

**AA-SC-073: Remote configuration override unprotected**
- **Description:** The agent accepts remote configuration changes that can alter behavior, permissions, or security settings without authentication or authorization checks.
- **Rationale:** Remote configuration is equivalent to code execution. Unprotected config overrides allow attackers to disable security controls, expand permissions, or redirect data flows.

**AA-SC-074: Dynamic tool loading without verification**
- **Description:** The agent dynamically loads tools or capabilities at runtime from external sources without verifying their integrity or authorization.
- **Rationale:** Dynamic tool loading extends the agent's capabilities at runtime. Without verification, attackers can inject malicious tools that appear legitimate.

**AA-SC-075: Rollback to vulnerable version possible**
- **Description:** The update mechanism allows rollback to older versions with known vulnerabilities without warning or blocking.
- **Rationale:** Version rollback attacks reintroduce patched vulnerabilities. The update system should maintain a minimum version floor and warn on downgrade attempts.

**AA-SC-076: Update notification spoofing possible**
- **Description:** Fake update notifications can trick administrators into manually installing malicious "updates" from attacker-controlled sources.
- **Rationale:** Spoofed update notifications leverage human trust in the update process. Notifications must be cryptographically verified and point only to authenticated sources.

**AA-SC-077: Staged rollout not used for updates**
- **Description:** Updates are deployed to all agent instances simultaneously rather than using staged rollouts that enable early detection of issues.
- **Rationale:** Staged rollouts limit blast radius by deploying to a small percentage first, enabling detection of malicious or buggy updates before full deployment.

**AA-SC-078: Update frequency anomaly undetected**
- **Description:** Unusual update patterns (unexpectedly frequent updates, updates at unusual times) are not monitored as potential indicators of compromise.
- **Rationale:** Anomalous update frequency can indicate an attacker pushing malicious updates through a compromised update channel.

**AA-SC-079: No update changelog review requirement**
- **Description:** Updates are applied without requiring review of the changelog or diff between versions, missing detection of suspicious changes.
- **Rationale:** Changelog review provides a human check on update contents. Automated updates without review skip this critical security gate.

**AA-SC-080: Update mechanism privilege not minimized**
- **Description:** The update mechanism runs with excessive privileges (root, admin) beyond what is needed to apply updates to the agent.
- **Rationale:** Privileged update mechanisms increase blast radius if compromised. The update process should run with minimum privileges needed for file replacement.

---

## 9. Slopsquatting (AA-SC-081 – AA-SC-090)

**Threat:** LLMs hallucinate package names that don't exist. Attackers register these hallucinated names on public registries, creating a novel supply chain attack vector where AI-suggested code installs malicious packages.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-SC-081 | Hallucinated package name in agent code | CRITICAL | static | stable | langchain, openai, autogen |
| AA-SC-082 | LLM-suggested dependency not verified | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-SC-083 | Package existence not validated before install | HIGH | static | stable | langchain, crewai, openai |
| AA-SC-084 | New package name similarity to known package unchecked | HIGH | static | stable | langchain, openai, mcp |
| AA-SC-085 | LLM code generation output not scanned | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-SC-086 | Package age check not enforced | MEDIUM | static | stable | langchain, openai, mcp |
| AA-SC-087 | No curated package recommendation list | MEDIUM | static | stable | langchain, crewai, autogen |
| AA-SC-088 | AI-generated dependency tree not reviewed | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-SC-089 | Slopsquatting monitoring for org packages absent | MEDIUM | dynamic | stable | langchain, openai, mcp |
| AA-SC-090 | No developer education on slopsquatting risks | MEDIUM | both | experimental | langchain, crewai, openai |

### Standards Mapping

- **ASI04:** Slopsquatting is a novel AI-specific supply chain attack vector
- **OWASP AIVSS AV:S:** Supply chain vector through AI-generated code
- **MITRE ATLAS:** AI-assisted software development threat surface

### Detailed Descriptions

**AA-SC-081: Hallucinated package name in agent code**
- **Description:** Agent code contains import or require statements for package names that are commonly hallucinated by LLMs and may have been registered by attackers.
- **Rationale:** LLMs consistently hallucinate certain package names. Attackers monitor these patterns and register the hallucinated names with malicious code, exploiting AI-assisted development.

**AA-SC-082: LLM-suggested dependency not verified**
- **Description:** Dependencies suggested by LLM code generation tools are installed without verifying they are legitimate, maintained, and not recently registered.
- **Rationale:** LLM suggestions carry no security guarantee. Every AI-suggested package must be independently verified against trusted package databases.

**AA-SC-083: Package existence not validated before install**
- **Description:** Package names are installed without first checking if the package has existed for a reasonable time, has real downloads, and is maintained.
- **Rationale:** Pre-install validation catches newly registered packages that may be slopsquatting attacks. Packages should demonstrate a history of legitimate use.

**AA-SC-084: New package name similarity to known package unchecked**
- **Description:** Newly encountered package names are not checked for suspicious similarity to well-known packages using edit distance or phonetic matching.
- **Rationale:** Slopsquatted packages often have names similar to but subtly different from real packages. Similarity analysis detects these impersonation attempts.

**AA-SC-085: LLM code generation output not scanned**
- **Description:** Code generated by LLMs is integrated into agent projects without automated scanning for suspicious imports, hardcoded credentials, or known attack patterns.
- **Rationale:** LLM-generated code may include hallucinated dependencies, insecure patterns, or prompt-injected malicious code. Automated scanning catches these issues before integration.

**AA-SC-086: Package age check not enforced**
- **Description:** No minimum age requirement exists for newly encountered packages, allowing installation of packages registered hours or days ago.
- **Rationale:** Legitimate packages have publication history. A minimum age threshold (e.g., 30 days) filters out newly registered slopsquatting or typosquatting packages.

**AA-SC-087: No curated package recommendation list**
- **Description:** Developers lack access to a curated, security-reviewed list of approved packages for common agent development tasks.
- **Rationale:** Curated lists reduce reliance on LLM suggestions and general web searches, steering developers toward vetted packages and away from slopsquatting targets.

**AA-SC-088: AI-generated dependency tree not reviewed**
- **Description:** When LLMs generate project scaffolding or dependency lists, the entire dependency tree is installed without human review of each package.
- **Rationale:** LLM-generated scaffolding may include dozens of dependencies, some hallucinated. Human review of the full dependency list catches suspicious packages.

**AA-SC-089: Slopsquatting monitoring for org packages absent**
- **Description:** The organization does not monitor public registries for registration of package names similar to their internal package names or commonly hallucinated variants.
- **Rationale:** Proactive monitoring enables organizations to detect and report squatted package names before developers accidentally install them.

**AA-SC-090: No developer education on slopsquatting risks**
- **Description:** Developers working on agent projects have not received training on slopsquatting risks and the importance of verifying AI-suggested dependencies.
- **Rationale:** Developer awareness is the last line of defense against slopsquatting. Training ensures developers question AI-suggested packages rather than blindly installing them.
