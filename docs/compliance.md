# Compliance & Standards Mapping

g0 maps all 1,182+ security rules to **10 industry standards and frameworks**. Every rule carries at minimum a domain-level default mapping, with individual rules specifying more granular control references.

## Supported Standards

| # | Standard | Key | Scope |
|---|---------|-----|-------|
| 1 | [OWASP Agentic Security](https://owasp.org/www-project-agentic-security/) | `owaspAgentic` | AI agent-specific threats (ASI01-ASI10) |
| 2 | [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework) | `nistAiRmf` | Federal AI risk governance |
| 3 | [ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html) | `iso42001` | AI management systems |
| 4 | [ISO/IEC 23894:2023](https://www.iso.org/standard/77304.html) | `iso23894` | AI risk management |
| 5 | [OWASP AI Vulnerability Scoring](https://owasp.org/www-project-ai-security/) | `owaspAivss` | AI vulnerability severity |
| 6 | [Agent-to-Agent Security (A2AS)](https://a2as.dev/) | `a2asBasic` | Multi-agent communication security |
| 7 | [AI Use Case Standard (AIUC-1)](https://aiuc.dev/) | `aiuc1` | AI deployment governance |
| 8 | [EU AI Act](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689) | `euAiAct` | EU regulatory compliance |
| 9 | [MITRE ATLAS](https://atlas.mitre.org/) | `mitreAtlas` | Adversarial threat landscape for AI |
| 10 | [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) | `owaspLlmTop10` | LLM application risks |

---

## Domain-to-Standards Matrix

### Goal Integrity

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI01 |
| NIST AI RMF | MAP-1.5, GOVERN-1.1 |
| ISO 42001 | A.4, A.7 |
| ISO 23894 | R.2, R.3, R.5 |
| OWASP AIVSS | AIVSS-PI, AIVSS-GH |
| A2AS BASIC | ISOL, COMM |
| AIUC-1 | UC-1.2 |
| EU AI Act | Article-15 |
| MITRE ATLAS | AML.T0051, AML.T0054 |
| OWASP LLM Top 10 | LLM01 |

### Tool Safety

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI03, ASI05 |
| NIST AI RMF | MAP-2.3, MANAGE-2.4 |
| ISO 42001 | A.6, A.8 |
| ISO 23894 | R.3, R.5, R.6 |
| OWASP AIVSS | AIVSS-TA, AIVSS-PI |
| A2AS BASIC | AUTHZ, AUDIT, ISOL |
| AIUC-1 | UC-2.1 |
| EU AI Act | Article-14, Article-15 |
| MITRE ATLAS | AML.T0040, AML.T0043 |
| OWASP LLM Top 10 | LLM07 |

### Identity & Access

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI02, ASI04 |
| NIST AI RMF | GOVERN-1.7, MANAGE-4.1 |
| ISO 42001 | A.5, A.9 |
| ISO 23894 | R.3, R.4, R.6 |
| OWASP AIVSS | AIVSS-AC, AIVSS-PE |
| A2AS BASIC | AUTH, AUTHZ, AUDIT |
| AIUC-1 | UC-3.1 |
| EU AI Act | Article-14 |
| MITRE ATLAS | AML.T0048 |
| OWASP LLM Top 10 | LLM06 |

### Supply Chain

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI06 |
| NIST AI RMF | MAP-3.4, GOVERN-6.1 |
| ISO 42001 | A.3, A.10 |
| ISO 23894 | R.4, R.7 |
| OWASP AIVSS | AIVSS-SC, AIVSS-MP |
| A2AS BASIC | AUTH, COMM |
| AIUC-1 | UC-4.1 |
| EU AI Act | Article-15 |
| MITRE ATLAS | AML.T0010, AML.T0018 |
| OWASP LLM Top 10 | LLM05, LLM03 |

### Code Execution

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI05, ASI03 |
| NIST AI RMF | MAP-2.3, MANAGE-2.4 |
| ISO 42001 | A.6, A.8 |
| ISO 23894 | R.3, R.5, R.6 |
| OWASP AIVSS | AIVSS-CE, AIVSS-SE |
| A2AS BASIC | ISOL, AUTHZ |
| AIUC-1 | UC-5.1 |
| EU AI Act | Article-15 |
| MITRE ATLAS | AML.T0043, AML.T0040 |
| OWASP LLM Top 10 | LLM07 |

### Memory & Context

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI07, ASI08 |
| NIST AI RMF | MAP-2.1, MEASURE-2.6 |
| ISO 42001 | A.7, A.4 |
| ISO 23894 | R.2, R.5 |
| OWASP AIVSS | AIVSS-DP, AIVSS-MP |
| A2AS BASIC | ISOL, AUDIT |
| AIUC-1 | UC-6.1 |
| EU AI Act | Article-14, Article-15 |
| MITRE ATLAS | AML.T0020, AML.T0018 |
| OWASP LLM Top 10 | LLM08 |

### Data Leakage

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI07, ASI08 |
| NIST AI RMF | MAP-5.1, MANAGE-3.2 |
| ISO 42001 | A.4, A.9 |
| ISO 23894 | R.2, R.4, R.6 |
| OWASP AIVSS | AIVSS-DL, AIVSS-IL |
| A2AS BASIC | COMM, AUDIT, ISOL |
| AIUC-1 | UC-7.1 |
| EU AI Act | Article-15 |
| MITRE ATLAS | AML.T0024, AML.T0025 |
| OWASP LLM Top 10 | LLM06, LLM02 |

### Cascading Failures

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI10, ASI09 |
| NIST AI RMF | MANAGE-4.1, MEASURE-3.3 |
| ISO 42001 | A.8, A.10 |
| ISO 23894 | R.5, R.6, R.8 |
| OWASP AIVSS | AIVSS-RF, AIVSS-DoS |
| A2AS BASIC | ISOL, COMM |
| AIUC-1 | UC-8.1 |
| EU AI Act | Article-15 |
| MITRE ATLAS | AML.T0029, AML.T0043 |
| OWASP LLM Top 10 | LLM10 |

### Human Oversight

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI09 |
| NIST AI RMF | GOVERN-1.1, GOVERN-1.7, MAP-1.6 |
| ISO 42001 | A.5, A.7 |
| ISO 23894 | R.6, R.8 |
| OWASP AIVSS | AIVSS-AC |
| A2AS BASIC | AUDIT, AUTH |
| AIUC-1 | UC-9.1 |
| EU AI Act | Article-14 |
| MITRE ATLAS | AML.T0048 |
| OWASP LLM Top 10 | LLM09 |

### Inter-Agent

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI01, ASI03 |
| NIST AI RMF | GOVERN-1.7, MAP-3.4 |
| ISO 42001 | A.6, A.9 |
| ISO 23894 | R.3, R.4 |
| OWASP AIVSS | AIVSS-AC, AIVSS-PI |
| A2AS BASIC | AUTH, AUTHZ, COMM, ISOL |
| AIUC-1 | UC-10.1 |
| EU AI Act | Article-14, Article-15 |
| MITRE ATLAS | AML.T0051, AML.T0048 |
| OWASP LLM Top 10 | LLM01, LLM06 |

### Reliability Bounds

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI07, ASI05 |
| NIST AI RMF | MEASURE-2.6, MANAGE-4.1 |
| ISO 42001 | A.8, A.10 |
| ISO 23894 | R.5, R.7 |
| OWASP AIVSS | AIVSS-RF |
| A2AS BASIC | ISOL |
| AIUC-1 | UC-11.1 |
| EU AI Act | Article-15 |
| MITRE ATLAS | AML.T0029 |
| OWASP LLM Top 10 | LLM04, LLM10 |

### Rogue Agent

| Standard | Controls |
|----------|----------|
| OWASP Agentic | ASI10, ASI01 |
| NIST AI RMF | MANAGE-4.1, GOVERN-1.7 |
| ISO 42001 | A.7, A.8 |
| ISO 23894 | R.3, R.5 |
| OWASP AIVSS | AIVSS-GH, AIVSS-CE |
| A2AS BASIC | ISOL, AUDIT |
| AIUC-1 | UC-12.1 |
| EU AI Act | Article-14, Article-15 |
| MITRE ATLAS | AML.T0043, AML.T0054 |
| OWASP LLM Top 10 | LLM01, LLM09 |

---

## OWASP Agentic Security (ASI01-ASI10) Coverage

| ASI Code | Threat | Primary Domains |
|----------|--------|----------------|
| ASI01 | Prompt Injection | goal-integrity, inter-agent, rogue-agent |
| ASI02 | Broken Authentication | identity-access |
| ASI03 | Tool Misuse | tool-safety, code-execution, inter-agent |
| ASI04 | Broken Access Control | identity-access, supply-chain |
| ASI05 | Code Execution | code-execution, tool-safety, reliability-bounds |
| ASI06 | Supply Chain | supply-chain |
| ASI07 | Data Leakage | data-leakage, memory-context, reliability-bounds |
| ASI08 | Context Poisoning | memory-context, data-leakage |
| ASI09 | Availability | cascading-failures, human-oversight |
| ASI10 | Autonomy Risks | cascading-failures, rogue-agent |

## Mapping Implementation

Standards are auto-populated at two levels:

1. **Domain defaults** — Every rule inherits its domain's standard mappings via `src/standards/mapping.ts`
2. **Rule overrides** — Individual rules can specify more granular mappings that merge with (never overwrite) domain defaults

The YAML compiler (`src/rules/yaml-compiler.ts`) auto-populates domain defaults into any rule missing a specific standard key. This ensures 100% coverage across all 1,182+ rules.
