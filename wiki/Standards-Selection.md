# Standards Selection

g0 maps all rules to 10 industry standards. This page explains why these 10 were chosen.

## Selection Criteria

Standards were selected based on:
1. **Relevance** — Does it address AI agent security specifically?
2. **Adoption** — Is it widely recognized and adopted?
3. **Maturity** — Is it stable enough to build against?
4. **Complementarity** — Does it cover gaps left by other standards?

## The 10 Standards

### 1. OWASP Agentic Top 10 (Primary)

**Why:** The only standard specifically designed for AI agent security. Covers the 10 most critical risks (ASI01-ASI10) that map directly to g0's domains.

**Coverage:** Prompt injection, identity, supply chain, tool misuse, code execution, data access, model compromise, output handling, multi-agent, and overreliance.

### 2. NIST AI Risk Management Framework

**Why:** The US federal standard for AI risk management. Required for government AI deployments and widely adopted in regulated industries.

**Coverage:** Four functions (GOVERN, MAP, MEASURE, MANAGE) covering AI risk governance, measurement, and mitigation.

### 3. ISO/IEC 42001:2023

**Why:** The international standard for AI management systems. Required for ISO certification and increasingly demanded by enterprise procurement.

**Coverage:** AI management system requirements including risk assessment, control objectives, and operational procedures.

### 4. ISO/IEC 23894:2023

**Why:** Complements ISO 42001 with specific AI risk management guidance. Provides risk categories (R.1-R.8) that map well to g0's security domains.

**Coverage:** AI-specific risk identification, analysis, evaluation, and treatment.

### 5. OWASP AI Vulnerability Scoring System (AIVSS)

**Why:** Extends CVSS for AI-specific vulnerabilities. Provides a vocabulary for describing AI vulnerability types.

**Coverage:** AI-specific vulnerability categories including prompt injection, data poisoning, model theft.

### 6. OWASP Agentic AI Top 10

**Why:** The definitive threat taxonomy for AI agent security, backed by 600+ contributors. Covers 10 categories of agent-specific threats from authorization hijacking to supply chain attacks.

**Coverage:** AAT-1 (Authorization Hijacking), AAT-2 (Untraceability), AAT-3 (Critical Systems Interaction), AAT-4 (Alignment Faking), AAT-5 (Goal Manipulation), AAT-6 (Impact Chain), AAT-7 (Memory/Context Manipulation), AAT-8 (Multi-Agent Exploitation), AAT-9 (Supply Chain), AAT-10 (Checker Out of Loop).

### 7. AI Use Case Standard (AIUC-1)

**Why:** Addresses AI deployment governance — when and how AI should be used. Complements technical standards with use-case level controls.

**Coverage:** Use case classification, deployment requirements, and monitoring standards.

### 8. EU AI Act

**Why:** The most comprehensive AI regulation globally. Applies to any AI system used in or affecting the EU.

**Coverage:** Risk classification, transparency requirements, human oversight mandates, conformity assessment, and technical documentation.

### 9. MITRE ATLAS

**Why:** The adversarial threat landscape for AI systems. Provides a taxonomy of attack techniques that maps to g0's detection rules.

**Coverage:** Attack techniques across the AI lifecycle — reconnaissance, resource development, initial access, ML attack execution.

### 10. OWASP LLM Top 10

**Why:** Widely adopted list of LLM-specific risks. Many organizations use it as their primary LLM security reference.

**Coverage:** Prompt injection, insecure output handling, training data poisoning, model DoS, supply chain, sensitive info disclosure, insecure plugin design, excessive agency, overreliance, model theft.

## Why Not Others?

Standards that were considered but not included:

- **SOC 2** — Too general (not AI-specific). g0 findings support SOC 2 audits but the mapping would be too loose.
- **GDPR** — Privacy regulation, not a security standard. Data Leakage findings support GDPR but don't map 1:1.
- **HIPAA** — Industry-specific. Could be added as a domain-specific extension.
- **PCI DSS** — Industry-specific, not AI-focused.

## Mapping Strategy

### Domain Defaults

Every rule gets a minimum standards mapping based on its domain. This ensures no rule is unmapped even if individual standards aren't specified:

```typescript
// Example: all goal-integrity rules automatically get
owaspAgentic: ['ASI01']
nistAiRmf: ['MAP-1.5', 'GOVERN-1.1']
iso42001: ['A.4', 'A.7']
// ... etc
```

### Rule-Level Overrides

Individual rules can specify more precise mappings that override domain defaults. For example, a specific prompt injection rule might map to additional MITRE ATLAS techniques.

### Standards Growth

The mapping system is extensible. New standards can be added by:
1. Adding a field to the standards mapping type
2. Adding domain defaults in `src/standards/mapping.ts`
3. Optionally specifying rule-level mappings
