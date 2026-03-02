---
name: New Security Rule
about: Propose a new detection rule for g0
title: "[Rule] "
labels: new-rule
assignees: ''
---

## What This Rule Detects

A clear description of the security issue or misconfiguration this rule catches.

## Security Domain

- [ ] Goal Integrity (AA-GI)
- [ ] Tool Safety (AA-TS)
- [ ] Identity & Access (AA-IA)
- [ ] Supply Chain (AA-SC)
- [ ] Code Execution (AA-CE)
- [ ] Memory & Context (AA-MP)
- [ ] Data Leakage (AA-DL)
- [ ] Cascading Failures (AA-CF)
- [ ] Human Oversight (AA-HO)
- [ ] Inter-Agent (AA-IAS)
- [ ] Reliability Bounds (AA-RB)
- [ ] Rogue Agent (AA-RA)

## Standards Mapping

Which standards does this map to? (check all that apply)

- [ ] OWASP Agentic (ASI01–ASI10): `ASI__`
- [ ] OWASP LLM Top 10
- [ ] NIST AI RMF
- [ ] MITRE ATLAS
- [ ] EU AI Act
- [ ] ISO 42001 / ISO 23894

## Vulnerable Example

```python
# Code, config, or prompt pattern that should trigger this rule
```

## Compliant Example

```python
# What the fixed / secure version looks like
```

## Detection Approach

How should g0 detect this? Code pattern, AST check, YAML `code_matches` / `prompt_contains`, config inspection, etc.

## Severity

- [ ] Critical
- [ ] High
- [ ] Medium
- [ ] Low

## Affected Frameworks

- [ ] All
- [ ] LangChain / LangChain4j
- [ ] CrewAI
- [ ] OpenAI / OpenAI Swarm / Agents SDK
- [ ] MCP
- [ ] Vercel AI SDK
- [ ] AWS Bedrock
- [ ] AutoGen
- [ ] Spring AI
- [ ] Golang AI (langchaingo / eino)

## References

- Link to CVE, advisory, or paper (if any):
