---
name: New Rule
about: Propose a new security rule
title: "[Rule] "
labels: new-rule
assignees: ''
---

## Rule Description

What security issue does this rule detect?

## Security Domain

Which domain does this belong to?
- [ ] Goal Integrity (AA-GI)
- [ ] Tool Safety (AA-TS)
- [ ] Identity & Access (AA-IA)
- [ ] Supply Chain (AA-SC)
- [ ] Code Execution (AA-CE)
- [ ] Memory & Context (AA-MP)
- [ ] Data Leakage (AA-DL)
- [ ] Cascading Failures (AA-CF)

## OWASP Agentic Mapping

Which OWASP Agentic items does this map to? (ASI01-ASI10)

## Detection Pattern

How should g0 detect this? Code patterns, config patterns, AST checks, etc.

## Example Vulnerable Code

```python
# Example of code that should trigger this rule
```

## Severity

- [ ] Critical
- [ ] High
- [ ] Medium
- [ ] Low

## Frameworks

Which frameworks does this apply to?
- [ ] All
- [ ] LangChain
- [ ] CrewAI
- [ ] OpenAI
- [ ] MCP
- [ ] Vercel AI
- [ ] Bedrock
- [ ] AutoGen
