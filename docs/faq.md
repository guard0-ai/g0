# FAQ

## General

### How is g0 different from Semgrep, Snyk, or other SAST tools?

g0 is purpose-built for AI agent security. Traditional SAST tools analyze general code patterns but don't understand AI-specific constructs like agent graphs, tool bindings, prompt templates, or model configurations. g0 builds a semantic graph of your AI agent architecture and evaluates it against 1,238+ rules across 12 AI-specific security domains.

### How is g0 different from Garak or Promptfoo?

Garak and Promptfoo focus on dynamic testing (sending payloads to running models). g0 does both: static analysis of source code and dynamic adversarial testing. The static analysis catches architectural issues (missing guardrails, unsafe tool bindings, supply chain risks) that dynamic testing alone can't find. When you use `g0 test --auto`, static findings inform which dynamic payloads to prioritize.

### What languages does g0 support?

Python, TypeScript, JavaScript, Java, and Go. g0 has framework-specific parsers for 10 AI agent frameworks across these languages.

### Does g0 need access to my AI provider API keys?

No — not for static scanning. API keys are only needed for:
- `g0 scan --ai` — AI-powered analysis of findings
- `g0 test --ai` — LLM-as-judge for dynamic testing
- `g0 test --provider` — Direct model testing

## Scanning

### How long does a scan take?

Most scans complete in 2-10 seconds. Larger monorepos may take 15-30 seconds. g0 uses regex-based parsing by default and optionally Tree-sitter AST analysis when native modules are available.

### Can I scan private repositories?

Yes. For local repos, just point g0 at the directory. For remote repos, g0 uses `git clone` — if your git credentials have access, g0 can clone it.

### Can I scan monorepos?

Yes. g0 walks the entire directory tree and detects multiple frameworks. Use `exclude_paths` in `.g0.yaml` to skip irrelevant directories.

### Why is my score low?

Common reasons:
- Missing system prompt guardrails (no refusal instructions, no boundary tokens)
- Tools without input validation or sandboxing
- No rate limiting or error handling
- Unsandboxed code execution
- Exposed secrets or API keys

Use `g0 scan . --show-all` to see all findings including suppressed ones.

## False Positives

### How do I suppress a false positive?

Three options:

1. **Inline:** Add `// g0-ignore: AA-XX-NNN` on the line
2. **Config:** Add the rule ID to `exclude_rules` in `.g0.yaml`
3. **Path:** Add the file/directory to `exclude_paths` in `.g0.yaml`

See [Understanding Findings](findings.md) for details.

### Does g0 have a high false positive rate?

g0 uses multiple FP reduction mechanisms:
- Block comment awareness (skips commented-out code)
- Compensating control detection (suppresses findings when mitigations exist)
- Reachability analysis (deprioritizes utility code)
- Confidence levels (each finding has a confidence rating)

For rules that run against prompts (e.g., "system prompt missing refusal instruction"), FP rates depend on your prompting style. Use `--min-confidence high` to see only high-confidence findings.

## CI/CD

### How do I add g0 to my CI pipeline?

```bash
npx @guard0/g0 gate . --min-score 70 --sarif results.sarif
```

See [CI/CD Integration](ci-cd.md) for GitHub Actions, GitLab CI, Jenkins, and pre-commit examples.

### What exit codes does `g0 gate` return?

- `0` — All thresholds passed
- `1` — One or more thresholds failed
- `2` — Scan error

### Can I use g0 with GitHub Code Scanning?

Yes. Use `--sarif` to produce SARIF 2.1.0 output, then upload with `github/codeql-action/upload-sarif@v3`. Findings appear as PR annotations and in the Security tab.

## Custom Rules

### Can I write custom rules?

Yes. Place YAML rules in a directory and set `rules_dir` in `.g0.yaml`. See [Custom Rules](custom-rules.md) for the full schema and all 13 check types.

### Can I disable built-in rules?

Yes, via `exclude_rules` in `.g0.yaml` or `--exclude-rules` on the CLI.

## Standards

### Which standards does g0 map to?

All 1,238+ rules are mapped to 10 industry standards:
1. OWASP Agentic Top 10 (ASI01-ASI10)
2. NIST AI Risk Management Framework
3. ISO/IEC 42001:2023
4. ISO/IEC 23894:2023
5. OWASP AI Vulnerability Scoring System
6. Agent-to-Agent Security (A2AS)
7. AI Use Case Standard (AIUC-1)
8. EU AI Act
9. MITRE ATLAS
10. OWASP LLM Top 10

See [Compliance Mapping](compliance.md) for the full matrix.

### Can I generate compliance reports?

Yes:

```bash
g0 scan . --report owasp-agentic    # OWASP Agentic Top 10 report
g0 scan . --report nist-ai-rmf      # NIST AI RMF report
g0 scan . --report iso42001         # ISO 42001 report
```

## Guard0 Cloud

### Is Guard0 Cloud free?

Yes, Guard0 Cloud is free for individual use. Run `g0 auth login` to authenticate and `g0 scan . --upload` to upload results.

### What data does `--upload` send?

Scan results (findings, scores, agent graph structure), inventory data, and test results. Source code is never uploaded.
