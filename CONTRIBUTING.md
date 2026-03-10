# Contributing to g0

Thanks for your interest in contributing to g0. This guide covers the most common contribution paths.

## Getting Started

```bash
git clone https://github.com/guard0-ai/g0.git
cd g0
npm install
npm test        # Run all tests (vitest)
npm run build   # Build with tsup
```

## Project Structure

```
src/
  analyzers/       # Security rules and AST analysis
    rules/         # Rule definitions by domain (12 files + index)
    parsers/       # Framework-specific parsers (10 frameworks)
    ast/           # AST utilities, taint tracking, context analysis
  discovery/       # File walking, framework detection
    detectors/     # Framework detectors (1 per framework)
  rules/           # YAML rule system
    builtin/       # 715+ YAML rules across 12 domains
    yaml-compiler  # Compiles YAML rules into executable Rule objects
    yaml-schema    # Zod schema for YAML rule validation
  testing/         # Dynamic adversarial testing engine
    payloads/      # Attack payloads (10 categories)
    providers/     # Test providers (HTTP, MCP, direct model)
    judge/         # 3-level progressive judge
    rubrics/       # Vendor-informed rubrics
    mutators       # Payload mutators (b64, l33t, zw, etc.)
  mcp/             # MCP security assessment
    hash-pinning   # Rug-pull detection via tool description hashing
    source-scanner # MCP server source code analysis
  inventory/       # AI-BOM builder
  flows/           # Agent flow analysis
  scoring/         # 0-100 scoring engine
  reporters/       # Output formatters (terminal, JSON, SARIF, HTML, CycloneDX, etc.)
  cli/             # CLI commands and UI
  platform/        # Guard0 Cloud integration
  standards/       # Standards mapping (10 standards)
  types/           # TypeScript type definitions
docs/              # Documentation
tests/
  unit/            # Unit tests
  integration/     # Integration tests
  fixtures/        # Test fixture projects
```

## Adding a Security Rule

Rules live in `src/analyzers/rules/` (TypeScript) and `src/rules/builtin/` (YAML). Each covers one of the 12 security domains:

| Code | Domain | TS File | YAML Directory |
|------|--------|---------|----------------|
| GI | Goal Integrity | `goal-integrity.ts` | `builtin/goal-integrity/` |
| TS | Tool Safety | `tool-safety.ts` | `builtin/tool-safety/` |
| IA | Identity & Access | `identity-access.ts` | `builtin/identity-access/` |
| SC | Supply Chain | `supply-chain.ts` | `builtin/supply-chain/` |
| CE | Code Execution | `code-execution.ts` | `builtin/code-execution/` |
| MP | Memory & Context | `memory-context.ts` | `builtin/memory-context/` |
| DL | Data Leakage | `data-leakage.ts` | `builtin/data-leakage/` |
| CF | Cascading Failures | `cascading-failures.ts` | `builtin/cascading-failures/` |
| HO | Human Oversight | `human-oversight.ts` | `builtin/human-oversight/` |
| IC | Inter-Agent | `inter-agent.ts` | `builtin/inter-agent/` |
| RB | Reliability Bounds | `reliability-bounds.ts` | `builtin/reliability-bounds/` |
| RA | Rogue Agent | `rogue-agent.ts` | `builtin/rogue-agent/` |

### TypeScript Rules

1. Choose the domain file (e.g., `tool-safety.ts`)
2. Add your rule with a unique ID: `AA-{DOMAIN}-{NUMBER}`
3. Map to OWASP Agentic standards (ASI01-ASI10)
4. Add test coverage in `tests/unit/*.test.ts`

### YAML Rules

See [docs/custom-rules.md](docs/custom-rules.md) for the full YAML schema and all 13 check types.

```yaml
id: AA-GI-100
info:
  name: "Descriptive rule name"
  domain: goal-integrity
  severity: high
  confidence: medium
  description: "What this rule detects"
  frameworks: [all]
  owasp_agentic: [ASI01]
check:
  type: code_matches
  pattern: "dangerous_pattern"
  message: "Human-readable explanation"
```

## Adding a Framework Parser

g0 supports 10 frameworks: LangChain, CrewAI, MCP, OpenAI, Vercel AI, Bedrock, AutoGen, LangChain4j, Spring AI, and Go AI frameworks.

To add support for a new AI agent framework:

1. **Detector** — Create `src/discovery/detectors/{framework}.ts`
   - Implement the `DetectionResult` interface
   - Register in `src/discovery/detector.ts`

2. **Parser** — Create `src/analyzers/parsers/{framework}.ts`
   - Extract agents, tools, prompts, and models from the framework's patterns
   - Register in the graph builder

3. **Fixture** — Create `tests/fixtures/{framework}-agent/` with sample code

4. **Tests** — Add detection and parsing tests

Look at existing parsers (e.g., `src/analyzers/parsers/langchain.ts`) as reference.

## Adding Attack Payloads

Payloads live in `src/testing/payloads/`. There are 10 attack categories:

1. `prompt-injection` — System prompt override, delimiter attacks
2. `data-exfiltration` — Data theft via tool abuse, markdown injection
3. `tool-abuse` — Unauthorized tool invocation, parameter injection
4. `jailbreak` — DAN, roleplay, hypothetical framing
5. `goal-hijacking` — Task substitution, priority manipulation
6. `content-safety` — Harmful content generation
7. `bias-detection` — Discriminatory responses
8. `pii-probing` — PII extraction and memorization
9. `agentic-attacks` — Multi-step exploitation, agent-specific vectors
10. `jailbreak-advanced` — Multi-turn, encoded, and obfuscated jailbreaks

To add a payload:

1. Add to the appropriate category file
2. Include `expectedPatterns` for the deterministic judge
3. Include `heuristicSignals` for the heuristic judge
4. Add test coverage in `tests/unit/dynamic-test.test.ts`

## Running Tests

```bash
npm test              # Run all tests
npm run test:watch    # Watch mode
npx vitest run tests/unit/rules.test.ts  # Run specific test
```

All PRs must pass the existing test suite. New features should include tests.

## Code Style

- ESM modules (`.js` extensions in imports)
- TypeScript strict mode
- No default exports
- Prefer explicit types over inference for public APIs

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes with tests
3. Run `npm test` and `npm run build` locally
4. Open a PR with a clear description of what changed and why
5. Link any related issues

## Key Documentation

- [docs/architecture.md](docs/architecture.md) — How the pipeline works
- [docs/custom-rules.md](docs/custom-rules.md) — Full YAML rule schema and examples
- [docs/frameworks.md](docs/frameworks.md) — Framework-specific detection and parsing

## Reporting Bugs

Open a [GitHub issue](https://github.com/guard0-ai/g0/issues) with:

- g0 version (`g0 --version`)
- Node.js version
- Minimal reproduction steps
- Expected vs. actual behavior

## Security Vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under [AGPL-3.0](LICENSE).
