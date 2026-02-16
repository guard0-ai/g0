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
    rules/         # Rule definitions by domain (8 files)
    parsers/       # Framework-specific parsers (7 frameworks)
    ast/           # AST utilities
  discovery/       # File walking, framework detection
    detectors/     # Framework detectors (1 per framework)
  testing/         # Dynamic adversarial testing engine
    payloads/      # Attack payloads (5 categories)
    providers/     # Test providers (HTTP, MCP, direct model)
    judge/         # 3-level progressive judge
  mcp/             # MCP security assessment
  inventory/       # AI-BOM builder
  flows/           # Agent flow analysis
  reporters/       # Output formatters (terminal, JSON, SARIF, HTML, etc.)
  cli/             # CLI commands and UI
  platform/        # Guard0 Cloud integration
  types/           # TypeScript type definitions
tests/
  unit/            # Unit tests
  integration/     # Integration tests
  fixtures/        # Test fixture projects
```

## Adding a Security Rule

Rules live in `src/analyzers/rules/`. Each file covers one security domain.

1. Choose the domain file (e.g., `tool-safety.ts` for tool-related rules)
2. Add your rule to the array with a unique ID following the pattern `AA-{DOMAIN}-{NUMBER}`
3. Map to OWASP Agentic standards (ASI01-ASI10)
4. Add test coverage in the relevant `tests/unit/*.test.ts`

### YAML Custom Rules

You can also contribute YAML rules that users load via `rules_dir`:

```yaml
id: AA-GI-100
info:
  name: "Descriptive rule name"
  domain: goal-integrity    # One of the 8 domains
  severity: high            # critical, high, medium, low
  confidence: medium        # high, medium, low
  description: "What this rule detects"
  frameworks: [all]         # Or specific: [langchain, crewai]
  owasp_agentic: [ASI01]
check:
  type: code_matches        # See README for all check types
  pattern: "dangerous_pattern"
  message: "Human-readable explanation"
```

## Adding a Framework Parser

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

Payloads live in `src/testing/payloads/`. Each file covers one attack category.

1. Add your payload to the appropriate category file
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

## Reporting Bugs

Open a [GitHub issue](https://github.com/guard0-ai/g0/issues) with:

- g0 version (`g0 --version`)
- Node.js version
- Minimal reproduction steps
- Expected vs. actual behavior

## Security Vulnerabilities

See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under [Apache-2.0](LICENSE).
