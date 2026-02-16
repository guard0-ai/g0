# Glossary

Key terms and concepts used in g0.

## A

**Agent Graph** — The core data structure g0 builds from source code. A directed graph connecting agents, tools, prompts, models, and vector databases, representing the architecture of your AI agent system.

**Agent Node** — A node in the Agent Graph representing an AI agent definition. Contains the agent's name, model, tools, prompt, and delegation settings.

**AI-BOM** — AI Bill of Materials. A complete inventory of all AI components in a codebase, produced by `g0 inventory`. Can be exported as CycloneDX 1.6.

## B

**Blast Radius** — The potential impact zone of an AI agent — what data it can access, which tools it can invoke, and what actions it can take. g0 maps the blast radius through flow analysis and tool enumeration.

## C

**Compensating Control** — A security mechanism that mitigates a risk detected by a rule. When g0 detects a compensating control (e.g., rate limiting, input validation), it can suppress related findings.

**Confidence** — How certain g0 is that a finding is a true positive. Levels: `high`, `medium`, `low`.

**Control Registry** — The system that detects security controls (rate limiting, input validation, sandboxing, etc.) present in a project, used for compensating control suppression.

## D

**Domain** — One of 12 security categories that organize g0's rules. Each domain covers a distinct aspect of AI agent security: Goal Integrity, Tool Safety, Identity & Access, Supply Chain, Code Execution, Memory & Context, Data Leakage, Cascading Failures, Human Oversight, Inter-Agent Communication, Reliability Bounds, Rogue Agent Detection.

**Domain Score** — A 0-100 score for a specific security domain, calculated from the findings in that domain. The overall score is a weighted average of domain scores.

## E

**Exploitability** — An assessment of how easily a finding can be exploited, factored into score calculation.

## F

**Finding** — A specific security issue detected by a rule. Contains the rule ID, severity, confidence, domain, location (file + line), reachability, and standards mapping.

## G

**g0-ignore** — An inline comment (`// g0-ignore: AA-XX-NNN`) that suppresses a specific rule for the annotated line.

**Grade** — A letter grade (A-F) derived from the overall score. A: 90-100, B: 80-89, C: 70-79, D: 60-69, F: 0-59.

## M

**Model Node** — A node in the Agent Graph representing an LLM model reference. Contains the provider, model name, and parameters (temperature, etc.).

## P

**Parser** — A framework-specific module that extracts agents, tools, prompts, and models from source code. g0 has 10 parsers covering major AI agent frameworks.

**Payload** — An adversarial input sent to a live AI agent during dynamic testing (`g0 test`). Designed to probe for specific vulnerabilities.

**Progressive Judge** — The 3-level evaluation system used in dynamic testing: deterministic (pattern matching), heuristic (signal scoring), and LLM-as-judge (AI evaluation).

**Prompt Node** — A node in the Agent Graph representing a prompt template. Contains the prompt content and type (system, user, template, few-shot).

## R

**Reachability** — How accessible a piece of code is from agent entry points. Determines score multipliers: agent-reachable (1.0x), tool-reachable (1.0x), endpoint-reachable (0.8x), utility-code (0.3x), unknown (0.6x).

**Rug-Pull** — An attack where an MCP server changes its tool descriptions after initial approval, potentially tricking the AI into unintended actions. Detected by `g0 mcp --check` using hash pinning.

**Rule** — A security check that evaluates the Agent Graph or source code for a specific vulnerability or misconfiguration. Each rule has an ID, domain, severity, and check function.

## S

**SARIF** — Static Analysis Results Interchange Format (version 2.1.0). A standard JSON format for static analysis results, supported by GitHub Code Scanning and other tools.

**Severity** — The impact level of a finding. Levels: `critical` (20-point deduction), `high` (10), `medium` (5), `low` (2.5), `info` (0).

**Smart Targeting** — The `--auto` mode in `g0 test` that uses static scan results to prioritize the most relevant adversarial payloads.

## T

**Taint Flow** — A data flow path from an untrusted source (user input) to a sensitive sink (code execution, file write) without proper sanitization. Detected by `taint_flow` check type.

**Tool Node** — A node in the Agent Graph representing a tool that an agent can invoke. Contains the tool's name, description, capabilities, and security properties.

**Toxic Flow** — An execution path through the agent graph where untrusted data can reach sensitive operations. Detected by `g0 flows`.

## V

**Vector DB Node** — A node in the Agent Graph representing a vector database connection. Contains the provider and index information.
