# Rule Design Principles

g0 ships 1,183+ rules. This page describes the principles that guide rule design, severity assignment, and the choice between TypeScript and YAML implementations.

## Core Principles

### 1. Every Finding Must Be Actionable

A finding should tell the developer:
- What was detected
- Where it was detected (file + line)
- Why it matters
- What to do about it (implied by the description)

Rules that produce "this might be a problem depending on context" findings are either lowered in confidence or not included.

### 2. Precision Over Recall

A false positive is worse than a missed finding. FPs erode trust in the tool and waste developer time. g0 trades some coverage for higher precision:

- Rules use specific patterns rather than broad regex
- Confidence levels signal uncertainty
- Compensating controls suppress findings when mitigations exist
- Reachability analysis deprioritizes utility code

### 3. Security Domain Isolation

Each rule belongs to exactly one domain. This:
- Makes findings easier to categorize and assign
- Enables per-domain scoring
- Avoids double-counting the same issue

### 4. Standards Alignment

Every rule maps to at least one industry standard. Rules that don't align with any standard are scrutinized — if no external authority considers the issue important, it might be noise.

## Severity Criteria

### Critical

The vulnerability can lead to complete agent compromise or data breach with minimal attacker effort:
- Unsandboxed code execution in agent-reachable code
- Hardcoded credentials in agent configuration
- System prompt extraction with high confidence
- Unrestricted tool access to sensitive resources

### High

Significant risk that requires remediation but may need specific conditions to exploit:
- Missing input validation on agent tools
- Agent delegation without scope restrictions
- Prompt injection vectors requiring specific formatting
- Missing authentication on agent endpoints

### Medium

Moderate risk that should be addressed but doesn't pose immediate danger:
- High model temperature settings
- Missing boundary tokens in prompts
- Unbounded conversation memory
- Missing rate limiting

### Low

Minor risk, often best-practice violations:
- Missing error handling in tools
- Verbose error messages
- Non-optimal model configuration
- Missing logging

### Info

Informational only — no security impact but useful context:
- Framework version information
- Component inventory notes
- Advisory controls requiring manual review

## TypeScript vs YAML

### When to Use TypeScript

- **Complex logic** — Multi-file correlation, AST traversal, conditional checks
- **Graph analysis** — Rules that examine relationships between Agent Graph nodes
- **Custom scoring** — Rules that need dynamic severity based on context
- **Performance-critical** — Rules that need optimized code paths

### When to Use YAML

- **Pattern matching** — Single regex against source code or prompts
- **Property checks** — Agent/model/tool property existence or values
- **Configuration checks** — Config file pattern matching
- **Declarative rules** — Rules that can be expressed as "if X then Y"

### Rule of Thumb

If you can express the rule as "look for this pattern in this context and report this message," use YAML. If you need if/else logic, multiple files, or graph traversal, use TypeScript.

## False Positive Reduction

### Block Comment Awareness

The YAML compiler checks whether a match occurs inside a block comment and skips it. This prevents findings in commented-out code or documentation strings.

### g0-ignore Suppression

Developers can suppress specific rules per-line:

```python
# g0-ignore: AA-GI-001
agent = create_react_agent(llm, tools, prompt)
```

### Compensating Controls

Rules can declare `suppressed_by` controls. If g0's control registry detects the compensating control in the project, the finding is suppressed:

```yaml
suppressed_by:
  - input-validation    # Suppress if input validation exists
  - rate-limiting       # Suppress if rate limiting exists
```

### Reachability Filtering

Findings in utility code (not on the agent execution path) are deprioritized with a 0.3x score multiplier and hidden from default terminal output.

## Rule Naming Convention

- **IDs:** `AA-{DOMAIN}-{NUMBER}` (AA-GI-001, AA-TS-042)
- **Names:** Descriptive, 3-8 words ("Missing system prompt boundary tokens")
- **Messages:** Action-oriented ("System prompt has no boundary tokens separating instructions from user content")

## Quality Checklist

Before a rule is added:
- [ ] Maps to at least one standard
- [ ] Has a clear, specific pattern (not overly broad)
- [ ] Tested against fixtures (true positive confirmed)
- [ ] False positive rate checked against common patterns
- [ ] Severity justified against criteria above
- [ ] Domain assignment is correct
- [ ] Message is actionable
