# Scoring Methodology

g0 produces a **0-100 security score** with a letter grade (A-F) for each scan. Scores are calculated per-domain and then combined via weighted average.

## Score Formula

```
Overall Score = ROUND( SUM(domain_score * domain_weight) / SUM(domain_weight) )

Domain Score  = MAX(0, ROUND(100 - total_deduction))

total_deduction = SUM( severity_base * reachability_mult * exploitability_mult )
                  for each finding in the domain
```

## Grade Thresholds

| Grade | Score Range | Meaning |
|-------|-----------|---------|
| **A** | 90-100 | Excellent — minimal security issues |
| **B** | 80-89 | Good — low risk, minor improvements needed |
| **C** | 70-79 | Acceptable — moderate risk, action recommended |
| **D** | 60-69 | Poor — significant risk, remediation required |
| **F** | 0-59 | Failing — critical risks, immediate action needed |

## Severity Deductions

Each finding deducts points from its domain score based on severity:

| Severity | Base Deduction |
|----------|---------------|
| Critical | 20 points |
| High | 10 points |
| Medium | 5 points |
| Low | 2.5 points |
| Info | 0 points |

## Reachability Multipliers

Findings are weighted by how accessible the vulnerable code is:

| Reachability | Multiplier | Description |
|-------------|-----------|-------------|
| `agent-reachable` | 1.0x | In agent definition or directly called by agent |
| `tool-reachable` | 1.0x | In tool implementation called by agent |
| `endpoint-reachable` | 0.8x | In API route handler or HTTP endpoint |
| `utility-code` | 0.3x | Helper/library code not on agent path |
| `unknown` | 0.6x | Reachability not determined |

Utility code gets a 70% reduction because vulnerabilities in code not reachable from agent entry points pose significantly lower risk.

## Exploitability Multipliers

Findings are further weighted by likelihood of exploitation:

| Exploitability | Multiplier | Description |
|---------------|-----------|-------------|
| `confirmed` | 1.2x | Taint flow confirmed from input to vulnerable sink |
| `likely` | 1.0x | High confidence the vulnerability is exploitable |
| `unlikely` | 0.4x | Constraints block typical exploitation paths |
| `not-assessed` | 0.7x | Default when taint analysis not available |

Utility-code findings are automatically tagged `unlikely` (0.4x).

## Domain Weights

Domains are weighted by their relative importance to agent security:

| Domain | Weight | Relative % |
|--------|--------|-----------|
| Goal Integrity | 1.5 | 10.4% |
| Tool Safety | 1.5 | 10.4% |
| Rogue Agent | 1.4 | 9.7% |
| Code Execution | 1.3 | 9.0% |
| Data Leakage | 1.3 | 9.0% |
| Identity & Access | 1.2 | 8.3% |
| Cascading Failures | 1.2 | 8.3% |
| Reliability Bounds | 1.2 | 8.3% |
| Memory & Context | 1.1 | 7.6% |
| Inter-Agent | 1.1 | 7.6% |
| Supply Chain | 1.0 | 6.9% |
| Human Oversight | 1.0 | 6.9% |

**Total weight sum:** 14.8

## Scoring Examples

### Example 1: Critical finding in agent code

```
Severity:       critical (20 pts)
Reachability:   agent-reachable (1.0x)
Exploitability: confirmed (1.2x)
Deduction:      20 * 1.0 * 1.2 = 24 points from domain score
```

### Example 2: High finding in utility code

```
Severity:       high (10 pts)
Reachability:   utility-code (0.3x)
Exploitability: unlikely (0.4x, auto-set)
Deduction:      10 * 0.3 * 0.4 = 1.2 points from domain score
```

88% reduction from full impact due to reachability + exploitability context.

### Example 3: Medium finding with compensating control

```
Severity:       medium (5 pts) -> low (2.5 pts) after control detection
Reachability:   endpoint-reachable (0.8x)
Exploitability: likely (1.0x)
Deduction:      2.5 * 0.8 * 1.0 = 2.0 points from domain score
```

## Score Calibration Pipeline

The full scoring pipeline applies these steps in order:

1. **Raw findings** — Rules produce initial finding set
2. **Deduplication** — Exact line, cross-rule, function scope, prompt cap
3. **Suppression** — `g0-ignore` inline comments
4. **Compensating controls** — ±5 line proximity check downgrades severity
5. **Control registry** — Project-wide security control detection adjusts confidence/severity
6. **Test file handling** — Downgrade or filter findings in test/fixture files
7. **Reachability tagging** — Categorize code accessibility
8. **Exploitability assessment** — AST-based taint analysis
9. **Score calculation** — Apply formula with multipliers
10. **Grade assignment** — Map score to letter grade
