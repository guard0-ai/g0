# Scoring Rationale

g0 produces a 0-100 security score with a letter grade. This page explains the design decisions behind the scoring system.

## Why 0-100?

- **Intuitive** — Everyone understands percentage-like scores
- **Granular enough** — Distinguishes between 72/100 and 78/100 (both "C" grade but different risk levels)
- **Not too granular** — A decimal score (72.34) implies false precision
- **Comparable** — Scores can be tracked over time and compared across projects

## Why Deduction-Based?

The score starts at 100 and deducts for findings, rather than adding up from 0. Rationale:

- **Safe by default** — A project with no findings scores 100, encouraging a "zero warnings" culture
- **Actionable** — Each finding has a clear score impact, making prioritization straightforward
- **Monotonic** — Fixing findings always improves the score (no cases where fixing one thing lowers the score)

## Severity Deductions

| Severity | Deduction | Rationale |
|----------|-----------|-----------|
| Critical | 20 points | Can compromise the entire agent system |
| High | 10 points | Significant risk requiring remediation |
| Medium | 5 points | Moderate risk, should be addressed |
| Low | 2.5 points | Minor risk, informational |
| Info | 0 points | No score impact, for awareness only |

The 2x ratio between levels (20→10→5→2.5) was chosen because:
- A single critical finding should dominate the score (a project with one critical is not "A" grade)
- But it shouldn't zero out a domain (a critical in one area doesn't mean everything is broken)
- 5 medium findings ≈ 1 critical finding feels right for prioritization

## Reachability Multipliers

| Level | Multiplier | Rationale |
|-------|-----------|-----------|
| agent-reachable | 1.0x | On the agent's direct execution path — full impact |
| tool-reachable | 1.0x | Called by agent tools — equivalent exposure |
| endpoint-reachable | 0.8x | In HTTP handlers — reachable but with more layers of defense |
| unknown | 0.6x | Can't determine reachability — moderate assumption |
| utility-code | 0.3x | Library/helper code — significantly lower risk |

The utility-code 70% reduction is aggressive but justified: a vulnerability in a utility function that no agent ever calls poses minimal actual risk. Without this multiplier, large codebases with many utility files would have artificially low scores.

## Domain Weighting

All domains are weighted equally (1.0x). This was a deliberate choice:

- **No artificial prioritization** — Different organizations care about different domains
- **Configuration-based** — Future versions may support custom weights in `.g0.yaml`
- **Fairness** — A project that's strong in Goal Integrity but weak in Tool Safety shouldn't mask the weakness

## Grade Thresholds

| Grade | Range | Design Intent |
|-------|-------|--------------|
| A | 90-100 | Minimal issues — ready for production |
| B | 80-89 | Low risk — minor improvements needed |
| C | 70-79 | Acceptable — moderate risk, plan improvements |
| D | 60-69 | Poor — significant gaps, prioritize remediation |
| F | 0-59 | Failing — critical risks, not production-ready |

The 70 threshold for "C" (acceptable) was chosen because:
- It aligns with common CI/CD gate defaults
- A project scoring 70+ has no critical findings in agent-reachable code (critical = 20pt deduction would push most domains below 80)
- It allows some medium-severity findings while still requiring a reasonable security baseline

## Score Floor

Domain scores floor at 0 (never negative). This prevents a single domain with many findings from dragging the overall score below what other domains justify.

## Calibration

The scoring system was calibrated against:
- Known-vulnerable AI agent projects (should score F)
- Production agent systems with good security practices (should score B+)
- Example projects from framework documentation (should score C-D, since examples rarely implement security)
- Minimal "hello world" agents (should score D-F due to missing guardrails)
