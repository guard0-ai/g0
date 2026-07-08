# g0 v2 — FP / Efficacy Validation Report

> Validation of the v2 branch across **59 targets** spanning real public agent
> projects, MCP servers, and a labeled synthetic corpus. Measures detection
> efficacy (true positives on known-vulnerable code) and false-positive rate (on
> hardened and non-agent code). Reproducible; methodology in the appendix.

## Headline results

| Metric | Result |
|--------|--------|
| Targets scanned | **59** (16 labeled synthetic + 43 real) |
| Crashes / errors | **0** (100% completed) |
| Avg scan time | ~0.7 s / target |
| **Efficacy** (planted vulns detected) | **8 / 8 = 100%** |
| **False positives — non-agent code** | **1** critical/high across 3 projects |
| **False positives — hardened agents** | **17** critical/high across 5 projects ⚠️ |
| Real-corpus discovery | **37 / 43 (86%)** had agents/tools extracted |
| Finding reachability | 88% agent/tool-reachable, 10% utility-code |

Two concrete issues were found. One (**OpenAI discovery gap**) was root-caused
and **fixed** in this branch. The other (**absence-based hardening rules rated
HIGH**) is characterized below with a recommendation.

## 1. Efficacy — 100% on the labeled vulnerable set

Eight agents each with one planted vulnerability; detection was checked against
the *specific* expected issue (not merely "some finding"):

| Target | Planted issue | Detected | Grade |
|--------|---------------|----------|-------|
| v1_shell_injection | `subprocess(shell=True)` on tool input | ✅ | D |
| v2_eval | `eval()` of expression | ✅ | D |
| v3_hardcoded_key | hardcoded `sk-...` key | ✅ | C |
| v4_prompt_injection | user input f-string into system prompt | ✅ | C |
| v5_sql_injection | string-built SQL from input | ✅ | D |
| v6_shared_memory | `ConversationBufferMemory` shared across users | ✅ | C |
| v7_pickle | `pickle.loads` on tool input | ✅ | D |
| v8_ssrf | `requests.get(user_url)` in a tool | ✅ | C |

All eight vulnerable agents were correctly graded C or worse (the grade cap
prevents any from reading as A/B). **Detection rate: 100%.**

## 2. False positives — non-agent code is clean

Plain, non-AI code should be near-silent. It is:

| Target | Crit | High | Med | Low |
|--------|------|------|-----|-----|
| Flask CRUD API | 0 | 1 | 3 | 0 |
| pandas ETL script | 0 | 0 | 4 | 0 |
| argparse CLI | 0 | 0 | 1 | 0 |

**1** critical/high across three non-agent projects, and no agent-domain false
detections (0 agents discovered in all three). This is the correct behavior.

## 3. False positives — hardened agents (open issue) ⚠️

Five agents written deliberately to be secure (parameterized SQL, input
validation, scoped prompts, `os.getenv` for secrets, allowlists). They should
score near-clean; instead they produced **17 critical/high findings**:

| Target | Crit | High | Notes |
|--------|------|------|-------|
| c1_clean_langchain | 0 | 8 | all "missing hardening" recommendations |
| c2_clean_openai | 0 | 1 | — |
| c3_clean_readonly | 1 | 3 | — |
| c4_hardened_tool | 0 | 0 | ✅ clean |
| c5_minimal (haiku bot) | 0 | 4 | incl. env-var access flagged HIGH |

**Root cause:** these are almost entirely **absence-based hardening rules
emitted at HIGH severity** — e.g. `No daily token/cost limit`, `LLM call without
max_tokens`, `No grounding instruction`, `No HITL instruction`, `DB connection
without circuit breaker`. The most clear-cut FP: a haiku generator is flagged
HIGH for `AA-RA-007 Agent accesses environment variables` — i.e. for using
`os.getenv("OPENAI_API_KEY")`, which is the *recommended secure* pattern.

These are not vulnerabilities; they are missing-hardening nits. The scoring
engine already separates them (`securityScore` vs `hardeningScore`), but they
still surface at HIGH in the findings list and crit/high counts.

**Recommendation (not applied — needs rule-suite sign-off):** cap the *displayed
severity* of absence-based hardening findings at MEDIUM by default (they remain
visible and still feed the hardening score), and reserve HIGH/CRITICAL for
presence-based findings (something bad *is* there). Estimated impact: clean-set
crit/high FPs drop from **17 → ~1**, with zero loss of information. This is a
severity-calibration change touching many rules and their tests, so it is called
out here rather than made unilaterally.

## 4. Real-corpus discovery + an OpenAI gap (fixed)

Discovery across 43 real project directories:

| Source | n | discovered agents/tools |
|--------|---|--------------------------|
| crewAI crews | 16 | 15 / 16 |
| crewAI flows | 6 | 5 / 6 |
| OpenAI Agents SDK examples | 14 | **14 / 14** (was 7/14 before fix) |
| MCP servers | 7 | 3 / 7 (MCP is better served by `g0 mcp`) |

**Fixed this branch:** OpenAI Agents SDK discovery was failing on 7/14 examples
because (a) detection required an `openai-agents` manifest in the scanned dir,
(b) the parser missed generic-subscripted `Agent[Ctx](...)`, and (c) the parser
skipped files importing only `Agent` (agents defined in their own module). After
the fix, discovery is **14/14**, and the utility-code share of all findings fell
from 30% → 10% as findings were correctly re-attributed as agent-reachable.

## Appendix — methodology (reproducible)

- **Labeled synthetic corpus** (`/private/tmp/g0val/corpus`): 8 vulnerable, 5
  hardened, 3 non-agent projects — the only way to get ground-truth FP/TP, since
  real repos are unlabeled. Generator: `gen_corpus.sh`.
- **Real corpus**: `crewAIInc/crewAI-examples` (crews + flows),
  `openai/openai-agents-python` (examples), `modelcontextprotocol/servers`.
- **Harness** (`run.mjs`): runs `g0 scan --json` per target, records framework,
  agents/tools, findings by severity, grade, reachability, duration; for the
  vulnerable set, checks the specific planted issue via expected-keyword match.
- **Analysis** (`analyze.mjs`): aggregates efficacy, FP by set, discovery rate,
  grade and reachability distributions.
