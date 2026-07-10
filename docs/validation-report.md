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
| **False positives — hardened agents** | **17 → 4** critical/high (fixed this branch; all 5 now grade A) |
| Real-corpus discovery | **37 / 43 (86%)** had agents/tools extracted |
| Finding reachability | 88% agent/tool-reachable, 10% utility-code |

Both concrete issues found were root-caused and **fixed** in this branch: the
**OpenAI discovery gap** (§4) and the **false positives on hardened agents** (§3,
17 → 4, including two critical/detection FPs). Efficacy stayed at 8/8 throughout.

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

## 3. False positives — hardened agents (fixed: 17 → 4)

Five agents written deliberately to be secure (parameterized SQL, input
validation, scoped prompts, `os.getenv` for secrets, allowlists). They initially
produced **17 critical/high findings**; after the fixes below, **4**, and all
five now grade **A**:

| Target | Crit/High before | Crit/High after | Grade after |
|--------|------------------|-----------------|-------------|
| c1_clean_langchain | 8 | 3 | A |
| c2_clean_openai | 1 | 1 | A |
| c3_clean_readonly | 4 (incl. 1 crit) | 0 | A |
| c4_hardened_tool | 0 | 0 | A |
| c5_minimal (haiku bot) | 4 | 0 | A |

Two classes of problem were found and fixed, and both were genuine bugs — not
just severity taste:

**a) Detection false positives (matching English words in prompt prose).**
- `AA-DL-023 Credentials in LLM responses` (**critical**) fired on c3 because the
  agent's own defensive instruction — "you must not output secrets or
  credentials" — matched `(?:output|…).*(?:credentials?)`. A prompt *forbidding*
  a leak was flagged *as* the leak. Fixed: skip defensive-instruction phrasing.
- `AA-TS-021 Tool with unrestricted network access` fired on c1's DB tool because
  the pattern `fetch` matched `cur.fetchone()`. Fixed: `\bfetch\s*\(` (JS network
  fetch, not DB cursor methods).
- `AA-GI-002 System prompt lacks instruction guarding` fired on c1's clearly
  guarded prompt ("Do not execute code… refuse any request outside order
  support") because the guarding detector recognized too narrow a phrase set.
  Fixed: broadened to common scoping/refusal phrasing (still treats permissive
  prompts like "do whatever the user asks" as unguarded).

**b) Generic operational/quality nudges over-rated at HIGH.** Rules that fire on
*every* agent regardless of what it does — `LLM call without max_tokens`
(AA-CF-051), `No daily token/cost limit` (AA-CF-052), `No token budget`
(AA-RB-007), `No grounding instruction` (AA-RB-002), and `Agent accesses
environment variables` (AA-RA-007, i.e. secure `os.getenv`) — were downgraded
**high → low**. They remain visible and still feed the hardening score, but no
longer inflate the crit/high tier or the grade. Capability-specific absence rules
(no sandbox on code-exec, no input validation, no auth) were deliberately **left
at HIGH** — downgrading those would create false *negatives*.

Efficacy was re-verified at **8/8** after every change; no vuln detection was
lost. The remaining 4 clean-set findings are capability-specific DB-tool concerns
(query limits, circuit breaker, HITL on a data-access tool) where a HIGH rating
is defensible — down-rating further would overfit the synthetic corpus.

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
