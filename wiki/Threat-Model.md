# Threat Model

This page describes what g0 covers, what it doesn't cover, and the assumptions behind its security model.

## What g0 Covers

### Static Analysis

g0 analyzes source code and configuration to detect:

| Threat Category | Examples |
|----------------|----------|
| **Prompt injection** | Direct injection, indirect injection (via DB/email/URL), delimiter attacks, encoding-based attacks |
| **Tool misuse** | Missing input validation, unsandboxed tools, overly broad capabilities, tool injection |
| **Code execution** | Unsandboxed eval/exec, template injection, arbitrary code generation |
| **Data leakage** | System prompt extraction, PII exposure, error message disclosure, training data memorization |
| **Identity/access** | Hardcoded credentials, missing auth, excessive permissions, session mismanagement |
| **Supply chain** | Unpinned dependencies, unverified packages, MCP rug-pull attacks |
| **Memory/context** | Unbounded memory, context poisoning, RAG injection, history manipulation |
| **Cascading failures** | Missing circuit breakers, no timeouts, unbounded retries, no error handling |
| **Human oversight** | Missing approval workflows, no escalation paths, inadequate audit trails |
| **Inter-agent** | Unrestricted delegation, message injection, trust boundary violations |
| **Reliability** | Missing rate limits, no cost controls, unbounded iterations |
| **Rogue detection** | Inadequate logging, no anomaly detection, missing behavioral monitoring |

### Dynamic Testing

g0 sends adversarial payloads to running agents to test:

| Attack Category | What's Tested |
|----------------|--------------|
| Prompt injection | Can the agent's instructions be overridden? |
| Data exfiltration | Can data be extracted via side channels? |
| Tool abuse | Can tools be invoked outside their intended scope? |
| Jailbreak | Can safety guidelines be bypassed? |
| Goal hijacking | Can the agent's objective be redirected? |
| Content safety | Will the agent generate harmful content? |
| Bias | Does the agent exhibit discriminatory behavior? |
| PII probing | Will the agent leak personal information? |
| Agentic attacks | Can multi-step exploitation chains be constructed? |
| Advanced jailbreak | Do encoded/obfuscated attacks bypass filters? |

### Architecture Analysis

g0 builds and analyzes the Agent Graph to detect:
- Agent-to-tool trust relationships
- Data flow paths (user input → tool execution)
- Agent delegation chains
- MCP server tool permissions
- Model configuration risks

## What g0 Does NOT Cover

### Runtime Behavior

g0's static analysis operates on source code, not runtime state. It cannot detect:
- Model hallucinations or factual errors
- Stochastic behavior differences between runs
- Issues that only manifest with specific user inputs (beyond dynamic testing)
- Memory corruption or buffer overflow (not relevant for Python/TS/Java/Go)

### Model-Level Attacks

g0 does not analyze the model itself:
- Training data poisoning (requires access to training pipeline)
- Model weight extraction (network-level attack)
- Adversarial examples in embeddings (requires model-specific analysis)
- Fine-tuning attacks (requires access to fine-tuning process)

### Infrastructure

g0 analyzes application code, not infrastructure:
- Network security (firewalls, VPNs, network segmentation)
- Container security (Docker misconfigurations, Kubernetes RBAC)
- Cloud IAM policies (AWS/GCP/Azure role assignments)
- OS-level vulnerabilities

### Business Logic

g0 can't evaluate whether your agent's behavior is correct for your use case:
- Is the agent answering questions accurately?
- Are the tool invocations producing correct results?
- Is the agent's personality appropriate for the brand?

## Assumptions

### Trusted Development Environment

g0 assumes the development environment is trusted:
- Source code has not been tampered with by an attacker
- Development dependencies are genuine (not typosquatted)
- The developer's machine is not compromised

### Attacker Model

g0 protects against:
- **External attackers** sending crafted inputs to the agent
- **Indirect injection** via data sources the agent reads (DB, email, URL)
- **Supply chain** compromise of agent dependencies and MCP servers
- **Privilege escalation** through tool and agent delegation chains

g0 does not protect against:
- **Insider threats** with commit access (they can disable rules)
- **Physical access** to the runtime environment
- **Model provider compromise** (if OpenAI/Anthropic is compromised)

### Framework Support

g0's analysis quality depends on framework detection. For supported frameworks (10), g0 produces comprehensive findings. For unknown frameworks, g0 still:
- Detects common patterns (API keys, eval, system prompts)
- Applies generic code analysis rules
- But may miss framework-specific constructs

## Risk Boundaries

```
┌─────────────────────────────────────────────────┐
│                g0 Coverage                       │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Source   │  │  Agent   │  │  Adversarial │  │
│  │  Code     │  │  Config  │  │  Testing     │  │
│  │  Analysis │  │  Review  │  │  (Dynamic)   │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │  Supply  │  │  MCP     │  │  Standards   │  │
│  │  Chain   │  │  Security│  │  Compliance  │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│             Out of Scope                         │
│  Infrastructure, Runtime ML, Model Training,    │
│  Network Security, Business Logic               │
└─────────────────────────────────────────────────┘
```
