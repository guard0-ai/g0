# AA-MP: Memory & Context Security Controls

**Domain:** Memory & Context Security  
**OWASP Mapping:** ASI06 — Memory & Context Manipulation  
**Control Range:** AA-MP-001 through AA-MP-100  
**Total Controls:** 100  
**Last Updated:** 2026-02-13  
**Status:** Active

---

## Overview

AI agents maintain state through various memory mechanisms — conversation history, RAG-based retrieval, vector databases, session stores, scratchpads, and tool result caches — each representing an attack surface that can be poisoned, manipulated, or exploited. Unlike traditional applications where memory is typed and bounded, agent memory is often unstructured natural language that blends user input, system instructions, and retrieved context into a single processing stream, making boundary enforcement exceptionally difficult.

Memory manipulation attacks target the agent's ability to recall, reason, and make decisions accurately. Conversation history injection can plant false context that influences future decisions. RAG poisoning inserts malicious content into the knowledge base that gets retrieved and acted upon as trusted information. Vector database manipulation exploits similarity search to surface attacker-controlled content. Context window overflow deliberately exhausts token budgets to push system instructions out of the processing window, degrading safety behavior.

These controls address the full spectrum of memory and context security: from input validation and boundary enforcement through integrity monitoring, persistence security, and cross-session isolation. They ensure that agent memory systems maintain confidentiality, integrity, and availability while preserving the agent's ability to accurately recall information and make well-founded decisions.

---

## Applicable Standards

| Standard | Sections |
|----------|----------|
| OWASP Agentic Security | ASI06 — Memory & Context Manipulation |
| NIST AI RMF | MAP-2.3, MEASURE-2.6, MANAGE-3.2 |
| ISO 42001 | A.8 — Data Management, A.10 — System Security |
| ISO 23894 | Clause 6.4 — Data Integrity Risks |
| MITRE ATLAS | AML.T0020 — Poison Training Data, AML.T0043 — Craft Adversarial Data |
| OWASP Agentic AI Top 10 | Principle 4 — Data Integrity, Principle 5 — State Management |
| OWASP AIVSS | Vectors: AV:M (Memory), AV:C (Context) |

---

## Sub-Categories Summary

| # | Sub-Category | Controls | Range |
|---|-------------|----------|-------|
| 1 | Memory Poisoning | 10 | AA-MP-001 – AA-MP-010 |
| 2 | Context Window Manipulation | 10 | AA-MP-011 – AA-MP-020 |
| 3 | Conversation History Injection | 10 | AA-MP-021 – AA-MP-030 |
| 4 | RAG Poisoning | 10 | AA-MP-031 – AA-MP-040 |
| 5 | Vector DB Manipulation | 10 | AA-MP-041 – AA-MP-050 |
| 6 | Memory Persistence Attacks | 10 | AA-MP-051 – AA-MP-060 |
| 7 | Context Overflow | 10 | AA-MP-061 – AA-MP-070 |
| 8 | State Deserialization | 10 | AA-MP-071 – AA-MP-080 |
| 9 | Cross-Session Contamination | 10 | AA-MP-081 – AA-MP-090 |
| 10 | Framework-Specific Memory Checks | 10 | AA-MP-091 – AA-MP-100 |

---

## 1. Memory Poisoning (AA-MP-001 – AA-MP-010)

**Threat:** Attackers inject malicious content into agent memory stores through crafted inputs, tool outputs, or indirect prompt injection, causing the agent to recall and act on false or manipulative information in subsequent interactions.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-001 | No input sanitization before memory storage | CRITICAL | static | stable | langchain, crewai, openai |
| AA-MP-002 | Tool output stored in memory without validation | CRITICAL | static | stable | langchain, crewai, mcp |
| AA-MP-003 | Memory write access not restricted | HIGH | static | stable | langchain, autogen, crewai |
| AA-MP-004 | Indirect prompt injection stored as trusted memory | HIGH | dynamic | stable | langchain, openai, vercel-ai |
| AA-MP-005 | Memory provenance tracking absent | HIGH | static | stable | langchain, crewai, autogen |
| AA-MP-006 | No memory content integrity verification | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-007 | Adversarial content detection in memory writes missing | MEDIUM | dynamic | stable | langchain, crewai, openai |
| AA-MP-008 | Memory poisoning via multi-turn conversation | MEDIUM | dynamic | stable | langchain, openai, vercel-ai |
| AA-MP-009 | No memory content anomaly detection | MEDIUM | dynamic | experimental | langchain, crewai, autogen |
| AA-MP-010 | Memory rollback capability absent | MEDIUM | both | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI06:** Memory poisoning is the primary memory manipulation attack
- **MITRE ATLAS AML.T0043:** Crafting adversarial data for memory injection
- **NIST AI RMF MAP-2.3:** Data integrity for AI system inputs

### Detailed Descriptions

**AA-MP-001: No input sanitization before memory storage**
- **Description:** User inputs and external data are stored directly into agent memory without sanitization, filtering, or validation of content type and structure.
- **Rationale:** Unsanitized memory writes allow injection of instructions, encoded payloads, or manipulative content that the agent later retrieves and treats as trusted context.

**AA-MP-002: Tool output stored in memory without validation**
- **Description:** Results returned from tool calls are stored in agent memory without verifying the output matches expected format, size, or content type.
- **Rationale:** Compromised tools can return payloads designed to poison agent memory. Tool outputs must be validated before being persisted as trusted context.

**AA-MP-003: Memory write access not restricted**
- **Description:** Any component, tool, or user can write to agent memory without authorization checks or role-based access controls.
- **Rationale:** Unrestricted memory writes allow any input source to poison the agent's state. Write access should be limited to authorized components with validated content.

**AA-MP-004: Indirect prompt injection stored as trusted memory**
- **Description:** Content from web pages, documents, or external sources that contain indirect prompt injection is stored in memory and later recalled as trusted context.
- **Rationale:** Indirect prompt injection through memory creates persistent attacks that activate whenever the poisoned memory is retrieved, potentially across multiple sessions.

**AA-MP-005: Memory provenance tracking absent**
- **Description:** Memory entries do not record their source, timestamp, or trust level, making it impossible to distinguish user-provided, system-generated, and externally-sourced memories.
- **Rationale:** Provenance enables trust-based filtering of memory during recall. Without it, attacker-injected memories are indistinguishable from legitimate ones.

**AA-MP-006: No memory content integrity verification**
- **Description:** Memory contents lack integrity checks (checksums, signatures) to detect unauthorized modification of stored entries.
- **Rationale:** Integrity verification detects memory tampering by malicious components, concurrent access issues, or storage corruption that could alter agent behavior.

**AA-MP-007: Adversarial content detection in memory writes missing**
- **Description:** Content written to memory is not scanned for adversarial patterns such as embedded instructions, encoding tricks, or known attack signatures.
- **Rationale:** Pattern-based detection catches known memory poisoning techniques including Base64-encoded instructions, unicode obfuscation, and prompt injection markers.

**AA-MP-008: Memory poisoning via multi-turn conversation**
- **Description:** Attackers gradually build malicious context across multiple conversation turns, with each individual message appearing benign but the accumulated memory creating a poisoned state.
- **Rationale:** Multi-turn poisoning evades per-message detection. Memory systems must analyze accumulated context patterns to detect gradual manipulation campaigns.

**AA-MP-009: No memory content anomaly detection**
- **Description:** Memory contents are not monitored for anomalous patterns such as sudden changes in content type, unexpected instruction-like entries, or statistical deviations.
- **Rationale:** Anomaly detection provides a defense-in-depth layer against novel memory poisoning techniques that bypass pattern-based detection.

**AA-MP-010: Memory rollback capability absent**
- **Description:** There is no mechanism to roll back agent memory to a known-good state after detecting poisoning or corruption.
- **Rationale:** Rollback enables recovery from memory poisoning incidents without destroying all accumulated context. Regular memory snapshots support forensic analysis and restoration.

---

## 2. Context Window Manipulation (AA-MP-011 – AA-MP-020)

**Threat:** Attackers exploit the fixed context window size of LLMs to manipulate what information the agent can process, either by flooding the context to push out safety instructions or by crafting inputs that maximize context consumption and degrade agent performance.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-011 | Context window budget not tracked | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-MP-012 | System prompt position not protected | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-MP-013 | Context window overflow not detected | HIGH | dynamic | stable | langchain, crewai, openai |
| AA-MP-014 | Context priority ordering absent | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-MP-015 | Large input not truncated or summarized | HIGH | static | stable | langchain, crewai, autogen |
| AA-MP-016 | Context composition logging absent | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-MP-017 | No context window utilization alerting | MEDIUM | dynamic | stable | langchain, openai, vercel-ai |
| AA-MP-018 | Context eviction strategy not security-aware | MEDIUM | static | stable | langchain, openai, crewai |
| AA-MP-019 | Token counting estimation inaccurate | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-MP-020 | Context window state not recoverable | MEDIUM | both | experimental | langchain, openai, autogen |

### Standards Mapping

- **ASI06:** Context window manipulation is a key memory attack vector
- **NIST AI RMF MEASURE-2.6:** Monitoring context integrity and availability
- **OWASP Agentic AI Top 10 Principle 5:** State management and context integrity

### Detailed Descriptions

**AA-MP-011: Context window budget not tracked**
- **Description:** The agent does not track token consumption across the context window, making it impossible to detect approaching limits or intentional context flooding.
- **Rationale:** Without token budget tracking, attackers can silently exhaust the context window, pushing critical safety instructions and system prompts out of the processing window.

**AA-MP-012: System prompt position not protected**
- **Description:** The system prompt is placed in a position where it can be pushed out of the context window by accumulated conversation history or large tool outputs.
- **Rationale:** System prompts contain safety instructions and behavioral constraints. If they are evicted from the context window, the agent loses its safety guardrails.

**AA-MP-013: Context window overflow not detected**
- **Description:** When context exceeds the model's token limit, truncation occurs silently without alerting or logging which content was removed.
- **Rationale:** Silent truncation can remove safety-critical context. Overflow events must be detected, logged, and handled with security-aware truncation strategies.

**AA-MP-014: Context priority ordering absent**
- **Description:** No priority system determines which context elements are preserved when the window is full, treating system instructions and user chat with equal importance.
- **Rationale:** Priority ordering ensures safety-critical content (system prompt, security instructions) is never evicted in favor of less important content.

**AA-MP-015: Large input not truncated or summarized**
- **Description:** The agent accepts arbitrarily large inputs without truncation, summarization, or segmentation, allowing context flooding attacks.
- **Rationale:** Input size limits prevent intentional context flooding. Large inputs should be summarized or segmented to preserve space for safety-critical context.

**AA-MP-016: Context composition logging absent**
- **Description:** The composition of the context window (percentage system prompt, user input, tool outputs, memory) is not logged or monitored.
- **Rationale:** Context composition logging enables detection of manipulation patterns where specific content types are being displaced by attacker-controlled content.

**AA-MP-017: No context window utilization alerting**
- **Description:** No alerts fire when context window utilization approaches dangerous thresholds that could lead to safety instruction eviction.
- **Rationale:** Proactive alerting enables intervention before context overflow occurs, preventing silent degradation of safety behavior.

**AA-MP-018: Context eviction strategy not security-aware**
- **Description:** When context must be reduced, the eviction strategy uses FIFO or random eviction rather than considering the security importance of each context element.
- **Rationale:** Security-aware eviction preserves system prompts, safety instructions, and authentication context even when the window is under pressure.

**AA-MP-019: Token counting estimation inaccurate**
- **Description:** Token count estimation uses approximate methods that diverge significantly from actual model tokenization, leading to incorrect context management decisions.
- **Rationale:** Inaccurate token counting can cause premature truncation (losing useful context) or overflow (losing safety context). Use model-specific tokenizers.

**AA-MP-020: Context window state not recoverable**
- **Description:** After context overflow or corruption, there is no mechanism to reconstruct a valid context state from logged or checkpointed data.
- **Rationale:** Context recovery enables resumption of agent operation with safety guarantees intact after overflow events or detected manipulation.

---

## 3. Conversation History Injection (AA-MP-021 – AA-MP-030)

**Threat:** Attackers inject fabricated conversation turns into agent history, creating false context that influences the agent's understanding of prior interactions, agreed-upon decisions, or granted permissions.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-021 | Conversation history tampering not detected | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-MP-022 | Synthetic assistant messages injectable | CRITICAL | dynamic | stable | langchain, openai, autogen |
| AA-MP-023 | History role field not validated | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-MP-024 | Conversation history not integrity-protected | HIGH | static | stable | langchain, crewai, openai |
| AA-MP-025 | History import from untrusted source | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-026 | Conversation ID spoofing possible | MEDIUM | dynamic | stable | langchain, openai, vercel-ai |
| AA-MP-027 | History replay attack not prevented | MEDIUM | dynamic | stable | langchain, openai, autogen |
| AA-MP-028 | History size not bounded per session | MEDIUM | static | stable | langchain, crewai, openai |
| AA-MP-029 | Deleted messages recoverable from history | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-MP-030 | History sharing between users possible | MEDIUM | static | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI06:** Conversation history is the primary stateful attack surface
- **ISO 42001 A.8:** Data management integrity for conversation records
- **NIST AI RMF MANAGE-3.2:** Conversation data integrity management

### Detailed Descriptions

**AA-MP-021: Conversation history tampering not detected**
- **Description:** Conversation history stored on the client side or in unprotected storage can be modified without server-side integrity verification.
- **Rationale:** Tampered history can insert fabricated exchanges where the agent "agreed" to actions or "confirmed" permissions, bypassing authorization controls.

**AA-MP-022: Synthetic assistant messages injectable**
- **Description:** The agent's message history API accepts fabricated assistant messages, allowing attackers to inject fake agent responses that establish false precedent.
- **Rationale:** Injected assistant messages create false context suggesting the agent previously approved actions, disclosed information, or adopted specific behaviors.

**AA-MP-023: History role field not validated**
- **Description:** Message role fields (user, assistant, system) in conversation history are not validated, allowing role confusion through injection.
- **Rationale:** Role manipulation can cause user messages to be treated as system instructions or system prompts to be treated as user input, bypassing safety controls.

**AA-MP-024: Conversation history not integrity-protected**
- **Description:** Stored conversation history lacks cryptographic integrity protection (MACs, signatures, or hash chains) to detect modifications.
- **Rationale:** Integrity protection creates a tamper-evident record. Without it, any process with storage access can silently modify history to influence agent behavior.

**AA-MP-025: History import from untrusted source**
- **Description:** The agent accepts conversation history imports from external sources (files, APIs, other systems) without validating the source's trustworthiness.
- **Rationale:** Imported history is a direct injection vector. Only history from authenticated, authorized sources should be accepted, with content validation.

**AA-MP-026: Conversation ID spoofing possible**
- **Description:** Conversation identifiers can be forged, allowing access to or injection into other users' conversation histories.
- **Rationale:** Conversation ID spoofing enables cross-user attacks where one user's session context is accessible to another, violating session isolation.

**AA-MP-027: History replay attack not prevented**
- **Description:** Old conversation segments can be replayed into current sessions without detection, potentially reintroducing revoked permissions or outdated context.
- **Rationale:** Replay attacks can reactivate expired authorizations or reintroduce context that was deliberately cleared, undermining session management.

**AA-MP-028: History size not bounded per session**
- **Description:** No limit exists on the amount of conversation history that can accumulate in a single session, enabling memory exhaustion attacks.
- **Rationale:** Unbounded history enables denial-of-service through storage exhaustion and increases the attack surface for context manipulation.

**AA-MP-029: Deleted messages recoverable from history**
- **Description:** Messages the user deletes from conversation history remain accessible through the agent API, undo functionality, or storage-level access.
- **Rationale:** Deleted messages may contain sensitive information. Deletion must be genuine, removing data from all storage layers and backup systems.

**AA-MP-030: History sharing between users possible**
- **Description:** Conversation history from one user's session can be accessed by or leaked to another user through shared storage, caching, or API vulnerabilities.
- **Rationale:** Cross-user history leakage violates privacy and can expose sensitive information, credentials, or personal data discussed in private sessions.

---

## 4. RAG Poisoning (AA-MP-031 – AA-MP-040)

**Threat:** Retrieval-Augmented Generation (RAG) systems extend agent knowledge by retrieving documents from knowledge bases. Attackers can poison these knowledge bases with documents containing malicious instructions, false information, or adversarial content that gets retrieved and acted upon.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-031 | RAG source documents not validated | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-MP-032 | RAG content contains embedded instructions | CRITICAL | dynamic | stable | langchain, openai, vercel-ai |
| AA-MP-033 | RAG indexing access not controlled | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-034 | RAG retrieval results not filtered | HIGH | static | stable | langchain, crewai, openai |
| AA-MP-035 | RAG document provenance not tracked | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-036 | RAG embedding adversarial robustness untested | MEDIUM | dynamic | experimental | langchain, openai, bedrock |
| AA-MP-037 | RAG chunk boundary manipulation possible | MEDIUM | static | stable | langchain, openai, autogen |
| AA-MP-038 | RAG relevance score manipulation undetected | MEDIUM | dynamic | experimental | langchain, openai, bedrock |
| AA-MP-039 | RAG index integrity monitoring absent | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-MP-040 | RAG poisoning detection and remediation missing | MEDIUM | both | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI06:** RAG poisoning is a high-impact memory manipulation attack
- **MITRE ATLAS AML.T0020:** Poisoning the data used for retrieval augmentation
- **ISO 23894 Clause 6.4:** Data integrity risks in RAG systems

### Detailed Descriptions

**AA-MP-031: RAG source documents not validated**
- **Description:** Documents ingested into the RAG knowledge base are not validated for content type, format compliance, or presence of adversarial content.
- **Rationale:** Unvalidated source documents can contain embedded prompt injections that activate when retrieved, causing the agent to execute attacker-controlled instructions.

**AA-MP-032: RAG content contains embedded instructions**
- **Description:** Retrieved RAG content contains instruction-like text (e.g., "Ignore previous instructions", "You are now...") that the agent may interpret as directives.
- **Rationale:** Embedded instructions in RAG content are a primary indirect prompt injection vector. Content must be scanned for instruction patterns before indexing.

**AA-MP-033: RAG indexing access not controlled**
- **Description:** The RAG knowledge base indexing pipeline lacks access controls, allowing unauthorized users or processes to add, modify, or delete documents.
- **Rationale:** Uncontrolled indexing access is the enabler for RAG poisoning. Only authorized, validated content sources should be able to write to the knowledge base.

**AA-MP-034: RAG retrieval results not filtered**
- **Description:** Retrieved documents are passed directly to the agent without post-retrieval filtering for adversarial content, instruction injection, or relevance validation.
- **Rationale:** Post-retrieval filtering provides a second defense layer, catching adversarial content that bypassed indexing-time checks or was injected post-indexing.

**AA-MP-035: RAG document provenance not tracked**
- **Description:** Retrieved documents lack provenance metadata (source, indexing date, author, trust level) that enables the agent to assess trustworthiness.
- **Rationale:** Provenance enables trust-based reasoning about retrieved content. Documents from verified internal sources can be weighted differently from external or user-submitted ones.

**AA-MP-036: RAG embedding adversarial robustness untested**
- **Description:** The embedding model used for RAG has not been tested against adversarial inputs designed to manipulate similarity scores and influence retrieval.
- **Rationale:** Adversarial embeddings can ensure malicious documents are retrieved for specific queries. Robustness testing validates the embedding model against such attacks.

**AA-MP-037: RAG chunk boundary manipulation possible**
- **Description:** Document chunking does not account for adversarial boundary manipulation where attackers craft content that splits across chunks to bypass detection.
- **Rationale:** Attackers can position malicious content at chunk boundaries so it appears in retrieval results but spans multiple chunks, evading per-chunk content filtering.

**AA-MP-038: RAG relevance score manipulation undetected**
- **Description:** Documents are not monitored for artificially inflated relevance scores achieved through keyword stuffing, embedding manipulation, or metadata gaming.
- **Rationale:** Relevance score manipulation ensures attacker content is preferentially retrieved. Anomalous score patterns should trigger review of affected documents.

**AA-MP-039: RAG index integrity monitoring absent**
- **Description:** The RAG index is not monitored for unauthorized changes, unexpected document additions, or bulk modifications that could indicate poisoning.
- **Rationale:** Continuous integrity monitoring detects poisoning campaigns that gradually introduce malicious content over time, below the threshold of individual detection.

**AA-MP-040: RAG poisoning detection and remediation missing**
- **Description:** No automated pipeline exists to detect RAG poisoning indicators and quarantine or remove compromised documents from the knowledge base.
- **Rationale:** Automated detection and remediation limits the dwell time of poisoned content, reducing the window where agents are influenced by malicious retrievals.

---

## 5. Vector DB Manipulation (AA-MP-041 – AA-MP-050)

**Threat:** Vector databases store embeddings used for semantic search and memory retrieval. Attackers who gain access to the vector store can manipulate embeddings, inject adversarial vectors, or alter metadata to control what information the agent retrieves and trusts.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-041 | Vector DB access not authenticated | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-MP-042 | Vector DB write access not restricted | HIGH | static | stable | langchain, crewai, openai |
| AA-MP-043 | Vector embedding integrity not verified | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-044 | Adversarial vector injection undetected | HIGH | dynamic | experimental | langchain, openai, autogen |
| AA-MP-045 | Vector DB network exposure unrestricted | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-MP-046 | Vector metadata tampering not detected | MEDIUM | static | stable | langchain, crewai, openai |
| AA-MP-047 | Vector DB backup integrity unchecked | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-MP-048 | Vector namespace isolation absent | MEDIUM | static | stable | langchain, openai, crewai |
| AA-MP-049 | Vector DB query logging absent | MEDIUM | dynamic | stable | langchain, openai, bedrock |
| AA-MP-050 | Vector DB version control missing | MEDIUM | static | stable | langchain, openai, autogen |

### Standards Mapping

- **ASI06:** Vector databases are the physical layer of agent memory
- **ISO 42001 A.10:** System security for AI data stores
- **OWASP Agentic AI Top 10 Principle 4:** Data integrity in vector storage

### Detailed Descriptions

**AA-MP-041: Vector DB access not authenticated**
- **Description:** The vector database allows unauthenticated connections, enabling any network-accessible client to read, write, or modify stored embeddings.
- **Rationale:** Unauthenticated vector DB access is equivalent to giving attackers direct write access to agent memory. All connections must require authentication.

**AA-MP-042: Vector DB write access not restricted**
- **Description:** Write access to the vector database is not restricted by role, limiting which collections or namespaces different components can modify.
- **Rationale:** Least-privilege write access prevents compromised components from poisoning vector collections they shouldn't modify.

**AA-MP-043: Vector embedding integrity not verified**
- **Description:** Stored embeddings lack integrity verification to detect corruption, tampering, or replacement with adversarial vectors.
- **Rationale:** Tampered embeddings alter retrieval behavior without changing the associated text content, making the attack invisible at the document level.

**AA-MP-044: Adversarial vector injection undetected**
- **Description:** Embeddings that are statistically anomalous (adversarially crafted to be retrieved for specific queries) are not detected during write operations.
- **Rationale:** Adversarial vectors are designed to hijack retrieval for targeted queries. Statistical analysis during write can flag vectors with suspicious proximity to common query patterns.

**AA-MP-045: Vector DB network exposure unrestricted**
- **Description:** The vector database is accessible from untrusted networks without firewall rules, VPC isolation, or network-level access controls.
- **Rationale:** Network exposure increases the attack surface for direct manipulation. Vector databases should be isolated to the agent's network segment with strict ingress rules.

**AA-MP-046: Vector metadata tampering not detected**
- **Description:** Metadata associated with vectors (source, timestamp, trust level, access control tags) can be modified without detection.
- **Rationale:** Metadata tampering can elevate the trust level of adversarial content or modify access control tags to make poisoned vectors accessible to more agents.

**AA-MP-047: Vector DB backup integrity unchecked**
- **Description:** Vector database backups are not integrity-verified, allowing corrupted or tampered backups to be restored into production.
- **Rationale:** Compromised backups enable persistent poisoning that survives incident response. Backup integrity must be verified before restoration.

**AA-MP-048: Vector namespace isolation absent**
- **Description:** Different agents, users, or tenants share the same vector namespace without isolation, enabling cross-boundary data access and poisoning.
- **Rationale:** Namespace isolation prevents one tenant's data from being retrieved by or contaminating another's, enforcing memory boundaries between agents.

**AA-MP-049: Vector DB query logging absent**
- **Description:** Queries to the vector database are not logged, preventing detection of reconnaissance, data exfiltration, or anomalous access patterns.
- **Rationale:** Query logging enables detection of adversarial probing, unusual retrieval patterns, and forensic analysis of memory-related incidents.

**AA-MP-050: Vector DB version control missing**
- **Description:** Changes to the vector database (inserts, updates, deletes) are not versioned, preventing rollback to known-good states after poisoning.
- **Rationale:** Version control enables point-in-time recovery and change tracking, critical capabilities for responding to vector manipulation incidents.

---

## 6. Memory Persistence Attacks (AA-MP-051 – AA-MP-060)

**Threat:** Persistent memory stores (databases, files, caches) maintain agent state across sessions. Attackers target persistence mechanisms to create long-lived backdoors, plant false memories that survive restarts, or exfiltrate accumulated knowledge.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-051 | Persistent memory not encrypted at rest | CRITICAL | static | stable | langchain, openai, crewai |
| AA-MP-052 | Memory persistence credentials exposed | CRITICAL | static | stable | langchain, crewai, autogen |
| AA-MP-053 | Memory store access logging absent | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-054 | No memory TTL enforcement | HIGH | static | stable | langchain, crewai, openai |
| AA-MP-055 | Cross-restart memory integrity unverified | HIGH | static | stable | langchain, openai, autogen |
| AA-MP-056 | Memory export functionality unprotected | MEDIUM | static | stable | langchain, crewai, openai |
| AA-MP-057 | Memory cleanup on session end incomplete | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-MP-058 | Persistent memory size not bounded | MEDIUM | static | stable | langchain, crewai, autogen |
| AA-MP-059 | Memory storage redundancy absent | MEDIUM | static | stable | langchain, openai, bedrock |
| AA-MP-060 | No memory garbage collection for stale entries | MEDIUM | both | stable | langchain, crewai, openai |

### Standards Mapping

- **ASI06:** Persistent memory is a long-lived attack surface
- **ISO 42001 A.8:** Data management for persistent AI memory
- **NIST AI RMF MANAGE-3.2:** Memory data lifecycle management

### Detailed Descriptions

**AA-MP-051: Persistent memory not encrypted at rest**
- **Description:** Agent memory stored in databases, files, or cache systems is not encrypted, exposing conversation history, decisions, and context to storage-level access.
- **Rationale:** Unencrypted persistent memory exposes all accumulated agent knowledge. Encryption at rest protects against storage compromise, unauthorized access, and data breach.

**AA-MP-052: Memory persistence credentials exposed**
- **Description:** Credentials for accessing memory stores (database passwords, API keys, connection strings) are hardcoded, stored in plaintext, or logged.
- **Rationale:** Exposed memory credentials grant full access to agent state. Credential management must use secret management systems with rotation and access auditing.

**AA-MP-053: Memory store access logging absent**
- **Description:** Read and write operations to persistent memory stores are not logged with timestamps, source identifiers, and operation details.
- **Rationale:** Access logging enables detection of unauthorized memory access, anomalous read patterns (data exfiltration), and forensic investigation of memory tampering.

**AA-MP-054: No memory TTL enforcement**
- **Description:** Memory entries persist indefinitely without time-to-live (TTL) policies, accumulating stale and potentially compromised data over time.
- **Rationale:** TTL enforcement limits the lifespan of memory entries, reducing the window of exposure for poisoned memories and ensuring data freshness.

**AA-MP-055: Cross-restart memory integrity unverified**
- **Description:** After agent restarts, persisted memory is loaded without integrity verification, allowing offline tampering to affect the restarted agent.
- **Rationale:** Restart is a vulnerable moment when tampered persistent memory can be loaded. Post-restart integrity checks detect offline manipulation.

**AA-MP-056: Memory export functionality unprotected**
- **Description:** Agent memory can be exported (backed up, transferred, or dumped) without authorization checks, enabling bulk data exfiltration.
- **Rationale:** Memory export provides a single operation to extract all accumulated knowledge. Export must require elevated authorization and produce audit logs.

**AA-MP-057: Memory cleanup on session end incomplete**
- **Description:** When sessions end, temporary memory (scratchpads, intermediate results, tool outputs) is not fully cleaned up, leaving sensitive residual data.
- **Rationale:** Incomplete cleanup leaves sensitive data accessible to subsequent sessions or attackers. Session teardown must clear all temporary memory stores.

**AA-MP-058: Persistent memory size not bounded**
- **Description:** No size limits exist for persistent memory stores, allowing unbounded growth that can exhaust storage and create denial-of-service conditions.
- **Rationale:** Bounded memory prevents storage exhaustion attacks and encourages garbage collection of stale entries, reducing the surface for memory poisoning.

**AA-MP-059: Memory storage redundancy absent**
- **Description:** Persistent memory relies on a single storage backend without replication or redundancy, creating a single point of failure.
- **Rationale:** Storage redundancy ensures memory availability during infrastructure failures and enables integrity verification through cross-replica comparison.

**AA-MP-060: No memory garbage collection for stale entries**
- **Description:** Old, unused, or low-relevance memory entries are never garbage collected, accumulating noise that can include poisoned content.
- **Rationale:** Garbage collection reduces the attack surface by removing stale entries that may have been poisoned and reduces storage costs and retrieval noise.

---

## 7. Context Overflow (AA-MP-061 – AA-MP-070)

**Threat:** Context overflow attacks deliberately exceed the model's context window capacity, causing truncation of safety instructions, loss of critical context, or forced summarization that strips security-relevant details.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-061 | Token budget allocation not implemented | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-MP-062 | System prompt immune zone not enforced | CRITICAL | static | stable | langchain, openai, bedrock |
| AA-MP-063 | Tool output size not bounded | HIGH | static | stable | langchain, crewai, mcp |
| AA-MP-064 | Multi-document retrieval overflow possible | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-065 | Context compression security not evaluated | HIGH | dynamic | experimental | langchain, openai, vercel-ai |
| AA-MP-066 | Recursive tool call context growth unbounded | MEDIUM | dynamic | stable | langchain, crewai, mcp |
| AA-MP-067 | Image/multimodal token consumption not tracked | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-MP-068 | Context fragmentation efficiency degradation | MEDIUM | dynamic | experimental | langchain, openai, autogen |
| AA-MP-069 | Forced summarization loses security context | MEDIUM | dynamic | stable | langchain, openai, vercel-ai |
| AA-MP-070 | Context overflow recovery plan absent | MEDIUM | both | stable | langchain, openai, crewai |

### Standards Mapping

- **ASI06:** Context overflow is a resource-based memory attack
- **OWASP Agentic AI Top 10 Principle 5:** Context state management and protection
- **NIST AI RMF MEASURE-2.6:** Monitoring context integrity

### Detailed Descriptions

**AA-MP-061: Token budget allocation not implemented**
- **Description:** The agent does not allocate token budgets across context components (system prompt, history, retrieval, tool outputs, user input), allowing any single component to consume the entire window.
- **Rationale:** Token budgets ensure each context component gets its required allocation. Without budgets, large tool outputs or history can crowd out safety instructions.

**AA-MP-062: System prompt immune zone not enforced**
- **Description:** No mechanism reserves a guaranteed portion of the context window for the system prompt, allowing it to be displaced by other content.
- **Rationale:** The system prompt defines the agent's safety behavior. An immune zone ensures it is always included regardless of other context pressure.

**AA-MP-063: Tool output size not bounded**
- **Description:** Tool call results can return arbitrary amounts of data without truncation, potentially consuming the majority of available context.
- **Rationale:** Unbounded tool outputs enable context flooding through a single tool call. Output size limits prevent tools from monopolizing the context window.

**AA-MP-064: Multi-document retrieval overflow possible**
- **Description:** RAG retrieval can return multiple large documents whose combined size exceeds the available context budget, forcing truncation of other content.
- **Rationale:** Retrieval count and size limits prevent RAG from overwhelming the context. Total retrieval size must fit within the allocated retrieval budget.

**AA-MP-065: Context compression security not evaluated**
- **Description:** Context compression techniques (summarization, pruning) have not been evaluated for their impact on security-relevant information preservation.
- **Rationale:** Compression may strip security-relevant details (permission restrictions, safety caveats) while preserving general content, silently degrading safety.

**AA-MP-066: Recursive tool call context growth unbounded**
- **Description:** Recursive or chained tool calls accumulate context without bounds, as each call's output becomes input for the next, growing exponentially.
- **Rationale:** Recursive tool chains can exhaust context budgets rapidly. Chain depth limits and cumulative output budgets prevent runaway context growth.

**AA-MP-067: Image/multimodal token consumption not tracked**
- **Description:** Multimodal inputs (images, audio) consume significant context tokens that are not tracked separately from text content.
- **Rationale:** A single high-resolution image can consume thousands of tokens. Multimodal content must be tracked against the overall context budget.

**AA-MP-068: Context fragmentation efficiency degradation**
- **Description:** Repeated additions and removals from the context create fragmentation that reduces effective capacity and retrieval quality.
- **Rationale:** Context fragmentation degrades agent performance over long sessions. Periodic defragmentation or context reconstruction maintains efficiency.

**AA-MP-069: Forced summarization loses security context**
- **Description:** When context is summarized to create space, security-relevant information (active permissions, pending validations, safety constraints) is lost in the summary.
- **Rationale:** Summarization must be security-aware, explicitly preserving safety constraints, active permissions, and pending security validations.

**AA-MP-070: Context overflow recovery plan absent**
- **Description:** No defined recovery procedure exists for context overflow events, leaving the agent in a degraded state with unknown security properties.
- **Rationale:** Recovery plans ensure the agent can resume safe operation after overflow by reconstructing critical context from persisted state.

---

## 8. State Deserialization (AA-MP-071 – AA-MP-080)

**Threat:** Agent state stored as serialized objects (JSON, pickle, protobuf) can be exploited through deserialization attacks that execute arbitrary code, inject crafted state, or bypass type validation when state is restored.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-071 | Unsafe deserialization of agent state | CRITICAL | static | stable | langchain, autogen, crewai |
| AA-MP-072 | Serialized state integrity not verified | CRITICAL | static | stable | langchain, openai, autogen |
| AA-MP-073 | Pickle used for state serialization | HIGH | static | stable | langchain, autogen |
| AA-MP-074 | Deserialized state type validation absent | HIGH | static | stable | langchain, crewai, openai |
| AA-MP-075 | State schema migration not secured | HIGH | static | stable | langchain, autogen, openai |
| AA-MP-076 | Serialized state contains executable code | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-MP-077 | State versioning absent | MEDIUM | static | stable | langchain, openai, autogen |
| AA-MP-078 | State size validation not performed | MEDIUM | static | stable | langchain, crewai, openai |
| AA-MP-079 | Nested object depth in state unbounded | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-MP-080 | State deserialization errors not handled securely | MEDIUM | static | stable | langchain, openai, autogen |

### Standards Mapping

- **ASI06:** State deserialization is a code execution vector through memory
- **ISO 42001 A.10:** System security for AI state management
- **NIST AI RMF MAP-2.3:** State data integrity and security

### Detailed Descriptions

**AA-MP-071: Unsafe deserialization of agent state**
- **Description:** Agent state is deserialized using unsafe methods that allow arbitrary code execution, object instantiation, or type coercion.
- **Rationale:** Unsafe deserialization is a critical vulnerability class. Crafted state payloads can achieve remote code execution during state restoration.

**AA-MP-072: Serialized state integrity not verified**
- **Description:** Serialized agent state lacks integrity protection (HMAC, digital signature) to detect tampering before deserialization.
- **Rationale:** Integrity verification before deserialization prevents processing of tampered state. Without it, modified state payloads are blindly deserialized.

**AA-MP-073: Pickle used for state serialization**
- **Description:** Python pickle is used to serialize or deserialize agent state, enabling arbitrary code execution through crafted pickle objects.
- **Rationale:** Pickle is fundamentally unsafe for untrusted data. Agent state should use safe formats (JSON, protobuf) with explicit schema validation.

**AA-MP-074: Deserialized state type validation absent**
- **Description:** Deserialized state objects are used without validating that their types, field names, and value ranges match the expected state schema.
- **Rationale:** Type validation catches state injection where attackers add unexpected fields, change types, or embed payloads in legitimate-looking state.

**AA-MP-075: State schema migration not secured**
- **Description:** State schema migrations (version upgrades, field additions) do not validate that the migration produces a valid, secure state from the old format.
- **Rationale:** Schema migration is a moment when type validation is relaxed. Attackers can craft state that exploits migration logic to inject invalid state.

**AA-MP-076: Serialized state contains executable code**
- **Description:** Serialized state objects contain references to functions, lambdas, or code objects that execute during or after deserialization.
- **Rationale:** Executable code in state creates a deserialization attack surface. State should contain only data, never executable references.

**AA-MP-077: State versioning absent**
- **Description:** Serialized state does not include version markers, making it impossible to detect outdated or incompatible state formats.
- **Rationale:** Version markers enable safe rejection of incompatible state rather than attempting deserialization that might produce corrupted or insecure results.

**AA-MP-078: State size validation not performed**
- **Description:** Serialized state payloads are processed without size validation, allowing oversized payloads that exhaust memory during deserialization.
- **Rationale:** Size validation prevents denial-of-service through memory exhaustion. State payloads exceeding reasonable limits should be rejected.

**AA-MP-079: Nested object depth in state unbounded**
- **Description:** Deserialization does not limit nesting depth, allowing deeply nested objects that cause stack overflow or performance degradation.
- **Rationale:** Deep nesting is a common deserialization attack vector. Bounded nesting depth prevents stack exhaustion and ensures predictable performance.

**AA-MP-080: State deserialization errors not handled securely**
- **Description:** Deserialization failures are handled by falling back to default state or logging detailed error messages that leak internal structure.
- **Rationale:** Deserialization errors must fail securely without exposing internal details. Error messages should be generic; state should not fall back to insecure defaults.

---

## 9. Cross-Session Contamination (AA-MP-081 – AA-MP-090)

**Threat:** Insufficient isolation between agent sessions allows information, context, or manipulated state to leak from one session to another, enabling cross-user attacks, privilege escalation, and persistent compromise.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-081 | Session memory isolation not enforced | CRITICAL | static | stable | langchain, openai, vercel-ai |
| AA-MP-082 | Shared memory pool between sessions | CRITICAL | static | stable | langchain, crewai, autogen |
| AA-MP-083 | Session ID predictability enables session hijacking | HIGH | static | stable | langchain, openai, vercel-ai |
| AA-MP-084 | Global state mutation from user sessions | HIGH | static | stable | langchain, autogen, crewai |
| AA-MP-085 | Cache key collision between sessions | HIGH | static | stable | langchain, openai, bedrock |
| AA-MP-086 | Thread-local storage not used for session state | MEDIUM | static | stable | langchain, openai, vercel-ai |
| AA-MP-087 | Session cleanup verification absent | MEDIUM | dynamic | stable | langchain, crewai, openai |
| AA-MP-088 | Temporary files shared between sessions | MEDIUM | static | stable | langchain, autogen, crewai |
| AA-MP-089 | Environment variable leakage between sessions | MEDIUM | static | stable | langchain, openai, autogen |
| AA-MP-090 | Session metrics aggregation leaks individual data | MEDIUM | dynamic | stable | langchain, openai, bedrock |

### Standards Mapping

- **ASI06:** Cross-session contamination is a critical isolation failure
- **ISO 42001 A.10:** System security for multi-tenant AI systems
- **OWASP Agentic AI Top 10 Principle 5:** State isolation between agent sessions

### Detailed Descriptions

**AA-MP-081: Session memory isolation not enforced**
- **Description:** Different user sessions share memory space without enforcement of read/write isolation between session contexts.
- **Rationale:** Session isolation is fundamental to multi-user agent security. Without it, one user's data, context, and instructions can influence another's session.

**AA-MP-082: Shared memory pool between sessions**
- **Description:** A shared memory pool (cache, scratchpad, or working memory) is accessible from multiple concurrent sessions without partition.
- **Rationale:** Shared memory enables cross-session data leakage and poisoning. Each session must have its own isolated memory partition.

**AA-MP-083: Session ID predictability enables session hijacking**
- **Description:** Session identifiers are generated using predictable patterns (sequential, time-based) that allow attackers to guess valid session IDs.
- **Rationale:** Predictable session IDs enable session hijacking, giving attackers access to another user's conversation context and memory.

**AA-MP-084: Global state mutation from user sessions**
- **Description:** User sessions can modify global agent state (configuration, shared tools, common memory) that affects all other sessions.
- **Rationale:** Global state mutation from user sessions enables one user to affect all users. Only administrative sessions should modify global state.

**AA-MP-085: Cache key collision between sessions**
- **Description:** Cache keys are constructed without session-scoping, allowing cache entries from one session to be read by or overwrite entries from another.
- **Rationale:** Cache key collisions enable both data leakage (reading another session's cached data) and cache poisoning (overwriting another session's cache).

**AA-MP-086: Thread-local storage not used for session state**
- **Description:** Session-specific state is stored in shared (global or static) variables rather than thread-local or request-scoped storage.
- **Rationale:** Thread-local storage prevents concurrent request handling from mixing session states, a critical requirement for multi-user agent deployments.

**AA-MP-087: Session cleanup verification absent**
- **Description:** After session teardown, there is no verification that all session-specific memory has been fully released and is inaccessible.
- **Rationale:** Verification ensures cleanup is complete. Residual session data can be accessed by subsequent sessions assigned the same resources.

**AA-MP-088: Temporary files shared between sessions**
- **Description:** Temporary files created during agent operation use shared directories without session-specific prefixes, enabling cross-session access.
- **Rationale:** Session-scoped temporary directories prevent one session from reading, modifying, or deleting another session's temporary data.

**AA-MP-089: Environment variable leakage between sessions**
- **Description:** Environment variables set during one session persist and are visible to subsequent sessions, leaking configuration or credentials.
- **Rationale:** Environment variables can contain session-specific credentials or configuration. Session isolation must extend to environment state.

**AA-MP-090: Session metrics aggregation leaks individual data**
- **Description:** Metrics collected across sessions are aggregated in ways that allow inference of individual session content or behavior.
- **Rationale:** Metrics aggregation must be designed to prevent individual session reconstruction. Differential privacy or k-anonymity thresholds should apply.

---

## 10. Framework-Specific Memory Checks (AA-MP-091 – AA-MP-100)

**Threat:** Each AI agent framework implements memory and context management differently, with framework-specific patterns that create unique vulnerabilities. These controls address memory security issues specific to individual frameworks' implementations.

| ID | Control Name | Severity | Mode | Tier | Frameworks |
|----|-------------|----------|------|------|------------|
| AA-MP-091 | LangChain ConversationBufferMemory unbounded | HIGH | static | stable | langchain |
| AA-MP-092 | LangChain memory serialization via pickle | HIGH | static | stable | langchain |
| AA-MP-093 | CrewAI shared crew memory not isolated per agent | HIGH | static | stable | crewai |
| AA-MP-094 | CrewAI delegation context leakage | MEDIUM | static | stable | crewai |
| AA-MP-095 | OpenAI Assistants thread retrieval not scoped | HIGH | static | stable | openai |
| AA-MP-096 | OpenAI file_search results not filtered | MEDIUM | static | stable | openai |
| AA-MP-097 | AutoGen GroupChat message history shared | HIGH | static | stable | autogen |
| AA-MP-098 | AutoGen agent state checkpoint not integrity-verified | MEDIUM | static | stable | autogen |
| AA-MP-099 | Vercel AI SDK streaming context not bounded | MEDIUM | static | stable | vercel-ai |
| AA-MP-100 | Bedrock agent session attributes not encrypted | MEDIUM | static | stable | bedrock |

### Standards Mapping

- **ASI06:** Framework-specific implementation risks require targeted controls
- **NIST AI RMF MAP-2.3:** Framework-specific data handling assessment
- **ISO 42001 A.10:** Framework security configuration for AI systems

### Detailed Descriptions

**AA-MP-091: LangChain ConversationBufferMemory unbounded**
- **Description:** LangChain's ConversationBufferMemory stores all conversation turns without size limits, enabling context overflow through extended conversation.
- **Rationale:** Unbounded buffer memory grows linearly with conversation length. Use ConversationSummaryBufferMemory or ConversationTokenBufferMemory with explicit limits.

**AA-MP-092: LangChain memory serialization via pickle**
- **Description:** LangChain memory components use pickle serialization for persistence, enabling arbitrary code execution through crafted memory state.
- **Rationale:** LangChain's pickle-based serialization is a known security risk. Use JSON-based serialization or configure safe deserialization settings.

**AA-MP-093: CrewAI shared crew memory not isolated per agent**
- **Description:** CrewAI crew memory is shared across all agents in the crew without per-agent isolation, allowing one agent's context to influence others.
- **Rationale:** Shared crew memory enables a compromised agent to poison memory used by all other crew members. Per-agent memory scoping limits blast radius.

**AA-MP-094: CrewAI delegation context leakage**
- **Description:** When CrewAI agents delegate tasks, the full context including sensitive information is passed without filtering to the delegate agent.
- **Rationale:** Delegation context should be filtered to include only task-relevant information, preventing leakage of sensitive data across agent boundaries.

**AA-MP-095: OpenAI Assistants thread retrieval not scoped**
- **Description:** OpenAI Assistants API thread retrieval returns all messages without scoping by user, role, or time range, potentially exposing cross-user data.
- **Rationale:** Thread retrieval must enforce access controls to prevent unauthorized access to conversation history across users or organizations.

**AA-MP-096: OpenAI file_search results not filtered**
- **Description:** OpenAI's file_search tool returns results from the knowledge base without post-retrieval filtering for instruction injection or sensitive content.
- **Rationale:** file_search results enter the assistant's context directly. Without filtering, poisoned knowledge base content becomes trusted context.

**AA-MP-097: AutoGen GroupChat message history shared**
- **Description:** AutoGen GroupChat maintains a shared message history visible to all participating agents, including potentially untrusted or compromised agents.
- **Rationale:** Shared message history in multi-agent conversations enables a compromised agent to inject messages that influence all other participants.

**AA-MP-098: AutoGen agent state checkpoint not integrity-verified**
- **Description:** AutoGen agent state checkpoints are loaded without integrity verification, allowing tampered checkpoints to restore malicious state.
- **Rationale:** State checkpoints are a persistence mechanism. Without integrity verification, offline tampering can inject malicious state into future sessions.

**AA-MP-099: Vercel AI SDK streaming context not bounded**
- **Description:** Vercel AI SDK streaming responses accumulate context without bounds, as partial results are concatenated into the context without size management.
- **Rationale:** Streaming context accumulation can exhaust the context window during long streaming responses. Explicit budgets must manage streaming context.

**AA-MP-100: Bedrock agent session attributes not encrypted**
- **Description:** Amazon Bedrock agent session attributes (key-value pairs persisted across turns) are stored without encryption, exposing session state.
- **Rationale:** Session attributes may contain sensitive context, user preferences, or security state. At-rest encryption prevents exposure through storage-level access.
