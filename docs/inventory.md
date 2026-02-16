# AI Asset Inventory

The `g0 inventory` command discovers and documents all AI components in your codebase, producing an AI Bill of Materials (AI-BOM).

## What It Discovers

| Component | Examples |
|-----------|---------|
| **AI Frameworks** | LangChain, CrewAI, OpenAI SDK, Vercel AI, Bedrock, AutoGen, LangChain4j, Spring AI, Go AI libs |
| **Models** | GPT-4, Claude, Gemini, Llama, Mistral — provider, name, and parameters |
| **Agents** | Agent definitions with roles, tools, and prompts |
| **Tools** | Tool bindings, function schemas, capabilities |
| **MCP Servers** | Model Context Protocol server configurations |
| **Vector Databases** | Pinecone, Weaviate, Chroma, Qdrant, pgvector connections |
| **Prompts** | System prompts, user templates, few-shot examples |

## Basic Usage

```bash
# Terminal output (default)
g0 inventory .

# Scan a remote repository
g0 inventory https://github.com/org/repo
```

## Output Formats

### Terminal (Default)

```bash
g0 inventory .
```

Displays a structured summary:

```
  AI Agent Inventory
  ──────────────────

  Frameworks (2)
    langchain    v0.2.0    Python
    openai       v1.12.0   Python

  Models (2)
    gpt-4o         OpenAI      temperature=0.7
    claude-3-opus  Anthropic   temperature=0

  Agents (3)
    ResearchBot    langchain   tools=3  model=gpt-4o
    WriterBot      langchain   tools=1  model=gpt-4o
    ReviewBot      openai      tools=2  model=claude-3-opus

  Tools (5)
    web_search     ResearchBot   capabilities: network
    file_read      ResearchBot   capabilities: filesystem
    ...
```

### JSON

```bash
g0 inventory . --json
g0 inventory . --json -o inventory.json
```

### Markdown

```bash
g0 inventory . --markdown
g0 inventory . --markdown -o inventory.md
```

### CycloneDX 1.6 SBOM

```bash
g0 inventory . --cyclonedx
g0 inventory . --cyclonedx inventory.cdx.json
```

Produces a CycloneDX 1.6 BOM with AI-specific component types. Compatible with OWASP Dependency-Track, Sonatype, and other SBOM tools.

## Diffing Against Baselines

Track changes to your AI inventory over time:

```bash
# Save a baseline
g0 inventory . --json -o baseline.json

# Later, diff against it
g0 inventory . --diff baseline.json
```

The diff shows:
- **Added** — New AI components since baseline
- **Removed** — Components no longer present
- **Changed** — Modified configurations (model versions, tool lists, etc.)

This is useful for:
- Detecting unauthorized model changes in CI
- Tracking AI component drift across releases
- Compliance auditing — documenting what changed and when

## Using Inventory for Compliance

### EU AI Act

The EU AI Act requires organizations to maintain documentation of AI system components. The AI-BOM provides:
- Complete list of AI models in use
- Framework and version information
- Tool capabilities and permissions

### ISO 42001

ISO 42001 (AI Management Systems) requires an AI asset inventory. Generate one:

```bash
g0 inventory . --cyclonedx ai-inventory.cdx.json
```

### NIST AI RMF

NIST AI RMF MAP function requires understanding of AI system composition:

```bash
g0 inventory . --markdown -o ai-components.md
```

## Uploading to Guard0 Cloud

```bash
g0 inventory . --upload
```

Guard0 Cloud provides:
- Visual component graph
- Historical inventory tracking
- Change notifications
- Integration with scan results for contextual risk

## Example: "What AI Components Are in My Codebase?"

```bash
$ g0 inventory ./my-project

  AI Agent Inventory
  ──────────────────

  Frameworks (3)
    langchain    v0.2.0    Python
    crewai       v0.28.0   Python
    mcp          -         Config

  Models (2)
    gpt-4o         OpenAI      temperature=0.7
    text-embedding-3-small  OpenAI

  Agents (4)
    Researcher     crewai    tools=3  model=gpt-4o
    Writer         crewai    tools=1  model=gpt-4o
    Reviewer       crewai    tools=2  model=gpt-4o
    Orchestrator   crewai    tools=0  model=gpt-4o  delegation=true

  Tools (6)
    web_search     Researcher    capabilities: network
    file_read      Researcher    capabilities: filesystem
    file_write     Writer        capabilities: filesystem, write
    code_exec      Writer        capabilities: code-execution
    lint_check     Reviewer      capabilities: filesystem
    publish        Reviewer      capabilities: network, write

  MCP Servers (2)
    filesystem     stdio    tools=5
    github         stdio    tools=12

  Vector DBs (1)
    pinecone       Researcher    index=knowledge-base

  Summary: 3 frameworks, 2 models, 4 agents, 6 tools, 2 MCP servers, 1 vector DB
```

## Programmatic API

```typescript
import { runDiscovery, runGraphBuild } from '@guard0/g0';

const discovery = await runDiscovery({ targetPath: './my-project' });
const graph = await runGraphBuild(discovery);

console.log(graph.agents);     // AgentNode[]
console.log(graph.tools);      // ToolNode[]
console.log(graph.models);     // ModelNode[]
console.log(graph.vectorDBs);  // VectorDBNode[]
```
