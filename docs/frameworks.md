# Framework Guide

g0 supports 10 AI agent frameworks across 5 languages. This guide covers what g0 detects for each framework and the types of findings you can expect.

## Framework Overview

| Framework | Language(s) | Detector | Parser |
|-----------|------------|----------|--------|
| [LangChain / LangGraph](#langchain--langgraph) | Python, TypeScript | `langchain.ts` | `langchain.ts` |
| [CrewAI](#crewai) | Python | `crewai.ts` | `crewai.ts` |
| [OpenAI Agents SDK](#openai-agents-sdk) | Python, TypeScript | `openai.ts` | `openai.ts` |
| [MCP](#model-context-protocol-mcp) | Any | `mcp.ts` | `mcp.ts` |
| [Vercel AI SDK](#vercel-ai-sdk) | TypeScript | `vercel-ai.ts` | `vercel-ai.ts` |
| [Amazon Bedrock](#amazon-bedrock) | Python, TypeScript | `bedrock.ts` | `bedrock.ts` |
| [AutoGen](#autogen) | Python | `autogen.ts` | `autogen.ts` |
| [LangChain4j](#langchain4j) | Java | `langchain4j.ts` | `langchain4j.ts` |
| [Spring AI](#spring-ai) | Java | `spring-ai.ts` | `spring-ai.ts` |
| [Go AI Frameworks](#go-ai-frameworks) | Go | `golang-ai.ts` | `golang-ai.ts` |

## Detection

g0 detects frameworks by scanning:
- **Package manifests** — `requirements.txt`, `pyproject.toml`, `package.json`, `pom.xml`, `build.gradle`, `go.mod`
- **Import statements** — Framework-specific import patterns in source code
- **Configuration files** — Framework config files (e.g., MCP config, Spring config)

---

## LangChain / LangGraph

**Languages:** Python, TypeScript/JavaScript

### What g0 Detects

- Agent definitions (`create_react_agent`, `AgentExecutor`, `StateGraph`)
- Tool bindings (`@tool`, `Tool()`, `StructuredTool`)
- Prompt templates (`ChatPromptTemplate`, `SystemMessage`)
- Model configurations (`ChatOpenAI`, `ChatAnthropic`, parameters)
- Memory/retrieval (`ConversationBufferMemory`, vector store integrations)
- LangGraph state machines and node connections

### Example Code

```python
from langchain.agents import create_react_agent
from langchain_openai import ChatOpenAI
from langchain.tools import tool

@tool
def search(query: str) -> str:
    """Search the web for information."""
    return web_search(query)

llm = ChatOpenAI(model="gpt-4", temperature=0.7)
agent = create_react_agent(llm, [search], prompt)
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-GI-001 | High | Missing system prompt safety boundaries |
| AA-TS-005 | High | Tool lacks input validation |
| AA-CE-003 | Critical | Code execution tool without sandboxing |
| AA-MP-002 | Medium | Unbounded conversation memory |

---

## CrewAI

**Language:** Python

### What g0 Detects

- Crew definitions (`Crew()`)
- Agent roles (`Agent(role=..., goal=..., backstory=...)`)
- Task assignments (`Task(description=..., agent=...)`)
- Tool integrations
- Agent delegation settings
- Process types (sequential, hierarchical)

### Example Code

```python
from crewai import Agent, Task, Crew

researcher = Agent(
    role="Researcher",
    goal="Find accurate information",
    backstory="You are an expert researcher.",
    tools=[search_tool],
    allow_delegation=True
)

crew = Crew(
    agents=[researcher],
    tasks=[research_task],
    process=Process.hierarchical
)
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-IC-003 | High | Unrestricted agent delegation |
| AA-GI-010 | Medium | Agent backstory lacks safety constraints |
| AA-HO-005 | Medium | No human approval in hierarchical process |

---

## OpenAI Agents SDK

**Languages:** Python, TypeScript

### What g0 Detects

- Agent definitions (`Agent()`, `new Agent()`)
- Tool definitions and function schemas
- Guardrails configuration
- Handoff patterns (agent-to-agent)
- Runner configuration

### Example Code

```python
from agents import Agent, Runner

agent = Agent(
    name="Assistant",
    instructions="You are a helpful assistant.",
    tools=[file_search, code_interpreter],
    model="gpt-4o"
)

result = Runner.run(agent, "Analyze this data")
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-TS-008 | Critical | Code interpreter enabled without restrictions |
| AA-GI-015 | High | Agent instructions lack scope limitations |
| AA-IC-010 | Medium | Agent handoff without context filtering |

---

## Model Context Protocol (MCP)

**Language:** Any (protocol-level)

### What g0 Detects

- MCP server configurations (Claude Desktop, Cursor, custom)
- Tool definitions and descriptions
- Server transport types (stdio, SSE, HTTP)
- Tool permissions and capabilities
- Configuration file security

### Example Config

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-TS-020 | High | MCP server with filesystem write access |
| AA-SC-015 | High | Unpinned MCP server package version |
| AA-CE-010 | Critical | MCP server with shell execution capability |

See [MCP Security](mcp-security.md) for the full MCP assessment guide.

---

## Vercel AI SDK

**Language:** TypeScript

### What g0 Detects

- `generateText` / `streamText` calls
- Tool definitions (`tool()`)
- Model provider configuration
- System prompt content
- Structured output schemas

### Example Code

```typescript
import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';

const result = await generateText({
  model: openai('gpt-4o'),
  system: 'You are a helpful assistant.',
  tools: {
    weather: tool({
      description: 'Get the weather',
      parameters: z.object({ city: z.string() }),
      execute: async ({ city }) => getWeather(city),
    }),
  },
  prompt: userMessage,
});
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-GI-020 | High | System prompt injectable via user input |
| AA-TS-025 | Medium | Tool has no parameter validation schema |
| AA-DL-008 | Medium | Streaming response may leak partial data |

---

## Amazon Bedrock

**Languages:** Python, TypeScript

### What g0 Detects

- Bedrock agent definitions
- Action groups and Lambda functions
- Knowledge base configurations
- Guardrail settings
- Model invocation parameters

### Example Code

```python
import boto3

client = boto3.client('bedrock-agent')

response = client.create_agent(
    agentName='my-agent',
    foundationModel='anthropic.claude-3-sonnet',
    instruction='You are a customer service agent.'
)
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-IA-010 | High | Bedrock agent with overly broad IAM role |
| AA-TS-030 | Medium | Action group Lambda without input validation |
| AA-GI-025 | Medium | Agent instruction lacks scope constraints |

---

## AutoGen

**Language:** Python

### What g0 Detects

- `AssistantAgent`, `UserProxyAgent` definitions
- Code execution configuration
- Group chat patterns
- Agent-to-agent communication settings
- Human input mode

### Example Code

```python
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent(
    name="assistant",
    llm_config={"model": "gpt-4"},
    system_message="You help with coding tasks."
)

user_proxy = UserProxyAgent(
    name="user",
    human_input_mode="NEVER",
    code_execution_config={"work_dir": "workspace"}
)
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-CE-020 | Critical | Code execution enabled with NEVER human input |
| AA-HO-010 | High | UserProxy set to never request human input |
| AA-IC-015 | Medium | Group chat with no message filtering |

---

## LangChain4j

**Language:** Java

### What g0 Detects

- AI service interfaces (`@AiService`)
- Tool annotations (`@Tool`)
- Chat model configuration
- Memory providers
- RAG pipeline components

### Example Code

```java
@AiService
interface Assistant {
    @SystemMessage("You are a helpful assistant.")
    String chat(@UserMessage String message);
}

Assistant assistant = AiServices.builder(Assistant.class)
    .chatLanguageModel(model)
    .tools(new SearchTool())
    .chatMemoryProvider(memoryProvider)
    .build();
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-GI-030 | High | System message lacks injection defenses |
| AA-MP-010 | Medium | Unbounded chat memory provider |
| AA-TS-035 | Medium | @Tool method with no input sanitization |

---

## Spring AI

**Language:** Java

### What g0 Detects

- `ChatClient` configuration
- Function callbacks and tool bindings
- Advisor chains
- Vector store integrations
- Spring configuration properties

### Example Code

```java
@Bean
ChatClient chatClient(ChatClient.Builder builder) {
    return builder
        .defaultSystem("You are a helpful assistant.")
        .defaultFunctions("searchTool", "calculatorTool")
        .defaultAdvisors(new SafeGuardAdvisor())
        .build();
}
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-GI-035 | High | Default system prompt without safety constraints |
| AA-SC-020 | Medium | Spring AI dependency with known vulnerability |
| AA-TS-040 | Medium | Function callback with no return value filtering |

---

## Go AI Frameworks

**Language:** Go

### What g0 Detects

- LLM client initialization (various Go AI libraries)
- Tool/function definitions
- Prompt construction
- Agent patterns
- HTTP handler integrations

### Example Code

```go
client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))

resp, err := client.CreateChatCompletion(ctx,
    openai.ChatCompletionRequest{
        Model: openai.GPT4,
        Messages: []openai.ChatCompletionMessage{
            {Role: "system", Content: "You are a helpful assistant."},
            {Role: "user", Content: userInput},
        },
        Tools: tools,
    },
)
```

### Common Findings

| Rule | Severity | Description |
|------|----------|-------------|
| AA-GI-040 | High | User input concatenated into prompt |
| AA-DL-015 | Medium | API key read from environment without validation |
| AA-TS-045 | Medium | Tool function with no error handling |

---

## Framework-Specific Scanning

To scan only specific frameworks:

```bash
g0 scan . --frameworks langchain,openai
```

This filters both detection and rule evaluation to the specified frameworks.
