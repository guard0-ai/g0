import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';

const AGENT_PATTERNS = [
  { pattern: /AiServices\s*\.\s*builder\s*\(/g, name: 'AiServices' },
  { pattern: /AiServices\s*\.\s*create\s*\(/g, name: 'AiServices' },
  { pattern: /StateGraph\s*\.\s*builder\s*\(/g, name: 'LangGraph4jAgent' },
  { pattern: /ConversationalRetrievalChain/g, name: 'RetrievalChain' },
];

const TOOL_PATTERNS = [
  { pattern: /@Tool\b/g, type: 'decorator' },
  { pattern: /ToolSpecification\s*\.\s*builder\s*\(/g, type: 'constructor' },
];

const MODEL_CONSTRUCTORS: Record<string, string> = {
  OpenAiChatModel: 'openai',
  AzureOpenAiChatModel: 'azure-openai',
  AnthropicChatModel: 'anthropic',
  GoogleAiGeminiChatModel: 'google',
  VertexAiGeminiChatModel: 'google',
  OllamaChatModel: 'ollama',
  BedrockChatModel: 'aws-bedrock',
  MistralAiChatModel: 'mistral',
  HuggingFaceChatModel: 'huggingface',
};

export function parseLangChain4j(graph: AgentGraph, files: FileInventory): void {
  for (const file of files.java) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('langchain4j') && !content.includes('langgraph4j') &&
        !content.includes('AiServices') && !content.includes('@Tool')) continue;

    const lines = content.split('\n');

    extractModels(content, file.relativePath, graph);
    extractAgents(content, lines, file.relativePath, graph);
    extractTools(content, lines, file.relativePath, graph);
    extractPrompts(content, file.relativePath, lines, graph);
  }
}

function extractModels(content: string, filePath: string, graph: AgentGraph): void {
  for (const [constructor, provider] of Object.entries(MODEL_CONSTRUCTORS)) {
    const pattern = new RegExp(`${constructor}\\s*\\.\\s*builder\\s*\\(|new\\s+${constructor}\\s*\\(`, 'g');
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 500);
      const modelMatch = region.match(/(?:modelName|model)\s*\(\s*"([^"]+)"\)/);

      graph.models.push({
        id: `langchain4j-model-${graph.models.length}`,
        name: modelMatch?.[1] ?? constructor,
        provider,
        framework: 'langchain4j',
        file: filePath,
        line,
      });
    }
  }
}

function extractAgents(content: string, lines: string[], filePath: string, graph: AgentGraph): void {
  for (const { pattern, name } of AGENT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;

      const agentNode: AgentNode = {
        id: `langchain4j-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || name,
        framework: 'langchain4j',
        file: filePath,
        line,
        tools: [],
      };

      graph.agents.push(agentNode);
    }
  }
}

function extractTools(content: string, lines: string[], filePath: string, graph: AgentGraph): void {
  for (const { pattern, type } of TOOL_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      let toolName: string;

      if (type === 'decorator') {
        // @Tool annotates a method — get the method name from next non-annotation line
        const nextLines = lines.slice(line - 1, line + 3);
        const methodMatch = nextLines.join('\n').match(/(?:public|private|protected)?\s*\w+\s+(\w+)\s*\(/);
        toolName = methodMatch?.[1] ?? `tool_${line}`;
      } else {
        toolName = extractAssignmentName(lines, line) || `tool_${line}`;
      }

      // Detect capabilities from surrounding code
      const region = content.substring(Math.max(0, match.index - 100), Math.min(content.length, match.index + 500));
      const capabilities = detectCapabilities(region);

      graph.tools.push({
        id: `langchain4j-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'langchain4j',
        file: filePath,
        line,
        description: '',
        parameters: [],
        hasSideEffects: capabilities.length > 0 && !capabilities.every(c => c === 'other'),
        hasInputValidation: false,
        hasSandboxing: false,
        capabilities: capabilities.length > 0 ? capabilities : ['other'],
      });
    }
  }
}

function extractPrompts(content: string, filePath: string, lines: string[], graph: AgentGraph): void {
  // @SystemMessage("...")
  const systemMsgPattern = /@SystemMessage\s*\(\s*"([\s\S]*?)"\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = systemMsgPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    graph.prompts.push({
      id: `langchain4j-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: match[1],
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: match[1].includes('{{'),
      scopeClarity: match[1].length > 50 ? 'vague' : 'missing',
    });
  }

  // @UserMessage("...")
  const userMsgPattern = /@UserMessage\s*\(\s*"([\s\S]*?)"\s*\)/g;
  while ((match = userMsgPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    graph.prompts.push({
      id: `langchain4j-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'user',
      content: match[1],
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: match[1].includes('{{'),
      scopeClarity: 'missing',
    });
  }

  // SystemMessage.from("...")
  const fromPattern = /SystemMessage\s*\.\s*from\s*\(\s*"([\s\S]*?)"\s*\)/g;
  while ((match = fromPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    graph.prompts.push({
      id: `langchain4j-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: match[1],
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: match[1].includes('{{'),
      scopeClarity: match[1].length > 50 ? 'vague' : 'missing',
    });
  }
}

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  // Java: Type varName = ...
  const match = line.match(/(?:var|final)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*=/);
  return match?.[1];
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  const caps: ToolNode['capabilities'] = [];
  if (/Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process\b/.test(body)) caps.push('shell');
  if (/FileOutputStream|FileWriter|Files\.write|Files\.read|BufferedReader/.test(body)) caps.push('filesystem');
  if (/HttpClient|HttpURLConnection|RestTemplate|WebClient|OkHttp/.test(body)) caps.push('network');
  if (/JdbcTemplate|PreparedStatement|DriverManager|EntityManager/.test(body)) caps.push('database');
  if (/ScriptEngine|eval\(|Nashorn|GraalVM/.test(body)) caps.push('code-execution');
  return caps;
}
