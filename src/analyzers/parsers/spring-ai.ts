import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';

const AGENT_PATTERNS = [
  { pattern: /ChatClient\s*\.\s*builder\s*\(/g, name: 'ChatClient' },
  { pattern: /ChatClient\s*\.\s*create\s*\(/g, name: 'ChatClient' },
  { pattern: /new\s+Advisor\s*\(/g, name: 'Advisor' },
];

const TOOL_PATTERNS = [
  { pattern: /FunctionCallback\s*\.\s*builder\s*\(/g, type: 'builder' },
  { pattern: /FunctionCallbackWrapper\s*\.\s*builder\s*\(/g, type: 'builder' },
  { pattern: /@Description\s*\(/g, type: 'annotation' },
];

const MODEL_CONSTRUCTORS: Record<string, string> = {
  OpenAiChatModel: 'openai',
  AzureOpenAiChatModel: 'azure-openai',
  AnthropicChatModel: 'anthropic',
  VertexAiGeminiChatModel: 'google',
  OllamaChatModel: 'ollama',
  BedrockAnthropicChatModel: 'aws-bedrock',
  MistralAiChatModel: 'mistral',
};

export function parseSpringAI(graph: AgentGraph, files: FileInventory): void {
  for (const file of files.java) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('springframework.ai') && !content.includes('ChatClient') &&
        !content.includes('ChatModel') && !content.includes('FunctionCallback')) continue;

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

      graph.models.push({
        id: `spring-ai-model-${graph.models.length}`,
        name: constructor,
        provider,
        framework: 'spring-ai',
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
        id: `spring-ai-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || name,
        framework: 'spring-ai',
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
      const region = content.substring(match.index, match.index + 500);

      let toolName = extractAssignmentName(lines, line) || `tool_${line}`;
      if (type === 'builder') {
        const nameMatch = region.match(/\.name\s*\(\s*"([^"]+)"\s*\)/);
        if (nameMatch) toolName = nameMatch[1];
      }

      const capabilities = detectCapabilities(region);

      graph.tools.push({
        id: `spring-ai-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'spring-ai',
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
  // PromptTemplate / SystemPromptTemplate
  const templatePattern = /(?:System)?PromptTemplate\s*\(\s*"([\s\S]*?)"\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = templatePattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    graph.prompts.push({
      id: `spring-ai-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: match[1],
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: /\{/.test(match[1]),
      scopeClarity: match[1].length > 50 ? 'vague' : 'missing',
    });
  }

  // .system("...")
  const systemCallPattern = /\.system\s*\(\s*"([\s\S]*?)"\s*\)/g;
  while ((match = systemCallPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    graph.prompts.push({
      id: `spring-ai-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: match[1],
      hasInstructionGuarding: false,
      hasSecrets: false,
      hasUserInputInterpolation: /\{/.test(match[1]),
      scopeClarity: match[1].length > 50 ? 'vague' : 'missing',
    });
  }
}

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  const match = line.match(/(?:var|final)?\s*\w+(?:<[^>]+>)?\s+(\w+)\s*=/);
  return match?.[1];
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  const caps: ToolNode['capabilities'] = [];
  if (/Runtime\.getRuntime\(\)\.exec|ProcessBuilder/.test(body)) caps.push('shell');
  if (/FileOutputStream|FileWriter|Files\.write|Files\.read/.test(body)) caps.push('filesystem');
  if (/HttpClient|RestTemplate|WebClient/.test(body)) caps.push('network');
  if (/JdbcTemplate|PreparedStatement|EntityManager/.test(body)) caps.push('database');
  return caps;
}
