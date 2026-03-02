import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';
import { detectCapabilitiesGo } from './shared.js';

const AGENT_PATTERNS = [
  { pattern: /agents\.NewExecutor\s*\(/g, name: 'LangChainGoAgent' },
  { pattern: /agents\.NewOpenAIFunctionsAgent\s*\(/g, name: 'OpenAIFunctionsAgent' },
  { pattern: /agents\.NewConversationalAgent\s*\(/g, name: 'ConversationalAgent' },
  { pattern: /chains\.NewLLMChain\s*\(/g, name: 'LLMChain' },
  { pattern: /chains\.NewConversationalRetrievalQA\s*\(/g, name: 'RetrievalQA' },
];

const TOOL_PATTERNS = [
  { pattern: /tools\.Tool\s*\{/g, type: 'struct' },
  { pattern: /tools\.Calculator\s*\{/g, type: 'calculator' },
  { pattern: /tools\.NewSearchTool\s*\(/g, type: 'network' },
];

const MODEL_CONSTRUCTORS: Record<string, string> = {
  'openai.New': 'openai',
  'openai.NewClient': 'openai',
  'anthropic.New': 'anthropic',
  'ollama.New': 'ollama',
  'googleai.New': 'google',
  'cohere.New': 'cohere',
  'huggingface.New': 'huggingface',
  'genai.NewClient': 'google',
};

export function parseGolangAI(graph: AgentGraph, files: FileInventory): void {
  for (const file of files.go) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Tightened gate: require full module path references, not bare 'agents.' or 'llms.'
    // which match any Go package with those names
    if (!content.includes('langchaingo') && !content.includes('eino') &&
        !content.includes('genkit') && !content.includes('go-openai') &&
        !content.includes('generative-ai-go') &&
        !content.includes('agents.NewExecutor') && !content.includes('agents.NewOpenAI') &&
        !content.includes('agents.NewConversational') &&
        !content.includes('llms.Call') && !content.includes('llms.WithSystem') &&
        !content.includes('chains.NewLLM')) continue;

    const lines = content.split('\n');

    extractModels(content, file.relativePath, graph);
    extractAgents(content, lines, file.relativePath, graph);
    extractTools(content, lines, file.relativePath, graph);
    extractPrompts(content, file.relativePath, lines, graph);
  }
}

function extractModels(content: string, filePath: string, graph: AgentGraph): void {
  for (const [constructor, provider] of Object.entries(MODEL_CONSTRUCTORS)) {
    const escaped = constructor.replace(/\\/g, '\\\\').replace(/\./g, '\\.');
    const pattern = new RegExp(`${escaped}\\s*\\(`, 'g');
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;

      graph.models.push({
        id: `golang-ai-model-${graph.models.length}`,
        name: constructor,
        provider,
        framework: 'golang-ai',
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
        id: `golang-ai-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || name,
        framework: 'golang-ai',
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

      // Extract Name: "..." from struct literal
      const nameMatch = region.match(/Name:\s*"([^"]+)"/);
      const toolName = nameMatch?.[1] ?? extractAssignmentName(lines, line) ?? `tool_${line}`;

      const capabilities = detectCapabilities(region);

      graph.tools.push({
        id: `golang-ai-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'golang-ai',
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
  // llms.WithSystem("...") or SystemMessage: "..."
  const systemPatterns = [
    /llms\.WithSystem\s*\(\s*"([\s\S]*?)"\s*\)/g,
    /llms\.MessageContent\s*\{[^}]*Role:\s*llms\.ChatMessageTypeSystem[^}]*Parts:\s*\[\]\s*llms\.ContentPart\s*\{[^}]*llms\.TextContent\s*\{[^}]*Text:\s*"([\s\S]*?)"/g,
    /SystemMessage:\s*"([\s\S]*?)"/g,
  ];

  for (const pattern of systemPatterns) {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const promptContent = match[1] ?? match[2] ?? '';
      if (promptContent.length < 5) continue;
      const line = content.substring(0, match.index).split('\n').length;

      graph.prompts.push({
        id: `golang-ai-prompt-${graph.prompts.length}`,
        file: filePath,
        line,
        type: 'system',
        content: promptContent,
        hasInstructionGuarding: false,
        hasSecrets: false,
        hasUserInputInterpolation: /fmt\.Sprintf/.test(content.substring(Math.max(0, match.index - 100), match.index + match[0].length + 100)),
        scopeClarity: promptContent.length > 50 ? 'vague' : 'missing',
      });
    }
  }
}

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  // Go: varName := ... or var varName = ...
  const match = line.match(/(\w+)\s*(?::=|=)/);
  return match?.[1];
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  return detectCapabilitiesGo(body);
}
