import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, ToolNode, PromptNode } from '../../types/agent-graph.js';
import {
  detectCapabilities as sharedDetectCapabilities,
  checkInstructionGuarding as sharedCheckInstructionGuarding,
  checkForSecrets as sharedCheckForSecrets,
  checkUserInputInterpolationJS as sharedCheckUserInputInterpolation,
  assessScopeClarity as sharedAssessScopeClarity,
} from './shared.js';

// ---------- patterns ----------

const AGENT_PATTERNS = [
  { pattern: /generateText\s*\(\s*\{/g, name: 'generateText' },
  { pattern: /streamText\s*\(\s*\{/g, name: 'streamText' },
];

const TOOL_CALL_PATTERN = /\btool\s*\(\s*\{/g;

const TOOL_OBJECT_PATTERN =
  /(\w+)\s*[:=]\s*\{[^}]*description\s*:\s*["'`][\s\S]*?execute\s*[:]\s*/g;

const MODEL_PROVIDERS: Record<string, string> = {
  openai: 'openai',
  anthropic: 'anthropic',
  google: 'google',
  mistral: 'mistral',
  cohere: 'cohere',
  amazon: 'aws-bedrock',
  azure: 'azure-openai',
  groq: 'groq',
  fireworks: 'fireworks',
  together: 'together',
  perplexity: 'perplexity',
};

// ---------- entry point ----------

export function parseVercelAI(graph: AgentGraph, files: FileInventory): void {
  const codeFiles = [...files.typescript, ...files.javascript];

  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Quick filter: only parse files that reference the AI SDK
    if (!content.includes('ai') && !content.includes('@ai-sdk')) continue;
    // Tighter check: must have a recognizable import
    if (
      !/@ai-sdk\//.test(content) &&
      !/(from|require)\s*\(?\s*['"]ai['"]/.test(content)
    ) {
      continue;
    }

    const lines = content.split('\n');

    extractModels(content, file.relativePath, graph);
    extractTools(content, lines, file.relativePath, graph);
    extractAgents(content, lines, file.relativePath, graph);
    extractPrompts(content, file.relativePath, lines, graph);
  }

  // Post-pass: bind tools to agents that have no tools yet
  bindToolsToAgents(graph);
}

// ---------- models ----------

function extractModels(
  content: string,
  filePath: string,
  graph: AgentGraph,
): void {
  // Match provider function calls: openai('gpt-4'), anthropic('claude-3'), etc.
  for (const [funcName, provider] of Object.entries(MODEL_PROVIDERS)) {
    const pattern = new RegExp(
      `\\b${funcName}\\s*\\(\\s*['"\`]([^'"\`]+)['"\`]`,
      'g',
    );
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const modelName = match[1];
      const line = content.substring(0, match.index).split('\n').length;

      graph.models.push({
        id: `vercel-ai-model-${graph.models.length}`,
        name: modelName,
        provider,
        framework: 'vercel-ai',
        file: filePath,
        line,
      });
    }
  }

  // Match createOpenAI / createAnthropic style factory+call
  const factoryPattern =
    /\bcreate(OpenAI|Anthropic|Google|Mistral|Cohere|Amazon|Azure|Groq|Fireworks|Together)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = factoryPattern.exec(content)) !== null) {
    const providerName = match[1].toLowerCase();
    const provider = MODEL_PROVIDERS[providerName] ?? providerName;
    const line = content.substring(0, match.index).split('\n').length;

    graph.models.push({
      id: `vercel-ai-model-${graph.models.length}`,
      name: match[1],
      provider,
      framework: 'vercel-ai',
      file: filePath,
      line,
    });
  }
}

// ---------- tools ----------

function extractTools(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  // Pattern 1: tool({ description: ..., parameters: ..., execute: ... })
  TOOL_CALL_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = TOOL_CALL_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 1500);

    // Extract description
    const descMatch = region.match(
      /description\s*:\s*['"`]([\s\S]*?)['"`]/,
    );
    const description = descMatch?.[1] ?? '';

    // Try to get a name from an assignment or object key on the same line
    const toolName = extractAssignmentName(lines, line) ?? `tool_${line}`;

    // Detect capabilities from the execute body
    const executeBody = extractExecuteBody(region);
    const capabilities = detectCapabilities(executeBody);

    const toolNode: ToolNode = {
      id: `vercel-ai-tool-${graph.tools.length}`,
      name: toolName,
      framework: 'vercel-ai',
      file: filePath,
      line,
      description,
      parameters: [],
      hasSideEffects:
        capabilities.length > 0 && !capabilities.every(c => c === 'other'),
      hasInputValidation: /z\./.test(region) || /zod/.test(region),
      hasSandboxing: false,
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    };

    graph.tools.push(toolNode);
  }

  // Pattern 2: object-literal tools with description + execute
  TOOL_OBJECT_PATTERN.lastIndex = 0;
  while ((match = TOOL_OBJECT_PATTERN.exec(content)) !== null) {
    // Skip if we already captured this position via the tool() pattern
    const line = content.substring(0, match.index).split('\n').length;
    if (
      graph.tools.some(
        t =>
          t.framework === 'vercel-ai' &&
          t.file === filePath &&
          Math.abs(t.line - line) <= 2,
      )
    ) {
      continue;
    }

    const region = content.substring(match.index, match.index + 1500);
    const descMatch = region.match(
      /description\s*:\s*['"`]([\s\S]*?)['"`]/,
    );
    const description = descMatch?.[1] ?? '';
    const toolName = match[1] || extractAssignmentName(lines, line) || `tool_${line}`;

    const executeBody = extractExecuteBody(region);
    const capabilities = detectCapabilities(executeBody);

    graph.tools.push({
      id: `vercel-ai-tool-${graph.tools.length}`,
      name: toolName,
      framework: 'vercel-ai',
      file: filePath,
      line,
      description,
      parameters: [],
      hasSideEffects:
        capabilities.length > 0 && !capabilities.every(c => c === 'other'),
      hasInputValidation: /z\./.test(region) || /zod/.test(region),
      hasSandboxing: false,
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }
}

// ---------- agents ----------

function extractAgents(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  for (const { pattern, name } of AGENT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 3000);

      // Extract system prompt from system: field
      const systemPrompt = extractSystemField(region);

      // Extract tool references from tools: { ... }
      const toolIds = extractToolIdsFromRegion(region, graph);

      // Try to find the model reference in the region
      const modelId = extractModelFromRegion(region, filePath, graph);

      const agentNode = {
        id: `vercel-ai-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || name,
        framework: 'vercel-ai' as const,
        file: filePath,
        line,
        tools: toolIds,
        systemPrompt: systemPrompt ?? undefined,
        modelId: modelId ?? undefined,
        memoryType: undefined,
        maxIterations: extractMaxSteps(region),
      };

      graph.agents.push(agentNode);
    }
  }
}

// ---------- prompts ----------

function extractPrompts(
  content: string,
  filePath: string,
  lines: string[],
  graph: AgentGraph,
): void {
  // Pattern 1: system: field inside generateText/streamText
  const systemFieldPattern =
    /(?:generateText|streamText)\s*\(\s*\{[\s\S]*?system\s*:\s*(?:['"`]([\s\S]*?)['"`]|(`[\s\S]*?`))/g;
  let match: RegExpExecArray | null;
  while ((match = systemFieldPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? stripTemplateTicks(match[2] ?? '');
    if (!promptContent) continue;
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `vercel-ai-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(
        promptContent,
        match[0],
      ),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }

  // Pattern 2: variables with prompt-like names containing template literals or strings
  const templatePattern =
    /(?:systemPrompt|system_prompt|SYSTEM_PROMPT|systemMessage|system_message|prompt)\s*=\s*(?:(['"`])([\s\S]*?)\1|(`[\s\S]*?`))/g;
  while ((match = templatePattern.exec(content)) !== null) {
    const promptContent =
      match[2] ?? stripTemplateTicks(match[3] ?? '');
    if (!promptContent) continue;
    const line = content.substring(0, match.index).split('\n').length;

    // Avoid duplicating prompts already captured above
    if (
      graph.prompts.some(
        p =>
          p.file === filePath &&
          Math.abs(p.line - line) <= 1,
      )
    ) {
      continue;
    }

    graph.prompts.push({
      id: `vercel-ai-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(
        promptContent,
        match[0],
      ),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }
}

// ---------- helpers ----------

function extractAssignmentName(
  lines: string[],
  lineNum: number,
): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  // const agent = generateText(... or const weather: tool({...
  const match = line.match(/(?:const|let|var|export\s+(?:const|let))\s+(\w+)/);
  if (match) return match[1];
  // object key pattern: weatherTool: tool({
  const keyMatch = line.match(/(\w+)\s*:/);
  if (keyMatch) return keyMatch[1];
  // simple assignment: agent =
  const assignMatch = line.match(/(\w+)\s*=/);
  return assignMatch?.[1];
}

function extractSystemField(region: string): string | null {
  // system: 'text' or system: "text" or system: `text`
  const match = region.match(
    /\bsystem\s*:\s*(?:(['"`])([\s\S]*?)\1|(`[\s\S]*?`))/,
  );
  if (!match) return null;
  return match[2] ?? stripTemplateTicks(match[3] ?? '') ?? null;
}

function extractModelFromRegion(
  region: string,
  filePath: string,
  graph: AgentGraph,
): string | undefined {
  // model: openai('gpt-4') — look for provider call in the region
  const modelFieldMatch = region.match(
    /\bmodel\s*:\s*(\w+)\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/,
  );
  if (modelFieldMatch) {
    const funcName = modelFieldMatch[1];
    const modelName = modelFieldMatch[2];
    // Find a matching model node
    const found = graph.models.find(
      m =>
        m.framework === 'vercel-ai' &&
        m.name === modelName,
    );
    if (found) return found.id;
  }

  // model: someVar — reference to a variable; find nearest model in same file
  const varRefMatch = region.match(/\bmodel\s*:\s*(\w+)/);
  if (varRefMatch) {
    const nearest = graph.models.find(
      m => m.framework === 'vercel-ai' && m.file === filePath,
    );
    if (nearest) return nearest.id;
  }

  return undefined;
}

function extractToolIdsFromRegion(
  region: string,
  graph: AgentGraph,
): string[] {
  // tools: { weatherTool, searchTool, ... }
  const toolsBlockMatch = region.match(/\btools\s*:\s*\{([^}]*)\}/);
  if (!toolsBlockMatch) return [];

  const block = toolsBlockMatch[1];
  // Extract identifiers (keys in the object shorthand or key: value pairs)
  const ids: string[] = [];
  const keyPattern = /(\w+)\s*(?:[:,}])/g;
  let keyMatch: RegExpExecArray | null;
  while ((keyMatch = keyPattern.exec(block)) !== null) {
    const varName = keyMatch[1];
    const tool = graph.tools.find(
      t =>
        t.framework === 'vercel-ai' &&
        (t.name === varName || t.id === varName),
    );
    if (tool) {
      ids.push(tool.id);
    }
  }

  return ids;
}

function extractMaxSteps(region: string): number | undefined {
  const match = region.match(/maxSteps\s*:\s*(\d+)/);
  return match ? parseInt(match[1]) : undefined;
}

function extractExecuteBody(region: string): string {
  const execIdx = region.indexOf('execute');
  if (execIdx === -1) return '';
  return region.substring(execIdx, Math.min(execIdx + 1000, region.length));
}

function stripTemplateTicks(s: string): string {
  return s.replace(/^`|`$/g, '');
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  return sharedDetectCapabilities(body);
}

function bindToolsToAgents(graph: AgentGraph): void {
  for (const agent of graph.agents) {
    if (agent.framework !== 'vercel-ai') continue;
    if (agent.tools.length > 0) continue;

    // Bind all vercel-ai tools in the same file as a fallback
    const fileTools = graph.tools.filter(
      t => t.framework === 'vercel-ai' && t.file === agent.file,
    );
    agent.tools = fileTools.map(t => t.id);
  }
}

// ---------- prompt analysis helpers ----------

function checkInstructionGuarding(prompt: string): boolean {
  return sharedCheckInstructionGuarding(prompt);
}

function checkForSecrets(prompt: string): boolean {
  return sharedCheckForSecrets(prompt);
}

function checkUserInputInterpolation(prompt: string, fullMatch: string): boolean {
  return sharedCheckUserInputInterpolation(prompt, fullMatch);
}

function assessScopeClarity(prompt: string): 'clear' | 'vague' | 'missing' {
  return sharedAssessScopeClarity(prompt);
}
