import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode } from '../../types/agent-graph.js';
import {
  detectCapabilities as sharedDetectCapabilities,
  checkInstructionGuarding as sharedCheckInstructionGuarding,
  checkForSecrets as sharedCheckForSecrets,
  checkUserInputInterpolation as sharedCheckUserInputInterpolation,
  assessScopeClarity as sharedAssessScopeClarity,
} from './shared.js';

/* ------------------------------------------------------------------ */
/*  Regex patterns for Bedrock agent/model/tool detection              */
/* ------------------------------------------------------------------ */

const AGENT_RUNTIME_CLIENT_PATTERN = /boto3\.client\s*\(\s*["']bedrock-agent-runtime["']\s*\)/g;

const INVOKE_AGENT_PATTERN = /invoke_agent\s*\(/g;
const CREATE_AGENT_PATTERN = /create_agent\s*\(/g;
const CHAT_BEDROCK_PATTERN = /ChatBedrock\s*\(/g;

const INVOKE_MODEL_PATTERN = /invoke_model\s*\(/g;
const CONVERSE_PATTERN = /\.converse\s*\(/g;

const CREATE_ACTION_GROUP_PATTERN = /create_agent_action_group\s*\(/g;

/* ------------------------------------------------------------------ */
/*  Model ID → provider mapping                                        */
/* ------------------------------------------------------------------ */

const MODEL_ID_PROVIDERS: Record<string, string> = {
  'anthropic': 'anthropic',
  'amazon': 'amazon',
  'meta': 'meta',
  'cohere': 'cohere',
  'ai21': 'ai21',
  'mistral': 'mistral',
  'stability': 'stability',
};

function resolveProvider(modelId: string): string {
  const prefix = modelId.split('.')[0];
  return MODEL_ID_PROVIDERS[prefix] ?? 'aws-bedrock';
}

/* ------------------------------------------------------------------ */
/*  Main entry point                                                   */
/* ------------------------------------------------------------------ */

export function parseBedrock(graph: AgentGraph, files: FileInventory): void {
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Tightened gate: require 'bedrock' in file — bare 'boto3' is too generic (all AWS projects)
    if (!content.includes('bedrock')) continue;

    const lines = content.split('\n');

    extractModels(content, lines, file.relativePath, graph);
    extractAgents(content, lines, file.relativePath, graph);
    extractTools(content, lines, file.relativePath, graph);
    extractPrompts(content, file.relativePath, lines, graph);
  }

  // Post-pass: bind tools to agents by file proximity
  bindToolsToAgents(graph);
}

/* ------------------------------------------------------------------ */
/*  Model extraction                                                   */
/* ------------------------------------------------------------------ */

function extractModels(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  // Pattern 1: invoke_model(... modelId="..." ...)
  INVOKE_MODEL_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = INVOKE_MODEL_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 500);
    const modelIdMatch = region.match(/modelId\s*=\s*["']([^"']+)["']/);

    if (modelIdMatch) {
      graph.models.push({
        id: `bedrock-model-${graph.models.length}`,
        name: modelIdMatch[1],
        provider: resolveProvider(modelIdMatch[1]),
        framework: 'bedrock',
        file: filePath,
        line,
      });
    }
  }

  // Pattern 2: ChatBedrock(model_id=...)
  CHAT_BEDROCK_PATTERN.lastIndex = 0;
  while ((match = CHAT_BEDROCK_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 500);
    const modelIdMatch = region.match(/model_id\s*=\s*["']([^"']+)["']/);
    const modelMatch = region.match(/model\s*=\s*["']([^"']+)["']/);
    const resolvedName = modelIdMatch?.[1] ?? modelMatch?.[1];

    graph.models.push({
      id: `bedrock-model-${graph.models.length}`,
      name: resolvedName ?? 'ChatBedrock',
      provider: resolvedName ? resolveProvider(resolvedName) : 'aws-bedrock',
      framework: 'bedrock',
      file: filePath,
      line,
    });
  }

  // Pattern 3: converse() calls with modelId
  CONVERSE_PATTERN.lastIndex = 0;
  while ((match = CONVERSE_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 500);
    const modelIdMatch = region.match(/modelId\s*=\s*["']([^"']+)["']/);

    if (modelIdMatch) {
      graph.models.push({
        id: `bedrock-model-${graph.models.length}`,
        name: modelIdMatch[1],
        provider: resolveProvider(modelIdMatch[1]),
        framework: 'bedrock',
        file: filePath,
        line,
      });
    }
  }

  // Pattern 4: bedrock-runtime client with modelId in nearby invoke_model calls
  // (already covered above via INVOKE_MODEL_PATTERN)

  // Pattern 5: standalone modelId variable assignments
  const modelIdAssignPattern = /modelId\s*=\s*["']([^"']+)["']/g;
  const seenModelNames = new Set(graph.models.filter(m => m.framework === 'bedrock').map(m => m.name));
  while ((match = modelIdAssignPattern.exec(content)) !== null) {
    const modelName = match[1];
    if (seenModelNames.has(modelName)) continue;
    seenModelNames.add(modelName);

    // Only count if not already captured by invoke_model or converse
    const line = content.substring(0, match.index).split('\n').length;
    const lineText = lines[line - 1] ?? '';
    // Skip if this line is inside an invoke_model or converse call (already captured)
    if (/invoke_model|converse|ChatBedrock/.test(lineText)) continue;

    graph.models.push({
      id: `bedrock-model-${graph.models.length}`,
      name: modelName,
      provider: resolveProvider(modelName),
      framework: 'bedrock',
      file: filePath,
      line,
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Agent extraction                                                   */
/* ------------------------------------------------------------------ */

function extractAgents(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  let match: RegExpExecArray | null;

  // Pattern 1: invoke_agent() calls — indicates a runtime agent invocation
  INVOKE_AGENT_PATTERN.lastIndex = 0;
  while ((match = INVOKE_AGENT_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 1000);

    const agentIdMatch = region.match(/agentId\s*=\s*["']([^"']+)["']/);
    const agentAliasMatch = region.match(/agentAliasId\s*=\s*["']([^"']+)["']/);

    const agentNode: AgentNode = {
      id: `bedrock-agent-${graph.agents.length}`,
      name: extractAssignmentName(lines, line) || agentIdMatch?.[1] || 'BedrockAgent',
      framework: 'bedrock',
      file: filePath,
      line,
      tools: [],
    };

    const modelId = findNearestModelId(content, line, graph);
    if (modelId) agentNode.modelId = modelId;

    const systemPrompt = extractSystemPromptNear(content, match.index);
    if (systemPrompt) agentNode.systemPrompt = systemPrompt;

    graph.agents.push(agentNode);
  }

  // Pattern 2: create_agent() calls — agent creation with instruction
  CREATE_AGENT_PATTERN.lastIndex = 0;
  while ((match = CREATE_AGENT_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 2000);

    const nameMatch = region.match(/agentName\s*=\s*["']([^"']+)["']/);
    const instructionMatch = region.match(
      /instruction\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([^"']+)["'])/,
    );
    const modelIdMatch = region.match(/foundationModel\s*=\s*["']([^"']+)["']/);

    // Register the model if found inline
    if (modelIdMatch) {
      graph.models.push({
        id: `bedrock-model-${graph.models.length}`,
        name: modelIdMatch[1],
        provider: resolveProvider(modelIdMatch[1]),
        framework: 'bedrock',
        file: filePath,
        line,
      });
    }

    const systemPrompt = instructionMatch?.[1] ?? instructionMatch?.[2] ?? instructionMatch?.[3];

    const agentNode: AgentNode = {
      id: `bedrock-agent-${graph.agents.length}`,
      name: extractAssignmentName(lines, line) || nameMatch?.[1] || 'BedrockAgent',
      framework: 'bedrock',
      file: filePath,
      line,
      tools: [],
    };

    if (systemPrompt) agentNode.systemPrompt = systemPrompt;

    const modelId = modelIdMatch
      ? `bedrock-model-${graph.models.length - 1}`
      : findNearestModelId(content, line, graph);
    if (modelId) agentNode.modelId = modelId;

    graph.agents.push(agentNode);
  }

  // Pattern 3: ChatBedrock() as agent (from langchain_aws)
  // Only register as agent if not already captured as a model-only reference
  CHAT_BEDROCK_PATTERN.lastIndex = 0;
  while ((match = CHAT_BEDROCK_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 1000);

    // Check for tools= or bind_tools indicating agent usage
    const hasToolsBinding = /\.bind_tools\s*\(|tools\s*=\s*\[/.test(region) ||
      /\.bind_tools\s*\(/.test(content.substring(match.index, match.index + 2000));

    if (hasToolsBinding) {
      const agentNode: AgentNode = {
        id: `bedrock-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || 'ChatBedrockAgent',
        framework: 'bedrock',
        file: filePath,
        line,
        tools: [],
      };

      const modelId = findNearestModelId(content, line, graph);
      if (modelId) agentNode.modelId = modelId;

      graph.agents.push(agentNode);
    }
  }

  // Pattern 4: boto3 agent runtime client creation
  AGENT_RUNTIME_CLIENT_PATTERN.lastIndex = 0;
  while ((match = AGENT_RUNTIME_CLIENT_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;

    // Only add if no invoke_agent was already found in this file
    const hasInvokeAgent = graph.agents.some(
      a => a.framework === 'bedrock' && a.file === filePath,
    );
    if (hasInvokeAgent) continue;

    const agentNode: AgentNode = {
      id: `bedrock-agent-${graph.agents.length}`,
      name: extractAssignmentName(lines, line) || 'BedrockAgentRuntime',
      framework: 'bedrock',
      file: filePath,
      line,
      tools: [],
    };

    graph.agents.push(agentNode);
  }
}

/* ------------------------------------------------------------------ */
/*  Tool extraction                                                    */
/* ------------------------------------------------------------------ */

function extractTools(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  let match: RegExpExecArray | null;

  // Pattern 1: create_agent_action_group() — Bedrock action groups
  CREATE_ACTION_GROUP_PATTERN.lastIndex = 0;
  while ((match = CREATE_ACTION_GROUP_PATTERN.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 2000);

    const nameMatch = region.match(/actionGroupName\s*=\s*["']([^"']+)["']/);
    const descMatch = region.match(/description\s*=\s*["']([^"']+)["']/);
    const lambdaArnMatch = region.match(
      /actionGroupExecutor\s*=\s*\{[^}]*['"]lambda['"]\s*:\s*["']([^"']+)["']/,
    );

    // Detect capabilities from the action group
    const capabilities = detectCapabilities(region);
    const hasLambda = lambdaArnMatch !== null;

    const toolNode: ToolNode = {
      id: `bedrock-tool-${graph.tools.length}`,
      name: nameMatch?.[1] ?? extractAssignmentName(lines, line) ?? `action_group_${line}`,
      framework: 'bedrock',
      file: filePath,
      line,
      description: descMatch?.[1] ?? (hasLambda ? `Lambda: ${lambdaArnMatch![1]}` : ''),
      parameters: [],
      hasSideEffects: hasLambda || capabilities.length > 0,
      hasInputValidation: false,
      hasSandboxing: hasLambda, // Lambda provides sandboxing
      capabilities: capabilities.length > 0 ? capabilities : (hasLambda ? ['api'] : ['other']),
    };

    graph.tools.push(toolNode);
  }

  // Pattern 2: toolConfiguration in converse() calls
  const toolConfigPattern = /toolConfiguration\s*=\s*\{/g;
  while ((match = toolConfigPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    const region = content.substring(match.index, match.index + 2000);

    // Extract tool names from toolSpec definitions
    const toolSpecPattern = /["']name["']\s*:\s*["']([^"']+)["']/g;
    let toolSpecMatch: RegExpExecArray | null;
    while ((toolSpecMatch = toolSpecPattern.exec(region)) !== null) {
      const toolName = toolSpecMatch[1];
      const descSpecMatch = region.match(
        new RegExp(`["']name["']\\s*:\\s*["']${escapeRegex(toolName)}["'][\\s\\S]*?["']description["']\\s*:\\s*["']([^"']+)["']`),
      );

      graph.tools.push({
        id: `bedrock-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'bedrock',
        file: filePath,
        line,
        description: descSpecMatch?.[1] ?? '',
        parameters: [],
        hasSideEffects: false,
        hasInputValidation: false,
        hasSandboxing: false,
        capabilities: ['other'],
      });
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Prompt extraction                                                  */
/* ------------------------------------------------------------------ */

function extractPrompts(
  content: string,
  filePath: string,
  lines: string[],
  graph: AgentGraph,
): void {
  let match: RegExpExecArray | null;

  // Pattern 1: instruction= parameter in create_agent() calls
  const instructionPattern = /instruction\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([^"'\n]+)["'])/g;
  while ((match = instructionPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `bedrock-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(promptContent, match[0]),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }

  // Pattern 2: system parameter in converse() calls
  const converseSystemPattern = /system\s*=\s*\[\s*\{[^}]*["']text["']\s*:\s*["']([^"']+)["']/g;
  while ((match = converseSystemPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `bedrock-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(promptContent, match[0]),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }

  // Pattern 3: system parameter in converse() using triple-quoted or multi-line strings
  const converseSystemMultiPattern = /system\s*=\s*\[\s*\{[^}]*["']text["']\s*:\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)''')/g;
  while ((match = converseSystemMultiPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    // Avoid duplicate if already captured by the single-line pattern
    const alreadyCaptured = graph.prompts.some(
      p => p.file === filePath && p.line === line,
    );
    if (alreadyCaptured) continue;

    graph.prompts.push({
      id: `bedrock-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(promptContent, match[0]),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }

  // Pattern 4: template strings assigned to instruction-like variables
  const templatePattern = /(?:system_prompt|system_message|instruction|SYSTEM_PROMPT|agent_instruction)\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["'`]([^"'`\n]+)["'`])/g;
  while ((match = templatePattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    // Avoid duplicate if already captured by the instruction pattern
    const alreadyCaptured = graph.prompts.some(
      p => p.file === filePath && p.line === line,
    );
    if (alreadyCaptured) continue;

    graph.prompts.push({
      id: `bedrock-prompt-${graph.prompts.length}`,
      file: filePath,
      line,
      type: 'system',
      content: promptContent,
      hasInstructionGuarding: checkInstructionGuarding(promptContent),
      hasSecrets: checkForSecrets(promptContent),
      hasUserInputInterpolation: checkUserInputInterpolation(promptContent, match[0]),
      scopeClarity: assessScopeClarity(promptContent),
    });
  }
}

/* ------------------------------------------------------------------ */
/*  Post-pass: bind tools to agents                                    */
/* ------------------------------------------------------------------ */

function bindToolsToAgents(graph: AgentGraph): void {
  for (const agent of graph.agents) {
    if (agent.framework !== 'bedrock') continue;
    if (agent.tools.length > 0) continue;

    // Bind all Bedrock tools found in the same file
    const fileTools = graph.tools.filter(
      t => t.framework === 'bedrock' && t.file === agent.file,
    );
    agent.tools = fileTools.map(t => t.id);
  }
}

/* ------------------------------------------------------------------ */
/*  Inline helpers                                                     */
/* ------------------------------------------------------------------ */

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  const match = line.match(/(\w+)\s*=/);
  return match?.[1];
}

function findNearestModelId(
  content: string,
  agentLine: number,
  graph: AgentGraph,
): string | undefined {
  let bestModel: string | undefined;
  let bestDist = Infinity;

  for (const model of graph.models) {
    if (model.framework !== 'bedrock') continue;
    const dist = agentLine - model.line;
    if (dist >= 0 && dist < bestDist) {
      bestDist = dist;
      bestModel = model.id;
    }
  }
  return bestModel;
}

function extractSystemPromptNear(content: string, index: number): string | undefined {
  const start = Math.max(0, index - 2000);
  const end = index + 2000;
  const region = content.substring(start, end);

  // Look for instruction= in nearby create_agent
  const instrMatch = region.match(
    /instruction\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([^"']+)["'])/,
  );
  if (instrMatch) return instrMatch[1] ?? instrMatch[2] ?? instrMatch[3];

  // Look for system prompt in converse
  const sysMatch = region.match(/system\s*=\s*\[\s*\{[^}]*["']text["']\s*:\s*["']([^"']+)["']/);
  return sysMatch?.[1];
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  return sharedDetectCapabilities(body);
}

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

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
