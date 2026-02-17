import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode } from '../../types/agent-graph.js';
import {
  detectCapabilities as sharedDetectCapabilities,
  checkInstructionGuarding as sharedCheckInstructionGuarding,
  checkForSecrets as sharedCheckForSecrets,
  checkUserInputInterpolation as sharedCheckUserInputInterpolation,
  assessScopeClarity as sharedAssessScopeClarity,
} from './shared.js';

/* ------------------------------------------------------------------ */
/*  Agent constructor patterns                                        */
/* ------------------------------------------------------------------ */

const AGENT_PATTERNS = [
  { pattern: /ConversableAgent\s*\(/g, name: 'ConversableAgent' },
  { pattern: /AssistantAgent\s*\(/g, name: 'AssistantAgent' },
  { pattern: /UserProxyAgent\s*\(/g, name: 'UserProxyAgent' },
  { pattern: /GroupChatManager\s*\(/g, name: 'GroupChatManager' },
];

/* ------------------------------------------------------------------ */
/*  Tool decorator pattern                                            */
/* ------------------------------------------------------------------ */

const TOOL_DECORATOR_PATTERN = /@.*register_for_llm/g;

/* ------------------------------------------------------------------ */
/*  GroupChat pattern                                                  */
/* ------------------------------------------------------------------ */

const GROUP_CHAT_PATTERN = /GroupChat\s*\(/g;

/* ------------------------------------------------------------------ */
/*  Main entry point                                                   */
/* ------------------------------------------------------------------ */

export function parseAutoGen(graph: AgentGraph, files: FileInventory): void {
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('autogen')) continue;

    const lines = content.split('\n');

    extractModels(content, file.relativePath, graph);
    extractAgents(content, lines, file.relativePath, graph);
    extractTools(content, lines, file.relativePath, graph);
    extractPrompts(content, file.relativePath, graph);
    extractGroupChats(content, file.relativePath, graph);
  }

  // Post-pass: bind tools to agents with empty tool arrays
  bindToolsToAgents(graph);
}

/* ------------------------------------------------------------------ */
/*  Model extraction                                                   */
/* ------------------------------------------------------------------ */

function extractModels(
  content: string,
  filePath: string,
  graph: AgentGraph,
): void {
  // Pattern 1: llm_config={"model": "gpt-4", ...}
  const directModelPattern = /llm_config\s*=\s*\{[^}]*"model"\s*:\s*"([^"]+)"/g;
  let match: RegExpExecArray | null;
  while ((match = directModelPattern.exec(content)) !== null) {
    const line = content.substring(0, match.index).split('\n').length;
    graph.models.push({
      id: `autogen-model-${graph.models.length}`,
      name: match[1],
      provider: inferProvider(match[1]),
      framework: 'autogen',
      file: filePath,
      line,
    });
  }

  // Pattern 2: llm_config={"config_list": [{"model": "..."}]}
  const configListPattern = /config_list\s*=?\s*\[\s*\{[^}]*"model"\s*:\s*"([^"]+)"/g;
  while ((match = configListPattern.exec(content)) !== null) {
    // Skip if this model name was already captured by the direct pattern
    const modelName = match[1];
    const alreadyFound = graph.models.some(
      m => m.framework === 'autogen' && m.name === modelName && m.file === filePath,
    );
    if (alreadyFound) continue;

    const line = content.substring(0, match.index).split('\n').length;
    graph.models.push({
      id: `autogen-model-${graph.models.length}`,
      name: modelName,
      provider: inferProvider(modelName),
      framework: 'autogen',
      file: filePath,
      line,
    });
  }

  // Pattern 3: {"model": "..."} in variable assignment (config_list = [...])
  const varConfigPattern = /["']model["']\s*:\s*["']([^"']+)["']/g;
  while ((match = varConfigPattern.exec(content)) !== null) {
    const modelName = match[1];
    const alreadyFound = graph.models.some(
      m => m.framework === 'autogen' && m.name === modelName && m.file === filePath,
    );
    if (alreadyFound) continue;

    const line = content.substring(0, match.index).split('\n').length;
    graph.models.push({
      id: `autogen-model-${graph.models.length}`,
      name: modelName,
      provider: inferProvider(modelName),
      framework: 'autogen',
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
  for (const { pattern, name: constructorName } of AGENT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      // Extract name= kwarg
      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const agentName = nameMatch?.[1]
        ?? extractAssignmentName(lines, line)
        ?? constructorName;

      // Extract system_message=
      const systemMsgMatch = region.match(
        /system_message\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([^"']*?)["'])/,
      );
      const systemPrompt = systemMsgMatch?.[1] ?? systemMsgMatch?.[2] ?? systemMsgMatch?.[3];

      // Extract human_input_mode=
      const himMatch = region.match(/human_input_mode\s*=\s*["']([^"']+)["']/);
      const humanInputMode = himMatch?.[1]; // ALWAYS, NEVER, TERMINATE

      // Extract max_consecutive_auto_reply=
      const maxReplyMatch = region.match(/max_consecutive_auto_reply\s*=\s*(\d+)/);
      const maxIterations = maxReplyMatch ? parseInt(maxReplyMatch[1]) : undefined;

      // Detect code_execution_config
      const hasCodeExec = /code_execution_config\s*=/.test(region);

      // Detect delegation: agents with human_input_mode=NEVER that participate in group chats
      const delegationEnabled = humanInputMode === 'NEVER' || constructorName === 'GroupChatManager';

      const agentNode: AgentNode = {
        id: `autogen-agent-${graph.agents.length}`,
        name: agentName,
        framework: 'autogen',
        file: filePath,
        line,
        tools: [],
        maxIterations,
        delegationEnabled,
      };

      if (systemPrompt) {
        agentNode.systemPrompt = systemPrompt;
      }

      // Link nearest model
      const modelId = findNearestModelId(filePath, line, graph);
      if (modelId) agentNode.modelId = modelId;

      // If code_execution_config is present, note it in the agent's tool set later
      if (hasCodeExec) {
        // Create a synthetic tool node for the code execution capability
        const toolId = `autogen-tool-${graph.tools.length}`;
        graph.tools.push({
          id: toolId,
          name: `${agentName}_code_executor`,
          framework: 'autogen',
          file: filePath,
          line,
          description: 'AutoGen built-in code execution via code_execution_config',
          parameters: [],
          hasSideEffects: true,
          hasInputValidation: false,
          hasSandboxing: false,
          capabilities: ['code-execution'],
        });
        agentNode.tools.push(toolId);
      }

      graph.agents.push(agentNode);
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Tool extraction (register_for_llm decorator)                       */
/* ------------------------------------------------------------------ */

function extractTools(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  TOOL_DECORATOR_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = TOOL_DECORATOR_PATTERN.exec(content)) !== null) {
    const decoratorLine = content.substring(0, match.index).split('\n').length;

    // The decorated function is on the next `def` line after the decorator
    let funcName: string | undefined;
    let description = '';

    for (let i = decoratorLine; i < lines.length; i++) {
      const funcMatch = lines[i].match(/def\s+(\w+)/);
      if (funcMatch) {
        funcName = funcMatch[1];

        // Extract docstring from function body
        const docRegion = lines.slice(i + 1, i + 10).join('\n');
        const docMatch = docRegion.match(/^\s*(?:"""([\s\S]*?)"""|'''([\s\S]*?)'''|"([^"]+)"|'([^']+)')/);
        description = (docMatch?.[1] ?? docMatch?.[2] ?? docMatch?.[3] ?? docMatch?.[4] ?? '').trim();
        break;
      }
    }

    // Detect capabilities from function body
    const funcBodyStart = content.indexOf(`def ${funcName}`, match.index);
    const funcBody = funcBodyStart >= 0
      ? content.substring(funcBodyStart, funcBodyStart + 2000)
      : '';
    const capabilities = detectCapabilities(funcBody);

    graph.tools.push({
      id: `autogen-tool-${graph.tools.length}`,
      name: funcName ?? `tool_${decoratorLine}`,
      framework: 'autogen',
      file: filePath,
      line: decoratorLine,
      description,
      parameters: [],
      hasSideEffects: capabilities.length > 0 && !capabilities.every(c => c === 'other'),
      hasInputValidation: false,
      hasSandboxing: false,
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }
}

/* ------------------------------------------------------------------ */
/*  GroupChat extraction & inter-agent linking                         */
/* ------------------------------------------------------------------ */

function extractGroupChats(
  content: string,
  filePath: string,
  graph: AgentGraph,
): void {
  GROUP_CHAT_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = GROUP_CHAT_PATTERN.exec(content)) !== null) {
    const region = content.substring(match.index, match.index + 2000);

    // Extract agents=[...] from GroupChat constructor
    const agentsMatch = region.match(/agents\s*=\s*\[([^\]]*)\]/);
    if (!agentsMatch) continue;

    const varNames = agentsMatch[1]
      .split(',')
      .map(s => s.trim())
      .filter(s => /^[a-zA-Z_]\w*$/.test(s));

    // Extract speaker_selection_method=
    const speakerMatch = region.match(/speaker_selection_method\s*=\s*["']([^"']+)["']/);
    const _speakerSelectionMethod = speakerMatch?.[1]; // auto, round_robin, random, manual

    // Resolve variable names to agent IDs in the graph
    const agentIds = resolveAgentVarNames(varNames, content, graph, filePath);

    // Create inter-agent links between all agents in the group
    for (let i = 0; i < agentIds.length; i++) {
      for (let j = i + 1; j < agentIds.length; j++) {
        graph.interAgentLinks.push({
          fromAgent: agentIds[i],
          toAgent: agentIds[j],
          communicationType: 'delegation',
          hasAuthentication: false,
          hasEncryption: false,
        });
      }
    }
  }
}

/**
 * Resolve Python variable names to agent IDs by matching variable assignments
 * to agent constructor calls.
 */
function resolveAgentVarNames(
  varNames: string[],
  content: string,
  graph: AgentGraph,
  filePath: string,
): string[] {
  const ids: string[] = [];

  for (const varName of varNames) {
    // Try matching by assignment name: `varName = SomeAgent(name="...")`
    const assignPattern = new RegExp(
      `${varName}\\s*=\\s*(?:ConversableAgent|AssistantAgent|UserProxyAgent|GroupChatManager)\\s*\\([^)]*name\\s*=\\s*["']([^"']+)["']`,
    );
    const assignMatch = content.match(assignPattern);

    if (assignMatch) {
      const agentName = assignMatch[1];
      const agent = graph.agents.find(
        a => a.framework === 'autogen' && a.name === agentName && a.file === filePath,
      );
      if (agent) {
        ids.push(agent.id);
        continue;
      }
    }

    // Fall back: match by variable name directly against agent name
    const agent = graph.agents.find(
      a => a.framework === 'autogen' && (a.name === varName) && a.file === filePath,
    );
    if (agent) {
      ids.push(agent.id);
    }
  }

  return ids;
}

/* ------------------------------------------------------------------ */
/*  Prompt extraction                                                  */
/* ------------------------------------------------------------------ */

function extractPrompts(
  content: string,
  filePath: string,
  graph: AgentGraph,
): void {
  // Extract system_message= from agent constructors
  const systemMsgPattern =
    /system_message\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([^"']*?)["'])/g;
  let match: RegExpExecArray | null;
  while ((match = systemMsgPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `autogen-prompt-${graph.prompts.length}`,
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

  // Extract prompt-like variable assignments
  const templatePattern =
    /(?:system_prompt|system_message|SYSTEM_PROMPT|SYSTEM_MESSAGE|prompt)\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["'`]([^"'`]*?)["'`])/g;
  while ((match = templatePattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    // Avoid duplicate prompts already captured by system_message= pattern
    const alreadyFound = graph.prompts.some(
      p => p.file === filePath && p.line === line,
    );
    if (alreadyFound) continue;

    graph.prompts.push({
      id: `autogen-prompt-${graph.prompts.length}`,
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
    if (agent.framework !== 'autogen') continue;
    if (agent.tools.length > 0) continue;

    // Bind all autogen tools in the same file
    const fileTools = graph.tools.filter(
      t => t.framework === 'autogen' && t.file === agent.file,
    );
    agent.tools = fileTools.map(t => t.id);
  }
}

/* ------------------------------------------------------------------ */
/*  Inline helpers                                                     */
/* ------------------------------------------------------------------ */

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

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  const match = line.match(/(\w+)\s*=/);
  return match?.[1];
}

function findNearestModelId(
  filePath: string,
  agentLine: number,
  graph: AgentGraph,
): string | undefined {
  let bestModel: string | undefined;
  let bestDist = Infinity;

  for (const model of graph.models) {
    if (model.framework !== 'autogen' || model.file !== filePath) continue;
    const dist = agentLine - model.line;
    if (dist >= 0 && dist < bestDist) {
      bestDist = dist;
      bestModel = model.id;
    }
  }
  return bestModel;
}

function inferProvider(modelName: string): string {
  const lower = modelName.toLowerCase();
  if (lower.includes('gpt') || lower.includes('o1') || lower.includes('o3')) return 'openai';
  if (lower.includes('claude')) return 'anthropic';
  if (lower.includes('gemini')) return 'google';
  if (lower.includes('llama') || lower.includes('mistral')) return 'meta/mistral';
  if (lower.includes('bedrock')) return 'aws-bedrock';
  return 'unknown';
}

function detectCapabilities(body: string): import('../../types/agent-graph.js').ToolCapability[] {
  return sharedDetectCapabilities(body);
}
