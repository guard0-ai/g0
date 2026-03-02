import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';
import { checkInstructionGuarding, checkForSecrets, assessScopeClarity } from './shared.js';

const ASSISTANT_CREATE_PATTERN = /(?:assistants\.create|Assistant\.create|client\.beta\.assistants\.create)\s*\(/g;
const RESPONSES_CREATE_PATTERN = /(?:responses\.create|client\.responses\.create)\s*\(/g;
// Flexible: match Agent( with name= anywhere in the first few kwargs (not just first)
// Note: [^,)"']+ excludes quote chars to prevent ambiguity with the quoted alternatives (avoids ReDoS)
const AGENT_SDK_PATTERN = /Agent\s*\(\s*(?:[\w]+=(?:"[^"]*"|'[^']*'|[^,)"']+),\s*)*name\s*=/g;
const FUNCTION_TOOL_PATTERN = /(?:function_tool|FunctionTool)\s*\(/g;

// Swarm-specific patterns
const SWARM_AGENT_PATTERN = /Agent\s*\(\s*\n?\s*name\s*=/g;
const SWARM_CLIENT_PATTERN = /Swarm\s*\(/g;

export function parseOpenAI(graph: AgentGraph, files: FileInventory): void {
  for (const file of [...files.python, ...files.typescript, ...files.javascript]) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    // Tightened gate: require openai/swarm/agents SDK import — not bare Agent()
    const hasOpenAI = content.includes('openai');
    const hasSwarm = /from\s+swarm\s+import|import\s+swarm/.test(content);
    const hasAgentsSDK = content.includes('from agents import');
    const hasAssistants = content.includes('client.beta.assistants') || content.includes('client.responses');

    if (!hasOpenAI && !hasSwarm && !hasAgentsSDK && !hasAssistants) continue;
    // If file only has 'from agents import' without openai/swarm, require corroborating evidence
    if (!hasOpenAI && !hasSwarm && hasAgentsSDK && !hasAssistants &&
        !content.includes('function_tool') && !content.includes('Runner')) continue;

    const lines = content.split('\n');

    // Extract assistants
    ASSISTANT_CREATE_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = ASSISTANT_CREATE_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
      const modelMatch = region.match(/model\s*=\s*["']([^"']+)["']/);

      // Extract model
      if (modelMatch) {
        graph.models.push({
          id: `openai-model-${graph.models.length}`,
          name: modelMatch[1],
          provider: 'openai',
          framework: 'openai',
          file: file.relativePath,
          line,
        });
      }

      // Extract tool references from tools=[...]
      const toolIds = extractToolRefsFromRegion(region, graph);

      const agentNode: AgentNode = {
        id: `openai-agent-${graph.agents.length}`,
        name: nameMatch?.[1] ?? `assistant_${line}`,
        framework: 'openai',
        file: file.relativePath,
        line,
        tools: toolIds,
        modelId: modelMatch ? `openai-model-${graph.models.length - 1}` : undefined,
      };

      const instructions = instructionsMatch?.[1] ?? instructionsMatch?.[2];
      if (instructions) {
        agentNode.systemPrompt = instructions;
        graph.prompts.push({
          id: `openai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: instructions,
          hasInstructionGuarding: checkInstructionGuarding(instructions),
          hasSecrets: checkForSecrets(instructions),
          hasUserInputInterpolation: /\{.*\}/.test(instructions),
          scopeClarity: assessScopeClarity(instructions),
        });
      }

      graph.agents.push(agentNode);
    }

    // Extract OpenAI Agents SDK agents
    AGENT_SDK_PATTERN.lastIndex = 0;
    while ((match = AGENT_SDK_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
      const modelMatch = region.match(/model\s*=\s*["']([^"']+)["']/);

      // Extract model
      if (modelMatch) {
        graph.models.push({
          id: `openai-model-${graph.models.length}`,
          name: modelMatch[1],
          provider: 'openai',
          framework: 'openai',
          file: file.relativePath,
          line,
        });
      }

      // Extract tool references — also register function-tools from functions= kwarg
      const funcRefs = extractFunctionRefsFromRegion(region);
      for (const funcName of funcRefs) {
        // Register as tool if not already known
        if (!graph.tools.some(t => t.name === funcName)) {
          graph.tools.push({
            id: `openai-tool-${graph.tools.length}`,
            name: funcName,
            framework: 'openai',
            file: file.relativePath,
            line,
            description: '',
            parameters: [],
            hasSideEffects: false,
            hasInputValidation: false,
            hasSandboxing: false,
            capabilities: ['other'],
          });
        }
      }
      const toolIds = extractToolRefsFromRegion(region, graph);

      // Extract delegation targets (handoffs=[agent1, agent2])
      const delegationTargets = extractDelegationTargets(region);

      const agentNode: AgentNode = {
        id: `openai-agent-${graph.agents.length}`,
        name: nameMatch?.[1] ?? `agent_${line}`,
        framework: 'openai',
        file: file.relativePath,
        line,
        tools: toolIds,
        modelId: modelMatch ? `openai-model-${graph.models.length - 1}` : undefined,
        delegationTargets: delegationTargets.length > 0 ? delegationTargets : undefined,
        delegationEnabled: delegationTargets.length > 0,
      };

      const instructions = instructionsMatch?.[1] ?? instructionsMatch?.[2];
      if (instructions) {
        agentNode.systemPrompt = instructions;
        graph.prompts.push({
          id: `openai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: instructions,
          hasInstructionGuarding: checkInstructionGuarding(instructions),
          hasSecrets: checkForSecrets(instructions),
          hasUserInputInterpolation: /\{.*\}/.test(instructions),
          scopeClarity: assessScopeClarity(instructions),
        });
      }

      graph.agents.push(agentNode);
    }

    // Extract Swarm agents (from swarm import Agent — uses name=, instructions=, functions=)
    if (hasSwarm) {
      SWARM_AGENT_PATTERN.lastIndex = 0;
      while ((match = SWARM_AGENT_PATTERN.exec(content)) !== null) {
        const line = content.substring(0, match.index).split('\n').length;
        // Skip if already captured by AGENT_SDK_PATTERN at same location
        if (graph.agents.some(a => a.framework === 'openai' && a.file === file.relativePath && Math.abs(a.line - line) <= 1)) continue;

        const region = content.substring(match.index, match.index + 2000);

        const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
        const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
        const modelMatch = region.match(/model\s*=\s*["']([^"']+)["']/);

        if (modelMatch) {
          graph.models.push({
            id: `openai-model-${graph.models.length}`,
            name: modelMatch[1],
            provider: 'openai',
            framework: 'openai',
            file: file.relativePath,
            line,
          });
        }

        // Extract function references (Swarm uses functions=[...])
        const funcRefs = extractFunctionRefsFromRegion(region);
        for (const funcName of funcRefs) {
          if (!graph.tools.some(t => t.name === funcName)) {
            graph.tools.push({
              id: `openai-tool-${graph.tools.length}`,
              name: funcName,
              framework: 'openai',
              file: file.relativePath,
              line,
              description: '',
              parameters: [],
              hasSideEffects: false,
              hasInputValidation: false,
              hasSandboxing: false,
              capabilities: ['other'],
            });
          }
        }
        const toolIds = extractToolRefsFromRegion(region, graph);

        const agentNode: AgentNode = {
          id: `openai-agent-${graph.agents.length}`,
          name: nameMatch?.[1] ?? `swarm_agent_${line}`,
          framework: 'openai',
          file: file.relativePath,
          line,
          tools: toolIds,
          modelId: modelMatch ? `openai-model-${graph.models.length - 1}` : undefined,
        };

        const instructions = instructionsMatch?.[1] ?? instructionsMatch?.[2];
        if (instructions) {
          agentNode.systemPrompt = instructions;
          graph.prompts.push({
            id: `openai-prompt-${graph.prompts.length}`,
            file: file.relativePath,
            line,
            type: 'system',
            content: instructions,
            hasInstructionGuarding: checkInstructionGuarding(instructions),
            hasSecrets: checkForSecrets(instructions),
            hasUserInputInterpolation: /\{.*\}/.test(instructions),
            scopeClarity: assessScopeClarity(instructions),
          });
        }

        graph.agents.push(agentNode);
      }
    }

    // Extract function tools
    FUNCTION_TOOL_PATTERN.lastIndex = 0;
    while ((match = FUNCTION_TOOL_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 500);
      const nameMatch = region.match(/name\s*=\s*["']([^"']+)["']/);
      const descMatch = region.match(/description\s*=\s*["']([^"']+)["']/);
      const assignMatch = lines[line - 1]?.match(/(\w+)\s*=/);

      graph.tools.push({
        id: `openai-tool-${graph.tools.length}`,
        name: nameMatch?.[1] ?? assignMatch?.[1] ?? `tool_${line}`,
        framework: 'openai',
        file: file.relativePath,
        line,
        description: descMatch?.[1] ?? '',
        parameters: [],
        hasSideEffects: false,
        hasInputValidation: /schema|parameters|strict/.test(region),
        hasSandboxing: false,
        capabilities: ['other'],
      });
    }

    // Extract responses.create calls (for tool use patterns)
    RESPONSES_CREATE_PATTERN.lastIndex = 0;
    while ((match = RESPONSES_CREATE_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 2000);

      const modelMatch = region.match(/model\s*=\s*["']([^"']+)["']/);
      if (modelMatch) {
        const exists = graph.models.some(
          m => m.name === modelMatch[1] && m.file === file.relativePath,
        );
        if (!exists) {
          graph.models.push({
            id: `openai-model-${graph.models.length}`,
            name: modelMatch[1],
            provider: 'openai',
            framework: 'openai',
            file: file.relativePath,
            line,
          });
        }
      }

      const instructionsMatch = region.match(/instructions\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
      if (instructionsMatch) {
        const instructions = instructionsMatch[1] ?? instructionsMatch[2] ?? '';
        graph.prompts.push({
          id: `openai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: instructions,
          hasInstructionGuarding: checkInstructionGuarding(instructions),
          hasSecrets: checkForSecrets(instructions),
          hasUserInputInterpolation: /\{.*\}/.test(instructions),
          scopeClarity: assessScopeClarity(instructions),
        });
      }
    }
  }

  // Post-pass: bind tools to agents that have empty tool arrays
  for (const agent of graph.agents) {
    if (agent.framework !== 'openai') continue;
    if (agent.tools.length > 0) continue;
    const fileTools = graph.tools.filter(
      t => t.framework === 'openai' && t.file === agent.file,
    );
    agent.tools = fileTools.map(t => t.id);
  }
}

function extractToolRefsFromRegion(region: string, graph: AgentGraph): string[] {
  // Match both tools=[...] and functions=[...] (swarm uses functions=)
  const toolsMatch = region.match(/(?:tools|functions)\s*=\s*\[([^\]]*)\]/);
  if (!toolsMatch) return [];

  const varNames = toolsMatch[1]
    .split(',')
    .map(s => s.trim())
    .filter(s => /^[a-zA-Z_]\w*$/.test(s));

  const ids: string[] = [];
  for (const name of varNames) {
    const tool = graph.tools.find(t => t.name === name || t.id === name);
    if (tool) ids.push(tool.id);
  }
  return ids;
}

function extractFunctionRefsFromRegion(region: string): string[] {
  const functionsMatch = region.match(/functions\s*=\s*\[([^\]]*)\]/);
  if (!functionsMatch) return [];
  return functionsMatch[1]
    .split(',')
    .map(s => s.trim())
    .filter(s => /^[a-zA-Z_]\w*$/.test(s));
}

function extractDelegationTargets(region: string): string[] {
  const handoffsMatch = region.match(/handoffs\s*=\s*\[([^\]]*)\]/);
  if (!handoffsMatch) return [];

  return handoffsMatch[1]
    .split(',')
    .map(s => s.trim())
    .filter(s => /^[a-zA-Z_]\w*$/.test(s));
}

