import * as fs from 'node:fs';
import * as yaml from 'yaml';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';

const CREW_AGENT_PATTERN = /Agent\s*\(/g;
const CREW_TASK_PATTERN = /Task\s*\(/g;
const DELEGATION_PATTERN = /allow_delegation\s*=\s*(True|true)/;

export function parseCrewAI(graph: AgentGraph, files: FileInventory): void {
  // Parse YAML config files first — verify content has CrewAI-specific keys
  for (const file of files.yaml) {
    const basename = file.relativePath.split('/').pop() ?? '';
    if (basename === 'agents.yaml' || basename === 'agents.yml') {
      let content: string;
      try {
        content = fs.readFileSync(file.path, 'utf-8');
      } catch {
        continue;
      }
      // Verify YAML has CrewAI-specific keys (not Ansible, Kubernetes, etc.)
      if (/\b(role|backstory|goal)\s*:/.test(content)) {
        parseAgentsYaml(file.path, file.relativePath, graph);
      }
    }
  }

  // Parse Python files for CrewAI patterns
  for (const file of files.python) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('crewai')) continue;

    const lines = content.split('\n');

    // Extract agents defined in Python
    CREW_AGENT_PATTERN.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = CREW_AGENT_PATTERN.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 1000);

      const roleMatch = region.match(/role\s*=\s*["']([^"']+)["']/);
      const goalMatch = region.match(/goal\s*=\s*["']([^"']+)["']/);
      const backstoryMatch = region.match(/backstory\s*=\s*(?:f?"""([\s\S]*?)"""|f?["']([^"']+)["'])/);
      const delegationEnabled = DELEGATION_PATTERN.test(region);
      const llmMatch = region.match(/llm\s*=\s*["']([^"']+)["']/);

      // Extract model from llm= kwarg
      if (llmMatch) {
        graph.models.push({
          id: `crewai-model-${graph.models.length}`,
          name: llmMatch[1],
          provider: inferProvider(llmMatch[1]),
          framework: 'crewai',
          file: file.relativePath,
          line,
        });
      }

      // Extract tool references
      const toolIds = extractToolRefsFromRegion(region, graph);

      const agentNode: AgentNode = {
        id: `crewai-agent-${graph.agents.length}`,
        name: roleMatch?.[1] ?? `agent_${line}`,
        framework: 'crewai',
        file: file.relativePath,
        line,
        tools: toolIds,
        delegationEnabled,
        modelId: llmMatch ? `crewai-model-${graph.models.length - 1}` : undefined,
      };

      // Backstory is effectively the system prompt
      const backstory = backstoryMatch?.[1] ?? backstoryMatch?.[2];
      if (backstory) {
        agentNode.systemPrompt = backstory;

        graph.prompts.push({
          id: `crewai-prompt-${graph.prompts.length}`,
          file: file.relativePath,
          line,
          type: 'system',
          content: backstory,
          hasInstructionGuarding: /ignore\s+(any\s+)?previous|do\s+not\s+(follow|obey)|under\s+no\s+circumstances|never\s+(reveal|share|disclose)/i.test(backstory),
          hasSecrets: /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|password\s*[:=]\s*["'][^"']{8,}["']/i.test(backstory),
          hasUserInputInterpolation: /\{[a-zA-Z_]\w*\}/.test(backstory) && /^f['"]/.test(region),
          scopeClarity: goalMatch && goalMatch[1].length > 20 ? 'clear' : (goalMatch ? 'vague' : 'missing'),
        });
      }

      graph.agents.push(agentNode);
    }

    // Extract tools
    extractCrewAITools(content, file.relativePath, lines, graph);
  }

  // Post-pass: bind tools to agents that have empty tool arrays
  for (const agent of graph.agents) {
    if (agent.framework !== 'crewai') continue;
    if (agent.tools.length > 0) continue;
    const fileTools = graph.tools.filter(
      t => t.framework === 'crewai' && t.file === agent.file,
    );
    agent.tools = fileTools.map(t => t.id);
  }
}

function parseAgentsYaml(filePath: string, relativePath: string, graph: AgentGraph): void {
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf-8');
  } catch {
    return;
  }

  let parsed: Record<string, any>;
  try {
    parsed = yaml.parse(content);
  } catch {
    return;
  }

  if (!parsed || typeof parsed !== 'object') return;

  for (const [name, config] of Object.entries(parsed)) {
    if (!config || typeof config !== 'object') continue;

    const agentConfig = config as Record<string, any>;
    const line = findKeyLine(content, name);

    // Extract model from llm field in YAML
    if (agentConfig.llm) {
      graph.models.push({
        id: `crewai-model-${graph.models.length}`,
        name: String(agentConfig.llm),
        provider: inferProvider(String(agentConfig.llm)),
        framework: 'crewai',
        file: relativePath,
        line,
      });
    }

    const agentNode: AgentNode = {
      id: `crewai-agent-${graph.agents.length}`,
      name: agentConfig.role ?? name,
      framework: 'crewai',
      file: relativePath,
      line,
      tools: [],
      delegationEnabled: agentConfig.allow_delegation === true,
      modelId: agentConfig.llm ? `crewai-model-${graph.models.length - 1}` : undefined,
    };

    if (agentConfig.backstory) {
      agentNode.systemPrompt = agentConfig.backstory;

      graph.prompts.push({
        id: `crewai-prompt-${graph.prompts.length}`,
        file: relativePath,
        line,
        type: 'system',
        content: agentConfig.backstory,
        hasInstructionGuarding: /ignore\s+(any\s+)?previous|do\s+not\s+(follow|obey)|under\s+no\s+circumstances|never\s+(reveal|share|disclose)/i.test(agentConfig.backstory),
        hasSecrets: /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}/i.test(agentConfig.backstory),
        hasUserInputInterpolation: /\{[a-zA-Z_]\w*\}/.test(agentConfig.backstory),
        scopeClarity: agentConfig.goal && String(agentConfig.goal).length > 20 ? 'clear' : (agentConfig.goal ? 'vague' : 'missing'),
      });
    }

    graph.agents.push(agentNode);
  }
}

function extractCrewAITools(
  content: string,
  filePath: string,
  lines: string[],
  graph: AgentGraph,
): void {
  const toolPatterns = [
    { pattern: /SerperDevTool/g, name: 'SerperDevTool', capabilities: ['network' as const] },
    { pattern: /ScrapeWebsiteTool/g, name: 'ScrapeWebsiteTool', capabilities: ['network' as const] },
    { pattern: /FileReadTool/g, name: 'FileReadTool', capabilities: ['filesystem' as const] },
    { pattern: /DirectoryReadTool/g, name: 'DirectoryReadTool', capabilities: ['filesystem' as const] },
    { pattern: /CodeInterpreterTool/g, name: 'CodeInterpreterTool', capabilities: ['code-execution' as const] },
  ];

  for (const { pattern, name, capabilities } of toolPatterns) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      graph.tools.push({
        id: `crewai-tool-${graph.tools.length}`,
        name,
        framework: 'crewai',
        file: filePath,
        line,
        description: '',
        parameters: [],
        hasSideEffects: capabilities.some(c => ['network', 'filesystem', 'code-execution', 'shell'].includes(c)),
        hasInputValidation: false,
        hasSandboxing: false,
        capabilities,
      });
    }
  }
}

function extractToolRefsFromRegion(region: string, graph: AgentGraph): string[] {
  const toolsMatch = region.match(/tools\s*=\s*\[([^\]]*)\]/);
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

function inferProvider(modelName: string): string {
  const lower = modelName.toLowerCase();
  if (lower.includes('gpt') || lower.includes('o1') || lower.includes('o3')) return 'openai';
  if (lower.includes('claude')) return 'anthropic';
  if (lower.includes('gemini')) return 'google';
  if (lower.includes('llama') || lower.includes('mistral')) return 'meta/mistral';
  if (lower.includes('bedrock')) return 'aws-bedrock';
  return 'unknown';
}

function findKeyLine(content: string, key: string): number {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(key + ':') || lines[i].startsWith(`"${key}":`)) {
      return i + 1;
    }
  }
  return 1;
}
