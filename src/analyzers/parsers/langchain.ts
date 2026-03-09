import * as fs from 'node:fs';
import type { FileInventory } from '../../types/common.js';
import type { AgentGraph, AgentNode, ToolNode, PromptNode } from '../../types/agent-graph.js';
import {
  isTreeSitterAvailable,
  getFileTreeForLang,
  findFunctionCalls,
  findNodes,
  type Tree,
} from '../ast/index.js';
import {
  findDecorators,
  getDecoratedFunction,
  findClassDefinitions,
  getKeywordArgInt,
  getKeywordArgString,
  getKeywordArgBool,
} from '../ast/python.js';
import { getKeywordArgument, extractStringValue, findImports } from '../ast/queries.js';
import {
  detectCapabilities as sharedDetectCapabilities,
  checkInstructionGuarding as sharedCheckInstructionGuarding,
  checkForSecrets as sharedCheckForSecrets,
  checkUserInputInterpolation as sharedCheckUserInputInterpolation,
  assessScopeClarity as sharedAssessScopeClarity,
} from './shared.js';

const AGENT_PATTERNS = [
  { pattern: /AgentExecutor\s*\(/g, name: 'AgentExecutor' },
  { pattern: /AgentExecutor\.from_agent_and_tools\s*\(/g, name: 'AgentExecutor' },
  { pattern: /create_react_agent\s*\(/g, name: 'ReactAgent' },
  { pattern: /create_openai_functions_agent\s*\(/g, name: 'OpenAIFunctionsAgent' },
  { pattern: /create_tool_calling_agent\s*\(/g, name: 'ToolCallingAgent' },
  { pattern: /StateGraph\s*\(/g, name: 'LangGraphAgent' },
  { pattern: /create_structured_chat_agent\s*\(/g, name: 'StructuredChatAgent' },
  { pattern: /ConversationalChatAgent\.from_llm_and_tools\s*\(/g, name: 'ConversationalChatAgent' },
  { pattern: /ConversationalAgent\.from_llm_and_tools\s*\(/g, name: 'ConversationalAgent' },
  { pattern: /ZeroShotAgent\.from_llm_and_tools\s*\(/g, name: 'ZeroShotAgent' },
  { pattern: /initialize_agent\s*\(/g, name: 'InitializedAgent' },
  { pattern: /create_csv_agent\s*\(/g, name: 'CSVAgent' },
  { pattern: /create_pandas_dataframe_agent\s*\(/g, name: 'PandasAgent' },
  { pattern: /create_sql_agent\s*\(/g, name: 'SQLAgent' },
  { pattern: /create_json_agent\s*\(/g, name: 'JSONAgent' },
  { pattern: /create_openapi_agent\s*\(/g, name: 'OpenAPIAgent' },
];

const TOOL_PATTERNS = [
  { pattern: /@tool\b/g, type: 'decorator' },
  { pattern: /Tool\s*\(\s*\n?\s*name\s*=/g, type: 'constructor' },
  { pattern: /StructuredTool/g, type: 'class' },
  { pattern: /BaseTool/g, type: 'class' },
  { pattern: /ShellTool/g, type: 'shell' },
  { pattern: /PythonREPLTool/g, type: 'code-exec' },
  { pattern: /SQLDatabaseToolkit/g, type: 'database' },
  { pattern: /FileManagementToolkit/g, type: 'filesystem' },
  { pattern: /RequestsToolkit/g, type: 'network' },
  // Common LangChain community tools
  { pattern: /TavilySearch\s*\(/g, type: 'network' },
  { pattern: /TavilySearchResults\s*\(/g, type: 'network' },
  { pattern: /DuckDuckGoSearchRun\s*\(/g, type: 'network' },
  { pattern: /WikipediaQueryRun\s*\(/g, type: 'network' },
  { pattern: /ArxivQueryRun\s*\(/g, type: 'network' },
  { pattern: /BraveSearchRun\s*\(/g, type: 'network' },
  { pattern: /GoogleSerperRun\s*\(/g, type: 'network' },
  { pattern: /SerpAPIWrapper\s*\(/g, type: 'network' },
  { pattern: /WebBrowser\s*\(/g, type: 'network' },
  { pattern: /WolframAlphaQueryRun\s*\(/g, type: 'network' },
  // LangGraph ToolNode
  { pattern: /ToolNode\s*\(/g, type: 'constructor' },
];

const MEMORY_PATTERNS = [
  /ConversationBufferMemory/,
  /ConversationBufferWindowMemory/,
  /ConversationSummaryMemory/,
  /RedisChatMessageHistory/,
  /PostgresChatMessageHistory/,
  /MemorySaver/,
];

const MODEL_CONSTRUCTORS: Record<string, string> = {
  ChatOpenAI: 'openai',
  OpenAI: 'openai',
  ChatAnthropic: 'anthropic',
  Anthropic: 'anthropic',
  BedrockChat: 'aws-bedrock',
  ChatBedrock: 'aws-bedrock',
  ChatOllama: 'ollama',
  OllamaLLM: 'ollama',
  ChatGoogleGenerativeAI: 'google',
  ChatCohere: 'cohere',
  ChatVertexAI: 'google',
  AzureChatOpenAI: 'azure-openai',
  ChatFireworks: 'fireworks',
  ChatTogether: 'together',
};

export function parseLangChain(graph: AgentGraph, files: FileInventory): void {
  const codeFiles = [...files.python, ...files.typescript, ...files.javascript];

  for (const file of codeFiles) {
    let content: string;
    try {
      content = fs.readFileSync(file.path, 'utf-8');
    } catch {
      continue;
    }

    if (!content.includes('langchain') && !content.includes('langgraph')) continue;

    const lines = content.split('\n');
    const isPython = file.language === 'python';
    const tree = isPython && isTreeSitterAvailable()
      ? getFileTreeForLang(file.path, content, 'python')
      : null;

    if (tree) {
      extractModelsAST(tree, file.relativePath, graph);
      extractAgentsAST(tree, content, lines, file.relativePath, graph);
      extractToolsAST(tree, content, lines, file.relativePath, graph);
    } else {
      extractModelsRegex(content, file.relativePath, graph);
      extractAgentsRegex(content, lines, file.relativePath, graph);
      extractToolsRegex(content, lines, file.relativePath, graph);
    }

    // Prompts use a mix of AST and regex
    extractPrompts(content, file.relativePath, lines, graph);
  }

  // Post-pass: bind tools to agents
  bindToolsToAgents(graph);
}

function extractModelsAST(
  tree: Tree,
  filePath: string,
  graph: AgentGraph,
): void {
  const modelPattern = new RegExp(
    `^(${Object.keys(MODEL_CONSTRUCTORS).join('|')})$`,
  );
  const calls = findFunctionCalls(tree, modelPattern);

  for (const call of calls) {
    const callee = call.childForFieldName('function');
    const constructorName = callee?.text ?? '';
    const provider = MODEL_CONSTRUCTORS[constructorName] ?? 'unknown';
    const line = call.startPosition.row + 1;

    // Try model= or model_name= kwarg
    const modelName =
      getKeywordArgString(call, 'model') ??
      getKeywordArgString(call, 'model_name') ??
      getKeywordArgString(call, 'model_id') ??
      undefined;

    graph.models.push({
      id: `langchain-model-${graph.models.length}`,
      name: modelName ?? constructorName,
      provider,
      framework: 'langchain',
      file: filePath,
      line,
    });
  }
}

function extractModelsRegex(
  content: string,
  filePath: string,
  graph: AgentGraph,
): void {
  for (const [constructor, provider] of Object.entries(MODEL_CONSTRUCTORS)) {
    const pattern = new RegExp(`${constructor}\\s*\\(`, 'g');
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const region = content.substring(match.index, match.index + 500);
      const modelMatch = region.match(/(?:model|model_name|model_id)\s*=\s*["']([^"']+)["']/);

      graph.models.push({
        id: `langchain-model-${graph.models.length}`,
        name: modelMatch?.[1] ?? constructor,
        provider,
        framework: 'langchain',
        file: filePath,
        line,
      });
    }
  }
}

function extractAgentsAST(
  tree: Tree,
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  const agentCallPatterns = /^(AgentExecutor|create_react_agent|create_openai_functions_agent|create_tool_calling_agent|StateGraph|create_structured_chat_agent|initialize_agent|create_csv_agent|create_pandas_dataframe_agent|create_sql_agent|create_json_agent|create_openapi_agent)$/;
  const agentCalls = findFunctionCalls(tree, agentCallPatterns);

  // Also find class method patterns: ClassName.from_llm_and_tools(), AgentExecutor.from_agent_and_tools()
  const classMethodNames = [
    /^(?:ConversationalChatAgent|ConversationalAgent|ZeroShotAgent)\.from_llm_and_tools$/,
    /^AgentExecutor\.from_agent_and_tools$/,
  ];
  const classMethodAgentCalls = findNodes(tree, (node) => {
    if (node.type !== 'call') return false;
    const fn = node.childForFieldName('function');
    if (!fn) return false;
    const fnText = fn.text;
    return classMethodNames.some(p => p.test(fnText));
  });
  agentCalls.push(...classMethodAgentCalls);

  for (const call of agentCalls) {
    const callee = call.childForFieldName('function');
    let name = callee?.text ?? 'Agent';
    // Normalize class method names: ConversationalChatAgent.from_llm_and_tools → ConversationalChatAgent
    if (name.includes('.')) {
      name = name.split('.')[0];
    }

    // Skip agent-creation functions (create_react_agent, etc.) that are nested
    // as arguments to AgentExecutor — they create the chain, not the executor
    if (name !== 'AgentExecutor' && name !== 'StateGraph') {
      let parent = call.parent;
      while (parent) {
        if ((parent.type === 'call' || parent.type === 'call_expression') &&
            parent.childForFieldName('function')?.text === 'AgentExecutor') {
          break;
        }
        parent = parent.parent;
      }
      if (parent) continue; // nested inside AgentExecutor, skip
    }

    const line = call.startPosition.row + 1;
    const memoryType = detectMemory(content);

    const maxIterations = getKeywordArgInt(call, 'max_iterations') ?? undefined;

    // Extract tools= kwarg for tool binding
    const toolIds = extractToolIdsFromKwarg(call, lines, graph);

    const agentNode: AgentNode = {
      id: `langchain-agent-${graph.agents.length}`,
      name: extractAssignmentName(lines, line) || name,
      framework: 'langchain',
      file: filePath,
      line,
      tools: toolIds,
      memoryType,
      maxIterations,
    };

    // Try to link model
    const modelId = findNearestModelId(content, line, graph);
    if (modelId) agentNode.modelId = modelId;

    const systemPrompt = extractSystemPromptNear(content, call.startPosition.row);
    if (systemPrompt) {
      agentNode.systemPrompt = systemPrompt;
    }

    graph.agents.push(agentNode);
  }
}

function extractToolIdsFromKwarg(
  call: import('../ast/parser.js').SyntaxNode,
  lines: string[],
  graph: AgentGraph,
): string[] {
  const toolsArg = getKeywordArgument(call, 'tools');
  if (!toolsArg) return [];

  // tools=[tool1, tool2, ...]  — extract identifiers from list
  if (toolsArg.type === 'list') {
    const names: string[] = [];
    for (const child of toolsArg.children) {
      if (child.type === 'identifier') {
        names.push(child.text);
      }
    }
    return matchToolNamesToIds(names, graph);
  }

  // tools=some_var — single variable reference
  if (toolsArg.type === 'identifier') {
    return matchToolNamesToIds([toolsArg.text], graph);
  }

  return [];
}

function matchToolNamesToIds(varNames: string[], graph: AgentGraph): string[] {
  const ids: string[] = [];
  for (const varName of varNames) {
    const tool = graph.tools.find(
      t => t.name === varName || t.id === varName,
    );
    if (tool) {
      ids.push(tool.id);
    }
  }
  return ids;
}

function findNearestModelId(
  content: string,
  agentLine: number,
  graph: AgentGraph,
): string | undefined {
  // Find the model node closest to (and before) the agent line in the same file
  let bestModel: string | undefined;
  let bestDist = Infinity;

  for (const model of graph.models) {
    const dist = agentLine - model.line;
    if (dist >= 0 && dist < bestDist) {
      bestDist = dist;
      bestModel = model.id;
    }
  }
  return bestModel;
}

function extractToolsAST(
  tree: Tree,
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  // Find @tool decorated functions
  const toolDecorators = findDecorators(tree, 'tool');
  for (const dec of toolDecorators) {
    const func = getDecoratedFunction(dec);
    const funcName = func?.childForFieldName('name')?.text;
    const line = dec.startPosition.row + 1;

    // Extract docstring as description
    let description = '';
    const body = func?.childForFieldName('body');
    if (body) {
      const firstStmt = body.children[0];
      if (firstStmt?.type === 'expression_statement') {
        const expr = firstStmt.children[0];
        if (expr?.type === 'string') {
          description = expr.text.replace(/^["']{1,3}|["']{1,3}$/g, '').trim();
        }
      }
    }

    // Detect capabilities from function body
    const funcText = func?.text ?? '';
    const capabilities = detectCapabilities(funcText);

    graph.tools.push({
      id: `langchain-tool-${graph.tools.length}`,
      name: funcName ?? `tool_${line}`,
      framework: 'langchain',
      file: filePath,
      line,
      description,
      parameters: [],
      hasSideEffects: capabilities.length > 0 && !capabilities.every(c => c === 'other'),
      hasInputValidation: false,
      hasSandboxing: false,
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }

  // Find known tool constructors
  const knownTools = [
    { pattern: /^ShellTool$/, type: 'shell' },
    { pattern: /^PythonREPLTool$/, type: 'code-exec' },
    { pattern: /^SQLDatabaseToolkit$/, type: 'database' },
    { pattern: /^FileManagementToolkit$/, type: 'filesystem' },
    { pattern: /^RequestsToolkit$/, type: 'network' },
    { pattern: /^StructuredTool$/, type: 'class' },
    { pattern: /^BaseTool$/, type: 'class' },
  ];

  for (const { pattern, type } of knownTools) {
    const calls = findFunctionCalls(tree, pattern);
    for (const call of calls) {
      const line = call.startPosition.row + 1;
      const toolName = extractAssignmentName(lines, line) || call.childForFieldName('function')?.text || `tool_${line}`;

      // Extract description= kwarg if present
      const descKwarg = getKeywordArgString(call, 'description');

      graph.tools.push({
        id: `langchain-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'langchain',
        file: filePath,
        line,
        description: descKwarg ?? '',
        parameters: [],
        hasSideEffects: ['shell', 'code-exec', 'database', 'filesystem', 'network'].includes(type),
        hasInputValidation: type === 'class',
        hasSandboxing: false,
        capabilities: mapToolType(type),
      });
    }
  }

  // Find Tool() constructor calls with name= kwarg
  const toolConstructors = findFunctionCalls(tree, /^Tool$/);
  for (const call of toolConstructors) {
    const line = call.startPosition.row + 1;
    const nameKwarg = getKeywordArgString(call, 'name');
    const descKwarg = getKeywordArgString(call, 'description');

    graph.tools.push({
      id: `langchain-tool-${graph.tools.length}`,
      name: nameKwarg ?? extractAssignmentName(lines, line) ?? `tool_${line}`,
      framework: 'langchain',
      file: filePath,
      line,
      description: descKwarg ?? '',
      parameters: [],
      hasSideEffects: false,
      hasInputValidation: false,
      hasSandboxing: false,
      capabilities: ['other'],
    });
  }

  // --- Generic inheritance-based tool detection ---
  // Find any class that inherits from BaseTool or StructuredTool.
  // This catches custom tool classes regardless of naming convention.
  // e.g. class MySearchTool(BaseTool): ...
  const TOOL_BASE_CLASSES = ['BaseTool', 'StructuredTool'];
  const existingToolLines = new Set(graph.tools.filter(t => t.file === filePath).map(t => t.line));
  const allClasses = findClassDefinitions(tree);

  for (const classDef of allClasses) {
    const superclassesNode = classDef.childForFieldName('superclasses');
    if (!superclassesNode) continue;

    // Check if any base class is a known tool base class
    const bases = superclassesNode.text; // e.g. "(BaseTool)" or "(BaseTool, ABC)"
    const isToolSubclass = TOOL_BASE_CLASSES.some(base =>
      new RegExp(`\\b${base}\\b`).test(bases),
    );
    if (!isToolSubclass) continue;

    const className = classDef.childForFieldName('name')?.text;
    const line = classDef.startPosition.row + 1;

    // Skip if we already detected a tool at this line (from constructor patterns above)
    if (existingToolLines.has(line)) continue;

    // Extract name and description from class body attributes
    const body = classDef.childForFieldName('body');
    let toolName = className ?? `tool_${line}`;
    let description = '';

    if (body) {
      for (const stmt of body.children) {
        if (stmt.type !== 'expression_statement') continue;
        const expr = stmt.children[0];
        if (expr?.type !== 'assignment') continue;

        const left = expr.childForFieldName('left')?.text;
        const right = expr.childForFieldName('right');
        if (!left || !right) continue;

        if (left === 'name') {
          const val = right.text.replace(/^["']|["']$/g, '');
          if (val) toolName = val;
        }
        if (left === 'description') {
          const val = right.text.replace(/^["']|["']$/g, '');
          if (val) description = val;
        }
      }
    }

    // Detect capabilities from class body text
    const classText = classDef.text;
    const capabilities = detectCapabilities(classText);

    graph.tools.push({
      id: `langchain-tool-${graph.tools.length}`,
      name: toolName,
      framework: 'langchain',
      file: filePath,
      line,
      description,
      parameters: [],
      hasSideEffects: capabilities.length > 0 && !capabilities.every(c => c === 'other'),
      hasInputValidation: true, // subclasses typically validate via Pydantic schema
      hasSandboxing: false,
      capabilities: capabilities.length > 0 ? capabilities : ['other'],
    });
  }
}

function extractAgentsRegex(
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
      const memoryType = detectMemory(content);
      const region = content.substring(match.index, match.index + 1000);

      // Extract tools from regex
      const toolIds = extractToolIdsFromRegex(region, graph);

      const agentNode: AgentNode = {
        id: `langchain-agent-${graph.agents.length}`,
        name: extractAssignmentName(lines, line) || name,
        framework: 'langchain',
        file: filePath,
        line,
        tools: toolIds,
        memoryType,
        maxIterations: extractMaxIterations(content, match.index),
      };

      const modelId = findNearestModelId(content, line, graph);
      if (modelId) agentNode.modelId = modelId;

      const systemPrompt = extractSystemPromptNear(content, match.index);
      if (systemPrompt) {
        agentNode.systemPrompt = systemPrompt;
      }

      graph.agents.push(agentNode);
    }
  }
}

function extractToolIdsFromRegex(region: string, graph: AgentGraph): string[] {
  const toolsMatch = region.match(/tools\s*=\s*\[([^\]]*)\]/);
  if (!toolsMatch) return [];

  const varNames = toolsMatch[1]
    .split(',')
    .map(s => s.trim())
    .filter(s => /^[a-zA-Z_]\w*$/.test(s));

  return matchToolNamesToIds(varNames, graph);
}

function extractToolsRegex(
  content: string,
  lines: string[],
  filePath: string,
  graph: AgentGraph,
): void {
  for (const { pattern, type } of TOOL_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = content.substring(0, match.index).split('\n').length;
      const toolName = extractToolName(lines, line, type);
      const region = content.substring(match.index, match.index + 500);

      // Extract description from docstring or kwarg
      let description = '';
      if (type === 'decorator') {
        const docMatch = region.match(/"""([\s\S]*?)"""|'''([\s\S]*?)'''/);
        description = (docMatch?.[1] ?? docMatch?.[2] ?? '').trim();
      } else if (type === 'constructor') {
        const descMatch = region.match(/description\s*=\s*["']([^"']+)["']/);
        description = descMatch?.[1] ?? '';
      }

      const toolNode: ToolNode = {
        id: `langchain-tool-${graph.tools.length}`,
        name: toolName,
        framework: 'langchain',
        file: filePath,
        line,
        description,
        parameters: [],
        hasSideEffects: ['shell', 'code-exec', 'database', 'filesystem', 'network'].includes(type),
        hasInputValidation: type === 'class',
        hasSandboxing: false,
        capabilities: mapToolType(type),
      };

      graph.tools.push(toolNode);
    }
  }

  // --- Generic inheritance-based tool detection (regex fallback) ---
  // Catches: class MyTool(BaseTool): ... or class MyTool(StructuredTool): ...
  const classPattern = /^class\s+(\w+)\s*\(\s*(?:\w+\s*,\s*)*(BaseTool|StructuredTool)(?:\s*,\s*\w+)*\s*\)\s*:/gm;
  const existingToolLines = new Set(graph.tools.filter(t => t.file === filePath).map(t => t.line));
  let classMatch: RegExpExecArray | null;
  while ((classMatch = classPattern.exec(content)) !== null) {
    const className = classMatch[1];
    const line = content.substring(0, classMatch.index).split('\n').length;

    if (existingToolLines.has(line)) continue;

    // Look for name = "..." and description = "..." in the class body
    const bodyStart = classMatch.index + classMatch[0].length;
    const bodyRegion = content.substring(bodyStart, bodyStart + 1000);
    const nameMatch = bodyRegion.match(/^\s+name\s*(?::\s*str\s*)?=\s*["']([^"']+)["']/m);
    const descMatch = bodyRegion.match(/^\s+description\s*(?::\s*str\s*)?=\s*["']([^"']+)["']/m);

    graph.tools.push({
      id: `langchain-tool-${graph.tools.length}`,
      name: nameMatch?.[1] ?? className,
      framework: 'langchain',
      file: filePath,
      line,
      description: descMatch?.[1] ?? '',
      parameters: [],
      hasSideEffects: false,
      hasInputValidation: true,
      hasSandboxing: false,
      capabilities: ['other'],
    });
  }
}

function bindToolsToAgents(graph: AgentGraph): void {
  // For agents that still have empty tool arrays, try to bind based on file proximity
  for (const agent of graph.agents) {
    if (agent.framework !== 'langchain') continue;
    if (agent.tools.length > 0) continue;

    // Fall back to binding all tools in the same file
    const fileTools = graph.tools.filter(
      t => t.framework === 'langchain' && t.file === agent.file,
    );
    agent.tools = fileTools.map(t => t.id);
  }
}

function extractAssignmentName(lines: string[], lineNum: number): string | undefined {
  const line = lines[lineNum - 1];
  if (!line) return undefined;
  const match = line.match(/(\w+)\s*=/);
  return match?.[1];
}

function extractMaxIterations(content: string, startIndex: number): number | undefined {
  const region = content.substring(startIndex, startIndex + 500);
  const match = region.match(/max_iterations\s*=\s*(\d+)/);
  return match ? parseInt(match[1]) : undefined;
}

function extractSystemPromptNear(content: string, index: number): string | undefined {
  const start = Math.max(0, typeof index === 'number' ? index - 2000 : 0);
  const end = typeof index === 'number' ? index + 2000 : content.length;
  const region = content.substring(start, end);

  // Direct inline: SystemMessage(content="...")
  const inlineMatch = region.match(/SystemMessage\s*\(\s*content\s*=\s*["'`]([\s\S]*?)["'`]\s*\)/);
  if (inlineMatch) return inlineMatch[1];

  // Variable reference: system_message=some_var — resolve the variable
  const varRefMatch = region.match(/system_message\s*=\s*(\w+)/);
  if (varRefMatch) {
    const varName = varRefMatch[1];
    const varPattern = new RegExp(
      `${varName}\\s*=\\s*(?:f?"""([\\s\\S]*?)"""|f?'''([\\s\\S]*?)'''|f?["'\`]([\\s\\S]*?)["'\`])`,
    );
    const varMatch = content.match(varPattern);
    if (varMatch) return varMatch[1] ?? varMatch[2] ?? varMatch[3];
  }

  return undefined;
}

function extractToolName(lines: string[], lineNum: number, type: string): string {
  if (type === 'decorator') {
    const nextLine = lines[lineNum];
    if (nextLine) {
      const funcMatch = nextLine.match(/def\s+(\w+)/);
      if (funcMatch) return funcMatch[1];
    }
  }
  const line = lines[lineNum - 1];
  if (line) {
    const nameMatch = line.match(/name\s*=\s*["']([^"']+)["']/);
    if (nameMatch) return nameMatch[1];
    const assignMatch = line.match(/(\w+)\s*=/);
    if (assignMatch) return assignMatch[1];
  }
  return `tool_${lineNum}`;
}

function mapToolType(type: string): ToolNode['capabilities'] {
  switch (type) {
    case 'shell': return ['shell'];
    case 'code-exec': return ['code-execution'];
    case 'database': return ['database'];
    case 'filesystem': return ['filesystem'];
    case 'network': return ['network'];
    default: return ['other'];
  }
}

function detectMemory(content: string): string | undefined {
  for (const pattern of MEMORY_PATTERNS) {
    if (pattern.test(content)) {
      const match = content.match(pattern);
      return match?.[0];
    }
  }
  return undefined;
}

function detectCapabilities(body: string): ToolNode['capabilities'] {
  return sharedDetectCapabilities(body);
}

function extractPrompts(
  content: string,
  filePath: string,
  lines: string[],
  graph: AgentGraph,
): void {
  // Extract SystemMessage content
  const systemMsgPattern = /SystemMessage\s*\(\s*content\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([\s\S]*?)["'])\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = systemMsgPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `langchain-prompt-${graph.prompts.length}`,
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

  // Extract ChatPromptTemplate.from_messages with ("system", "...") tuples
  const chatPromptPattern = /\(\s*["']system["']\s*,\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["']([\s\S]*?)["'])\s*\)/g;
  while ((match = chatPromptPattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    if (promptContent.length < 10) continue; // skip trivial
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `langchain-prompt-${graph.prompts.length}`,
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

  // Extract template strings assigned to prompt-like variables
  const templatePattern = /(?:system_prompt|system_message|system_msg|SYSTEM_PROMPT|SYSTEM_MESSAGE|SYSTEM_MSG|sys_prompt|sys_msg|instructions|agent_instructions|prefix|suffix|prompt_template|prompt)\s*=\s*(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)'''|f?["'`]([\s\S]*?)["'`])/g;
  while ((match = templatePattern.exec(content)) !== null) {
    const promptContent = match[1] ?? match[2] ?? match[3] ?? '';
    const line = content.substring(0, match.index).split('\n').length;

    graph.prompts.push({
      id: `langchain-prompt-${graph.prompts.length}`,
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

  // --- Import-scoped prompt extraction ---
  // Only runs in files that import LangChain prompt classes.
  // Scans ALL string constants (50+ chars) for instruction-like content.
  // This is generic: it doesn't depend on variable names or string formatting.
  const PROMPT_IMPORT_MARKERS = [
    'ChatPromptTemplate', 'SystemMessagePromptTemplate',
    'HumanMessagePromptTemplate', 'PromptTemplate',
    'MessagesPlaceholder', 'BasePromptTemplate',
    'FewShotPromptTemplate', 'PipelinePromptTemplate',
  ];

  const hasPromptImport = PROMPT_IMPORT_MARKERS.some(marker => content.includes(marker));
  if (!hasPromptImport) return; // Not a prompt-related file — skip

  // Keywords that indicate a string is an LLM instruction (not a docstring or error msg)
  const INSTRUCTION_KEYWORDS = [
    /\byou (?:are|shall|should|must|will|can)\b/i,
    /\byour (?:role|task|job|goal|purpose)\b/i,
    /\banswer\b.*\b(?:concise|markdown|format|language)\b/i,
    /\bdo not\b.*\b(?:invent|hallucinate|apologize|make up)\b/i,
    /\bgiven (?:a |the )?(?:following|context|chat|user|document)/i,
    /\b(?:formulate|rephrase|reformulate|determine|split)\b.*\b(?:task|question|input|query)\b/i,
    /\{[\w_]+\}/,  // Has template variables like {task}, {context}
  ];

  // Minimum keyword hits to consider a string a prompt (avoid FPs from docstrings)
  const MIN_KEYWORD_HITS = 2;

  // Collect lines where we already found prompts (to avoid duplicates)
  const existingPromptLines = new Set(
    graph.prompts.filter(p => p.file === filePath).map(p => p.line),
  );

  // Extract all string constants >= 50 chars
  // Handles: "...", '...', """...""", '''...''', and parenthesized string concatenation
  const stringBlocks = extractStringBlocks(content, lines);

  for (const block of stringBlocks) {
    if (block.text.length < 50) continue;

    // Skip if we already have a prompt near this line
    let isDuplicate = false;
    for (const existingLine of existingPromptLines) {
      if (Math.abs(existingLine - block.line) <= 3) { isDuplicate = true; break; }
    }
    if (isDuplicate) continue;

    // Count instruction keyword hits
    let hits = 0;
    for (const kw of INSTRUCTION_KEYWORDS) {
      if (kw.test(block.text)) hits++;
    }
    if (hits < MIN_KEYWORD_HITS) continue;

    graph.prompts.push({
      id: `langchain-prompt-${graph.prompts.length}`,
      file: filePath,
      line: block.line,
      type: 'system',
      content: block.text,
      hasInstructionGuarding: checkInstructionGuarding(block.text),
      hasSecrets: checkForSecrets(block.text),
      hasUserInputInterpolation: checkUserInputInterpolation(block.text, block.text),
      scopeClarity: assessScopeClarity(block.text),
    });
    existingPromptLines.add(block.line);
  }
}

/**
 * Extract all substantial string blocks from Python source.
 * Handles triple-quoted strings, single-line strings, and
 * parenthesized multi-line string concatenation.
 */
function extractStringBlocks(
  content: string,
  lines: string[],
): Array<{ text: string; line: number }> {
  const blocks: Array<{ text: string; line: number }> = [];

  // Triple-quoted strings: """...""" or '''...'''
  const triplePattern = /(?:f?"""([\s\S]*?)"""|f?'''([\s\S]*?)''')/g;
  let match: RegExpExecArray | null;
  while ((match = triplePattern.exec(content)) !== null) {
    const text = match[1] ?? match[2] ?? '';
    const line = content.substring(0, match.index).split('\n').length;
    blocks.push({ text, line });
  }

  // Parenthesized multi-line string concatenation:
  //   variable = (
  //       "string part 1"
  //       "string part 2"
  //   )
  // This is a common Python pattern for long strings without triple quotes.
  for (let i = 0; i < lines.length; i++) {
    // Look for: variable_name = ( or variable_name += (
    if (!/\w+\s*(?:=|\+=)\s*\(\s*$/.test(lines[i])) continue;

    // Collect all string parts until closing )
    const parts: string[] = [];
    for (let j = i + 1; j < lines.length; j++) {
      const trimmed = lines[j].trim();
      if (trimmed === ')' || trimmed.startsWith(')')) break;

      // Extract string content from this line
      const strMatch = trimmed.match(/^f?["'](.*?)["']\s*$/);
      if (strMatch) parts.push(strMatch[1]);
    }

    if (parts.length > 0) {
      blocks.push({ text: parts.join(' '), line: i + 1 });
    }
  }

  return blocks;
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
