import * as crypto from 'node:crypto';
import type { FileInventory, FileInfo } from '../types/common.js';
import type { AgentGraph } from '../types/agent-graph.js';
import type { DetectionSummary } from './detector.js';
import { detectFrameworks } from './detector.js';
import { parseLangChain } from '../analyzers/parsers/langchain.js';
import { parseCrewAI } from '../analyzers/parsers/crewai.js';
import { parseMCP } from '../analyzers/parsers/mcp.js';
import { parseOpenAI } from '../analyzers/parsers/openai.js';
import { parseVercelAI } from '../analyzers/parsers/vercel-ai.js';
import { parseBedrock } from '../analyzers/parsers/bedrock.js';
import { parseAutoGen } from '../analyzers/parsers/autogen.js';
import { parseLangChain4j } from '../analyzers/parsers/langchain4j.js';
import { parseSpringAI } from '../analyzers/parsers/spring-ai.js';
import { parseGolangAI } from '../analyzers/parsers/golang-ai.js';
import { isTestFile } from '../analyzers/engine.js';
import { ASTStore } from '../analyzers/ast/store.js';
import { ModuleGraph } from '../analyzers/ast/module-graph.js';

/**
 * Filter test files from FileInventory so parsers don't register
 * test agents/tools/prompts into the graph.
 *
 * Test status is judged by each file's path RELATIVE to the scan root, not its
 * absolute path — otherwise scanning a project that itself lives under a
 * directory like `tests/`, `examples/`, or `fixtures/` (or a repo named with
 * "test") would filter out every file and silently discover nothing.
 *
 * As a safety net, if filtering would remove *all* files in a language bucket,
 * the originals are kept — a project made entirely of "test-looking" paths is
 * still worth analyzing, and finding nothing is the worse failure mode.
 */
export function filterTestFiles(files: FileInventory): FileInventory {
  // Normalize to a leading-slash relative path so directory patterns anchored
  // like /\/tests?\// still match a *top-level* tests/ dir (which has no leading
  // slash in a relativePath), while the scan-root prefix is excluded.
  const relPath = (f: FileInfo) => '/' + (f.relativePath || f.path).replace(/^\/+/, '');
  const filter = (list: FileInfo[]) => {
    const kept = list.filter(f => !isTestFile(relPath(f)));
    return kept.length === 0 && list.length > 0 ? list : kept;
  };
  return {
    ...files,
    all: filter(files.all),
    python: filter(files.python),
    typescript: filter(files.typescript),
    javascript: filter(files.javascript),
    java: files.java ? filter(files.java) : [],
    go: files.go ? filter(files.go) : [],
  };
}

/**
 * Build agent graph with optional pre-built ASTStore.
 * When called from the pipeline, ASTStore is created first and shared
 * with both detection and graph building to avoid double-parsing.
 */
export function buildAgentGraph(
  rootPath: string,
  files: FileInventory,
  detection: DetectionSummary,
  includeTests = false,
  existingAstStore?: ASTStore,
): AgentGraph {
  // Filter test files for parsers (don't register test agents/tools).
  // graph.files stays unfiltered so YAML rules can scan all source files;
  // the engine handles test-file findings with severity downgrade/removal.
  const filteredFiles = includeTests ? files : filterTestFiles(files);

  // Reuse existing AST store or create a new one
  const astStore = existingAstStore ?? new ASTStore();
  if (!existingAstStore) astStore.parseAll(files.all);

  const graph: AgentGraph = {
    id: crypto.randomUUID(),
    rootPath,
    primaryFramework: detection.primary,
    secondaryFrameworks: detection.secondary,
    agents: [],
    tools: [],
    prompts: [],
    configs: [],
    models: [],
    vectorDBs: [],
    frameworkVersions: [],
    interAgentLinks: [],
    files,
    permissions: [],
    apiEndpoints: [],
    databaseAccesses: [],
    authFlows: [],
    permissionChecks: [],
    piiReferences: [],
    messageQueues: [],
    rateLimits: [],
    callGraph: [],
    astStore,
    moduleGraph: ModuleGraph.build(astStore, rootPath),
    edges: [],
    llmCalls: [],
    dataStores: [],
    apiCalls: [],
  };

  const frameworks = [detection.primary, ...detection.secondary];

  for (const framework of frameworks) {
    switch (framework) {
      case 'langchain':
        parseLangChain(graph, filteredFiles);
        break;
      case 'crewai':
        parseCrewAI(graph, filteredFiles);
        break;
      case 'mcp':
        parseMCP(graph, filteredFiles);
        break;
      case 'openai':
        parseOpenAI(graph, filteredFiles);
        break;
      case 'vercel-ai':
        parseVercelAI(graph, filteredFiles);
        break;
      case 'bedrock':
        parseBedrock(graph, filteredFiles);
        break;
      case 'autogen':
        parseAutoGen(graph, filteredFiles);
        break;
      case 'langchain4j':
        parseLangChain4j(graph, filteredFiles);
        break;
      case 'spring-ai':
        parseSpringAI(graph, filteredFiles);
        break;
      case 'golang-ai':
        parseGolangAI(graph, filteredFiles);
        break;
    }
  }

  return graph;
}
