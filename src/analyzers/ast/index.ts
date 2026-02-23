export {
  isTreeSitterAvailable,
  parseCode,
  getASTLanguage,
  type SyntaxNode,
  type Tree,
  type ASTLanguage,
} from './parser.js';

export {
  getFileContent,
  getFileTree,
  getFileTreeForLang,
  clearASTCache,
} from './cache.js';

export {
  findNodes,
  findFunctionCalls,
  findImports,
  findAssignments,
  getCallArgument,
  getKeywordArgument,
  extractStringValue,
  isInDangerousContext,
  canDataFlow,
  isCommentLine,
  isInStringLiteral,
  findAllStrings,
  findTryCatchBlocks,
  findLoopConstructs,
  findEnclosingFunctionByLine,
} from './queries.js';

export {
  findDecorators,
  getDecoratedFunction,
  findFStrings,
  findClassDefinitions,
  getKeywordArgBool,
  getKeywordArgInt,
  getKeywordArgString,
  findExceptHandlers,
  findWithStatements,
} from './python.js';

export {
  findObjectProperty,
  findRouteHandlers,
  findTemplateWithInterpolation,
  findNewExpressions,
  findTryCatchStatements,
} from './typescript.js';

export {
  isExcludedContext,
  findNodeAtPosition,
  isMatchInExcludedContext,
} from './context.js';

export {
  findPatternMatches,
  canFlowWithinScope,
  checkProximityFlow,
  assessExploitability,
  crossFileTaint,
  buildFunctionSummaries,
  summarizeFunction,
  type MatchLocation,
  type Exploitability,
  type FunctionSummary,
  type CrossFileTaintResult,
} from './taint.js';

export {
  ASTStore,
  type ASTStoreEntry,
} from './store.js';

export {
  ModuleGraph,
  resolveImports,
  type ImportTarget,
} from './module-graph.js';
