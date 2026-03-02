import type { FrameworkId, FileInventory } from './common.js';
import type { ASTStore } from '../analyzers/ast/store.js';
import type { ModuleGraph } from '../analyzers/ast/module-graph.js';

export interface AgentGraph {
  id: string;
  rootPath: string;
  primaryFramework: FrameworkId;
  secondaryFrameworks: FrameworkId[];
  agents: AgentNode[];
  tools: ToolNode[];
  prompts: PromptNode[];
  configs: ConfigNode[];
  models: ModelNode[];
  vectorDBs: VectorDBNode[];
  frameworkVersions: FrameworkInfo[];
  interAgentLinks: InterAgentLink[];
  files: FileInventory;
  permissions: PromptPermission[];
  apiEndpoints: APIEndpoint[];
  databaseAccesses: DatabaseAccess[];
  authFlows: AuthFlow[];
  permissionChecks: PermissionCheck[];
  piiReferences: PIIReference[];
  messageQueues: MessageQueue[];
  rateLimits: RateLimitConfig[];
  callGraph: CallGraphEdge[];
  astStore?: ASTStore;
  moduleGraph?: ModuleGraph;
  /** Phase 2: Typed edges between all graph nodes */
  edges: GraphEdge[];
  /** Phase 2: LLM call sites for flow analysis */
  llmCalls: LLMCallNode[];
  /** Phase 2: Data store nodes (SQL, NoSQL, vector, file) */
  dataStores: DataStoreNode[];
  /** Phase 2: External API call nodes */
  apiCalls: APICallNode[];
}

// ── Phase 2: Property graph types ────────────────────────────────────

export type GraphEdgeType =
  | 'binds_tool'           // agent → tool binding
  | 'delegates_to'         // agent → agent delegation
  | 'injects_into_prompt'  // data source → prompt assembly
  | 'calls_llm'            // prompt → LLM call
  | 'dispatches_tool'      // LLM response → tool invocation
  | 'reads_db'             // tool → database read
  | 'writes_db'            // tool → database write
  | 'calls_api'            // tool → external API
  | 'receives_input'       // user → agent entry point
  | 'returns_output'       // agent → user response
  | 'feeds_context'        // tool result → next prompt context
  | 'queries_vectordb';    // retrieval → vector DB

export interface GraphEdge {
  id: string;
  source: string;          // node ID
  target: string;          // node ID
  type: GraphEdgeType;
  /** Does untrusted data flow through this edge? */
  tainted: boolean;
  /** Is there validation/sanitization on this edge? */
  validated: boolean;
  file?: string;
  line?: number;
}

export interface LLMCallNode {
  id: string;
  model?: string;
  provider?: string;
  file: string;
  line: number;
  systemPromptRef?: string;   // reference to PromptNode.id
  hasStreaming: boolean;
}

export interface DataStoreNode {
  id: string;
  type: 'sql' | 'nosql' | 'vector' | 'file';
  name?: string;
  file: string;
  line: number;
  operations: Array<'read' | 'write' | 'delete' | 'admin'>;
  hasParameterizedQueries: boolean;
}

export interface APICallNode {
  id: string;
  url?: string;
  method?: string;
  file: string;
  line: number;
  authenticated: boolean;
  isExternal: boolean;
}

export interface ErrorHandlingInfo {
  hasTryCatch: boolean;
  hasGlobalHandler: boolean;
  hasToolErrorHandling: boolean;
  hasCircuitBreaker: boolean;
  hasRetryWithBackoff: boolean;
  hasTimeout: boolean;
}

export interface RetryConfig {
  hasMaxRetries: boolean;
  hasBackoff: boolean;
  maxRetryCount?: number;
}

export interface ResourceLimits {
  hasTokenLimit: boolean;
  hasToolCallLimit: boolean;
  hasTimeoutLimit: boolean;
  hasCostLimit: boolean;
}

export interface InterAgentLink {
  fromAgent: string;
  toAgent: string;
  communicationType: 'direct' | 'message-queue' | 'shared-memory' | 'api' | 'delegation';
  hasAuthentication: boolean;
  hasEncryption: boolean;
}

export interface AgentNode {
  id: string;
  name: string;
  framework: FrameworkId;
  file: string;
  line: number;
  systemPrompt?: string;
  tools: string[];
  modelId?: string;
  delegationTargets?: string[];
  memoryType?: string;
  maxIterations?: number;
  delegationEnabled?: boolean;
  errorHandling?: ErrorHandlingInfo;
  retryConfig?: RetryConfig;
  resourceLimits?: ResourceLimits;
  isolationLevel?: 'none' | 'process' | 'container' | 'vm';
}

export interface ModelNode {
  id: string;
  name: string;
  provider: string;
  framework: FrameworkId;
  file: string;
  line: number;
}

export interface VectorDBNode {
  id: string;
  name: string;
  framework: string;
  file: string;
  line: number;
}

export interface FrameworkInfo {
  name: string;
  version?: string;
  file: string;
}

export interface ToolNode {
  id: string;
  name: string;
  framework: FrameworkId;
  file: string;
  line: number;
  description: string;
  parameters: ToolParameter[];
  hasSideEffects: boolean;
  hasInputValidation: boolean;
  hasSandboxing: boolean;
  capabilities: ToolCapability[];
}

export interface ToolParameter {
  name: string;
  type: string;
  required: boolean;
  hasValidation: boolean;
}

export type ToolCapability =
  | 'filesystem'
  | 'network'
  | 'database'
  | 'shell'
  | 'code-execution'
  | 'email'
  | 'api'
  | 'other';

export interface PromptNode {
  id: string;
  file: string;
  line: number;
  type: 'system' | 'user' | 'template' | 'few_shot';
  content: string;
  hasInstructionGuarding: boolean;
  hasSecrets: boolean;
  hasUserInputInterpolation: boolean;
  scopeClarity: 'clear' | 'vague' | 'missing';
  permissions?: PromptPermission[];
}

export interface ConfigNode {
  id: string;
  file: string;
  type: 'env' | 'yaml' | 'json' | 'toml' | 'python_config';
  secrets: SecretReference[];
  issues: ConfigIssue[];
}

export interface SecretReference {
  key: string;
  line: number;
  isHardcoded: boolean;
}

export interface ConfigIssue {
  type: string;
  message: string;
  line: number;
}

export interface PromptPermission {
  type: 'allowed' | 'forbidden' | 'boundary';
  action: string;
  source: string;
  file: string;
  line: number;
}

export interface APIEndpoint {
  url: string;
  method?: string;
  file: string;
  line: number;
  framework: FrameworkId;
  isExternal: boolean;
}

export interface DatabaseAccess {
  type: 'sql' | 'nosql' | 'orm';
  operation: 'read' | 'write' | 'delete' | 'admin';
  table?: string;
  file: string;
  line: number;
  hasParameterizedQuery: boolean;
}

export interface AuthFlow {
  type: 'oauth2' | 'oidc' | 'api-key' | 'jwt' | 'basic' | 'bearer';
  file: string;
  line: number;
  provider?: string;
  hasTokenValidation: boolean;
  hasTokenExpiry: boolean;
}

export interface PermissionCheck {
  type: 'rbac' | 'abac' | 'scope' | 'role-check';
  file: string;
  line: number;
  roles?: string[];
  scopes?: string[];
}

export interface PIIReference {
  type: 'email' | 'phone' | 'ssn' | 'address' | 'name' | 'dob' | 'financial' | 'health' | 'generic';
  file: string;
  line: number;
  context: 'collection' | 'storage' | 'transmission' | 'logging';
  hasMasking: boolean;
  hasEncryption: boolean;
}

export interface MessageQueue {
  type: 'kafka' | 'rabbitmq' | 'sqs' | 'redis-pub-sub' | 'nats' | 'celery' | 'bull';
  file: string;
  line: number;
  topic?: string;
  hasAuthentication: boolean;
  hasEncryption: boolean;
}

export interface RateLimitConfig {
  file: string;
  line: number;
  type: 'api' | 'llm' | 'tool' | 'general';
  hasLimit: boolean;
  limitValue?: string;
}

export interface CallGraphEdge {
  caller: string;
  callee: string;
  file: string;
  line: number;
  isAsync: boolean;
  crossesFile: boolean;
  taintFlow?: 'tool-to-prompt' | 'api-to-decision';
}
